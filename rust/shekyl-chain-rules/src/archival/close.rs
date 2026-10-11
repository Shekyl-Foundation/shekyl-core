// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The epoch close and the open epoch's accrual (CEN-L8, `ARW-Q3`, `ARW-Q4`).
//!
//! The close writes an `RMarket` for every shard in its snapshot, zeros
//! included, and freezes the accrual's post-image as `budget(E)`.

use core::marker::PhantomData;
use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::{
    epoch_close_compute, CreditPair, EpochCloseBond, EpochCloseInputs, EpochCloseShard,
    SettlementSchedule, ShardClose,
};
use shekyl_economics::ClosedShardCount;
use shekyl_types::archival::{
    BondRecord, RMarket, SettlementOutcome, SettlementRow, SigmaWorkMilli,
};
use shekyl_types::{
    shard_start, ArchivalLength, BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, ViewRead};
use crate::rules::miner::{closed_shards_before, closed_shards_through};
use crate::rules::recorded;
use crate::view::ChainView;

use super::{Accrual, EpochClose, EpochGather};

/// The height at which closed shard `shard` closed, for a non-decreasing
/// archival fold: the smallest `h ≤ parent` with
/// `cumulative_archival_len(h) ≥ (shard + 1) · W`
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.7, on `SHT-Q2`'s partition). The height
/// inside `g(age)`'s operand, [`ShardClose::ClosedAt`]. [`shard_close`]
/// decides which shards have one, and the height it searches is the parent
/// [`ClosedUniverse`] carries — the height [`closed_shards_before`] read —
/// not a count named beside it.
///
/// Public for the one reason [`closed_shards_before`] is: the producer
/// composing a close reads the operand here, never from a second copy of
/// the definition. That producer is in flight; the close below is the
/// caller that exists today.
///
/// SI-13, enforced when the store connects each block, is the monotone
/// belt. Under it the landing height is the first to reach the shard's
/// end. [`Corrupt::ShardCloseUnplaced`] is that landing height failing to
/// carry the end: the shard is still open through `parent`, or the fold
/// fell below the end and stayed down.
///
/// # Errors
///
/// The view's fault, or [`Corrupt::ShardCloseUnplaced`].
pub fn shard_close_height<'id, V: ChainView<'id>>(
    view: &V,
    shard: ShardId,
    parent: BlockHeight,
) -> Result<BlockHeight, ViewRead<V::Fault>> {
    let unplaced = |at: u64| {
        ViewRead::Corrupt(Corrupt::ShardCloseUnplaced {
            shard,
            at: BlockHeight::from_raw(at),
        })
    };
    // The shard's end, `(shard + 1) · W`. A closed shard's end is at most
    // the parent's fold, so one that does not fit was never closed.
    let target = shard
        .to_raw()
        .checked_add(1)
        .and_then(|next| shard_start(ShardId::from_raw(next)))
        .ok_or_else(|| unplaced(parent.to_raw()))?;
    let fold_through = |h: u64| -> Result<ArchivalLength, ViewRead<V::Fault>> {
        Ok(recorded(view, BlockHeight::from_raw(h))?.cumulative_archival_len)
    };
    let (mut lo, mut hi) = (0u64, parent.to_raw());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if fold_through(mid)? >= target {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    // Under a non-decreasing fold the landing height is the first to reach
    // the end. A landing still short of it is an open shard, or a fold that
    // fell below the end and stayed down.
    if fold_through(lo)? < target {
        return Err(unplaced(lo));
    }
    Ok(BlockHeight::from_raw(lo))
}

/// Invariant in `'id`: neither shrinks nor grows, so a universe read
/// against one view is not a universe for any other view. The same brand
/// `ChainValid` carries.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// Where [`closed_shards_before`] put the closed-shard count, and the
/// parent that read went through.
///
/// One value, produced only by [`ClosedUniverse::before`]. The count and
/// its parent cannot be supplied apart, and the `'id` brand cannot be
/// moved onto another view: the failure Copilot named, a raw `universe`
/// that selects `Open` or `ClosedAt` before the fold is consulted, has no
/// field to be written into. Genesis (`connecting == 0`) is its own arm —
/// [`closed_shards_before`] returns [`ClosedShardCount::ZERO`] there and
/// there is no parent to search.
///
/// # Closed alone, and why that is enough here
///
/// Two bounds exist on this file's reads, one shard-count apart in the
/// common case and `reorg_cap` blocks apart at the frontier: *closed*
/// (this universe) and *closed and final* ([`closed_and_final`]). Which
/// one a read takes is decided by what the read's result becomes, not by
/// which function is nearer (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`
/// §7.4): **a recomputed operand may be bounded by closed; a persisted
/// commitment must be bounded by closed and final.**
///
/// `g(age)`'s operand is recomputed. [`shard_close`] is re-derived from
/// the fold on every judgement, and nothing it returns is written down
/// as a fact about the shard. If a reorg within `reorg_cap` moves the
/// block that reached a shard's end, the next judgement reads the moved
/// fold and derives the moved close — the operand follows the chain
/// rather than having been committed against it, so a close that is not
/// yet final costs nothing to have read. Bounding it by final would only
/// delay a shard's age by `reorg_cap` blocks on every judgement, for a
/// reorg that recomputation already absorbs.
///
/// A bond's held set is the other kind: the admitting block writes the
/// shard into a record that later blocks read back as settled. That is a
/// commitment, and CEN-J15 bounds it by [`closed_and_final`]. The two
/// bounds are not interchangeable at either site. The reason is written
/// here, beside the bound, because DRS-E4's one-apart defects
/// (`HEIGHT_SEMANTICS.md`, the close height and the slash-log key) were
/// each a reader who found two nearby quantities and no reason, and
/// picked by proximity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedUniverse<'id> {
    state: UniverseState,
    _brand: Brand<'id>,
}

/// Private so the two arms stay the only ways to hold a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniverseState {
    /// `connecting` is genesis. The count is zero; no shard has closed.
    Genesis,
    /// `count` is [`closed_shards_before`] at the block connecting after
    /// `parent`, which is the height that function read.
    At {
        parent: BlockHeight,
        count: ClosedShardCount,
    },
}

impl ClosedUniverse<'_> {
    /// The closed universe for a block connecting at `connecting`:
    /// [`closed_shards_before`] of that height, paired with the parent the
    /// count was read through.
    ///
    /// # Errors
    ///
    /// As [`closed_shards_before`].
    pub fn before<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
    ) -> Result<ClosedUniverse<'id>, ViewRead<V::Fault>> {
        let count = closed_shards_before(view, connecting)?;
        let state = match connecting.to_raw().checked_sub(1) {
            // The same subtraction `closed_shards_before` makes. Genesis
            // returns `ZERO` and has no parent; a later connecting stores
            // the count beside the parent that function read.
            None => {
                debug_assert_eq!(count, ClosedShardCount::ZERO);
                UniverseState::Genesis
            }
            Some(raw) => UniverseState::At {
                parent: BlockHeight::from_raw(raw),
                count,
            },
        };
        Ok(ClosedUniverse {
            state,
            _brand: PhantomData,
        })
    }

    /// The universe of shards **closed and final** for a block connecting
    /// at `connecting`: the bound a persisted commitment takes (type
    /// docs). The emission gather reads this one
    /// (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D11f`): its `RMarket` rows are
    /// what CEN-J15 prices a join by, and a shard that closed inside the
    /// last `reorg_cap` blocks is not yet bondable, so a row for it would
    /// price joins on a shard nobody can hold.
    ///
    /// It is [`closed_and_final`] taken over every shard at once, by that
    /// predicate's own arithmetic. A shard is final as of the parent `p`
    /// iff its close height is at most `p − reorg_cap`, which is to say it
    /// is closed for a block connecting `reorg_cap` lower. So this is
    /// [`Self::before`] at `connecting − reorg_cap`, and empty while the
    /// chain is not `reorg_cap` deep.
    ///
    /// # Errors
    ///
    /// As [`Self::before`].
    pub fn final_before<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        reorg_cap: BlockCount,
    ) -> Result<ClosedUniverse<'id>, ViewRead<V::Fault>> {
        match connecting.checked_sub_count(reorg_cap) {
            Some(lowered) => Self::before(view, lowered),
            None => Ok(ClosedUniverse {
                state: UniverseState::Genesis,
                _brand: PhantomData,
            }),
        }
    }

    /// The closed-shard count. Zero at genesis.
    #[must_use]
    pub const fn count(self) -> ClosedShardCount {
        match self.state {
            UniverseState::Genesis => ClosedShardCount::ZERO,
            UniverseState::At { count, .. } => count,
        }
    }
}

/// `g(age)`'s operand for one shard against a [`ClosedUniverse`] (`SHT-Q2`).
///
/// A shard below the universe's count is [`ShardClose::ClosedAt`] the
/// height [`shard_close_height`] places at the universe's parent. A shard
/// at or beyond the count is [`ShardClose::Open`] and ages nothing. No
/// height closes a shard — only the fold reaching the shard's end does —
/// so this is `SHT-Q1`'s falsifier (i) on the Rust reward path.
/// `ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F's `g(age)` row.
///
/// The close below is the caller that exists today. The producer still in
/// flight reads the operand here, with a universe from [`ClosedUniverse::before`],
/// rather than a second copy of the comparison.
///
/// # Errors
///
/// Those of [`shard_close_height`] for a closed shard.
pub fn shard_close<'id, V: ChainView<'id>>(
    view: &V,
    shard: ShardId,
    universe: &ClosedUniverse<'id>,
) -> Result<ShardClose, ViewRead<V::Fault>> {
    match universe.state {
        UniverseState::Genesis => Ok(ShardClose::Open),
        UniverseState::At { parent, count } => {
            if shard.to_raw() < count.get() {
                Ok(ShardClose::ClosedAt(shard_close_height(
                    view, shard, parent,
                )?))
            } else {
                Ok(ShardClose::Open)
            }
        }
    }
}

/// Whether `shard` is **closed and final** as of `at` — the bound a
/// persisted commitment to a shard takes (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`
/// §8.0 input 4; §7.4's discriminator is on [`ClosedUniverse`]).
///
/// `at` is the last height whose state is read. CEN-J15 passes the
/// admitting block's parent; Slice C's `h_open(E)` will pass its own.
/// Both operands read the cumulative archival fold and nothing else:
///
/// - *closed*: `shard < closed_shards_through(at)` — the fold through
///   `at` has reached the shard's end;
/// - *final*: `shard_close_height(shard) + reorg_cap ≤ at` — the block
///   that reached it is at least `reorg_cap` deep below `at`.
///
/// `reorg_cap` is the in-force [`RuleSet::reorg_cap`](crate::RuleSet::reorg_cap),
/// the reorg-cap job — never the pass-anchor setting it inherits its
/// value from today (`docs/FOLLOWUPS.md`, the count-versus-height row's
/// pass-anchor item). A shard closing at `c` is therefore `false` for
/// every `at < c + reorg_cap` — `at = c` included, the close itself being
/// the newest block — and `true` from `c + reorg_cap` on; monotone in
/// `at`. No slash state is read, so a same-block slash has no side here,
/// and nothing at `at + 1` can change the answer. An open shard is
/// `false` at every height. A close height that `reorg_cap` carries past
/// `u64::MAX` is not final at any representable `at`.
///
/// # Errors
///
/// The view's fault from either operand's read, or
/// [`Corrupt::ShardCloseUnplaced`] if a shard the count says is closed
/// has no height that closed it — a fold SI-13 refuses.
pub fn closed_and_final<'id, V: ChainView<'id>>(
    view: &V,
    shard: ShardId,
    at: BlockHeight,
    reorg_cap: BlockCount,
) -> Result<bool, ViewRead<V::Fault>> {
    if shard.to_raw() >= closed_shards_through(view, at)?.get() {
        return Ok(false);
    }
    let closed_at = shard_close_height(view, shard, at)?;
    Ok(closed_at
        .checked_add(reorg_cap)
        .is_some_and(|final_from| final_from <= at))
}

/// The as-of-`E` snapshot: the operands [`epoch_close_compute`] folds
/// `Σwork(E)` and every `R_market(E, shard)` from, assembled by
/// [`gather_epoch_snapshot`].
///
/// One assembly for two readers. The slash pass (`Transition::gather`)
/// freezes what it computes over this; the claim verify (CEN-J23's per-epoch
/// gather, CEN-J25's `EmissionEpochSource`) recomputes `Σwork(E)` over the
/// same shape and compares it to the frozen row. The C++ reaches the same
/// end by having the close and the verify call one LMDB gather (WS-1 §5.5);
/// here the one function is this type's constructor, so the two readers
/// cannot fold different index orders or different `Open`/`ClosedAt`
/// operands and only find out at the compare.
pub(crate) struct EpochSnapshot<'r> {
    /// Every record with a credit at `E`, in the order `records` gave them
    /// (persona-key order from A11 or from the transition's merge).
    pub(crate) bonds: Vec<EpochCloseBond<'r>>,
    /// Every closed shard first, `0..count`, then each open shard some
    /// bond holds a credit on, in first-encounter order.
    pub(crate) shards: Vec<EpochCloseShard>,
    /// One pair per `(bond, credited shard)`, bonds outer, shards ascending.
    pub(crate) pairs: Vec<CreditPair>,
    /// The claimant's index into `bonds`, when the gather was asked for
    /// one and that persona has a credit at `E` — the verify's
    /// `EmissionEpochSource::claimant_bond_idx` (the C++ gather sets it
    /// where `p_canonical_id` matches, `db_lmdb.cpp:7648`). `None` for the
    /// close, which names no claimant, and for a claimant with no credit
    /// at `E`: it is not in the snapshot, and the verify says so.
    pub(crate) claimant_bond_idx: Option<usize>,
}

/// Assemble the [`EpochSnapshot`] for the epoch whose close read
/// `universe`.
///
/// `records` are the bond records the reader holds, borrowed and in
/// persona-key order — the slash pass lends its post-images, the verify
/// A11's rows — and `credited` names the shards each persona has a
/// credit on at the epoch, ascending and distinct: its Served settlement
/// rows (`SO-D11a`), pending in the pass and held by [`ServedAt`] in the
/// verify. A persona whose credited set is empty is not in the snapshot:
/// it earned nothing at `E`, and a bond with no pair would be a zero term
/// `epoch_close_compute` never asked for.
///
/// `claimant` is the persona the verify is judging a claim for, whose
/// index among the bonds it needs ([`EpochSnapshot::claimant_bond_idx`]);
/// the close passes `None`.
///
/// The shards are every closed shard (`ARW-Q4`: zeros included, the close
/// writes an `RMarket` for each) at the close height the universe places,
/// then every open shard a credit names — it counts toward scarcity and
/// has no age (`SHT-Q2`).
///
/// # Errors
///
/// The view's, from `credited` or from [`shard_close`].
pub(crate) fn gather_epoch_snapshot<'id, 'r, V: ChainView<'id>>(
    view: &V,
    universe: &ClosedUniverse<'id>,
    records: impl IntoIterator<Item = (&'r PCanonicalId, &'r BondRecord)>,
    claimant: Option<&PCanonicalId>,
    mut credited: impl FnMut(&PCanonicalId) -> Result<Vec<u64>, ViewRead<V::Fault>>,
) -> Result<EpochSnapshot<'r>, ViewRead<V::Fault>> {
    let mut shards = Vec::new();
    for k in 0..universe.count().get() {
        // Every id in the prefix is below the count, so this arm is
        // `ClosedAt`. The assert is that fact, checked.
        let close = shard_close(view, ShardId::from_raw(k), universe)?;
        debug_assert!(matches!(close, ShardClose::ClosedAt(_)));
        shards.push(EpochCloseShard { shard_id: k, close });
    }

    let mut bonds = Vec::new();
    let mut pairs = Vec::new();
    let mut claimant_bond_idx = None;
    for (persona, record) in records {
        let shards_credited = credited(persona)?;
        if shards_credited.is_empty() {
            continue;
        }
        let bond_idx = bonds.len();
        if claimant == Some(persona) {
            claimant_bond_idx = Some(bond_idx);
        }
        bonds.push(EpochCloseBond {
            join_settlement_epoch: record.join_settlement_epoch.to_raw(),
            is_foundation_complete_tree: record.is_complete_tree(),
            bad_intervals: &record.bad_intervals,
        });
        for shard in shards_credited {
            let shard_idx = match shards.iter().position(|s| s.shard_id == shard) {
                Some(idx) => idx,
                None => {
                    // Absent from the prefix, so the id is at or beyond
                    // the count and this arm is `Open`.
                    debug_assert!(shard >= universe.count().get());
                    let close = shard_close(view, ShardId::from_raw(shard), universe)?;
                    debug_assert!(matches!(close, ShardClose::Open));
                    shards.push(EpochCloseShard {
                        shard_id: shard,
                        close,
                    });
                    shards.len() - 1
                }
            };
            pairs.push(CreditPair {
                bond_idx,
                shard_idx,
            });
        }
    }
    Ok(EpochSnapshot {
        bonds,
        shards,
        pairs,
        claimant_bond_idx,
    })
}

/// The open epoch's accruing budget after adding this block's inflow
/// (§3.5). CEN-L8's overflow clause: a total that does not fit is a fold
/// that ran ahead of the chain, [`Corrupt::AccrualOverflow`].
///
/// # Errors
///
/// [`Corrupt::AccrualOverflow`] on overflow.
pub(crate) fn accrue(
    accrued: AtomicUnits,
    inflow: AtomicUnits,
    epoch: SettlementEpoch,
) -> Result<AtomicUnits, Corrupt> {
    accrued
        .checked_add(inflow)
        .ok_or(Corrupt::AccrualOverflow { epoch })
}

impl super::Transition {
    // ---- phase 9: the block's own writes ---------------------------------

    /// The accrual post-image (§3.5): what the open epoch has accrued so
    /// far plus this block's inflow.
    pub(super) fn accrue<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        inflow: AtomicUnits,
    ) -> Result<Accrual, ViewRead<V::Fault>> {
        let accrued = view
            .budget_accruing(self.epoch)
            .map_err(ViewRead::View)?
            .unwrap_or(AtomicUnits::ZERO);
        let total = accrue(accrued, inflow, self.epoch).map_err(ViewRead::Corrupt)?;
        Ok(Accrual {
            epoch: self.epoch,
            total,
        })
    }

    /// The epoch close, when `count` is a settlement boundary: it freezes
    /// the open epoch's accrual as `budget(E)` and nothing else. The
    /// epoch's co-holder counts and `Σwork` are folded over its settlement
    /// rows, which the slash pass writes an epoch later
    /// ([`Self::gather`]; `SO-D11`).
    pub(super) fn close(&self, accrual: Accrual) -> Option<EpochClose> {
        // The schedule's edge is `u64` (Phase 2g); the count is decoded
        // once, as the count it is.
        let closing = self.schedule.close_due_at_height(self.count().to_raw())?;
        let epoch = SettlementEpoch::from_raw(closing);
        // `count = (E + 1) · SEB` puts `connecting` in `E`, so the open
        // epoch's accrual is the closing epoch's budget.
        debug_assert_eq!(accrual.epoch, epoch, "the close's epoch is the open epoch");
        Some(EpochClose {
            epoch,
            budget: accrual.total,
        })
    }

    /// The emission gather of `epoch`, run by the slash pass after it has
    /// settled the epoch and slashed on it (`SO-D8c`, `SO-D11`).
    ///
    /// A pair is credited iff its settlement row for the epoch is Served
    /// (`SO-D11a`). The records are the transition's post-images, borrowed
    /// where they sit: the state as of the pass (`SO-D11f`), and
    /// specifically **after the epoch's own slashes**. The caller has run
    /// [`Self::merged`] in this pass, so the map holds every recorded bond.
    /// A record slashed for `epoch` has the bad interval that opens at
    /// `epoch`, so it is not in the epoch's market, here or when a claim's
    /// verify re-reads the record later. Gathering before the slashes would
    /// freeze a `Σwork` no later reader could reproduce whenever a record
    /// Served on one shard was slashed on another in the same pass.
    ///
    /// It runs for every settled epoch, Served pairs or none: an epoch
    /// with none gets a zero for each shard and a zero `Σwork` (`ARW-Q4`),
    /// and that row is what lets a claim cite the epoch at all.
    pub(super) fn gather<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<V::Fault>> {
        let universe = gather_universe(view, self.schedule, self.reorg_cap, epoch)?;
        let settled = &self.settled;
        let records = self
            .posts
            .iter()
            .map(|(persona, post)| (persona, &post.record));
        let snapshot = gather_epoch_snapshot(view, &universe, records, None, |persona| {
            Ok(settled_for(settled, epoch, persona)
                .filter(|(_, row)| row.outcome() == SettlementOutcome::Served)
                .map(|(shard, _)| shard.to_raw())
                .collect())
        })?;
        let gathered = fold_epoch(self.schedule, epoch, &snapshot);
        self.gathers.push(gathered);
        Ok(())
    }
}

/// Rows this pass has settled for one persona in one epoch, in shard order.
///
/// The map is keyed `(epoch, persona, shard)`, so one persona's rows are
/// the range that starts at [`ShardId::ZERO`]. The slash scan reads every
/// row; the gather keeps the ones whose outcome is Served.
pub(super) fn settled_for<'a>(
    settled: &'a BTreeMap<(SettlementEpoch, PCanonicalId, ShardId), SettlementRow>,
    epoch: SettlementEpoch,
    persona: &PCanonicalId,
) -> impl Iterator<Item = (ShardId, &'a SettlementRow)> + 'a {
    let persona = *persona;
    settled
        .range((epoch, persona, ShardId::ZERO)..)
        .take_while(move |((row_epoch, row_persona, _), _)| {
            *row_epoch == epoch && *row_persona == persona
        })
        .map(|((_, _, shard), row)| (*shard, row))
}

/// The universe `epoch`'s emission gather reads: every shard **closed and
/// final** as of the block that runs the epoch's slash pass
/// ([`ClosedUniverse::final_before`]; `SO-D11f`).
///
/// One function for the two readers of the gather. The pass freezes what
/// it folds over this; the claim verify (CEN-J23) re-gathers over it and
/// CEN-J25 compares. The height is the epoch's slash deadline — the
/// connecting height of the first block whose count passes it, which is
/// the block that settles the epoch — read off the schedule and not off
/// whichever block the caller is in, so the two cannot name different
/// universes.
///
/// # Errors
///
/// As [`ClosedUniverse::before`].
pub(crate) fn gather_universe<'id, V: ChainView<'id>>(
    view: &V,
    schedule: SettlementSchedule,
    reorg_cap: BlockCount,
    epoch: SettlementEpoch,
) -> Result<ClosedUniverse<'id>, ViewRead<V::Fault>> {
    let settling = BlockHeight::from_raw(schedule.slash_deadline_height(epoch.to_raw()));
    ClosedUniverse::final_before(view, settling, reorg_cap)
}

/// The Served shards of the personas a claim gathers over, for every epoch
/// the claim cites.
///
/// One [`ChainView::served_at`] per persona: the store hops that persona's
/// shards once and point-reads every cited epoch. Each per-epoch snapshot
/// then looks the persona up. The slash pass does not use this. Its rows
/// are still pending, and it reads them from the transition's own map.
pub(crate) struct ServedAt {
    by_persona: BTreeMap<PCanonicalId, BTreeMap<SettlementEpoch, Vec<ShardId>>>,
}

impl ServedAt {
    /// Read `epochs` for each persona. An empty `epochs` reads nothing.
    ///
    /// # Errors
    ///
    /// The view's, from [`ChainView::served_at`].
    pub(crate) fn read<'id, V: ChainView<'id>>(
        view: &V,
        personas: impl IntoIterator<Item = PCanonicalId>,
        epochs: &BTreeSet<SettlementEpoch>,
    ) -> Result<Self, ViewRead<V::Fault>> {
        let mut by_persona = BTreeMap::new();
        for persona in personas {
            let served = view.served_at(&persona, epochs).map_err(ViewRead::View)?;
            if served.is_empty() {
                continue;
            }
            by_persona.insert(persona, served);
        }
        Ok(Self { by_persona })
    }

    /// Shards `persona` was Served on at `epoch`, ascending. Empty when
    /// that persona has none at `epoch`.
    #[must_use]
    pub(crate) fn shards(&self, persona: &PCanonicalId, epoch: SettlementEpoch) -> &[ShardId] {
        self.by_persona
            .get(persona)
            .and_then(|by_epoch| by_epoch.get(&epoch))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Fold an [`EpochSnapshot`] into the epoch's gather: each shard's
/// co-holder count and `Σwork(E)`, with ages read at the epoch's close
/// height under `schedule`.
fn fold_epoch(
    schedule: SettlementSchedule,
    epoch: SettlementEpoch,
    snapshot: &EpochSnapshot<'_>,
) -> EpochGather {
    let close_height = schedule
        .close_height(epoch.to_raw())
        .expect("a settled epoch's close height fits: its slash deadline, which is later, did");
    let inputs = EpochCloseInputs::under_schedule(
        schedule,
        epoch.to_raw(),
        close_height,
        &snapshot.bonds,
        &snapshot.shards,
        &snapshot.pairs,
    );
    let result = epoch_close_compute(&inputs)
        .expect("every credit pair indexes the bonds and shards it was built from");
    let r_market = snapshot
        .shards
        .iter()
        .zip(result.r_market_by_shard)
        .map(|(shard, r)| (ShardId::from_raw(shard.shard_id), RMarket::from_raw(r)))
        .collect();
    EpochGather {
        epoch,
        r_market,
        sigma_work: SigmaWorkMilli::from_raw(result.sigma_work_milli),
    }
}
