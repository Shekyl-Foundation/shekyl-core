// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The epoch close and the open epoch's accrual (CEN-L8, `ARW-Q3`, `ARW-Q4`).
//!
//! The close writes an `RMarket` for every shard in its snapshot, zeros
//! included, and freezes the accrual's post-image as `budget(E)`.

use core::marker::PhantomData;

use shekyl_archival_retention::{
    epoch_close_compute, CreditPair, EpochCloseBond, EpochCloseInputs, EpochCloseShard, ShardClose,
};
use shekyl_economics::ClosedShardCount;
use shekyl_types::archival::{BondRecord, RMarket, SigmaWorkMilli};
use shekyl_types::{
    shard_start, ArchivalLength, BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, ViewRead};
use crate::rules::miner::{closed_shards_before, closed_shards_through};
use crate::rules::recorded;
use crate::view::ChainView;

use super::{Accrual, EpochClose};

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
/// One assembly for two readers. The close (`Transition::close`) freezes
/// what it computes over this; the claim verify (CEN-J23's per-epoch
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
}

/// Assemble the [`EpochSnapshot`] for the epoch whose close read
/// `universe`.
///
/// `records` are the bond records the reader holds — the close passes its
/// merged post-images, the verify passes A11's rows — and `credited`
/// names the shards each persona has a credit on at the epoch, ascending
/// and distinct ([`recorded_credits`], with the block's own credits added
/// by the close). A persona whose credited set is empty is not in the
/// snapshot: it earned nothing at `E`, and a bond with no pair would be a
/// zero term `epoch_close_compute` never asked for.
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
    records: &'r [(PCanonicalId, BondRecord)],
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
    for (persona, record) in records {
        let shards_credited = credited(persona)?;
        if shards_credited.is_empty() {
            continue;
        }
        let bond_idx = bonds.len();
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
    })
}

/// The shards `persona` has a **recorded** credit on at `epoch`, ascending
/// and distinct: A4 narrows the candidates to shards served through
/// `epoch`, A5 confirms a pass at `epoch` on each. The verify's whole
/// answer (a closed epoch's credits are all recorded); the close adds the
/// closing block's own on top.
///
/// # Errors
///
/// The view's.
pub(crate) fn recorded_credits<'id, V: ChainView<'id>>(
    view: &V,
    persona: PCanonicalId,
    epoch: SettlementEpoch,
) -> Result<Vec<u64>, ViewRead<V::Fault>> {
    let mut out = Vec::new();
    for served in view.served_shards(&persona).map_err(ViewRead::View)? {
        if served.last_served >= epoch
            && view
                .pass_count(&persona, served.shard, epoch)
                .map_err(ViewRead::View)?
                .any()
        {
            out.push(served.shard.to_raw());
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
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

    /// The epoch close (`process_archival_epoch_close_at_height`), when
    /// `count` is a settlement boundary.
    pub(super) fn close<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        accrual: Accrual,
    ) -> Result<Option<EpochClose>, ViewRead<V::Fault>> {
        // The schedule's edge is `u64` (Phase 2g); the count is decoded
        // once, as the count it is.
        let count = self.count().to_raw();
        let Some(closing) = self.schedule.close_due_at_height(count) else {
            return Ok(None);
        };
        let epoch = SettlementEpoch::from_raw(closing);
        // `count = (E + 1) · SEB` puts `connecting` in `E`, so the open
        // epoch's accrual is the closing epoch's budget.
        debug_assert_eq!(accrual.epoch, epoch, "the close's epoch is the open epoch");

        // The snapshot: every closed shard (ARW-Q4) at the close height its
        // age is measured from — the universe is one read, the count and
        // the parent it was read through — and every record with a credit
        // at `epoch`, in persona-key order, after this block's slashes. The
        // verify re-gathers this same shape from the same universe when a
        // claim cites `epoch` (CEN-J23).
        let universe = ClosedUniverse::before(view, self.connecting)?;
        let records = self.merged(view)?;
        let EpochSnapshot {
            bonds,
            shards,
            pairs,
        } = gather_epoch_snapshot(view, &universe, &records, |persona| {
            self.credited_shards(view, *persona, epoch)
        })?;

        let inputs = EpochCloseInputs::under_schedule(
            self.schedule,
            closing,
            count,
            &bonds,
            &shards,
            &pairs,
        );
        let result = epoch_close_compute(&inputs)
            .expect("every credit pair indexes the bonds and shards it was built from");
        let r_market = shards
            .iter()
            .zip(result.r_market_by_shard)
            .map(|(shard, r)| (ShardId::from_raw(shard.shard_id), RMarket::from_raw(r)))
            .collect();
        Ok(Some(EpochClose {
            epoch,
            r_market,
            sigma_work: SigmaWorkMilli::from_raw(result.sigma_work_milli),
            budget: accrual.total,
        }))
    }

    /// The shards `persona` has a credit on at `epoch`, ascending and
    /// distinct: [`recorded_credits`] and this block's.
    fn credited_shards<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        epoch: SettlementEpoch,
    ) -> Result<Vec<u64>, ViewRead<V::Fault>> {
        let mut out = recorded_credits(view, persona, epoch)?;
        out.extend(
            self.serve_credits
                .iter()
                .filter(|k| k.persona == persona && k.epoch == epoch)
                .map(|k| k.shard.to_raw()),
        );
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}
