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
use shekyl_types::archival::{RMarket, SigmaWorkMilli};
use shekyl_types::{
    shard_start, ArchivalLength, BlockHeight, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, ViewRead};
use crate::rules::miner::closed_shards_before;
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
                Ok(ShardClose::ClosedAt(
                    shard_close_height(view, shard, parent)?.to_raw(),
                ))
            } else {
                Ok(ShardClose::Open)
            }
        }
    }
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
        let count = self.count();
        let Some(closing) = self.schedule.close_due_at_height(count) else {
            return Ok(None);
        };
        let epoch = SettlementEpoch::from_raw(closing);
        // `count = (E + 1) · SEB` puts `connecting` in `E`, so the open
        // epoch's accrual is the closing epoch's budget.
        debug_assert_eq!(accrual.epoch, epoch, "the close's epoch is the open epoch");

        // The snapshot's shards: every closed shard (ARW-Q4), with the
        // close height its age is measured from. The universe is one read:
        // the count and the parent it was read through.
        let universe = ClosedUniverse::before(view, self.connecting)?;
        let mut shards = Vec::new();
        for k in 0..universe.count().get() {
            // Every id in the prefix is below the count, so this arm is
            // `ClosedAt`. The assert is that fact, checked.
            let close = shard_close(view, ShardId::from_raw(k), &universe)?;
            debug_assert!(matches!(close, ShardClose::ClosedAt(_)));
            shards.push(EpochCloseShard { shard_id: k, close });
        }

        // The snapshot's bonds: every record with a credit at `epoch`, in
        // persona-key order, after this block's slashes; a credit on a
        // shard beyond the closed count names a shard still open (it
        // counts toward scarcity, it has no age).
        let snapshot = self.merged(view)?;
        let mut bonds = Vec::new();
        let mut pairs = Vec::new();
        for (persona, record) in &snapshot {
            let credited = self.credited_shards(view, *persona, epoch)?;
            if credited.is_empty() {
                continue;
            }
            let bond_idx = bonds.len();
            bonds.push(EpochCloseBond {
                join_settlement_epoch: record.join_settlement_epoch.to_raw(),
                is_foundation_complete_tree: record.is_complete_tree(),
                bad_intervals: &record.bad_intervals,
            });
            for shard in credited {
                let shard_idx = match shards.iter().position(|s| s.shard_id == shard) {
                    Some(idx) => idx,
                    None => {
                        // Absent from the prefix, so the id is at or beyond
                        // the count and this arm is `Open`.
                        debug_assert!(shard >= universe.count().get());
                        let close = shard_close(view, ShardId::from_raw(shard), &universe)?;
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
    /// distinct: recorded (A4 narrows the candidates, A5 confirms) and
    /// this block's.
    fn credited_shards<'id, V: ChainView<'id>>(
        &self,
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
