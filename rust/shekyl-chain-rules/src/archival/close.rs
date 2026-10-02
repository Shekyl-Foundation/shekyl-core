// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The epoch close and the open epoch's accrual (CEN-L8, `ARW-Q3`, `ARW-Q4`).
//!
//! The close writes an `RMarket` for every shard in its snapshot, zeros
//! included, and freezes the accrual's post-image as `budget(E)`.

use shekyl_archival_retention::{
    epoch_close_compute, CreditPair, EpochCloseBond, EpochCloseInputs, EpochCloseShard,
};
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
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.7, on `SHT-Q2`'s partition). The close's
/// age operand (`EpochCloseShard::freeze_height`).
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

        // The snapshot's shards: every closed shard (ARW-Q4), with the
        // close height its age is measured from.
        let universe = closed_shards_before(view, self.connecting)?.get();
        let mut shards = Vec::new();
        for k in 0..universe {
            // `universe > 0` needs a fold of at least `W`, so a parent
            // exists; `saturating_sub` only spells that.
            let parent = BlockHeight::from_raw(self.connecting.to_raw().saturating_sub(1));
            shards.push(EpochCloseShard {
                shard_id: k,
                has_segment: true,
                freeze_height: shard_close_height(view, ShardId::from_raw(k), parent)?.to_raw(),
            });
        }

        // The snapshot's bonds: every record with a credit at `epoch`, in
        // persona-key order, after this block's slashes; a credit on a
        // shard beyond the closed count names a shard without a segment
        // (the C++'s `has_segment = false`: it counts, it has no age).
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
                        shards.push(EpochCloseShard {
                            shard_id: shard,
                            has_segment: false,
                            freeze_height: 0,
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
