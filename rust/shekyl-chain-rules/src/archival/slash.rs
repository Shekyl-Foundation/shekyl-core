// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The slash scan and the one-record slash fold (CEN-L9).
//!
//! The scan judges a snapshot taken as the epoch's scan begins and slashes
//! the live post-image (P2B-9 Pin 5). Record-shaped failures of that fold
//! are [`Corrupt`](crate::Corrupt), not refusals of the block.

use shekyl_archival_retention::{
    challenge_fire_height, challenge_seal_height, failure_window_slashable, good_through,
    holds_shard_at, slash_open_interval_to_append, BaselineObservation, ARCHIVAL_BOND_FLOOR_ATOMIC,
    FAILURE_WINDOW_N, FAILURE_WINDOW_SERVE_BUDGET, MAX_BOND_BAD_INTERVALS,
};
use shekyl_types::archival::{BondRecord, HeldShard, Holdings, SlashLogEntry, SlashedHolding};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, RecordInvariant, ViewRead};
use crate::rules::miner::closed_shards_before;
use crate::rules::recorded;
use crate::view::ChainView;

use super::{emptied, Slash};

/// Apply one slash to `record` (`db_lmdb.cpp` `apply_archival_slash_one`,
/// the record half): a complete-tree record becomes an empty compact one;
/// a compact record loses `shard`; an open bad interval is appended unless
/// one is open already (P2B-9 Pin 5 coalescing); one bond floor leaves
/// `bonded_total`. Returns the log entry and the burn.
///
/// The record-shaped `FATAL`s of the C++ are [`Corrupt`] here (CEN-L9): a
/// compact record that does not hold the shard it is slashed on, an
/// interval log at its cap when a slash must append, a `bonded_total`
/// below the floor a held shard implies.
///
/// # Errors
///
/// [`Corrupt::BondRecordInvariant`] with the invariant named.
pub(crate) fn apply_slash(
    persona: PCanonicalId,
    record: &mut BondRecord,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<Slash, Corrupt> {
    let invariant = |which| Corrupt::BondRecordInvariant { persona, which };
    let holding = match &record.holdings {
        Holdings::CompleteTree => {
            record.holdings = emptied();
            SlashedHolding::CompleteTree
        }
        Holdings::ShardSet(held) => {
            let Some(add_epoch) = held.iter().find(|h| h.shard == shard).map(|h| h.add_epoch)
            else {
                return Err(invariant(RecordInvariant::ShardNotHeld));
            };
            let remaining = held
                .iter()
                .filter(|h| h.shard != shard)
                .copied()
                .collect::<Vec<HeldShard>>();
            record.holdings = Holdings::shard_set(remaining)
                .expect("a subset of a valid held set is a valid held set");
            SlashedHolding::Shard { add_epoch }
        }
    };
    // Decided on the pre-append log: append `[E, ∞)` only when no interval
    // is open, so N same-epoch slashes append one interval, not N.
    if let Some(open) = slash_open_interval_to_append(&record.bad_intervals, epoch.to_raw()) {
        if record.bad_intervals.len() >= MAX_BOND_BAD_INTERVALS {
            return Err(invariant(RecordInvariant::IntervalLogFull));
        }
        record.bad_intervals.push(open);
    }
    let burned = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
    record.bonded_total = record
        .bonded_total
        .checked_sub(burned)
        .ok_or_else(|| invariant(RecordInvariant::BondedUnderflow))?;
    Ok(Slash {
        entry: SlashLogEntry {
            persona,
            shard,
            epoch,
            holding,
        },
        burned,
    })
}

impl super::Transition {
    /// The slash scheduler (`process_archival_slash_at_height`): every
    /// epoch above the watermark whose deadline `count` passes, ascending.
    pub(super) fn scan_slashes<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
    ) -> Result<(), ViewRead<V::Fault>> {
        let count = self.count();
        let mut next = view
            .last_settled_slash_epoch()
            .map_err(ViewRead::View)?
            .map_or(0, |last| last.to_raw().saturating_add(1));
        while count > self.schedule.slash_deadline_height(next) {
            let epoch = SettlementEpoch::from_raw(next);
            self.scan_epoch(view, epoch)?;
            self.slash_watermark = Some(epoch);
            let Some(after) = next.checked_add(1) else {
                break;
            };
            next = after;
        }
        Ok(())
    }

    /// One epoch's scan (`process_archival_slash_for_epoch`): every record
    /// in persona-key order, judged against a snapshot taken as the scan
    /// begins (module docs, *The stale eligibility copy*). A complete-tree
    /// record is challenged on every closed shard and slashed on the first
    /// failure only; a compact record on each shard it holds.
    fn scan_epoch<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<V::Fault>> {
        let universe = closed_shards_before(view, self.connecting)?.get();
        let snapshot = self.merged(view)?;
        for (persona, record) in &snapshot {
            match &record.holdings {
                Holdings::CompleteTree => {
                    for k in 0..universe {
                        let shard = ShardId::from_raw(k);
                        if self.challenge_failed(view, *persona, record, shard, epoch)? {
                            self.slash(*persona, shard, epoch)?;
                            break;
                        }
                    }
                }
                Holdings::ShardSet(held) => {
                    for h in held.as_slice() {
                        if self.challenge_failed(view, *persona, record, h.shard, epoch)? {
                            self.slash(*persona, h.shard, epoch)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// `archival_challenge_failed_at_height`: no pass, not already
    /// slashed, baseline observed, and the failure window says slash.
    fn challenge_failed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        if self.passed(view, persona, shard, epoch)? {
            return Ok(false);
        }
        let applied = view
            .slash_applied(&persona, shard, epoch)
            .map_err(ViewRead::View)?
            || self.slashes.iter().any(|s| {
                s.entry.persona == persona && s.entry.shard == shard && s.entry.epoch == epoch
            });
        if applied {
            return Ok(false);
        }
        if !self.baseline_observed(view, persona, record, shard, epoch)? {
            return Ok(false);
        }
        self.window_slashable(view, persona, record, shard, epoch)
    }

    /// `archival_baseline_observed_at_epoch`: the persona was good through
    /// `epoch`, the deadline has passed, the seal block is recorded, and
    /// the persona held the shard as of the fire height.
    fn baseline_observed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let e = epoch.to_raw();
        if !good_through(
            record.join_settlement_epoch.to_raw(),
            e,
            &record.bad_intervals,
        ) {
            return Ok(false);
        }
        if self.count() <= self.schedule.slash_deadline_height(e) {
            return Ok(false);
        }
        let h_open = self.schedule.open_height(e);
        let h_close = self.schedule.last_block(e);
        let h_seal = challenge_seal_height(h_open);
        // The seal is a recorded block's hash, so it must sit below the
        // connecting height. Under the pinned constants a passed deadline
        // puts it there always; the guard is the observability boundary
        // stated, not a reachable arm.
        if h_seal >= self.connecting.to_raw() {
            return Ok(false);
        }
        let seal = recorded(view, BlockHeight::from_raw(h_seal))?.hash;
        let h_fire = challenge_fire_height(
            h_open,
            h_close,
            seal.as_bytes(),
            persona.as_bytes(),
            shard.to_raw(),
            e,
        );
        let fire = BlockHeight::from_raw(h_fire);
        // A2 plus this block's own entries for the persona — the fire
        // height is below `connecting`, so they qualify as "after".
        let mut slashed_after = view
            .slash_log_after(&persona, fire)
            .map_err(ViewRead::View)?;
        slashed_after.extend(
            self.slashes
                .iter()
                .map(|s| s.entry)
                .filter(|entry| entry.persona == persona),
        );
        Ok(holds_shard_at(
            self.schedule,
            record,
            shard,
            fire,
            &slashed_after,
        ))
    }

    /// `archival_failure_window_slashable`: the decision epoch is a miss;
    /// walk back through the pair's continuous challengeable run, at most
    /// `FAILURE_WINDOW_N` observations, stopping once passes exceed the
    /// serve budget.
    fn window_slashable<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let window = usize::try_from(FAILURE_WINDOW_N).expect("a u32 fits a usize");
        let mut observations = vec![BaselineObservation::missed(epoch.to_raw())];
        let mut passes_seen = 0u32;
        let mut e = epoch.to_raw();
        while observations.len() < window && e > 0 {
            e -= 1;
            let earlier = SettlementEpoch::from_raw(e);
            if !self.baseline_observed(view, persona, record, shard, earlier)? {
                break;
            }
            let passed = self.passed(view, persona, shard, earlier)?;
            observations.push(if passed {
                BaselineObservation::served(e)
            } else {
                BaselineObservation::missed(e)
            });
            if passed {
                passes_seen += 1;
                if passes_seen > FAILURE_WINDOW_SERVE_BUDGET {
                    break;
                }
            }
        }
        // The sequence always holds the decision epoch and never more than
        // the window: the fold's two refusals are unreachable from here.
        Ok(failure_window_slashable(&observations)
            .expect("the gathered window holds the decision epoch and at most FAILURE_WINDOW_N observations"))
    }

    /// Apply one slash to the persona's post-image and record it.
    fn slash<VF>(
        &mut self,
        persona: PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<VF>> {
        let post = self
            .posts
            .get_mut(&persona)
            .expect("the scan slashes a record it read into the snapshot; nothing removes one");
        let slash =
            apply_slash(persona, &mut post.record, shard, epoch).map_err(ViewRead::Corrupt)?;
        post.touch();
        self.slashes.push(slash);
        Ok(())
    }
}
