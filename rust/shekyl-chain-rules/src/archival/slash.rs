// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The slash pass: settle the epoch, then slash on what it settled
//! (CEN-L9; `ARCHIVAL_SETTLEMENT_WRITER.md` §14, `SO-D10`).
//!
//! # Order inside one epoch
//!
//! 1. **Settle.** Read the epoch's issued-draw index whole, check it
//!    against the epoch's running digest, and fold each pair's counted
//!    draws into its row ([`settle_pair`]). The rows go into the delta; the
//!    store writes them ahead of the slashes (`SO-D7`).
//! 2. **Slash.** A pair whose row for the epoch is Missed is judged on its
//!    failure window. Nothing else is a candidate: Served, NonObservation
//!    and no row at all are each "no slash here".
//!
//! With no draw issued — the state until the secret draw lands
//! (`SO-D10a`) — step 1 writes nothing and step 2 slashes nothing.
//!
//! # Which draws count for a pair
//!
//! A draw at `h` counts only if the pair held its shard in the state after
//! `h` connected (specification §9.3 step 2), read as [`holds_shard_at`]
//! reads it: slashes strictly above `h`. A pair that stopped holding the
//! shard during the epoch is not charged for the draws that followed. The
//! digest check covers every stored draw, counted or not, because that is
//! what was folded when each was indexed.
//!
//! # The window (`SO-D10b`)
//!
//! From a Missed epoch, [`settlement_window_slashable`] gathers the pair's
//! earlier observations. What counts as an observation, where the walk
//! stops, and the retention horizon ruled 2026-10-09 live with the
//! arithmetic in `shekyl-archival-retention::failure_window`. This pass
//! supplies the standing predicate ([`good_through`]) and the settlement-row
//! read, and the floor ([`settlement_retention_floor`]) the gather stops at.
//!
//! # The stale snapshot
//!
//! The scan judges a snapshot taken as the epoch's scan begins and slashes
//! the live post-image (P2B-9 Pin 5). Record-shaped failures of that fold
//! are [`Corrupt`](crate::Corrupt), not refusals of the block.

use core::num::NonZeroU64;
use std::collections::BTreeMap;

use shekyl_archival_retention::settlement_select::{
    issued_draw_term, settle_pair, SETTLEMENT_BEACON_LEN,
};
use shekyl_archival_retention::{
    good_through, holds_shard_at, settlement_retention_floor, settlement_window_slashable,
    slash_open_interval_to_append, ARCHIVAL_BOND_FLOOR_ATOMIC, MAX_BOND_BAD_INTERVALS,
};
use shekyl_types::archival::{
    BondRecord, HeldShard, Holdings, IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome,
    SettlementRow, SlashLogEntry, SlashedHolding,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, RecordInvariant, SettlementCheck, ViewRead};
use crate::rules::recorded;
use crate::view::ChainView;

use super::close::settled_for;
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

/// Whether the record's persona was in good standing through `epoch`:
/// joined by then and in no bad interval. Where this is false is where a
/// pair's challengeable run began.
fn in_standing(record: &BondRecord, epoch: SettlementEpoch) -> bool {
    good_through(
        record.join_settlement_epoch.to_raw(),
        epoch.to_raw(),
        &record.bad_intervals,
    )
}

impl super::Transition {
    /// The slash scheduler (`process_archival_slash_at_height`): every
    /// epoch above the watermark whose deadline `count` passes, ascending.
    pub(super) fn scan_slashes<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
    ) -> Result<(), ViewRead<V::Fault>> {
        // The schedule is `u64` at its edge (Phase 2g); the count crosses
        // it as the count it is, decoded once here.
        let count = self.count().to_raw();
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

    /// One epoch's pass: settle it, then judge every record in persona-key
    /// order against a snapshot taken as the pass begins (module docs, *The
    /// stale snapshot*). A complete-tree record is slashed on its first
    /// failing shard only; a compact record on each shard it holds.
    fn scan_epoch<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<V::Fault>> {
        let snapshot = self.merged(view)?;
        self.settle(view, epoch, &snapshot)?;
        for (persona, record) in &snapshot {
            match &record.holdings {
                Holdings::CompleteTree => {
                    // A complete tree holds every shard, so its candidates
                    // are the shards it has a row for, in shard order.
                    let settled: Vec<ShardId> = settled_for(&self.settled, epoch, persona)
                        .map(|(shard, _)| shard)
                        .collect();
                    for shard in settled {
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
        // The emission gather, over the records as the epoch's slashes
        // left them: a record slashed for `epoch` carries the interval
        // that opens at `epoch` and is out of its market, and that is the
        // record a later claim's verify reads back (`close.rs`, `gather`).
        self.gather(view, epoch)
    }

    /// Settle `epoch`: check its issued-draw index against its digest and
    /// fold each pair's counted draws into a row (module docs, *Order
    /// inside one epoch*, step 1).
    fn settle<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
        snapshot: &[(PCanonicalId, BondRecord)],
    ) -> Result<(), ViewRead<V::Fault>> {
        let draws = view.issued_draws(epoch).map_err(ViewRead::View)?;
        // Every stored draw, before any is dropped: the digest was folded
        // over issuance, and a pair that later stopped holding its shard
        // still had its draws issued. An epoch with no draw must have the
        // digest of no draws.
        let mut folded = IssuedDigest::ZERO;
        for draw in &draws {
            folded.fold(&issued_draw_term(
                &draw.persona,
                draw.shard,
                epoch,
                draw.issuing_height,
                draw.draw,
            ));
        }
        if folded != view.issued_digest(epoch).map_err(ViewRead::View)? {
            return Err(ViewRead::Corrupt(Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::IssuedIndexDigest,
            }));
        }
        if draws.is_empty() {
            return Ok(());
        }
        let beacon = self.settlement_beacon(view, epoch)?;
        let records: BTreeMap<&PCanonicalId, &BondRecord> =
            snapshot.iter().map(|(p, record)| (p, record)).collect();
        // The persona's slash log above the epoch's first block, read once
        // per persona: the index is persona-major, so one persona's pairs
        // are adjacent.
        let mut after_open: Option<(PCanonicalId, Vec<SlashLogEntry>)> = None;
        for pair in draws.chunk_by(|a, b| a.persona == b.persona && a.shard == b.shard) {
            let (persona, shard) = (pair[0].persona, pair[0].shard);
            // A draw is issued to a pair of the drawable set, and the set
            // is of bonded personas; admission is what holds an index row
            // to that. A row naming no record here has no holding to count
            // a draw against.
            let Some(record) = records.get(&persona) else {
                continue;
            };
            if after_open.as_ref().map(|(p, _)| *p) != Some(persona) {
                let h_open = BlockHeight::from_raw(self.schedule.open_height(epoch.to_raw()));
                let log = self.slashed_after(view, persona, h_open)?;
                after_open = Some((persona, log));
            }
            let log = after_open
                .as_ref()
                .map_or(&[][..], |(_, log)| log.as_slice());
            let counted = self.counted(view, persona, record, shard, epoch, pair, log)?;
            match settle_pair(&beacon, &persona, shard, epoch, &counted) {
                Ok(Some(row)) => {
                    self.settled.insert((epoch, persona, shard), row);
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(ViewRead::Corrupt(Corrupt::SettlementIntegrity {
                        epoch,
                        check: SettlementCheck::PassesExceedCounted { persona, shard },
                    }));
                }
            }
        }
        Ok(())
    }

    /// The settlement beacon of `epoch`: the hash of the block `W₂` after
    /// the epoch's last, by which every reveal for the epoch has landed or
    /// can no longer land (specification §9.3 step 1). A schedule whose
    /// epoch is too short to have a response window has none to wait out,
    /// and the beacon is the epoch's last block.
    ///
    /// The block must sit strictly below the connecting height. The slash
    /// grace is at least `W₂` on every schedule that has one
    /// (`constants.rs`), so a passed deadline always puts it there. A
    /// re-pin that makes the arm reachable is still
    /// [`SettlementCheck::BeaconNotRecorded`]: the block at the slash
    /// height is not invalid, and this node cannot settle the epoch. The
    /// pass does not advance its watermark on that fault.
    ///
    /// # Errors
    ///
    /// [`ViewRead::Corrupt`] when the beacon block is not strictly below
    /// the connecting height, or when the view has no block recorded there.
    fn settlement_beacon<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<[u8; SETTLEMENT_BEACON_LEN], ViewRead<V::Fault>> {
        let window = self
            .schedule
            .challenge_response_blocks()
            .map_or(0, NonZeroU64::get);
        let at = self
            .schedule
            .last_block(epoch.to_raw())
            .saturating_add(window);
        if at >= self.connecting.to_raw() {
            return Err(ViewRead::Corrupt(Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::BeaconNotRecorded,
            }));
        }
        let beacon = recorded(view, BlockHeight::from_raw(at))?.hash;
        Ok(*beacon.as_bytes())
    }

    /// The slashes logged against `persona` strictly above `height`: the
    /// recorded ones (A2) and this block's own, which sit at the connecting
    /// height and so are above every height the pass asks about.
    ///
    /// The read is handed `self.slash_floor`. A scan whose start key lies
    /// in the retired range is SI-26 (`SlashLogReadBelowFloor`).
    fn slashed_after<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        height: BlockHeight,
    ) -> Result<Vec<SlashLogEntry>, ViewRead<V::Fault>> {
        let mut log = view
            .slash_log_after(&persona, height, self.slash_floor)
            .map_err(ViewRead::View)?;
        log.extend(
            self.slashes
                .iter()
                .map(|s| s.entry)
                .filter(|entry| entry.persona == persona),
        );
        Ok(log)
    }

    /// The draws of `pair` that count: those issued while the pair held
    /// the shard (module docs, *Which draws count for a pair*), in the
    /// `(h, j)` order the index gives them in.
    ///
    /// `after_open` is the persona's slash log above the epoch's first
    /// block. The log above any later height of the epoch is a subset of
    /// it, so when it is empty no draw needs its own read. When it is not
    /// — the persona was slashed during or after the epoch — each draw
    /// reads the log above its own height.
    #[allow(clippy::too_many_arguments)]
    fn counted<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
        pair: &[IndexedDraw],
        after_open: &[SlashLogEntry],
    ) -> Result<Vec<IssuedDraw>, ViewRead<V::Fault>> {
        let h_open = self.schedule.open_height(epoch.to_raw());
        let mut counted = Vec::with_capacity(pair.len());
        for draw in pair {
            let at = draw.issuing_height;
            let held = if after_open.is_empty() && at.to_raw() >= h_open {
                holds_shard_at(self.schedule, record, shard, at, &[])
            } else {
                let log = self.slashed_after(view, persona, at)?;
                holds_shard_at(self.schedule, record, shard, at, &log)
            };
            if held {
                counted.push(draw.state);
            }
        }
        Ok(counted)
    }

    /// What an earlier `epoch` settled for the pair: this block's own rows
    /// first (an epoch the same pass caught up on), then the recorded row
    /// (A14). `None` is no row.
    fn outcome<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<SettlementOutcome>, ViewRead<V::Fault>> {
        if let Some(row) = self.settled.get(&(epoch, persona, shard)) {
            return Ok(Some(row.outcome()));
        }
        Ok(view
            .settlement_row(&persona, shard, epoch)
            .map_err(ViewRead::View)?
            .map(SettlementRow::outcome))
    }

    /// Whether the pair is slashed for `epoch`: its row is Missed, the
    /// slash is not already applied, the persona was in good standing
    /// through the epoch, and the failure window says slash.
    fn challenge_failed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        // The epoch in hand was settled by this pass a moment ago, so its
        // rows are the pending ones and no recorded row can exist for it:
        // the common case, a pair with no row, costs no read.
        let missed = self
            .settled
            .get(&(epoch, persona, shard))
            .is_some_and(|row| row.outcome() == SettlementOutcome::Missed);
        if !missed {
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
        if !in_standing(record, epoch) {
            return Ok(false);
        }
        self.window_slashable(view, persona, record, shard, epoch)
    }

    /// The failure window from a Missed `epoch`. The gather, and where it
    /// stops, is [`settlement_window_slashable`]; this pass names the
    /// record's standing and the row each earlier epoch settled.
    fn window_slashable<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let floor = settlement_retention_floor(self.schedule, self.connecting);
        settlement_window_slashable(
            epoch,
            floor,
            |earlier| in_standing(record, earlier),
            |earlier| self.outcome(view, persona, shard, earlier),
        )
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
