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
//! read, and the floor the gather stops at: the claimable family's
//! [`EpochFloor`](crate::EpochFloor), equal to the retention crate's
//! `settlement_retention_floor`.
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
    good_through, holds_shard_at, settle_support, settlement_window_slashable,
    slash_open_interval_to_append, SupportSettlementKey, ARCHIVAL_BOND_FLOOR_ATOMIC,
    MAX_BOND_BAD_INTERVALS,
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
use crate::Claimable;

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
                    // The support row is one per tree. A miss there demotes
                    // the whole holding. Economy rows, if any remain, are
                    // the same demotion and stop at the first.
                    if self.support_failed(view, *persona, record, epoch)? {
                        self.slash(*persona, ShardId::from_raw(0), epoch)?;
                        continue;
                    }
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

    /// Settle `epoch`: check its drawable set against the digest written at
    /// its open, check its issued-draw index against its digest, and fold
    /// each pair's counted draws into a row (module docs, *Order inside one
    /// epoch*, step 1).
    fn settle<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
        snapshot: &[(PCanonicalId, BondRecord)],
    ) -> Result<(), ViewRead<V::Fault>> {
        self.check_drawable(view, epoch)?;
        let draws = view
            .issued_draws(epoch, self.floor())
            .map_err(ViewRead::View)?;
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
        if folded
            != view
                .issued_digest(epoch, self.floor())
                .map_err(ViewRead::View)?
        {
            return Err(ViewRead::Corrupt(Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::IssuedIndexDigest,
            }));
        }
        let support_draws = view
            .support_issued(epoch, self.floor())
            .map_err(ViewRead::View)?;
        if draws.is_empty() && support_draws.is_empty() {
            return Ok(());
        }
        let beacon = self.settlement_beacon(view, epoch)?;
        if !draws.is_empty() {
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
        }
        for tree in support_draws.chunk_by(|a, b| a.persona == b.persona) {
            let persona = tree[0].persona;
            let issued: Vec<_> = tree.iter().map(|draw| draw.state).collect();
            let key = SupportSettlementKey { persona, epoch };
            match settle_support(&beacon, key, &issued) {
                Ok(Some(row)) => {
                    self.support_settled.insert((epoch, persona), row);
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(ViewRead::Corrupt(Corrupt::SettlementIntegrity {
                        epoch,
                        check: SettlementCheck::SupportPassesExceedCounted { persona },
                    }));
                }
            }
        }
        Ok(())
    }

    /// §9.5 check 2: the drawable set rebuilt from the bond journals is the
    /// one whose digest was written when `epoch` opened. Every epoch that
    /// settles is checked, whether or not anything was drawn from it: the
    /// set is the operand every index of the epoch was resolved against.
    ///
    /// The rebuild is the walk back ([`super::drawable_epoch_walked_back`])
    /// over this view, under this pass's floor. It reads no value the open
    /// produced but the digest it is compared with, so a Release pre-image,
    /// a slash-log row, a record or the digest that changed after the open
    /// is a mismatch here. The comparison itself is
    /// [`super::drawable::compare_recorded_digest`]: a missing digest, a
    /// digest for an epoch this view has not opened, and a digest that
    /// differs are three faults.
    ///
    /// # Errors
    ///
    /// [`ViewRead::Corrupt`]. [`SettlementCheck::DrawableDigestMissing`]
    /// when the open wrote no digest. [`SettlementCheck::DrawableDrift`]
    /// when the rebuilt set's digest is not the recorded one.
    /// [`Corrupt::DrawableEpoch`] when the set cannot be rebuilt, including
    /// [`crate::DrawableEpochFault::Unopened`] when the view's tip is below
    /// `h_open` while a digest is recorded. Each halts the writer. None is
    /// a verdict on the block.
    fn check_drawable<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<V::Fault>> {
        let h_open = BlockHeight::from_raw(self.schedule.open_height(epoch.to_raw()));
        let written = view
            .drawable_digest(epoch, self.floor())
            .map_err(ViewRead::View)?;
        let rebuilt = super::drawable_epoch_walked_back(
            view,
            epoch,
            self.schedule,
            self.reorg_cap,
            crate::ReleaseJournalFloor::of(self.floor(), self.schedule),
            self.slash_floor,
        )?;
        super::drawable::compare_recorded_digest(epoch, h_open, written, rebuilt.as_ref())
            .map_err(ViewRead::Corrupt)
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
        let beacon = recorded(view, BlockHeight::from_raw(at))?.header.hash;
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
            .settlement_row(&persona, shard, epoch, self.floor())
            .map_err(ViewRead::View)?
            .map(SettlementRow::outcome))
    }

    /// Whether the tree's one support row for `epoch` slashes it. The row
    /// is keyed by the tree and the epoch, not by a shard.
    fn support_failed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let missed = self
            .support_settled
            .get(&(epoch, persona))
            .is_some_and(|row| row.outcome() == SettlementOutcome::Missed);
        if !missed || !in_standing(record, epoch) {
            return Ok(false);
        }
        let floor = self
            .floor::<Claimable>()
            .kept_from()
            .unwrap_or(SettlementEpoch::from_raw(0));
        settlement_window_slashable(
            epoch,
            floor,
            |earlier| in_standing(record, earlier),
            |earlier| {
                if let Some(row) = self.support_settled.get(&(earlier, persona)) {
                    return Ok(Some(row.outcome()));
                }
                view.support_settlement(&persona, earlier, self.floor())
                    .map_err(ViewRead::View)
                    .map(|row| row.map(SettlementRow::outcome))
            },
        )
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
            .slash_applied(&persona, shard, epoch, self.floor())
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
        // The walk stops at the claimable floor its own row reads take
        // (`EpochFloor`), one value for both. It equals the retention
        // crate's `settlement_retention_floor`, the ruled bound, which
        // `epoch_floor_tests` holds to it at every height.
        let floor = self
            .floor::<Claimable>()
            .kept_from()
            .unwrap_or(SettlementEpoch::from_raw(0));
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

#[cfg(test)]
mod support_settlement_tests {
    use core::convert::Infallible;

    use shekyl_archival_retention::{
        settlement_window_slashable, SettlementEpochBlocks, SettlementSchedule,
        ARCHIVAL_BOND_FLOOR_ATOMIC,
    };
    use shekyl_types::archival::{
        BondRecord, Holdings, IndexedDraw, IssuedDraw, ReceiptSignPk, SettlementOutcome,
        SlashedHolding, RECEIPT_SIGN_PK_LEN,
    };
    use shekyl_types::{
        BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, LongTermWeight, PCanonicalId,
        SettlementEpoch, ShardId, TxHash,
    };
    use shekyl_units::AtomicUnits;

    use crate::harness::fixture::{recorded, root};
    use crate::harness::{MockChain, MockView};
    use crate::tree_growth::TreeFrontier;
    use crate::view::{
        AtHeight, BlockOutputs, ChainView, HeaderRecord, HeaderView, RecordedBlock,
        RecordedWeights, Tip,
    };
    use crate::{EpochFloor, Settling};

    use super::super::Transition;
    use super::apply_slash;

    /// Two shards of one tree. Neither is the selection sentinel.
    const TREE_SHARDS: [u64; 2] = [0, 1];

    /// The support-draw index for one epoch, over a bondless chain.
    ///
    /// The issued-row writer is still staged. This is the read the slash
    /// pass already makes: every other fact is the inner chain's, and
    /// [`ChainView::support_issued`] answers `draws` for `epoch` only.
    /// The floor check stays the store's (SI-32).
    struct SupportIndex<'a, 'id> {
        inner: MockView<'a, 'id>,
        epoch: SettlementEpoch,
        draws: Vec<IndexedDraw>,
    }

    impl<'id> HeaderView<'id> for SupportIndex<'_, 'id> {
        type Fault = Infallible;

        fn tip(&self) -> Result<Option<Tip>, Infallible> {
            self.inner.tip()
        }

        fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
            self.inner.header_at(height)
        }
    }

    impl<'id> ChainView<'id> for SupportIndex<'_, 'id> {
        fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
            self.inner.has_key_image(key_image)
        }

        fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
            self.inner.total_burned()
        }

        fn long_term_effective_median_at(
            &self,
            height: BlockHeight,
        ) -> Result<AtHeight<LongTermWeight>, Infallible> {
            self.inner.long_term_effective_median_at(height)
        }

        fn burned_through(&self, height: BlockHeight) -> Result<AtHeight<AtomicUnits>, Infallible> {
            self.inner.burned_through(height)
        }

        fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
            self.inner.block_at(height)
        }

        fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
            self.inner.height_of(hash)
        }

        fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
            self.inner.root_at(height)
        }

        fn weights_window(
            &self,
            end: BlockHeight,
            at_most: BlockCount,
        ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
            self.inner.weights_window(end, at_most)
        }

        fn has_transaction(&self, hash: &TxHash) -> Result<bool, Infallible> {
            self.inner.has_transaction(hash)
        }

        fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
            self.inner.tree_frontier()
        }

        fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
            self.inner.leaf_count_at(height)
        }

        fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
            self.inner.outputs_at(height)
        }

        fn support_issued(
            &self,
            epoch: SettlementEpoch,
            _floor: EpochFloor<Settling>,
        ) -> Result<Vec<IndexedDraw>, Infallible> {
            if epoch == self.epoch {
                Ok(self.draws.clone())
            } else {
                Ok(Vec::new())
            }
        }

        crate::archival_reads!(delegate inner);
    }

    /// The shortest epoch that still has a response window. `W₂` is one
    /// block, so the beacon is the block after the epoch's last and the
    /// chain that records it is that tall.
    fn shortest_windowed_schedule() -> SettlementSchedule {
        let blocks =
            SettlementEpochBlocks::new(shekyl_archival_retention::constants::W2_EPOCH_DIVISOR)
                .expect("the response divisor is a positive schedule");
        SettlementSchedule::new(blocks)
    }

    fn tree() -> BondRecord {
        BondRecord {
            hybrid_pubkey: vec![1],
            bond_spend_pk: vec![2],
            receipt_sign_pk: ReceiptSignPk::from_bytes([3; RECEIPT_SIGN_PK_LEN]),
            endpoint: [4; 32],
            join_settlement_epoch: SettlementEpoch::from_raw(0),
            bonded_total: AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC),
            holdings: Holdings::CompleteTree,
            bad_intervals: Vec::new(),
            claimed_settlement_epochs: Vec::new(),
            first_paying_emission_height: None,
        }
    }

    fn window(missed_through: u64) -> bool {
        settlement_window_slashable(
            SettlementEpoch::from_raw(missed_through),
            SettlementEpoch::from_raw(0),
            |_| true,
            |epoch| {
                Ok::<_, ()>(if epoch.to_raw() <= missed_through {
                    Some(SettlementOutcome::Missed)
                } else {
                    None
                })
            },
        )
        .expect("the rows answer")
    }

    /// Eleven missed epochs demote the tree. Ten do not. Red edit: slash
    /// one shard of the tree and leave the rest a complete tree.
    #[test]
    fn eleven_missed_epochs_demote_the_tree() {
        assert!(!window(9), "ten missed epochs are inside the budget");
        assert!(window(10), "eleven missed epochs slash");
        let persona = PCanonicalId::from_bytes([0x3C; 32]);
        let mut record = tree();
        let slash = apply_slash(
            persona,
            &mut record,
            ShardId::from_raw(0),
            SettlementEpoch::from_raw(10),
        )
        .expect("a complete tree demotes");
        assert_eq!(slash.entry.holding, SlashedHolding::CompleteTree);
        assert!(matches!(record.holdings, Holdings::ShardSet(ref held) if held.is_empty()));
    }

    /// Two shards of one tree are one support row. The economy index is
    /// empty, so a fold that dropped the support loop, or that keyed the
    /// row by shard, leaves this empty or issued at one. Red edit: delete
    /// the support fold in `settle`.
    #[test]
    fn two_shards_of_one_tree_settle_as_one_support_row() {
        let schedule = shortest_windowed_schedule();
        let epoch = SettlementEpoch::from_raw(0);
        let window = schedule
            .challenge_response_blocks()
            .expect("this schedule has a window");
        let beacon_height = schedule
            .last_block(epoch.to_raw())
            .checked_add(window.get())
            .expect("the beacon is one window past the epoch");
        let connecting = BlockHeight::from_raw(
            beacon_height
                .checked_add(1)
                .expect("the connecting height follows the beacon"),
        );
        // The slash-log window is `(k + n)` epochs. This tip is one epoch
        // and a window, so the floor retires nothing and the empty
        // drawable digest is the walk's.
        let chain = (0..=beacon_height).fold(MockChain::default(), |chain, timestamp| {
            chain.push(recorded(timestamp), root(0x11))
        });
        let persona = PCanonicalId::from_bytes([0x3C; 32]);
        let issuing = BlockHeight::from_raw(
            schedule
                .open_height(epoch.to_raw())
                .checked_add(1)
                .expect("the epoch opens below its last block"),
        );
        let revealed_at = BlockHeight::from_raw(beacon_height);
        // The later shard passed. Below three issued draws that is not an observation.
        let draws: Vec<IndexedDraw> = TREE_SHARDS
            .into_iter()
            .enumerate()
            .map(|(index, shard)| IndexedDraw {
                persona,
                shard: ShardId::from_raw(shard),
                issuing_height: issuing,
                draw: u32::try_from(index).expect("two draws fit a draw index"),
                state: IssuedDraw {
                    revealed_at,
                    passed: index == 1,
                },
            })
            .collect();
        chain.with_view(|view| {
            let index = SupportIndex {
                inner: view,
                epoch,
                draws,
            };
            let mut transition = Transition::new(connecting, schedule, BlockCount::ONE);
            transition
                .settle(&index, epoch, &[])
                .expect("the empty drawable set matches and the fold is a row");
            assert!(
                transition.settled.is_empty(),
                "a support draw is not an economy row"
            );
            assert_eq!(transition.support_settled.len(), 1);
            let row = transition
                .support_settled
                .get(&(epoch, persona))
                .expect("the tree's row");
            assert_eq!(row.issued(), 2, "both shards count toward the tree");
            assert_eq!(row.passes(), 0, "fewer than three draws is not observed");
            assert_eq!(row.outcome(), SettlementOutcome::NonObservation);
        });
    }
}
