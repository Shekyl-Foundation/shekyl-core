// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The as-of-height holdings question: *did `P` hold shard `s` at height
//! `h`?* — not *does `P` hold `s` now*.
//!
//! Both consumers — serve-credit acceptance (CEN-J8: held at the derived
//! fire height) and slash eligibility (the failure-window look-back) — ask
//! it at the challenge's fire height, so one answer is the shared consensus
//! boundary for reward and punishment alike (WS-1,
//! `REWARD_EMISSION_E3_GATING_ROUND.md` §5; extended to mutable holdings by
//! `PHASE_2B_FSM_RETOOL.md` P2B-7 Pins 4/5). A tip read is the defect this
//! fold exists to close: a shard slashed away *after* the fire would read
//! not-held and the challenge would escape accounting.
//!
//! # Where the fold lives, and why here
//!
//! The C++ computed this inside the LMDB layer
//! (`db_lmdb.cpp:archival_bond_holds_shard_of`), a cursor walk and an epoch
//! comparison fused into one method — the R8-class placement
//! `CONSENSUS_STORE_RECONCILIATION.md` CEN-L16 records. The store's job is
//! the two reads it composes: the record (S-ARCH A1) and the slashes logged
//! against the persona **strictly above** `h` (A2, `slash_log_after`). The
//! judgement over them is consensus arithmetic, which is this crate's (E4
//! commit 2, the `SAR-Q7` staged pair). The C++ stays live until the
//! cutover; the LMDB as-of-height cases (`archival_substrate_lmdb.cpp:1674–
//! 1893`) are this module's tests.
//!
//! # Three sources, one answer
//!
//! Holdings at `h` are the **post-connect** state of block `h`. They only
//! shrink (slash) since the immutable-bond ruling (2026-09-20,
//! `PRINCIPAL_STAKE_LIFECYCLE.md` §5.3): a shard joins at `JoinMarket` or
//! never, so a compact record's per-shard add epoch is its join epoch and
//! "held at tip" reaches back exactly that far. The bound below is written
//! against the add epoch rather than the join epoch because the record
//! field is per shard and a slash's log row carries the add epoch of the
//! tenure it ended; it degenerates to the join epoch, and is the add-epoch
//! substrate enumerated at §5.3.2 row 7. *(As written: "Under
//! `HoldingsUpdate` they grow (add) as well as shrink (drop, slash), so
//! 'held at tip' … reaches back to the shard's latest **add**". That kind
//! is REJECTED; there is no later add and no voluntary drop.)*
//!
//! - **Held at tip, complete tree** ⇒ held at every height. A foundation
//!   record's holdings cannot change, and every caller's record-epoch
//!   gating puts the fire height after join.
//! - **Held at tip, compact** ⇒ held for every height in epochs **strictly
//!   after** the shard's add epoch. The add connected at an unknown height
//!   *within* its epoch, so holding is epoch-guaranteed only from the next
//!   one — P2B-7 Pin 5's per-shard `E_add + 1`: the partial add epoch is
//!   forfeited in both directions (no serve credit earned in it, no
//!   challenge fired in it can slash). At or before the add epoch, fall
//!   through to the log: an earlier tenure a slash removed still answers
//!   held for its own heights.
//! - **Not held at tip** ⇒ held at `h` iff a slash logged strictly above
//!   `h` removed it — either a compact erase of exactly `s` (bounded below
//!   by the row's add epoch, the same way), or a complete-tree demotion,
//!   whose pre-image held every shard. A slash *at* `h` is already removed.
//! - **A voluntarily dropped shard keeps no interval** (P2B-7 Pin 2,
//!   ratified: no drop sub-state, no event row): it answers not-held at
//!   every height, and the drop epoch's pending acceptances are forfeited —
//!   the symmetric twin of the forfeited add epoch.
//!
//! # Which schedule places the height in an epoch
//!
//! The caller's. Every arm compares `at_height`'s epoch against an add
//! epoch, and *which* epoch a height falls in is the settlement schedule's
//! to say — rule-set data since `ARW-15` (`RuleSet::settlement_schedule`),
//! not a process fact. The fold takes the [`SettlementSchedule`] it is
//! judged under; it does not read the process latch
//! (`settlement_epoch_at_height`), which is the entry point for callers
//! that hold no rule set (the type's doc). Under a fakechain schedule that
//! differs from the latch the two would classify the same fire height into
//! different epochs, and this fold would then answer *held* for a reward
//! the validator's own schedule says was not yet earned.
//!
//! # What the fold does not check
//!
//! That the rows are this persona's: A2 scopes them by the read, and the
//! fold takes them as scoped (a re-check here would be the second copy of
//! a filter, which drifts). Reopens (rule 21) if a caller appears holding an
//! unscoped log — there is none, and `ChainView::slash_log_after` is the
//! only producer.

use shekyl_types::archival::{BondRecord, SlashLogEntry, SlashedHolding};
use shekyl_types::{BlockHeight, SettlementEpoch, ShardId};

use crate::consensus_state::SettlementSchedule;

/// Whether `record`'s persona held `shard` **as of** `at_height` — the
/// post-connect state of block `at_height` — given every slash logged
/// against the persona strictly above `at_height` (`slashed_after`, the
/// S-ARCH A2 read at the same height), with `schedule` placing
/// `at_height` in its settlement epoch. The fold `db_lmdb.cpp:4890`
/// computed inside the LMDB layer, over the store's two reads instead.
///
/// `slashed_after` is the persona's rows already: the fold does not
/// re-scope them (module docs, *What the fold does not check*). Log order
/// does not matter to the answer — any one qualifying row proves the
/// holding — so the walk stops at the first.
#[must_use]
pub fn holds_shard_at(
    schedule: SettlementSchedule,
    record: &BondRecord,
    shard: ShardId,
    at_height: BlockHeight,
    slashed_after: &[SlashLogEntry],
) -> bool {
    let at_epoch = schedule.epoch_at(at_height);
    if record.holdings.holds(shard) {
        match record.holdings.add_epoch(shard) {
            // Complete tree: held back to join, at every height.
            None => return true,
            // Compact: epoch-guaranteed from `E_add + 1` on. At or before
            // the add epoch, fall through — a previous tenure may answer.
            Some(add_epoch) if at_epoch > add_epoch => return true,
            Some(_) => {}
        }
    }
    slashed_after
        .iter()
        .any(|entry| removed_holding(entry, shard, at_epoch))
}

/// Whether one logged slash — at a height strictly above the asked one, by
/// the caller's read — proves the persona held `shard` at `at_epoch`: a
/// complete-tree demotion held every shard; a compact erase of exactly
/// `shard` held it for epochs strictly after the tenure's add epoch (the
/// row's, journaled with the slash so the reconstruction is bounded exactly
/// as the tip-held arm is).
fn removed_holding(entry: &SlashLogEntry, shard: ShardId, at_epoch: SettlementEpoch) -> bool {
    match entry.holding {
        SlashedHolding::CompleteTree => true,
        SlashedHolding::Shard { add_epoch } => entry.shard == shard && at_epoch > add_epoch,
    }
}

#[cfg(test)]
mod tests {
    //! The LMDB as-of-height cases (`archival_substrate_lmdb.cpp:1674–1893`),
    //! as the fold over the two reads: the log is a `(height, entry)` list
    //! and `after(h)` is A2's contract — rows strictly above `h` — applied
    //! in the test, so what is asserted is the composition the C++ fused.
    //! The `slash_revert_*` cases beside them are pop-revert tests, which
    //! is `undo_log`'s job (`ARW-Q2`) and not this fold's.
    //!
    //! Every case runs under one named schedule, [`SCHEDULE`] — the genesis
    //! geometry, as the C++ fixtures ran — and the last case runs the same
    //! record under two schedules to show the argument decides.

    use shekyl_types::archival::{HeldShard, Holdings};
    use shekyl_types::PCanonicalId;
    use shekyl_units::AtomicUnits;

    use super::*;
    use crate::consensus_state::SettlementEpochBlocks;

    /// The schedule the LMDB cases ran under.
    const SCHEDULE: SettlementSchedule = SettlementSchedule::GENESIS;

    fn shard(n: u64) -> ShardId {
        ShardId::from_raw(n)
    }

    fn epoch(n: u64) -> SettlementEpoch {
        SettlementEpoch::from_raw(n)
    }

    fn h(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    /// The first height of epoch `e` under [`SCHEDULE`] — the C++ fixture's
    /// `shekyl_archival_epoch_open_height`.
    fn open(e: u64) -> BlockHeight {
        h(SCHEDULE.open_height(e))
    }

    /// Epoch `e`'s last block under [`SCHEDULE`], `(e + 1)·SEB − 1` — the
    /// C++ fixture's `shekyl_archival_epoch_last_block`, one below the
    /// close-*processing* height `consensus_state::epoch_close_height`
    /// names.
    fn last(e: u64) -> BlockHeight {
        h(SCHEDULE.last_block(e))
    }

    fn persona() -> PCanonicalId {
        PCanonicalId::from_bytes([0x76; 32])
    }

    fn record(holdings: Holdings) -> BondRecord {
        BondRecord {
            hybrid_pubkey: vec![0x0a; 64],
            bond_spend_pk: vec![0x0b; 32],
            endpoint: [0; 32],
            join_settlement_epoch: epoch(2),
            bonded_total: AtomicUnits::from_raw(2),
            holdings,
            bad_intervals: vec![],
            claimed_settlement_epochs: vec![],
            first_paying_emission_height: None,
        }
    }

    fn compact(pairs: &[(u64, u64)]) -> Holdings {
        Holdings::shard_set(
            pairs
                .iter()
                .map(|&(s, e)| HeldShard {
                    shard: shard(s),
                    add_epoch: epoch(e),
                })
                .collect(),
        )
        .expect("small, duplicate-free")
    }

    /// The log as the store holds it: rows keyed by height.
    struct Log(Vec<(BlockHeight, SlashLogEntry)>);

    impl Log {
        /// A2's contract: the rows strictly above `at`, in log order.
        fn after(&self, at: BlockHeight) -> Vec<SlashLogEntry> {
            self.0
                .iter()
                .filter(|(height, _)| *height > at)
                .map(|(_, entry)| *entry)
                .collect()
        }
    }

    fn slash(at: u64, s: u64, holding: SlashedHolding) -> (BlockHeight, SlashLogEntry) {
        (
            h(at),
            SlashLogEntry {
                persona: persona(),
                shard: shard(s),
                epoch: SCHEDULE.epoch_at(h(at)),
                holding,
            },
        )
    }

    fn held(record: &BondRecord, log: &Log, s: u64, at: BlockHeight) -> bool {
        holds_shard_at(SCHEDULE, record, shard(s), at, &log.after(at))
    }

    /// `holds_shard_honors_at_height_across_slash_removal` (:1697). Add
    /// epoch 2 for both shards, so held heights start at epoch 3's open;
    /// shard 7 is slashed mid-epoch 3 and its tenure is erased from the
    /// record, the log row carrying the add epoch it ended.
    #[test]
    fn a_slashed_shard_was_held_from_its_add_epoch_close_to_the_slash() {
        let held_from = open(3);
        let slash_height = held_from.to_raw() + 6000;
        // Post-slash record: 7 erased, 9 still held.
        let record = record(compact(&[(9, 2)]));
        let log = Log(vec![slash(
            slash_height,
            7,
            SlashedHolding::Shard {
                add_epoch: epoch(2),
            },
        )]);
        assert!(
            !record.holdings.holds(shard(7)),
            "the tip no longer holds 7"
        );

        // Held at every post-add-epoch height strictly below the slash …
        assert!(held(&record, &log, 7, h(slash_height - 1)));
        assert!(held(&record, &log, 7, held_from));
        // … not at the slash height or after (holdings at h are the
        // post-connect state of block h) …
        assert!(!held(&record, &log, 7, h(slash_height)));
        assert!(!held(&record, &log, 7, h(slash_height + 1000)));
        // … and not at or before its add epoch, though the row is strictly
        // above: the row's add epoch bounds the reconstruction exactly as
        // the tip-held arm's bound does.
        assert!(!held(&record, &log, 7, h(held_from.to_raw() - 1)));
        assert!(!held(&record, &log, 7, h(0)));

        // A shard never slashed reads from tip at any post-add-epoch height
        // — and not-held for its forfeited add epoch and earlier.
        assert!(held(&record, &log, 9, held_from));
        assert!(held(&record, &log, 9, h(slash_height + 1000)));
        assert!(!held(&record, &log, 9, h(held_from.to_raw() - 1)));
        assert!(!held(&record, &log, 9, h(0)));

        // The last height: nothing is strictly above it, so the answer is
        // the tip state. In the C++ this was an early return guarding a
        // wrapping start key; here A2 has no range to scan (the key's
        // `above` is `None` there) and the fold sees no rows.
        assert!(log.after(h(u64::MAX)).is_empty());
        assert!(!held(&record, &log, 7, h(u64::MAX)));
        assert!(held(&record, &log, 9, h(u64::MAX)));

        // A shard never held is not resurrected by a row naming another.
        assert!(!held(&record, &log, 42, h(slash_height - 1)));
    }

    /// `holds_shard_bounds_added_shard_by_its_add_epoch` (:1756): a record
    /// whose shard 9 carries add epoch 5 against a join at epoch 2 — held
    /// from its *own* add epoch's close, not from join, so a fire height
    /// before or inside the add epoch reads not-held and no unjust slash
    /// or add-epoch credit is possible. No connect path produces such a
    /// record since `HoldingsUpdate` was REJECTED (2026-09-20); the test
    /// pins the bound's per-shard reading of the field, which is what a
    /// slash log row relies on.
    #[test]
    fn an_added_shard_is_held_only_from_the_epoch_after_its_add() {
        let record = record(compact(&[(7, 2), (9, 5)]));
        let log = Log(Vec::new());

        // The join-time shard is held from epoch 3 on.
        assert!(held(&record, &log, 7, open(3)));
        assert!(held(&record, &log, 7, open(5)));
        // The added shard is held only from epoch 6 (add epoch 5
        // forfeited): a fire height in epochs 3–5 answers not-held.
        assert!(held(&record, &log, 9, open(6)));
        assert!(!held(&record, &log, 9, open(5)));
        assert!(!held(&record, &log, 9, last(5)));
        assert!(!held(&record, &log, 9, open(3)));
    }

    /// `holds_shard_reconstructs_complete_tree_demotion` (:1787): the slash
    /// cleared *every* holding, so the pre-image held every shard —
    /// including ones the row does not name. The row's holding kind is
    /// what tells a demoted complete tree from a compact bond that lost its
    /// last shard; without it the fold would have to guess.
    #[test]
    fn a_demoted_complete_tree_held_every_shard_before_the_slash() {
        let slash_height = 6000;
        // Demoted at tip: compact, empty.
        let record = record(compact(&[]));
        let log = Log(vec![slash(slash_height, 7, SlashedHolding::CompleteTree)]);
        assert!(!record.is_complete_tree());

        assert!(held(&record, &log, 7, h(slash_height - 1)));
        assert!(held(&record, &log, 999, h(slash_height - 1)));
        assert!(!held(&record, &log, 7, h(slash_height)));
        assert!(!held(&record, &log, 999, h(slash_height)));
    }

    /// A complete tree still held at tip is held at every height — the
    /// tip-held arm's first case, which the LMDB cases reach only through
    /// the demotion row.
    #[test]
    fn a_complete_tree_at_tip_is_held_at_every_height() {
        let record = record(Holdings::CompleteTree);
        let log = Log(Vec::new());
        assert!(held(&record, &log, 7, h(0)));
        assert!(held(&record, &log, 999, open(1)));
        assert!(held(&record, &log, 3, h(u64::MAX)));
    }

    /// The fall-through: a shard held at tip whose *current* tenure began
    /// too late to cover `h` answers held if an *earlier* tenure, ended by
    /// a logged slash, covered it — and not-held in the gap between.
    #[test]
    fn a_previous_tenure_answers_for_its_own_heights_under_a_later_add() {
        // Tenure one: added epoch 2, slashed mid-epoch 4. Tenure two: added
        // epoch 6, held at tip.
        let slash_height = open(4).to_raw() + 10;
        let record = record(compact(&[(7, 6)]));
        let log = Log(vec![slash(
            slash_height,
            7,
            SlashedHolding::Shard {
                add_epoch: epoch(2),
            },
        )]);

        // Tenure one covers epoch 3 up to the slash.
        assert!(held(&record, &log, 7, open(3)));
        assert!(held(&record, &log, 7, h(slash_height - 1)));
        // The gap: from the slash through the second add's forfeited epoch.
        assert!(!held(&record, &log, 7, h(slash_height)));
        assert!(!held(&record, &log, 7, open(5)));
        assert!(!held(&record, &log, 7, last(6)));
        // Tenure two from epoch 7 on.
        assert!(held(&record, &log, 7, open(7)));
    }

    /// The schedule argument decides which epoch a height is in — not the
    /// process latch. The same record and fire height, under two
    /// schedules: a short fakechain geometry places the height past the
    /// add epoch (held); the genesis geometry — which is also what the
    /// latch holds in this process — places it inside epoch 0 (not held).
    /// Had the fold read the latch, the first answer would be wrong.
    #[test]
    fn the_schedule_passed_in_places_the_height_not_the_process_latch() {
        let short = SettlementSchedule::new(
            SettlementEpochBlocks::new(100).expect("a non-zero fakechain epoch"),
        );
        let record = record(compact(&[(7, 2)]));
        let log = Log(Vec::new());
        // Epoch 3's open under the short schedule …
        let fire = h(short.open_height(3));
        // … which the genesis geometry (and so the latch) reads as epoch 0.
        assert_eq!(SCHEDULE.epoch_at(fire), epoch(0));
        assert_eq!(SettlementSchedule::effective().epoch_at(fire), epoch(0));

        assert!(holds_shard_at(
            short,
            &record,
            shard(7),
            fire,
            &log.after(fire)
        ));
        assert!(!holds_shard_at(
            SCHEDULE,
            &record,
            shard(7),
            fire,
            &log.after(fire)
        ));
    }
}
