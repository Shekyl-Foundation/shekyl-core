// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two hazards [`DepartureLedger`] exists to close, and the gate
//! semantics that must survive closing them.
//!
//! `SETTLEMENT_EPOCH_BLOCKS` is 10 000, so epoch opens are 0 / 10 000 /
//! 20 000. Heights below are chosen against that and nothing else.

use super::*;

use shekyl_types::ChainCount;

use shekyl_types::BlockHash;

use crate::engine::daemon::synced_chain_facts::{CoherentChainView, SyncedChainFacts};
use crate::engine::test_support::test_block_hash_at;

/// A view both reads agree on at `tip`.
///
/// Built through the real constructor rather than the private field so the
/// `min` relation is exercised by every test here, not only the one that
/// names it.
fn view_at(tip: u64) -> AnchoredView {
    let synced = SyncedChainFacts::new(
        ChainCount::from_raw(tip + 1),
        0,
        true,
        BlockHash::from_bytes(test_block_hash_at(tip)),
    )
    .expect("synced");
    CoherentChainView::reconcile(
        &synced.bracket(synced.top_hash()).expect("bracketed"),
        ChainCount::from_raw(tip + 1),
    )
    .anchored()
    .expect("agreeing reads are anchored")
}

/// What an **unbroken** chain reports at the ledger's anchor: the very block
/// it rests on. Every single-timeline test below carries observations with
/// this; the fork bite is the one that hands back something else.
fn unbroken(ledger: &DepartureLedger) -> Continuity {
    match ledger.resting_on() {
        None => Continuity::FirstObservation,
        Some(anchor) => Continuity::Verified {
            canonical_now: anchor.hash,
        },
    }
}

fn owed(ids: &[u64]) -> BTreeSet<u64> {
    ids.iter().copied().collect()
}

// ── The gate semantics, unchanged by the hazard fixes ───────────────────

/// A departed shard is not releasable while the pair can still be drawn.
///
/// This is the slash-vs-disk asymmetry, and it is the property the two
/// hazard fixes below must not break.
#[test]
fn a_departed_shard_is_not_releasable_while_it_is_still_drawable() {
    let mut ledger = DepartureLedger::default();

    // Dropped mid-epoch-0; still drawable for the rest of epoch 0.
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    // A reorg depth later — what a reorg-shaped gate would have released on.
    assert!(ledger
        .observe(
            view_at(1_720),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    // Epoch 1's open: not drawable in epoch 1, but an epoch-0 challenge
    // issued in block 9 999 still has to resolve.
    assert!(ledger
        .observe(
            view_at(10_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert!(ledger
        .observe(
            view_at(19_999),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    // Epoch 2's open: absent across two consecutive opens, and the last
    // epoch it could have been drawn in closed a full epoch ago.
    assert_eq!(
        ledger.observe(
            view_at(20_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

/// A departure that reverses inside the window costs nothing, and the clock
/// restarts if the shard leaves again.
#[test]
fn a_shard_that_returns_clears_its_departure_clock() {
    let mut ledger = DepartureLedger::default();

    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    // Back in the record inside epoch 0: held at every open it might have
    // missed, so nothing has elapsed.
    assert!(ledger
        .observe(
            view_at(5_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1, 9])),
            &[1, 9]
        )
        .is_empty());
    // It leaves again in epoch 1. Had the first clock survived, epoch 2's
    // open would release it while it was still drawable in epoch 1.
    assert!(ledger
        .observe(
            view_at(15_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert!(ledger
        .observe(
            view_at(20_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(
        ledger.observe(
            view_at(30_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

/// A shard still owed is never releasable, however long it has been pinned —
/// the direction that causes a slash rather than wasting disk.
#[test]
fn an_owed_shard_is_never_releasable() {
    let mut ledger = DepartureLedger::default();
    assert!(ledger
        .observe(
            view_at(10 * SETTLEMENT_EPOCH_BLOCKS),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1, 9])),
            &[1, 9]
        )
        .is_empty());
}

// ── Hazard 1: a sync gap ────────────────────────────────────────────────

/// **The stale-timestamp hazard.** A shard absent before a break, re-added
/// while the wallet was blind, and departed again after it must not resume
/// the pre-break clock — that clock measured an absence which *ended*.
///
/// The edit that turns this red is making `break_timeline` frozen rather
/// than forgetful. It bites against a release granted on an interval nobody
/// observed; it does **not** cover a daemon that lies about being synced.
#[test]
fn a_break_forgets_absences_so_a_stale_clock_cannot_resume() {
    let mut ledger = DepartureLedger::default();

    // Shard 9 departs early in epoch 0.
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(ledger.observed_absences(), 1);

    // The wallet goes blind. Whatever happened to shard 9 across the gap —
    // re-added, departed again — it did not see.
    ledger.break_timeline(TimelineBreak::DaemonSyncing);
    assert_eq!(
        ledger.observed_absences(),
        0,
        "a break must forget, not freeze: a frozen entry is a claim about an \
         interval nobody watched"
    );

    // Two epoch opens later, the first post-break observation is the FIRST
    // observation. Had the pre-break entry survived, this would release.
    assert!(
        ledger
            .observe(
                view_at(20_000),
                unbroken(&ledger),
                Obligation::Exactly(&owed(&[1])),
                &[1, 9]
            )
            .is_empty(),
        "the clock restarts at the first observation after the break"
    );
    // And it releases only two opens after THAT.
    assert!(ledger
        .observe(
            view_at(29_999),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(
        ledger.observe(
            view_at(40_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

// ── Hazard 2: a rollback between refreshes ──────────────────────────────

/// A rollback *between* refreshes resets rather than merely declining to
/// elapse. The saturating subtraction this replaces kept stale entries alive.
///
/// Under identity, a rollback is not a *lower height* — it is an anchor the
/// chain can no longer answer for. The ledger rested on the block at 50 000;
/// on a chain now at 100 there is no block at 50 000, `get_block_hash`
/// fails, and the pinner hands back [`Continuity::Unverifiable`]. That is
/// the honest model, and it is why this test does **not** use `unbroken`
/// at the rollback step: that helper echoes the anchor back and would be
/// asserting the block still exists.
#[test]
fn a_rollback_between_refreshes_resets_the_ledger() {
    let mut ledger = DepartureLedger::default();

    assert!(ledger
        .observe(
            view_at(50_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(ledger.observed_absences(), 1);

    // The chain moves backwards under the ledger: the anchor at 50 000 is
    // not a height this chain has, so it cannot be re-read.
    assert!(ledger
        .observe(
            view_at(100),
            Continuity::Unverifiable,
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());

    // The entry from the pre-rollback timeline is gone; this shard is being
    // observed for the first time, so two opens from HERE are required.
    assert!(ledger
        .observe(
            view_at(10_100),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(
        ledger.observe(
            view_at(20_100),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

// ── Hazard 3: a reorg that catches back up ──────────────────────────────

/// **The identity hazard.** A branch rewinds across an epoch open and is
/// *above* the last observed height by the next refresh; on that branch the
/// shard was held at the open and dropped again. Height monotonicity passes
/// this — 20 000 > 1 000 — and would release a shard that was held when it
/// mattered. Identity refuses it: the block at 1 000 is not the block the
/// observation was anchored to.
///
/// The edit that turns this red is comparing heights instead of hashes in
/// `observe`'s continuity match — the check this replaced. It bites against
/// a release granted across a fork; it does **not** cover a daemon that
/// answers a forged hash at the anchor height.
#[test]
fn a_fork_that_catches_back_up_does_not_carry_the_old_absence() {
    let mut ledger = DepartureLedger::default();

    // Shard 9 observed absent early in epoch 0, anchored to the block at
    // 1 000 on branch A.
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    let anchored_to = ledger.resting_on().expect("resting on branch A");
    assert_eq!(
        anchored_to.height,
        shekyl_curve_tree::BlockHeight::from_raw(1_000)
    );

    // Branch B replaces everything from below 1 000, restores shard 9 at
    // epoch 1's open, drops it again, and is at 20 000 by the next refresh.
    // The chain now reports a DIFFERENT block at 1 000.
    let branch_b_at_1000 = Continuity::Verified {
        canonical_now: BlockHash::from_bytes([0xFF; 32]),
    };
    assert_ne!(
        branch_b_at_1000,
        unbroken(&ledger),
        "the fixture must actually fork"
    );
    assert!(
        ledger
            .observe(
                view_at(20_000),
                branch_b_at_1000,
                Obligation::Exactly(&owed(&[1])),
                &[1, 9]
            )
            .is_empty(),
        "two epoch opens have elapsed by HEIGHT, but not on this chain: the \
         observation at 1 000 was of a block that no longer exists"
    );

    // From here the clock restarts on branch B, and releases only two opens
    // after THIS observation.
    assert!(ledger
        .observe(
            view_at(29_999),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(
        ledger.observe(
            view_at(40_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

/// The control for the bite above: the identical height sequence on an
/// UNBROKEN chain does release at 20 000. This is what a height-only check
/// would have done on the fork too, and it is why the previous test is not
/// merely "two epochs were not enough".
#[test]
fn the_same_heights_on_an_unbroken_chain_do_release() {
    let mut ledger = DepartureLedger::default();
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert_eq!(
        ledger.observe(
            view_at(20_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        ),
        vec![9]
    );
}

/// An anchor the chain cannot re-read is not comparable, and forgets — the
/// same verdict as a mismatch, because "I could not check" must never be
/// read as "it matched".
#[test]
fn an_unverifiable_anchor_forgets() {
    let mut ledger = DepartureLedger::default();
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert!(ledger
        .observe(
            view_at(20_000),
            Continuity::Unverifiable,
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    // And claiming a first observation while resting on something is the
    // same lie in a different coat.
    let mut ledger = DepartureLedger::default();
    assert!(ledger
        .observe(
            view_at(1_000),
            unbroken(&ledger),
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
    assert!(ledger
        .observe(
            view_at(20_000),
            Continuity::FirstObservation,
            Obligation::Exactly(&owed(&[1])),
            &[1, 9]
        )
        .is_empty());
}

// ── The owed-everything observation ─────────────────────────────────────

/// A `CompleteTree` record owes every shard, so an observation under it
/// **forgets** every absence clock and still moves the anchor — the next
/// compact refresh carries nothing across it, and verifies continuity
/// against the block this observation stood on, not an older one.
///
/// The edit that turns this red is the caller skipping `observe` for a
/// `CompleteTree` record; the pinner-level bite for that lives in
/// `serve_set_source`. This one pins what the ledger does with the input.
#[test]
fn an_owed_everything_observation_forgets_every_absence_and_moves_the_anchor() {
    let mut ledger = DepartureLedger::default();
    ledger.observe(
        view_at(1_000),
        unbroken(&ledger),
        Obligation::Exactly(&owed(&[1])),
        &[1, 9],
    );
    assert_eq!(
        ledger.observed_absences(),
        1,
        "9 is absent under the compact record"
    );

    let everything = view_at(10_000);
    let released = ledger.observe(
        everything,
        unbroken(&ledger),
        Obligation::Everything,
        &[1, 9],
    );
    assert!(
        released.is_empty(),
        "nothing is releasable when everything is owed"
    );
    assert_eq!(
        ledger.observed_absences(),
        0,
        "an owed shard is not departed"
    );
    assert_eq!(
        ledger.resting_on(),
        Some(everything.anchor()),
        "the anchor moves to this observation so the next refresh verifies continuity here"
    );

    // Absent again under a compact record two epoch opens later: the clock
    // restarted at 20 000, so this is the FIRST absence, not the third.
    let released = ledger.observe(
        view_at(20_000),
        unbroken(&ledger),
        Obligation::Exactly(&owed(&[1])),
        &[1, 9],
    );
    assert!(
        released.is_empty(),
        "the pre-CompleteTree clock must not resume"
    );
}
