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

use shekyl_curve_tree::BlockHeight;
use shekyl_types::ChainCount;

use crate::engine::daemon::synced_chain_facts::SyncedChainFacts;

/// A view both reads agree on at `tip`.
///
/// Built through the real constructor rather than the private field so the
/// `min` relation is exercised by every test here, not only the one that
/// names it.
fn view_at(tip: u64) -> CoherentChainView {
    let synced = SyncedChainFacts::new(ChainCount::from_raw(tip + 1), 0, true).expect("synced");
    CoherentChainView::reconcile(&synced, ChainCount::from_raw(tip + 1))
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
        .observe(view_at(1_000), &owed(&[1]), &[1, 9])
        .is_empty());
    // A reorg depth later — what a reorg-shaped gate would have released on.
    assert!(ledger
        .observe(view_at(1_720), &owed(&[1]), &[1, 9])
        .is_empty());
    // Epoch 1's open: not drawable in epoch 1, but an epoch-0 challenge
    // issued in block 9 999 still has to resolve.
    assert!(ledger
        .observe(view_at(10_000), &owed(&[1]), &[1, 9])
        .is_empty());
    assert!(ledger
        .observe(view_at(19_999), &owed(&[1]), &[1, 9])
        .is_empty());
    // Epoch 2's open: absent across two consecutive opens, and the last
    // epoch it could have been drawn in closed a full epoch ago.
    assert_eq!(
        ledger.observe(view_at(20_000), &owed(&[1]), &[1, 9]),
        vec![9]
    );
}

/// A departure that reverses inside the window costs nothing, and the clock
/// restarts if the shard leaves again.
#[test]
fn a_shard_that_returns_clears_its_departure_clock() {
    let mut ledger = DepartureLedger::default();

    assert!(ledger
        .observe(view_at(1_000), &owed(&[1]), &[1, 9])
        .is_empty());
    // Back in the record inside epoch 0: held at every open it might have
    // missed, so nothing has elapsed.
    assert!(ledger
        .observe(view_at(5_000), &owed(&[1, 9]), &[1, 9])
        .is_empty());
    // It leaves again in epoch 1. Had the first clock survived, epoch 2's
    // open would release it while it was still drawable in epoch 1.
    assert!(ledger
        .observe(view_at(15_000), &owed(&[1]), &[1, 9])
        .is_empty());
    assert!(ledger
        .observe(view_at(20_000), &owed(&[1]), &[1, 9])
        .is_empty());
    assert_eq!(
        ledger.observe(view_at(30_000), &owed(&[1]), &[1, 9]),
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
            &owed(&[1, 9]),
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
        .observe(view_at(1_000), &owed(&[1]), &[1, 9])
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
            .observe(view_at(20_000), &owed(&[1]), &[1, 9])
            .is_empty(),
        "the clock restarts at the first observation after the break"
    );
    // And it releases only two opens after THAT.
    assert!(ledger
        .observe(view_at(29_999), &owed(&[1]), &[1, 9])
        .is_empty());
    assert_eq!(
        ledger.observe(view_at(40_000), &owed(&[1]), &[1, 9]),
        vec![9]
    );
}

// ── Hazard 2: a rollback between refreshes ──────────────────────────────

/// A rollback *between* refreshes resets rather than merely declining to
/// elapse. The saturating subtraction this replaces kept stale entries alive.
#[test]
fn a_rollback_between_refreshes_resets_the_ledger() {
    let mut ledger = DepartureLedger::default();

    assert!(ledger
        .observe(view_at(50_000), &owed(&[1]), &[1, 9])
        .is_empty());
    assert_eq!(ledger.observed_absences(), 1);

    // The chain moves backwards under the ledger.
    assert!(ledger
        .observe(view_at(100), &owed(&[1]), &[1, 9])
        .is_empty());

    // The entry from the pre-rollback timeline is gone; this shard is being
    // observed for the first time, so two opens from HERE are required.
    assert!(ledger
        .observe(view_at(10_100), &owed(&[1]), &[1, 9])
        .is_empty());
    assert_eq!(
        ledger.observe(view_at(20_100), &owed(&[1]), &[1, 9]),
        vec![9]
    );
}
