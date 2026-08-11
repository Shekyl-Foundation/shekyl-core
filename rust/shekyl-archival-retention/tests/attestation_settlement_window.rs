// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end: challenge outcome counts → settlement fold → failure window.
//!
//! The unit tests for [`settle_epoch`] and [`failure_window_slashable`] each
//! live on one side of the settlement/window seam. This test drives the whole
//! chain — fold each epoch's `(passes, issued)`, project the three-valued
//! settlement to the window's two-valued observation at the seam (the bridge
//! the deleted `to_observation` used to be; consumers now own it), drop the
//! non-observations, and evaluate the assembled window — because that is the
//! only place the pruned-epoch hazard (`failure_window.rs` prune
//! const-assert) actually bites: a pruned or under-issued epoch decays to
//! `NonObservation`, which must be *dropped* from the window, never counted
//! as a miss.

use shekyl_archival_retention::{
    failure_window_slashable, settle_epoch, BaselineObservation, EpochSettlement, FAILURE_WINDOW_M,
    FAILURE_WINDOW_N,
};

/// The settlement/window seam: project the three-valued settlement to the
/// window's two-valued observation, `None` for a non-observation the window
/// must not count.
fn observe(epoch: u64, passes: u32, issued: u32) -> Option<BaselineObservation> {
    match settle_epoch(passes, issued).expect("test inputs keep passes within issued") {
        EpochSettlement::Served => Some(BaselineObservation::served(epoch)),
        EpochSettlement::Missed => Some(BaselineObservation::missed(epoch)),
        EpochSettlement::NonObservation => None,
    }
}

#[test]
fn a_full_window_of_missed_epochs_slashes_and_two_of_three_clears() {
    // n observed epochs, most-recent-first. m settle Missed (0 of 3); the
    // remaining (n − m) settle Served at exactly the 2-of-3 threshold — a
    // pair passing two of its three challenges clears the epoch even though
    // one challenge expired against it.
    let (m, n) = (u64::from(FAILURE_WINDOW_M), u64::from(FAILURE_WINDOW_N));
    let head = 1000 + n;
    let mut window = Vec::new();
    for i in 0..n {
        let epoch = head - i; // strictly descending
        let obs = if i < m {
            observe(epoch, 0, 3)
        } else {
            observe(epoch, 2, 3)
        };
        window.push(obs.expect("an observed epoch"));
    }
    assert_eq!(window.len(), usize::try_from(n).unwrap());
    assert_eq!(failure_window_slashable(&window), Ok(true));
}

#[test]
fn one_of_three_counts_as_a_miss_the_signal_pass_priority_hid() {
    // The doctrine change absolute-2 encodes: a pair scraping ONE pass per
    // epoch settles Missed every epoch and slashes — under the retired
    // pass-priority OR gate these same epochs all settled Served and the
    // window could never fill. This is the strictly-stronger per-epoch
    // claim the (m, n) re-pin prices.
    let n = u64::from(FAILURE_WINDOW_N);
    let head = 3000 + n;
    let window: Vec<BaselineObservation> = (0..n)
        .map(|i| observe(head - i, 1, 3).expect("observed"))
        .collect();
    assert_eq!(failure_window_slashable(&window), Ok(true));
}

#[test]
fn under_issued_epochs_decay_to_non_observation_and_do_not_slash() {
    // The hazard, end to end: an archiver with two real Missed epochs and a
    // long run of under-issued epochs between them — including a 1-pass-of-
    // 1-issued epoch, which absolute-2 refuses to count as Served OR
    // Missed. The under-issued epochs are dropped, so the window is just
    // the two misses — below m, not slashable. Were NonObservation to
    // collapse to Missed, the window would fill and wrongly slash.
    let n = u64::from(FAILURE_WINDOW_N);
    let mut raw = Vec::new();
    let mut epoch = 2000 + n + 5;
    raw.push(observe(epoch, 0, 3)); // head: a real missed epoch
    epoch -= 1;
    for i in 0..(FAILURE_WINDOW_N + 5) {
        // Alternate the under-issuance shapes, including the 1-of-1 pass.
        let (passes, issued) = if i % 2 == 0 { (0, 0) } else { (1, 1) };
        raw.push(observe(epoch, passes, issued)); // → None, dropped
        epoch -= 1;
    }
    raw.push(observe(epoch, 0, 2)); // one older real missed epoch

    let window: Vec<BaselineObservation> = raw.into_iter().flatten().collect();
    assert_eq!(window.len(), 2, "only the two real observations survive");
    assert_eq!(failure_window_slashable(&window), Ok(false));

    // Negative control at genuinely the same epoch positions: re-walk the
    // scenario's own head-down sequence (head 2000 + n + 5, the epochs the
    // under-issued run occupied above), now with every epoch observed as a
    // real Missed (0 of 3). The window fills and DOES slash — proving it
    // was the non-observation drop that spared the archiver, not the
    // epoch geometry or a window too short for some unrelated reason.
    let mut all_miss = Vec::new();
    let mut e = 2000 + n + 5; // the scenario's head epoch
    for _ in 0..FAILURE_WINDOW_N {
        all_miss.push(observe(e, 0, 3).expect("observed"));
        e -= 1;
    }
    assert_eq!(failure_window_slashable(&all_miss), Ok(true));
}
