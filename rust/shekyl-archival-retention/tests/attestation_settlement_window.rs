// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end: attestation records → settlement fold → failure window.
//!
//! The unit tests for [`settle_epoch`] and [`failure_window_slashable`] each
//! live on one side of the `to_observation` bridge. This test drives the whole
//! chain — fold each epoch's records, project through `to_observation`, drop the
//! non-observations, and evaluate the assembled window — because that is the
//! only place the pruned-epoch hazard (`failure_window.rs:178-184`) actually
//! bites: a pruned epoch decays to `NonObservation`, which must be *dropped*
//! from the window, never counted as a miss.

use shekyl_archival_retention::{
    failure_window_slashable, settle_epoch, AttestationKind, BaselineObservation, FAILURE_WINDOW_M,
    FAILURE_WINDOW_N,
};

/// Fold one epoch's record multiset and project it to the window's two-valued
/// observation — `None` for a non-observation the window must not count.
fn observe(epoch: u64, kinds: &[AttestationKind]) -> Option<BaselineObservation> {
    settle_epoch(kinds).to_observation(epoch)
}

#[test]
fn a_full_window_of_misses_slashes_and_pass_priority_clears_mixed_epochs() {
    // n observed epochs, most-recent-first, head a miss. m of them miss; the
    // remaining (n − m) are *mixed* sets [Miss, Miss, Pass] that pass-priority
    // resolves to Served — so a real pass clears an epoch even when misses were
    // also filed against it.
    let (m, n) = (u64::from(FAILURE_WINDOW_M), u64::from(FAILURE_WINDOW_N));
    let mut window = Vec::new();
    for i in 0..n {
        let epoch = 1000 - i; // strictly descending, head = 1000
        let kinds: Vec<AttestationKind> = if i < m {
            vec![AttestationKind::Miss]
        } else {
            // Served despite two misses in the same epoch — pass-priority.
            vec![
                AttestationKind::Miss,
                AttestationKind::Miss,
                AttestationKind::Pass,
            ]
        };
        window.push(observe(epoch, &kinds).expect("an observed epoch"));
    }
    assert_eq!(window.len(), usize::try_from(n).unwrap());
    assert_eq!(failure_window_slashable(&window), Ok(true));
}

#[test]
fn pruned_epochs_decay_to_non_observation_and_do_not_slash() {
    // The hazard, end to end: an archiver with only two observed misses but a run
    // of pruned/unchallenged epochs between them. The pruned epochs (empty record
    // sets) fold to NonObservation and are dropped, so the window is just the two
    // misses — below m, not slashable. Were NonObservation to collapse to Missed,
    // the window would be full of misses and wrongly slash.
    let mut raw = Vec::new();
    let mut epoch = 2000u64;
    raw.push(observe(epoch, &[AttestationKind::Miss])); // head: a real miss
    epoch -= 1;
    for _ in 0..(FAILURE_WINDOW_N + 5) {
        raw.push(observe(epoch, &[])); // pruned / never challenged → None
        epoch -= 1;
    }
    raw.push(observe(epoch, &[AttestationKind::Miss])); // one older real miss

    let window: Vec<BaselineObservation> = raw.into_iter().flatten().collect();
    assert_eq!(window.len(), 2, "only the two real observations survive");
    assert_eq!(failure_window_slashable(&window), Ok(false));

    // Negative control: the SAME epoch positions filled with real misses DO
    // slash. This proves it was the non-observation *drop* that spared the
    // archiver — not a window that was too short for some unrelated reason.
    let mut all_miss = Vec::new();
    let mut e = 2000u64;
    for _ in 0..FAILURE_WINDOW_N {
        all_miss.push(observe(e, &[AttestationKind::Miss]).expect("observed"));
        e -= 1;
    }
    assert_eq!(failure_window_slashable(&all_miss), Ok(true));
}
