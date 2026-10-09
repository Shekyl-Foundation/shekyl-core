// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end: settlement row → failure window.
//!
//! The unit tests for the row and for [`failure_window_slashable`] each live
//! on one side of the settlement/window seam. This test drives the whole
//! chain — settle each epoch's row, project its three-valued outcome to the
//! window's two-valued observation at the seam, drop what is not an
//! observation, and evaluate the assembled window — because that is the
//! only place the pruned-epoch hazard (`failure_window.rs` prune
//! const-assert) actually bites: an absent row and a `NonObservation` row
//! must both be *dropped* from the window, never counted as a miss.

use shekyl_archival_retention::{
    failure_window_slashable, BaselineObservation, FAILURE_WINDOW_M, FAILURE_WINDOW_N,
};
use shekyl_types::archival::{SettlementOutcome, SettlementRow};

/// The settlement/window seam: project the row's outcome to the window's
/// two-valued observation. `None` for an epoch the window must not count:
/// a pair with no issued draw has no row, and a pair with fewer than three
/// was not observed.
fn observe(epoch: u64, passes: u8, issued: usize) -> Option<BaselineObservation> {
    if issued == 0 {
        return None;
    }
    let row = SettlementRow::settle(passes, issued).expect("test inputs are rows");
    match row.outcome() {
        SettlementOutcome::Served => Some(BaselineObservation::served(epoch)),
        SettlementOutcome::Missed => Some(BaselineObservation::missed(epoch)),
        SettlementOutcome::NonObservation => None,
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
    // long run of under-issued epochs between them: no draw issued, one, or
    // two, none of which is Served or Missed. The under-issued epochs are
    // dropped, so the window is just
    // the two misses — below m, not slashable. Were NonObservation to
    // collapse to Missed, the window would fill and wrongly slash.
    let n = u64::from(FAILURE_WINDOW_N);
    let mut raw = Vec::new();
    let mut epoch = 2000 + n + 5;
    raw.push(observe(epoch, 0, 3)); // head: a real missed epoch
    epoch -= 1;
    for i in 0..(FAILURE_WINDOW_N + 5) {
        // Cycle the under-issuance shapes: no row, one issued, two issued.
        let issued = usize::from(u8::try_from(i % 3).expect("below three"));
        raw.push(observe(epoch, 0, issued)); // → None, dropped
        epoch -= 1;
    }
    raw.push(observe(epoch, 0, 3)); // one older real missed epoch

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
