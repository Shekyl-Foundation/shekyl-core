// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

//! How far each shipped hop is from the next embargo step, and how big it is.
//!
//! Lives here rather than in `carrier_window.rs`: that file enforces the
//! window and the fragment cap against the wire model. This file is the
//! embargo-solver instrument — `derive::next_embargo_step` at the actual hop,
//! because interpolating near a step is wrong (`DAEMON_RELAY_PRIVACY.md`
//! §94.10).

use shekyl_relay_privacy::derive::next_embargo_step;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::verify_cost::{
    ADOPTED_TRANSIT_ASSUMPTION_MS, ANON_ZONE_TRANSIT_ASSUMPTION_MS, GENESIS_TREE_DEPTH,
    SPEC_VERIFY_COST,
};

/// # A record, not a gate
///
/// Nothing in the design picks a hop for its distance from a step, so a
/// threshold here would be another self-invented bar. What this prevents is a
/// hop moving onto a step silently — the bands go red when a distance changes,
/// which tells the next reader something happened, where a bar would only tell
/// them someone once had an opinion.
///
/// # What it measures, and why it is a search
///
/// `derive_embargo` accumulates `div_ceil(h * hop + F, tick)` over the
/// stem-length sum, so the embargo steps where many `h` cross a tick boundary
/// together. `next_embargo_step` searches for the real next change rather than
/// modelling a grid: the structure has harmonics from larger `h` and it moves
/// with `F`, so a closed form for the `h = 1` family alone is wrong in both
/// directions.
///
/// # The finding this carries
///
/// The **shipped interim** anonymity hop is 1 ms from a 12-second step.
/// Whether that instance is exercised is the checklist at §89.8.4, not
/// restated here.
///
/// And the two genesis shapes sit at different distances, so **hop sensitivity
/// is shape-dependent** — §89.3's zone-disclosure question one axis over, with
/// numbers instead of a hypothesis. Raised there, not ruled here.
///
/// What edit reds this: any change to a transit assumption, a verify-cost cell,
/// `fluff_return_ms`, or `DEFAULT_EMBARGO_TICK_MILLIS`.
#[test]
fn the_distance_from_each_shipped_hop_to_the_next_embargo_step_is_recorded() {
    // The §94 round's candidate anonymity transit. A local literal ON PURPOSE:
    // it is BANKED, NOT ADOPTED — the flood-suite re-baseline is its
    // prerequisite — so there is no tree constant to read.
    const CANDIDATE_ANON_TRANSIT_MS: f64 = 590.6;
    const SEARCH_MS: u32 = 400;

    let f1 = SPEC_VERIFY_COST
        .f_ms(1, GENESIS_TREE_DEPTH)
        .expect("populated");
    let f8 = SPEC_VERIFY_COST
        .f_ms(8, GENESIS_TREE_DEPTH)
        .expect("populated");

    let mut seen = Vec::new();
    for (label, hop) in [
        ("clearnet modal", ADOPTED_TRANSIT_ASSUMPTION_MS + f1),
        ("SHIPPED anon modal", ANON_ZONE_TRANSIT_ASSUMPTION_MS + f1),
        ("SHIPPED anon 8-input", ANON_ZONE_TRANSIT_ASSUMPTION_MS + f8),
        ("candidate anon modal", CANDIDATE_ANON_TRANSIT_MS + f1),
        ("candidate anon 8-input", CANDIDATE_ANON_TRANSIT_MS + f8),
    ] {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let hop_ms = hop.round() as u32;
        let params = DandelionParams {
            time_between_hop_ms: hop_ms,
            ..DandelionParams::inherited()
        };
        let step = next_embargo_step(
            &params,
            DEFAULT_EMBARGO_TICK_MILLIS,
            SEARCH_MS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        );
        seen.push((label, hop_ms, step));
    }

    let rendered: Vec<String> = seen
        .iter()
        .map(|(l, h, s)| match s {
            Some((d, delta)) => format!("{l} (hop {h} ms): +{d} ms -> {delta:+} s"),
            None => format!("{l} (hop {h} ms): stable over {SEARCH_MS} ms"),
        })
        .collect();

    // The recorded distances. Each is the measured answer, not a chosen one.
    // The magnitude matters as much as the distance: a +1 s step is the
    // ordinary quantization of a solver that answers in whole seconds, while a
    // +12 s step is the resonance — many `h` crossing a tick boundary together.
    let want = [
        ("clearnet modal", 4_u32, 1_i64),
        // THE SHIPPED INTERIM, and the reason this test exists: one
        // millisecond from an eleven-second jump. Liveness is the checklist
        // at §89.8.4, not restated here.
        ("SHIPPED anon modal", 1, 11),
        ("SHIPPED anon 8-input", 4, 1),
        ("candidate anon modal", 3, 1),
        // And the shape-dependence, live at the candidate: the modal shape is
        // 3 ms from a 1 s step while this one is 7 ms from a 12 s step.
        ("candidate anon 8-input", 7, 12),
    ];
    for ((label, _, step), (want_label, want_d, want_delta)) in seen.iter().zip(want) {
        assert_eq!(*label, want_label, "row order");
        let (d, delta) = step.expect("a step exists inside the search window");
        assert_eq!(
            (d, delta),
            (want_d, want_delta),
            "{label}: the next embargo step is {d} ms away and moves {delta} s; \
             recorded {want_d} ms / {want_delta} s — a hop moved relative to the \
             step structure.\nAll rows:\n  {}",
            rendered.join("\n  ")
        );
    }
}
