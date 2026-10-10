// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The D3 exception measurement (`P2P_3_SLICE_1_PEERLIST_BRIEF.md` §5a,
//! §16.5): the uniform sample against the sample that leaves our current
//! outbound sessions out, scored by a presence observer and an absence
//! observer. Run with `--nocapture` for the table that §5a records.
//!
//! Pinned on the shape the rule turns on: leaving `O` out silences the
//! presence observer (it can never name an outbound session) **and hands
//! `O` to the absence observer** — with knowledge of `W` its precision on
//! our outbound sessions goes to one once every other white address has
//! been disclosed, where under the uniform sample it stays at `|O| / |W|`.
//! An observer gains, so the exception is not adopted.

#![allow(clippy::cast_precision_loss)]

use shekyl_peerlist::conformance::simulate_disclosure_exception;
use shekyl_peerlist::{white_diversity_floor, DISCLOSE_COUNT};
use shekyl_relay_privacy::rng::SplitMix64;

#[test]
fn leaving_outbound_sessions_out_hands_them_to_the_absence_observer() {
    const OUTBOUND: usize = 12;
    const HIDDEN: usize = 12; // the hidden connector: every outbound session hides the address
    let trials = 400;
    println!(
        "\n§5a D3 exception: |O|={OUTBOUND}, DISCLOSE_COUNT={DISCLOSE_COUNT}, {trials} trials. \
         precision/recall on uncontrolled O; hidden-slot hit."
    );
    println!(
        "  |W|  beyond  ctrl   k    uniform presence   uniform absence    excluded presence  excluded absence"
    );
    let mut rows = Vec::new();
    for (white, beyond) in [
        (white_diversity_floor(), 0),
        (white_diversity_floor(), 48),
        (100, 0),
        (100, 100),
    ] {
        for controlled in [0, 4] {
            for windows in [1, 7, 30] {
                let mut rng = SplitMix64::new(
                    0x5a_0000
                        + (white * 1_000 + beyond * 10 + controlled) as u64 * 64
                        + windows as u64,
                );
                let r = simulate_disclosure_exception(
                    white, OUTBOUND, HIDDEN, controlled, beyond, windows, trials, &mut rng,
                );
                println!(
                    "  {:>3}  {:>5}  {:>4}  {:>2}   {:.3}/{:.3} {:.3}   {:.3}/{:.3} {:.3}   {:.3}/{:.3} {:.3}   {:.3}/{:.3} {:.3}",
                    white,
                    beyond,
                    controlled,
                    windows,
                    r.uniform.presence.precision,
                    r.uniform.presence.recall,
                    r.uniform.presence.hidden_slot_hit,
                    r.uniform.absence.precision,
                    r.uniform.absence.recall,
                    r.uniform.absence.hidden_slot_hit,
                    r.excluded.presence.precision,
                    r.excluded.presence.recall,
                    r.excluded.presence.hidden_slot_hit,
                    r.excluded.absence.precision,
                    r.excluded.absence.recall,
                    r.excluded.absence.hidden_slot_hit,
                );
                rows.push(r);
            }
        }
    }

    for r in &rows {
        // Under the uniform sample neither observer learns anything about
        // O beyond its base rate: presence precision is about |O|/|W| and
        // absence precision is about the share of O among the never-seen.
        let base = (OUTBOUND - r.controlled) as f64 / (r.white - r.controlled) as f64;
        assert!(
            (r.uniform.presence.precision - base).abs() < 0.05,
            "uniform presence precision is the base rate: {} vs {base} at {r:?}",
            r.uniform.presence.precision
        );
        // The exception silences the presence observer entirely...
        assert!(
            r.excluded.presence.precision == 0.0 && r.excluded.presence.recall == 0.0,
            "under exclusion a disclosed address is never outbound: {r:?}"
        );
        // ...and hands O to the absence observer: perfect recall at every k,
        // and precision rising with k toward |O| / (|O| + beyond).
        assert!(
            (r.excluded.absence.recall - 1.0).abs() < 1e-9,
            "under exclusion every uncontrolled outbound session is never disclosed: {r:?}"
        );
        assert!(
            r.excluded.absence.precision >= r.uniform.absence.precision - 1e-9,
            "the absence observer never loses by the exception: {r:?}"
        );
        if r.windows == 30 {
            // The never-disclosed set after k windows is O, the nodes beyond
            // W, and the non-O white addresses the draw has not yet reached:
            // (|W| - |O|) (1 - 12 / (|W| - |O|))^k of them in expectation.
            let non_outbound = (r.white - OUTBOUND) as f64;
            let unseen = non_outbound * (1.0 - DISCLOSE_COUNT as f64 / non_outbound).powi(30);
            let targets = (OUTBOUND - r.controlled) as f64;
            let expected = targets / (targets + r.known_beyond_white as f64 + unseen);
            assert!(
                (r.excluded.absence.precision - expected).abs() < 0.03,
                "after 30 windows the absence observer's precision is {expected:.3}: {}",
                r.excluded.absence.precision
            );
            if r.known_beyond_white == 0 {
                assert!(
                    r.excluded.absence.hidden_slot_hit > 1.0 / (OUTBOUND - r.controlled) as f64 - 0.02,
                    "with W known the hidden slot is one guess among the outbound hidden sessions: {r:?}"
                );
            }
        }
    }
}
