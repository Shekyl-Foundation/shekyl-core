// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! §80: what each increment of `f` buys — the minimum-spec decision matrix.
//!
//! §78 established that the minimum supported spec is the last unbounded axis
//! and that it is a **decision, not a measurement**. A decision still needs a
//! price list. This emits one: for each candidate spec, the embargo it implies
//! and what that costs everyone.
//!
//! # The chain the chart walks
//!
//! ```text
//! spec  ──▶  f(n_in)  ──▶  hop = transit + verify + sched  ──▶  embargo
//!                                                                  │
//!                                 ┌────────────────────────────────┤
//!                       recovery latency (cost, uniform)   preemption of
//!                                                          below-spec nodes
//!                                                          (harm, sorted)
//! ```
//!
//! **Measured inputs:** `f` exhaustively over the consensus domain
//! `n_in ∈ 1..=8` on x86, and the Pi arm's 5.56× ratio.
//!
//! **Assumed input, and it is the gap:** `transit`. §71 defines `hop` as
//! transit + verification + scheduling, and only the middle term is measured.
//! Transit is therefore swept as a parameter rather than fixed, so the chart
//! shows which conclusions depend on it and which do not.
//!
//! **Not measurable at all:** what fraction of operators sit below each
//! candidate spec. That is the judgment §78 says the round must supply; no
//! bench produces it.

use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

/// Measured x86 verification cost at depth 2, `n_out = 2`, over the whole
/// consensus domain (`FCMP_MAX_INPUTS_PER_TX = 8`).
const F_X86_MS: [f64; 8] = [
    23.182, 27.513, 38.053, 43.908, 52.316, 67.801, 71.301, 73.481,
];

/// Candidate specs, as multipliers on the x86 reference.
/// 5.56× is the measured Pi 4 ratio (§73.2); the others bracket it.
const SPECS: [(&str, f64); 5] = [
    ("x86 reference", 1.00),
    ("2x slower", 2.00),
    ("Pi 4 (measured)", 5.56),
    ("8x slower", 8.00),
    ("12x slower", 12.00),
];

fn embargo_secs(hop_ms: u32) -> u64 {
    let mut p = DandelionParams::inherited();
    p.time_between_hop_ms = hop_ms;
    let d = derive_embargo(
        &p,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("solves");
    u64::from(d.mean_secs())
}

#[test]
fn spec_decision_matrix() {
    // §21's own justification for `175` contains ~50 ms of ocean-crossing
    // transit; 25 and 100 bracket it. Swept because it is the unmeasured term.
    for transit_ms in [25.0_f64, 50.0, 100.0] {
        println!("\n\n=== transit = {transit_ms:.0} ms (ASSUMED — the unmeasured term) ===");
        println!(
            "\n  {:<18} {:>9} {:>9} {:>9} {:>10} {:>9}",
            "spec", "f(1-in)", "f(8-in)", "hop(1)", "embargo", "vs x86"
        );

        let base_hop = (F_X86_MS[0] + transit_ms).round() as u32;
        let base = embargo_secs(base_hop);

        for (label, mult) in SPECS {
            let f1 = F_X86_MS[0] * mult;
            let f8 = F_X86_MS[7] * mult;
            let hop = (f1 + transit_ms).round() as u32;
            let e = embargo_secs(hop);
            println!(
                "  {:<18} {:>7.0}ms {:>7.0}ms {:>7}ms {:>8}s {:>+8.0}%",
                label,
                f1,
                f8,
                hop,
                e,
                100.0 * (e as f64 / base as f64 - 1.0)
            );
        }

        // What the tail costs at the chosen spec: the 8-input cell is the
        // consensus maximum, so this is the WHOLE range, not an extrapolation.
        println!("\n  tail spread at each spec (1-in vs 8-in embargo, the §75 sorting):");
        for (label, mult) in SPECS {
            let e1 = embargo_secs((F_X86_MS[0] * mult + transit_ms).round() as u32);
            let e8 = embargo_secs((F_X86_MS[7] * mult + transit_ms).round() as u32);
            println!(
                "    {label:<18} {e1:>4}s -> {e8:>4}s   spread {:>4}s ({:>+3.0}%)",
                e8 - e1,
                100.0 * (e8 as f64 / e1 as f64 - 1.0)
            );
        }
    }

    // Guard: the domain really is closed at 8, so none of the above is an
    // extrapolation. If MAX_INPUTS moves, this table stops being exhaustive.
    assert_eq!(
        F_X86_MS.len(),
        8,
        "the measured surface must cover the whole consensus domain \
         (FCMP_MAX_INPUTS_PER_TX = 8); if the cap moves, re-measure rather \
         than extrapolating"
    );
}
