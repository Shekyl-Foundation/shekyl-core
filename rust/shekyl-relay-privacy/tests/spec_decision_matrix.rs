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
//! `n_in ∈ 1..=8` on x86 (§82), and the spec machine's own 1-input and
//! 8-input cells at genesis depth (§85.3).
//!
//! **Assumed input, and it is the gap:** `transit`. §71 defines `hop` as
//! transit + verification + scheduling, and only the middle term is measured.
//! Transit is therefore swept as a parameter rather than fixed, so the chart
//! shows which conclusions depend on it and which do not.
//!
//! **Not measurable at all:** what fraction of operators sit below each
//! candidate spec. That is the judgment §78 says the round must supply; no
//! bench produces it.
//!
//! # What is asserted and what is merely printed
//!
//! The tables are a report — `cargo test` captures stdout, so they are visible
//! only under `--nocapture`, and **nothing may depend on a human having looked
//! at them.** The gate is the assertions below: the price list at the decided
//! spec, the provenance of the row that price is read off, and the domain the
//! table claims to cover. A test whose whole product is `println!` passes
//! identically whether the derivation is right or nonsense.

use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::verify_cost::{
    Provenance, TreeBasis, ADOPTED_TRANSIT_ASSUMPTION_MS, GENESIS_TREE_DEPTH, MAX_TABLE_INPUTS,
    SPEC_VERIFY_COST,
};

/// Measured x86 verification cost at depth 2, `n_out = 2`, over the whole
/// consensus domain (`FCMP_MAX_INPUTS_PER_TX = 8`; asserted against
/// [`shekyl_fcmp::MAX_INPUTS`] below).
///
/// **Diagnostic, not spec (§84.2).** The x86 arm exists to detect a workload
/// change. Nothing on the spec path derives from it.
const F_X86_MS: [f64; 8] = [
    23.182, 27.513, 38.053, 43.908, 52.316, 67.801, 71.301, 73.481,
];

// `Provenance` is a production type now — the table this test prices landed
// in `verify_cost.rs` with the field and its assertion (§87.2), and this file
// consumes it rather than keeping a twin (rule 50: test the production code).

/// The spec machine's own cells, read from the production table rather than
/// restated. A `const` panic here is unreachable while the module tests pin
/// the modal and tail genesis cells.
const F_PI4_1IN_MS: f64 = match SPEC_VERIFY_COST.f_ms(1, GENESIS_TREE_DEPTH) {
    Ok(v) => v,
    Err(_) => panic!("the modal genesis cell is a pinned §85.3 measurement"),
};
const F_PI4_8IN_MS: f64 = match SPEC_VERIFY_COST.f_ms(8, GENESIS_TREE_DEPTH) {
    Ok(v) => v,
    Err(_) => panic!("the 8-input genesis cell is a pinned §85.3 measurement"),
};

/// One candidate minimum spec, priced at the two ends of the legal shape
/// domain. The chart's questions — what the embargo is, and how far it spreads
/// across shapes — are both answered by the endpoints, so a row carries the
/// 1-input and 8-input cells rather than all eight.
struct SpecRow {
    label: &'static str,
    /// Verification cost at 1 input, depth 2, 2 outputs (ms).
    f_1in_ms: f64,
    /// Verification cost at 8 inputs — the consensus maximum — same cell
    /// otherwise (ms).
    f_8in_ms: f64,
    provenance: Provenance,
}

/// The label of the row the guarantee is provisioned to (§80.4).
const DECIDED_SPEC: &str = "Pi 4";

/// Candidate specs. The Pi 4 row is the decision; the rest bracket it.
///
/// The bracket rows are `x86 × k` and say so. The **Pi 4 row is not**: 124.5
/// and 399.2 ms are the spec machine's own genesis-depth cells (§85.3). The
/// scaled stand-ins they replace — `23.182 × 5.56 = 128.9` and
/// `73.481 × 5.56 = 408.6` — are what §80.2/§80.3 priced the decision with,
/// and they are 3.5 % and 2.4 % high. Small, and in the over-provisioning
/// direction, which is exactly why the shortcut survives review.
const SPECS: [SpecRow; 5] = [
    SpecRow {
        label: "x86 reference",
        f_1in_ms: F_X86_MS[0],
        f_8in_ms: F_X86_MS[7],
        provenance: Provenance::MeasuredX86,
    },
    SpecRow {
        label: "2x slower",
        f_1in_ms: F_X86_MS[0] * 2.0,
        f_8in_ms: F_X86_MS[7] * 2.0,
        provenance: Provenance::ScaledFromX86,
    },
    SpecRow {
        label: DECIDED_SPEC,
        f_1in_ms: F_PI4_1IN_MS,
        f_8in_ms: F_PI4_8IN_MS,
        provenance: Provenance::MeasuredPi4,
    },
    SpecRow {
        label: "8x slower",
        f_1in_ms: F_X86_MS[0] * 8.0,
        f_8in_ms: F_X86_MS[7] * 8.0,
        provenance: Provenance::ScaledFromX86,
    },
    SpecRow {
        label: "12x slower",
        f_1in_ms: F_X86_MS[0] * 12.0,
        f_8in_ms: F_X86_MS[7] * 12.0,
        provenance: Provenance::ScaledFromX86,
    },
];

/// The transit values swept. §21's own justification for `175` contains ~50 ms
/// of ocean-crossing transit; 25 and 100 bracket it. Swept because it is the
/// unmeasured term.
const TRANSIT_MS: [f64; 3] = [25.0, 50.0, 100.0];

/// The pinned reading of the chart at the decided spec (§80.2): the embargo at
/// the modal 1-input shape and at the 8-input tail, at each swept transit —
/// `(transit_ms, e_1in_secs, e_8in_secs)`.
///
/// These are the numbers the decision was priced with, so they are the ones a
/// change to `derive_embargo`, to `DandelionParams::inherited()`, or to the
/// measured `f` must be forced to restate.
///
/// The 1-input→8-input spread they give (57 / 55 / 52 s) is what §80.2 states
/// as *"a scalar leaves ~56 s uncovered across the whole legal shape domain"*
/// — and it survives the switch from the scaled stand-ins to the spec
/// machine's own cells, which is why §80.3's choice does not move with it.
/// **Re-priced 2026-08-23** when the node-crypto term folded into `f_ms`.
/// The 1-input column did not move at any transit point; the 8-input column
/// moved **0 s at 25 ms transit, +1 s at 50, and +12 s at 100** — not uniformly,
/// and the 12-second jump is the embargo step structure, not the crypto term.
/// A 4.26 ms input change producing a 12 s output change is `derive_embargo`
/// being high-gain near a step (`derive::next_embargo_step`), which is why the
/// re-derivation round must call it at the actual hop rather than interpolate.
/// That the columns move differently at all is the fold's own
/// premise showing up in the output: the crypto term scales with message size,
/// so it is 0.94 ms at the modal shape's 13,122 B message and 4.26 ms at the
/// 8-input shape's 59,348 B one. §80.2's "~56 s uncovered across the legal
/// shape domain" reading is unchanged in substance — the gap between the two
/// columns moves from 55 s to 56 s at the shipped transit point.
const DECIDED_SPEC_PRICE_LIST: [(f64, u64, u64); 3] =
    [(25.0, 184, 241), (50.0, 190, 246), (100.0, 198, 262)];

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

fn embargo_for(f_ms: f64, transit_ms: f64) -> u64 {
    embargo_secs((f_ms + transit_ms).round() as u32)
}

fn decided_row() -> &'static SpecRow {
    SPECS
        .iter()
        .find(|r| r.label == DECIDED_SPEC)
        .expect("the decided spec must be a row in the table it is decided from")
}

#[test]
fn spec_decision_matrix() {
    for transit_ms in TRANSIT_MS {
        println!("\n\n=== transit = {transit_ms:.0} ms (ASSUMED — the unmeasured term) ===");
        println!(
            "\n  {:<18} {:>9} {:>9} {:>9} {:>10} {:>9}  provenance",
            "spec", "f(1-in)", "f(8-in)", "hop(1)", "embargo", "vs x86"
        );

        let base = embargo_for(F_X86_MS[0], transit_ms);

        for row in &SPECS {
            let hop = (row.f_1in_ms + transit_ms).round() as u32;
            let e = embargo_secs(hop);
            println!(
                "  {:<18} {:>7.0}ms {:>7.0}ms {:>7}ms {:>8}s {:>+8.0}%  {:?}",
                row.label,
                row.f_1in_ms,
                row.f_8in_ms,
                hop,
                e,
                100.0 * (e as f64 / base as f64 - 1.0),
                row.provenance
            );
        }

        // What the tail costs at each spec: the 8-input cell is the consensus
        // maximum, so this is the WHOLE range, not an extrapolation.
        println!("\n  tail spread at each spec (1-in vs 8-in embargo, the §75 sorting):");
        for row in &SPECS {
            let e1 = embargo_for(row.f_1in_ms, transit_ms);
            let e8 = embargo_for(row.f_8in_ms, transit_ms);
            println!(
                "    {:<18} {e1:>4}s -> {e8:>4}s   spread {:>4}s ({:>+3.0}%)",
                row.label,
                e8 - e1,
                100.0 * (e8 as f64 / e1 as f64 - 1.0)
            );
        }
    }

    // The shipped transit assumption must be one of the swept points, or the
    // sweep prices a decision production does not make (§86.2).
    assert!(
        TRANSIT_MS.contains(&ADOPTED_TRANSIT_ASSUMPTION_MS),
        "the sweep must include the shipped transit assumption \
         ({ADOPTED_TRANSIT_ASSUMPTION_MS} ms)"
    );

    // The gate: the price list at the decided spec, restated from the
    // derivation rather than from the chart. §80.2 read the sorting cost off
    // these numbers ("a scalar leaves ~56 s uncovered across the whole legal
    // shape domain") and §80.3 chose D over B with them; a change to
    // `derive_embargo`, to the inherited params, or to the measured `f` moves
    // them and owes that reading a re-derivation.
    let row = decided_row();
    for (transit_ms, want_e1, want_e8) in DECIDED_SPEC_PRICE_LIST {
        let got_e1 = embargo_for(row.f_1in_ms, transit_ms);
        let got_e8 = embargo_for(row.f_8in_ms, transit_ms);
        assert_eq!(
            (got_e1, got_e8),
            (want_e1, want_e8),
            "the embargo priced at the decided spec ({DECIDED_SPEC}) moved at \
             transit = {transit_ms} ms; §80.2's sorting cost and §80.3's \
             D-over-B choice were read off these values"
        );
    }
}

/// Named for the harm, not for the mechanism (§87.1/§87.3).
///
/// **A spec row filled by scaling the x86 arm gives every operator an embargo
/// derived for a machine faster than the one the guarantee is provisioned to.**
/// The tail rows are where that bites: §85.4 measured the *marginal* Pi/x86
/// ratio at 5.98× against the 5.56× the totals establish, so an increment
/// carried over by scaling under-provisions the deep-tree, many-input shapes
/// by ~7.5 % — the shapes §75's sorting is about — and below-spec nodes lose
/// anonymity with no feedback channel to report it.
///
/// Failing this test means someone filled a spec-path cell from the fast
/// machine. The fix is a measurement on the Pi, not a relaxation here.
#[test]
fn scaling_the_spec_row_from_x86_would_underprovision_the_tail() {
    let row = decided_row();
    assert_eq!(
        row.provenance,
        Provenance::MeasuredPi4,
        "the decided spec's numbers must come from the spec machine (§84.2); \
         a scaled row is a diagnostic wearing a spec value's clothes"
    );

    // And the acquittal beside the conviction (§87.4): the check discriminates
    // — the scaled stand-in really is a different number, so this is not a
    // tautology that would pass whatever the row held. The 5.56× ratio is
    // §80.6's invariant, i.e. the most defensible scaling anyone would reach
    // for, and it still misses both measured cells.
    const RATIO: f64 = 5.56;
    assert!(
        (row.f_1in_ms - F_X86_MS[0] * RATIO).abs() > 1.0
            && (row.f_8in_ms - F_X86_MS[7] * RATIO).abs() > 1.0,
        "measured Pi cells coincide with x86 × {RATIO} to within 1 ms; if that \
         is ever true the assertion above stops discriminating and this test \
         needs a sharper instrument, not a waiver"
    );
}

/// The table claims to be exhaustive over the legal input domain. This is what
/// makes that claim falsifiable.
///
/// `F_X86_MS` is `[f64; 8]`, so its length is a compile-time constant — an
/// assertion against the literal `8` could never fail, and would go on
/// reporting "the whole range, not an extrapolation" after the cap moved. The
/// comparison has to be against the cap **as the code enforces it**:
/// [`shekyl_fcmp::MAX_INPUTS`] is checked by `proof::verify` itself, which is
/// the call the surface times. Its consensus twin is
/// `FCMP_MAX_INPUTS_PER_TX` (`cryptonote_config.h`).
#[test]
fn the_measured_surface_covers_the_whole_consensus_domain() {
    assert_eq!(
        MAX_TABLE_INPUTS,
        shekyl_fcmp::MAX_INPUTS,
        "the production table's input domain must be the consensus domain; if \
         the cap moves, `MAX_TABLE_INPUTS` moves with it and the new cells are \
         measured on the spec machine, never extrapolated (§84.2) — otherwise \
         `f_ms` refuses consensus-legal shapes as `InputCountOutsideDomain`, \
         which reads as designed behaviour rather than a stale cap"
    );
    assert_eq!(
        F_X86_MS.len(),
        shekyl_fcmp::MAX_INPUTS,
        "the measured surface must cover the whole consensus domain; if the \
         cap moves, re-measure the new cells rather than extrapolating into \
         them — the tail is where §75's sorting lives"
    );
}

/// §85.3 restated: every cell the production table publishes, with the value
/// the spec machine actually produced.
///
/// This is the gate `verify_cost.rs` delegates to when it says its own
/// structural tests do "NOT check the numbers are *correct* Pi measurements —
/// that is what pinning them against §85.3 in the price-list gate is for".
/// Nothing else pins the values: `adopted_hop_ms` adds 50 ms and rounds to
/// `u32`, so `Ok(175)` holds for anything in `[124.5, 125.5)` and `Ok(449)`
/// for anything in `[398.5, 399.5)` — a cell mis-transcribed as `125.4` would
/// enter the shipped `DandelionParams` with every test still green.
///
/// The comparison is set-exhaustive rather than cell-by-cell so the 44 owed
/// cells cannot land unpinned: a populated cell with no row here fails, and a
/// row here with no populated cell fails.
const SPEC_85_3_CELLS: [(usize, u32, f64, TreeBasis); 4] = [
    (1, 2, 124.5, TreeBasis::Genesis),
    (1, 7, 143.3, TreeBasis::SynthesizedProjection),
    (8, 2, 399.2, TreeBasis::Genesis),
    (8, 7, 791.9, TreeBasis::SynthesizedProjection),
];

#[test]
fn every_published_cell_is_its_pinned_85_3_measurement() {
    let published: Vec<(usize, u32, f64, TreeBasis)> = SPEC_VERIFY_COST
        .populated()
        .map(|(n_in, depth, cell)| {
            assert_eq!(
                cell.provenance,
                Provenance::MeasuredPi4,
                "a published cell ({n_in}-in, depth {depth}) is not a spec-machine \
                 measurement; rule 76.4 forbids a scaled or reference-machine \
                 number standing in the spec table"
            );
            (n_in, depth, cell.millis, cell.basis)
        })
        .collect();

    assert_eq!(
        published.as_slice(),
        SPEC_85_3_CELLS.as_slice(),
        "the production verification-cost table no longer matches §85.3. If a \
         cell moved, it is a re-measurement: update §85.3 and this pin \
         together. If a cell appeared, transcribe its measured value here — \
         an unpinned cell is a number nobody checked feeding the shipped \
         `hop`."
    );
}
