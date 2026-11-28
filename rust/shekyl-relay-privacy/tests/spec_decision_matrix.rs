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
//! **Measured inputs:** `f` exhaustively over the consensus domain at genesis
//! depth on x86 (§82, the diagnostic arm), and the spec machine's own cells:
//! every legal shape, measured on the floor device in one session
//! (`CEN_I4_INPUT_CAP_DERIVATION.md` `ICD-R5`). The chart reads the 1-input
//! cell and the consensus maximum at genesis depth.
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

use shekyl_relay_privacy::basis::DerivationMs;
use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::verify_cost::{
    Provenance, TreeBasis, ADOPTED_TRANSIT_ASSUMPTION_MS, GENESIS_TREE_DEPTH, MAX_TABLE_INPUTS,
    SPEC_VERIFY_COST,
};

/// Measured x86 verification cost at depth 2, `n_out = 2`, over the whole
/// consensus domain (asserted against
/// [`shekyl_wire::transaction::MAX_FCMP_INPUTS`] below): the masks-and-proof
/// term, shared layout, criterion's point estimate per count.
///
/// Re-taken with the floor session (`CEN_I4_INPUT_CAP_DERIVATION.md` §8.1) at
/// the same head, `4354a1cf1d`, on an x86-64 reference laptop (Core
/// i9-11950H, Windows 11, MSVC toolchain, mains power, unused during the run).
///
/// **Diagnostic, not spec (§84.2).** The x86 arm exists to detect a workload
/// change. Nothing on the spec path derives from it.
const F_X86_MS: [f64; 22] = [
    22.133, 26.872, 36.685, 39.501, 59.789, 62.448, 66.969, 69.464, 79.911, 110.99, 111.83, 115.36,
    120.21, 121.29, 125.23, 130.2, 145.52, 148.99, 206.1, 211.4, 212.63, 214.06,
];

// `Provenance` is a production type now — the table this test prices landed
// in `verify_cost.rs` with the field and its assertion (§87.2), and this file
// consumes it rather than keeping a twin (rule 50: test the production code).

/// The spec machine's own cells, read from the production table rather than
/// restated. A `const` panic here is unreachable while the module tests pin
/// the modal and tail genesis cells.
const F_PI4_1IN_MS: f64 = match SPEC_VERIFY_COST.f_ms(1, GENESIS_TREE_DEPTH) {
    Ok(v) => v,
    Err(_) => panic!("the modal genesis cell is a floor measurement"),
};
const F_PI4_TAIL_MS: f64 = match SPEC_VERIFY_COST.f_ms(MAX_TABLE_INPUTS, GENESIS_TREE_DEPTH) {
    Ok(v) => v,
    Err(_) => panic!("the consensus-maximum genesis cell is a floor measurement"),
};

/// The x86 arm's cell at the consensus maximum.
const F_X86_TAIL_MS: f64 = F_X86_MS[MAX_TABLE_INPUTS - 1];

/// One candidate minimum spec, priced at the two ends of the legal shape
/// domain. The chart's questions — what the embargo is, and how far it spreads
/// across shapes — are both answered by the endpoints, so a row carries the
/// 1-input cell and the consensus maximum rather than every count.
struct SpecRow {
    label: &'static str,
    /// Verification cost at 1 input, depth 2, 2 outputs (ms).
    f_1in_ms: f64,
    /// Verification cost at the consensus maximum (`MAX_TABLE_INPUTS`
    /// inputs), same cell otherwise (ms).
    f_tail_ms: f64,
    provenance: Provenance,
}

/// The label of the row the guarantee is provisioned to (§80.4).
const DECIDED_SPEC: &str = "Pi 4";

/// Candidate specs. The Pi 4 row is the decision; the rest bracket it.
///
/// The bracket rows are `x86 × k` and say so. The **Pi 4 row is not**: it is
/// the spec machine's own genesis-depth cells, the door's whole sequence
/// (§72.2, amended 2026-11-08). The scaled stand-ins §80.2/§80.3 priced the
/// decision with — `23.182 × 5.56 = 128.9` and `73.481 × 5.56 = 408.6` at the
/// then-cap of 8 — were 3.5 % and 2.4 % above §85.3's masks-and-proof term
/// (124.5 and 399.2 ms): small, and in the over-provisioning direction, which
/// is exactly why the shortcut survives review.
///
/// The x86 arm times the masks-and-proof term alone, so the bracket rows
/// price that term and the Pi 4 row prices the door's sequence. The bracket
/// is diagnostic (§84.2) and no derived value reads it.
const SPECS: [SpecRow; 5] = [
    SpecRow {
        label: "x86 reference",
        f_1in_ms: F_X86_MS[0],
        f_tail_ms: F_X86_TAIL_MS,
        provenance: Provenance::MeasuredX86,
    },
    SpecRow {
        label: "2x slower",
        f_1in_ms: F_X86_MS[0] * 2.0,
        f_tail_ms: F_X86_TAIL_MS * 2.0,
        provenance: Provenance::ScaledFromX86,
    },
    SpecRow {
        label: DECIDED_SPEC,
        f_1in_ms: F_PI4_1IN_MS,
        f_tail_ms: F_PI4_TAIL_MS,
        provenance: Provenance::MeasuredPi4,
    },
    SpecRow {
        label: "8x slower",
        f_1in_ms: F_X86_MS[0] * 8.0,
        f_tail_ms: F_X86_TAIL_MS * 8.0,
        provenance: Provenance::ScaledFromX86,
    },
    SpecRow {
        label: "12x slower",
        f_1in_ms: F_X86_MS[0] * 12.0,
        f_tail_ms: F_X86_TAIL_MS * 12.0,
        provenance: Provenance::ScaledFromX86,
    },
];

/// The transit values swept. §21's own justification for `175` contains ~50 ms
/// of ocean-crossing transit; 25 and 100 bracket it. Swept because it is the
/// unmeasured term.
const TRANSIT_MS: [f64; 3] = [25.0, 50.0, 100.0];

/// The pinned reading of the chart at the decided spec (§80.2): the embargo at
/// the modal 1-input shape and at the consensus-maximum tail, at each swept
/// transit — `(transit_ms, e_1in_secs, e_tail_secs)`.
///
/// These are the numbers the decision was priced with, so they are the ones a
/// change to `derive_embargo`, to `DandelionParams::inherited()`, or to the
/// measured `f` must be forced to restate.
///
/// At the then-cap of 8 inputs, the 1-input→8-input spread (58 / 53 / 55 s)
/// is what §80.2 read as *"a scalar leaves ~56 s uncovered across the whole
/// legal shape domain"*, and §80.3's choice of a per-shape table over a
/// scalar rests on that gap being large. At the derived cap of 22 the gap is
/// about 240 s (238 / 240 / 243 s): a modal-shape embargo leaves the largest
/// legal spend's 434 s embargo less than half covered at the shipped transit.
///
/// **Re-priced 2026-11-27 (`ICD-R5`)**: every cell is the floor session's,
/// so the modal cell is 147.99 ms and the 22-input cell 1 332.34 ms (each the
/// door's whole sequence, §72.2). The input landed with the floor session's
/// fold and these pins moved with it: `derive_embargo` is high-gain near a
/// step (`derive::next_embargo_step`), so a few milliseconds of hop can move
/// the embargo by seconds, and the re-derivation calls it at the actual hop
/// rather than interpolating (`DAEMON_RELAY_PRIVACY.md` §94.10).
const DECIDED_SPEC_PRICE_LIST: [(f64, u64, u64); 3] =
    [(25.0, 190, 428), (50.0, 194, 434), (100.0, 200, 443)];

fn embargo_secs(hop_ms: u32) -> u64 {
    let mut p = DandelionParams::inherited();
    p.time_between_hop_ms = DerivationMs::model(hop_ms);
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
            "spec", "f(1-in)", "f(tail)", "hop(1)", "embargo", "vs x86"
        );

        let base = embargo_for(F_X86_MS[0], transit_ms);

        for row in &SPECS {
            let hop = (row.f_1in_ms + transit_ms).round() as u32;
            let e = embargo_secs(hop);
            println!(
                "  {:<18} {:>7.0}ms {:>7.0}ms {:>7}ms {:>8}s {:>+8.0}%  {:?}",
                row.label,
                row.f_1in_ms,
                row.f_tail_ms,
                hop,
                e,
                100.0 * (e as f64 / base as f64 - 1.0),
                row.provenance
            );
        }

        // What the tail costs at each spec: the tail cell is the consensus
        // maximum, so this is the WHOLE range, not an extrapolation.
        println!(
            "\n  tail spread at each spec (1-in vs {MAX_TABLE_INPUTS}-in embargo, the §75 sorting):"
        );
        for row in &SPECS {
            let e1 = embargo_for(row.f_1in_ms, transit_ms);
            let et = embargo_for(row.f_tail_ms, transit_ms);
            println!(
                "    {:<18} {e1:>4}s -> {et:>4}s   spread {:>4}s ({:>+3.0}%)",
                row.label,
                et - e1,
                100.0 * (et as f64 / e1 as f64 - 1.0)
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
    for (transit_ms, want_e1, want_et) in DECIDED_SPEC_PRICE_LIST {
        let got_e1 = embargo_for(row.f_1in_ms, transit_ms);
        let got_et = embargo_for(row.f_tail_ms, transit_ms);
        assert_eq!(
            (got_e1, got_et),
            (want_e1, want_et),
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
            && (row.f_tail_ms - F_X86_TAIL_MS * RATIO).abs() > 1.0,
        "measured Pi cells coincide with x86 × {RATIO} to within 1 ms; if that \
         is ever true the assertion above stops discriminating and this test \
         needs a sharper instrument, not a waiver"
    );
}

/// The table covers every legal shape and refuses everything else.
///
/// Its input domain is the cap the wire enforces, the diagnostic arm covers
/// the same domain, and each depth's row is exactly as long as the number of
/// inputs the weight limit admits at that depth (`max_inputs_at`, the one
/// legal-shape function). A count consensus refuses everywhere is
/// `InputCountOutsideDomain`; a count a deeper tree cannot carry is
/// `NoLegalShapeAtDepth`. Neither is filled from a neighbouring cell.
#[test]
fn the_table_covers_every_legal_shape_and_refuses_the_rest() {
    use shekyl_relay_privacy::verify_cost::{VerifyCostRefusal, MAX_TABLE_DEPTH};
    use shekyl_tx_weight::{max_inputs_at, NonCoinbaseOutputs, SpendLayers};

    let cap = shekyl_wire::transaction::MAX_FCMP_INPUTS;
    assert_eq!(
        MAX_TABLE_INPUTS, cap,
        "the table's input domain is the consensus cap"
    );
    assert_eq!(
        F_X86_MS.len(),
        MAX_TABLE_INPUTS,
        "the diagnostic array covers the production domain"
    );
    let two_outputs = NonCoinbaseOutputs::new(2).expect("2 outputs are mineable");
    for depth in GENESIS_TREE_DEPTH..=MAX_TABLE_DEPTH {
        let layers = SpendLayers::new(u8::try_from(depth).expect("a table depth is small"))
            .expect("a table depth is a spend depth");
        let legal = max_inputs_at(two_outputs, layers);
        for n_in in 1..=legal {
            assert!(
                SPEC_VERIFY_COST.f_ms(n_in, depth).is_ok(),
                "the legal shape ({n_in} inputs, depth {depth}) is not priced"
            );
        }
        for n_in in legal + 1..=cap {
            assert_eq!(
                SPEC_VERIFY_COST.f_ms(n_in, depth),
                Err(VerifyCostRefusal::NoLegalShapeAtDepth { n_in, depth }),
                "a count the weight limit refuses at depth {depth} is not priced"
            );
        }
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(cap + 1, depth),
            Err(VerifyCostRefusal::InputCountOutsideDomain { n_in: cap + 1 }),
        );
    }
}

/// The floor session's capture, committed beside the other floor captures.
/// Every operand in `verify_cost/door.rs` is a point estimate from this file.
const FLOOR_CAPTURE: &str =
    include_str!("../../../docs/benchmarks/relay_admission_verify_pi4_rust_20261127T144430Z.txt");

/// Criterion's point estimates in a capture, in milliseconds, keyed by the
/// benchmark id: the id line, then the first `time:` line after it (the
/// middle of its three figures). A `change:` line's percentages carry no
/// unit and are skipped.
fn point_estimates_ms(capture: &str) -> std::collections::BTreeMap<String, f64> {
    let mut out = std::collections::BTreeMap::new();
    let mut id: Option<String> = None;
    for line in capture.lines() {
        let mut trimmed = line.trim();
        if trimmed.starts_with("relay_admission_verify/")
            || trimmed.starts_with("block_connect_terms/")
        {
            id = trimmed.split_whitespace().next().map(str::to_owned);
            // A short id shares its line with its `time:` figures.
            match trimmed.find("time:") {
                Some(at) => trimmed = &trimmed[at..],
                None => continue,
            }
        }
        let Some(rest) = trimmed.strip_prefix("time:") else {
            continue;
        };
        let figures: Vec<&str> = rest
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split_whitespace()
            .collect();
        if figures.len() != 6 {
            continue;
        }
        let scale = match figures[3] {
            "s" => 1_000.0,
            "ms" => 1.0,
            "µs" => 0.001,
            _ => continue,
        };
        let Ok(value) = figures[2].parse::<f64>() else {
            continue;
        };
        if let Some(id) = id.take() {
            out.insert(id, value * scale);
        }
    }
    out
}

/// Every cell the production table publishes, recomputed from the committed
/// floor capture: its masks-and-proof term, `n_in` times the hybrid
/// signature, and the lone range proof, in that order. The signature and the
/// range proof each take the larger of their two readings (1 and 22 inputs),
/// as `door.rs` states.
///
/// This is the gate `verify_cost.rs` delegates to when it says its own
/// structural tests do "NOT check the numbers are *correct* Pi measurements".
/// Nothing else pins the values: `adopted_hop_ms` adds 50 ms and rounds to
/// `u32`, so the modal hop holds for anything within half a millisecond of
/// the cell — an operand mis-transcribed by a tenth of a millisecond would
/// enter the shipped `DandelionParams` with every test still green.
///
/// The comparison is set-exhaustive: a published cell with no measurement in
/// the capture fails, and a measured cell the table does not publish fails.
/// Depth 2 reads the spread layout (`d2spread`), the production arrangement;
/// depths 3 to 7 read the synthesized trees (`d{depth}proj`).
#[test]
#[allow(clippy::cast_precision_loss)] // n_in <= 22
fn every_published_cell_is_its_floor_capture() {
    let measured = point_estimates_ms(FLOOR_CAPTURE);
    let term = |name: &str| -> f64 {
        let readings: Vec<f64> = measured
            .iter()
            .filter(|(id, _)| id.starts_with(&format!("block_connect_terms/{name}/")))
            .map(|(_, ms)| *ms)
            .collect();
        assert_eq!(readings.len(), 2, "{name} is read at 1 and 22 inputs");
        readings.into_iter().fold(f64::MIN, f64::max)
    };
    let signature = term("pqc_per_input");
    let range_proof = term("bp_lone");

    let mut from_capture = std::collections::BTreeMap::new();
    for depth in 2u32..=7 {
        let family = if depth == GENESIS_TREE_DEPTH {
            "d2spread".to_owned()
        } else {
            format!("d{depth}proj")
        };
        let prefix = format!("relay_admission_verify/{family}_in");
        for (id, masks_and_proof) in &measured {
            let Some(n_in) = id
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix("_out2"))
                .and_then(|n| n.parse::<usize>().ok())
            else {
                continue;
            };
            let basis = if depth == GENESIS_TREE_DEPTH {
                TreeBasis::Genesis
            } else {
                TreeBasis::SynthesizedProjection
            };
            from_capture.insert(
                (n_in, depth),
                (
                    masks_and_proof + n_in as f64 * signature + range_proof,
                    basis,
                ),
            );
        }
    }

    let mut published = std::collections::BTreeMap::new();
    for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
        assert_eq!(
            cell.provenance,
            Provenance::MeasuredPi4,
            "a published cell ({n_in}-in, depth {depth}) is not a spec-machine \
             measurement; rule 176.4 forbids a scaled or reference-machine \
             number standing in the spec table"
        );
        published.insert((n_in, depth), (cell.millis, cell.basis));
    }

    assert_eq!(
        published.keys().collect::<Vec<_>>(),
        from_capture.keys().collect::<Vec<_>>(),
        "the table's shapes and the capture's shapes differ"
    );
    let mut moved = Vec::new();
    for (shape, (millis, basis)) in &published {
        let (want, want_basis) = from_capture[shape];
        // Relative: a literal such as 1_221.2 and the capture's "1.2212 s"
        // scaled to milliseconds can differ in the last bit.
        if (millis - want).abs() > want * 1e-12 || *basis != want_basis {
            moved.push(format!(
                "{shape:?}: the table has {millis} ms ({basis:?}), the capture gives {want} ms \
                 ({want_basis:?})"
            ));
        }
    }
    assert!(
        moved.is_empty(),
        "the production verification-cost table no longer matches its floor capture. \
         If an operand moved, it is a re-measurement: commit the new capture and \
         update door.rs together.\n{}",
        moved.join("\n")
    );
}
