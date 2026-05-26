// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2h Round 3 Pass-3 per-recipe latency bench harness — C1
//! placeholder (single-recipe via random-corpus pair).
//!
//! Per
//! [`docs/design/RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! §11 Round 3 close artifact 1 and
//! [`docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
//! §3.1, this integration test is the per-recipe latency bench
//! harness whose CI-on-`ubuntu-latest` invocations produce the
//! measurement basis for the three substrate-derived constants
//! in
//! [`shekyl_randomx_differential::adversarial_canonical_outputs`].
//!
//! ## C1 disposition (this commit)
//!
//! The C1 form of this test is a **placeholder bench harness**
//! exercising the Phase 2g `mode_latency::run` orchestrator over a
//! single random-corpus seedhash pair (no recipe corpus exists yet;
//! the recipe types + first-class interpreter + initial corpus
//! land at C3 + C4 of the Phase 2h implementation commit plan).
//!
//! The C1 harness:
//!
//! - Demonstrates the measurement methodology is reachable from
//!   integration-test scope (the `#[ignore]` gate + `--ignored`
//!   invocation is the substrate the per-PR CI cadence will use
//!   for the real per-recipe bench at C7 + C8).
//! - Asserts the observed Rust/C ratio is within the Phase 2h
//!   Claim 1 hard gate (`5.0 - RUNNER_NOISE_MARGIN`) per
//!   [`RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
//!   §3.3. The C1 gate is looser than Phase 2g's `mode_latency`
//!   gate (`LATENCY_RATIO_BUDGET = 3.0`) because Phase 2h's recipes
//!   intentionally exercise adversarial paths whose per-recipe
//!   ratios are expected to push above the random-corpus baseline.
//! - Emits a single-line `PHASE2H_PASS3_OBSERVATION:` JSON record
//!   to stdout for CI log capture; the M1 amendment commit that
//!   refines the provisional constants consumes this record's
//!   structure.
//!
//! At C6 + C7 + C8, this file is replaced (or supplemented) with
//! the real recipe-based bench that iterates the
//! [`adversarial`](https://example.invalid/anchor-pending-c3)
//! corpus, applies the per-recipe modifications, and computes the
//! per-class median ratio for Claim 2's tracking signal. The C1
//! placeholder is a deletion-target per
//! [`15-deletion-and-debt.mdc`](../../../.cursor/rules/15-deletion-and-debt.mdc)
//! pre-genesis discount; the deletion site is named at C6's commit
//! message.
//!
//! ## Invocation
//!
//! Per the methodology doc §3.1:
//!
//! ```bash
//! cargo test --release \
//!   --package shekyl-randomx-differential \
//!   --test per_recipe_latency \
//!   -- --ignored --nocapture
//! ```
//!
//! The `--ignored` flag is required because the test is
//! `#[ignore]`-gated at the source level (per Phase 2g §5.3 / §9
//! test-cadence discipline: latency-sensitive tests do not run on
//! default `cargo test` invocations). The `--nocapture` flag
//! surfaces the `PHASE2H_PASS3_OBSERVATION:` record to the CI log.

use shekyl_randomx_differential::adversarial_canonical_outputs::{
    CLAIM_2_THRESHOLD, MEASUREMENT_RUNNER_CLASS, RUNNER_NOISE_MARGIN, SAMPLE_BUDGET_PER_RECIPE,
};
use shekyl_randomx_differential::mode_latency;

/// Phase 2h Claim 1 hard-gate ceiling per R1-D5 close.
///
/// The per-recipe ratio gate is `rust_median / c_median ≤ 5.0 -
/// RUNNER_NOISE_MARGIN`. The `5.0` ceiling is the R1-D5-close-
/// pinned worst-case allowance for adversarial-recipe paths; the
/// `RUNNER_NOISE_MARGIN` subtraction absorbs single-allocation
/// runner-class noise per the methodology doc §3.3.
const PHASE2H_CLAIM_1_CEILING: f64 = 5.0;

#[test]
#[ignore = "Phase 2h Round 3 Pass-3 bench harness — requires --ignored invocation per methodology doc §3.1"]
fn pass_3_per_recipe_latency_placeholder() {
    let report = match mode_latency::run(SAMPLE_BUDGET_PER_RECIPE) {
        Ok(report) => report,
        Err(mode_latency::LatencyError::RatioBudgetExceeded { report }) => {
            // Phase 2g's `mode_latency::run` gates at
            // `LATENCY_RATIO_BUDGET = 3.0`, which is the
            // random-corpus baseline. Phase 2h's per-recipe gate
            // is looser (`5.0 - RUNNER_NOISE_MARGIN`) because the
            // recipe corpus intentionally exercises adversarial
            // paths. Extract the report from the budget-exceeded
            // error and re-check against the Phase 2h ceiling.
            report
        }
        Err(other) => panic!(
            "Phase 2h Pass-3 placeholder bench failed at the precondition level (not the \
             ratio gate); cannot produce a measurement observation: {other}"
        ),
    };

    let claim_1_gate = PHASE2H_CLAIM_1_CEILING - RUNNER_NOISE_MARGIN;

    // The Phase 2h Claim 1 hard gate. A failure here is a true
    // substrate finding: either the Rust verifier has regressed
    // significantly against the C reference, or the runner-class
    // variance exceeds RUNNER_NOISE_MARGIN's assumption (in which
    // case the methodology-doc §5 R4 reopening criterion fires
    // and the M1 amendment commit refines RUNNER_NOISE_MARGIN).
    assert!(
        report.ratio <= claim_1_gate,
        "Phase 2h Claim 1 hard gate failed: observed ratio {observed:.3}x exceeds \
         gate {gate:.3}x (= {ceiling:.1} - {margin:.3}). This is either a true \
         performance regression (Rust verifier slower than C reference per the \
         R1-D5 ceiling) or a runner-class-variance substrate finding (per \
         RANDOMX_V2_PHASE2H_MEASUREMENT.md §5 R4 reopening criterion). \
         Investigate via the methodology doc §3.2; if the runner-class variance \
         is the issue, land an amendment commit refining RUNNER_NOISE_MARGIN.",
        observed = report.ratio,
        gate = claim_1_gate,
        ceiling = PHASE2H_CLAIM_1_CEILING,
        margin = RUNNER_NOISE_MARGIN,
    );

    // Emit a single-line observation record for CI log capture.
    // The amendment commit that refines the provisional constants
    // consumes this record's structure; the `PHASE2H_PASS3_OBSERVATION:`
    // prefix is grep-friendly for CI extraction. Hand-rolled JSON
    // avoids pulling `serde_json` into the test file's import
    // surface for one observation line.
    println!(
        "PHASE2H_PASS3_OBSERVATION: {{\
         \"runner_class\":\"{runner_class}\",\
         \"samples\":{samples},\
         \"rust_median_ns\":{rust_median},\
         \"rust_p95_ns\":{rust_p95},\
         \"rust_max_ns\":{rust_max},\
         \"c_median_ns\":{c_median},\
         \"c_p95_ns\":{c_p95},\
         \"c_max_ns\":{c_max},\
         \"observed_ratio\":{ratio:.6},\
         \"claim_1_gate\":{gate:.6},\
         \"runner_noise_margin\":{margin:.6},\
         \"claim_2_threshold\":{claim_2:.6},\
         \"sample_budget_per_recipe\":{budget},\
         \"phase2h_pin\":\"c1-placeholder\"\
         }}",
        runner_class = MEASUREMENT_RUNNER_CLASS,
        samples = report.samples,
        rust_median = report.rust_median_ns,
        rust_p95 = report.rust_p95_ns,
        rust_max = report.rust_max_ns,
        c_median = report.c_median_ns,
        c_p95 = report.c_p95_ns,
        c_max = report.c_max_ns,
        ratio = report.ratio,
        gate = claim_1_gate,
        margin = RUNNER_NOISE_MARGIN,
        claim_2 = CLAIM_2_THRESHOLD,
        budget = SAMPLE_BUDGET_PER_RECIPE,
    );
}
