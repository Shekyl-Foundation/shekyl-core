// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! T6 — `worst_case_ratio`.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D5 / R1-D6 close: T6 reactivates at C7 once the
//! recipe corpus (C4), the canonical-output meta-pin (C5), and the
//! `mode_adversarial_ratio` orchestrator (C6) all exist.
//!
//! The Phase 2g name `worst_case_ratio` is preserved in this file
//! name for plan-doc continuity; the underlying mode is now
//! `--mode=adversarial-ratio` per R1-D5 close's rename. T6's
//! conceptual scope is unchanged: assert the parent
//! [`RANDOMX_V2_PLAN.md`](../../../docs/design/RANDOMX_V2_PLAN.md)
//! §6 *≤5.0× on adversarial inputs* bound holds against the recipe
//! corpus.
//!
//! ## What T6 asserts
//!
//! 1. Invoke [`mode_adversarial_ratio::run`] with the per-recipe
//!    sample budget [`SAMPLE_BUDGET_PER_RECIPE`].
//! 2. Surface the orchestrator's two-claim output:
//!    - **Claim 1 (hard gate).** Any per-recipe `max_ratio`
//!      exceeding `CLAIM_1_RATIO_BOUND − RUNNER_NOISE_MARGIN` fails
//!      the test. Implemented inside the orchestrator via
//!      [`AdversarialRatioError::Claim1BoundExceeded`]; T6 propagates
//!      the failure with full diagnostic context.
//!    - **Claim 2 (tracking signal).** Per-class systematic ratio
//!      drift surfaced in
//!      [`AdversarialRatioReport::claim_2_violations`]. T6 does not
//!      *fail* on Claim-2 violations — per R1-D5 close, Claim 2 is a
//!      regression-tracking signal — but it emits a
//!      `T6_CLAIM_2_TRACKING:` log line for the CI workflow's
//!      regression-tracking dashboard to harvest.
//! 3. Emit a single-line `T6_OBSERVATION:` JSON record summarizing
//!    the run for CI log capture (mirrors the Phase 2h Round 3
//!    Pass-3 measurement record shape; the C8 CI workflow consumes
//!    the structure).
//!
//! ## Cadence
//!
//! Per R1-D6 close Reframe 2: T6 runs **nightly** during pre-genesis
//! (constants still drifting; recipes being added; noise margin
//! being baselined) and **release-gate** post-genesis. The
//! per-recipe sample cost (~100 samples × 25 ms × 8 recipes × 2
//! sides ≈ 40 s on the C4 corpus) is too heavy for per-PR cadence.
//!
//! Mechanically: the test is `#[ignore]`-gated; `cargo test
//! --ignored worst_case_ratio` invokes it. The C8 CI workflow runs
//! this on `workflow_dispatch` and on the nightly schedule per R1-D7
//! close's separate-workflow disposition.
//!
//! ## Post-PR-#79 substrate note (FOLLOWUP closed)
//!
//! T6's measurement orchestrator (`mode_adversarial_ratio::run`)
//! invokes the same `(seedhash, data)` → hash path that T2
//! exercises. Originally that path diverged from the C reference per
//! the V3.0 verifier-divergence FOLLOWUP, which made T6's ratio
//! interpretation suspect (the Rust hash chain was incomplete
//! relative to C; latency comparisons against semantically
//! non-equivalent work are meaningless). The FOLLOWUP closed on
//! `dev` via [PR #79](https://github.com/Shekyl-Foundation/shekyl-core/pull/79)
//! (`989610cac`, 2026-05-26; root cause: `RANDOMX_FLAG_V2` missing
//! at `randomx_create_vm`); PR #78's post-rebase commit
//! (`c71ce2413`) extended the same fix to
//! [`COracleSession::from_raw_for_testing`](shekyl_randomx_differential::c_oracle::COracleSession::from_raw_for_testing)
//! (the constructor `mode_adversarial_ratio` uses). T6's ratio
//! measurements are now semantically load-bearing.
//!
//! T6's `#[ignore]` attribute persists for an unrelated
//! (runtime-cost) reason — the per-recipe sample cost still puts T6
//! outside the per-PR cadence budget per R1-D6 close Reframe 2.
//! The C8 workflow's `if: false` gate, which was paired with the
//! now-closed FOLLOWUP, lifts in this PR.
//!
//! ## Actionable failure semantics (R1-D6 close Reframe 3)
//!
//! On Claim-1 failure (the hard gate), the test panics with:
//!
//! - The list of offending recipe names (the orchestrator's
//!   `offending_recipes` vector).
//! - The full [`AdversarialRatioReport`] Display rendering so a
//!   reviewer reading CI output sees per-recipe + per-class context
//!   inline.
//! - A pointer to the methodology doc § that controls the bound's
//!   tightening / loosening procedure.
//!
//! On Claim-2 violation (tracking signal only), the test emits the
//! `T6_CLAIM_2_TRACKING:` record but does not fail.

#![cfg(unix)]

use shekyl_randomx_differential::adversarial_canonical_outputs::{
    CLAIM_2_THRESHOLD, MEASUREMENT_RUNNER_CLASS, RUNNER_NOISE_MARGIN, SAMPLE_BUDGET_PER_RECIPE,
};
use shekyl_randomx_differential::mode_adversarial_ratio::{
    self, AdversarialRatioError, CLAIM_1_RATIO_BOUND,
};

#[test]
#[ignore = "Phase 2h T6 (worst_case_ratio): ~40 s on the C4 corpus, nightly/release-gate cadence per R1-D6 close; invoke with --ignored"]
fn t6_worst_case_ratio() {
    // Per-PR-#78 Round-3 finding F10: the
    // `randomx-v2-adversarial-ratio.yml` workflow's
    // `samples_per_recipe` workflow_dispatch input is wired
    // through the `T6_SAMPLES_PER_RECIPE` environment variable.
    // Parsing as `usize` is strict: an unparseable value is a
    // workflow-author bug (the dispatch UI passes a free-form
    // string), surfaced loudly with `expect`. An empty/unset
    // variable means "use the default `SAMPLE_BUDGET_PER_RECIPE`"
    // per the workflow's input `default: ''` shape.
    //
    // Per-PR-#78 Round-6 finding F13 (comment 3307805569): zero
    // is also rejected at parse time to match the CLI's
    // `parse_positive_usize` contract (in `src/main.rs`) and the
    // orchestrator's `AdversarialRatioError::ZeroSamples`
    // precondition. Without this check, a dispatch value of `0`
    // would parse successfully here and fail later in
    // `mode_adversarial_ratio::run` with a less direct error;
    // rejecting at parse time keeps the dispatch-input semantics
    // identical to the CLI's per-flag contract.
    let samples_override: Option<usize> = match std::env::var("T6_SAMPLES_PER_RECIPE") {
        Ok(s) if s.is_empty() => None,
        Ok(s) => {
            let parsed: usize = s.parse().expect(
                "T6_SAMPLES_PER_RECIPE must be a positive integer (workflow_dispatch input); \
                 unparseable value is a workflow-author bug",
            );
            assert!(
                parsed >= 1,
                "T6_SAMPLES_PER_RECIPE must be >= 1; got 0 (matches `parse_positive_usize` CLI contract \
                 + `AdversarialRatioError::ZeroSamples` orchestrator precondition)",
            );
            Some(parsed)
        }
        Err(_) => None,
    };
    let report = match mode_adversarial_ratio::run(samples_override) {
        Ok(report) => report,
        Err(AdversarialRatioError::Claim1BoundExceeded {
            report,
            offending_recipes,
        }) => {
            // R1-D6 close Reframe 3: the failure message contains
            // mechanically actionable diagnostic content. The
            // orchestrator's Display impl carries per-recipe and
            // per-class context; we panic with both surfaces so a
            // reviewer reading the CI log doesn't have to spelunk
            // the harness to find the regressing recipe.
            panic!(
                "T6: Claim 1 hard gate FAILED for {n} recipe(s): {offenders:?}\n\
                 ===== Adversarial-ratio report =====\n\
                 {report}\n\
                 ===================================\n\
                 The per-recipe `max_ratio` exceeded the effective \
                 Claim 1 gate ({ceiling:.1} − {margin:.3} = \
                 {effective:.3}x). Investigate via the methodology \
                 doc (RANDOMX_V2_PHASE2H_MEASUREMENT.md §5 R4 \
                 reopening criterion): either a true Rust verifier \
                 regression (Rust slower than C reference past the \
                 R1-D5 ceiling) or a runner-class-variance substrate \
                 finding (amend RUNNER_NOISE_MARGIN).",
                n = offending_recipes.len(),
                offenders = offending_recipes,
                report = report,
                ceiling = CLAIM_1_RATIO_BOUND,
                margin = RUNNER_NOISE_MARGIN,
                effective = CLAIM_1_RATIO_BOUND - RUNNER_NOISE_MARGIN,
            );
        }
        Err(other) => panic!(
            "T6: adversarial-ratio orchestrator failed at the precondition level \
             (not the Claim 1 gate); cannot produce a ratio observation: {other}"
        ),
    };

    // Claim-2 tracking signal: emit but do NOT fail the test. Per
    // R1-D5 close Reframe: Claim 2 is regression-tracking, not
    // gate-blocking. The C8 CI workflow's tracking-dashboard
    // harvester consumes the `T6_CLAIM_2_TRACKING:` line if
    // claim_2_violations is non-empty.
    if !report.claim_2_violations.is_empty() {
        println!(
            "T6_CLAIM_2_TRACKING: {{\
             \"violating_categories\":{violations:?},\
             \"corpus_median_ratio\":{corpus_median:.6},\
             \"claim_2_threshold\":{threshold:.6},\
             \"per_class\":[{per_class}]\
             }}",
            violations = report.claim_2_violations,
            corpus_median = report.corpus_median_ratio,
            threshold = report.claim_2_threshold,
            per_class = report
                .per_class
                .iter()
                .map(|c| format!(
                    "{{\"category\":{},\"recipe_count\":{},\"class_median_ratio\":{:.6}}}",
                    c.category, c.recipe_count, c.class_median_ratio
                ))
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    // Per-run observation record for the CI log harvester. Mirrors
    // the Phase 2h Round 3 Pass-3 measurement record shape so the
    // M1 amendment commit's tooling can co-process T6 outputs with
    // the methodology pass-3 outputs.
    println!(
        "T6_OBSERVATION: {{\
         \"runner_class\":\"{runner_class}\",\
         \"corpus_size\":{corpus_size},\
         \"samples_per_recipe\":{samples_per_recipe},\
         \"corpus_median_ratio\":{corpus_median:.6},\
         \"claim_1_effective_bound\":{claim_1:.6},\
         \"claim_2_threshold\":{claim_2:.6},\
         \"claim_2_violation_count\":{claim_2_count},\
         \"runner_noise_margin\":{margin:.6},\
         \"sample_budget_per_recipe\":{budget}\
         }}",
        runner_class = MEASUREMENT_RUNNER_CLASS,
        corpus_size = report.corpus_size,
        samples_per_recipe = report.samples_per_recipe,
        corpus_median = report.corpus_median_ratio,
        claim_1 = report.claim_1_effective_bound,
        claim_2 = CLAIM_2_THRESHOLD,
        claim_2_count = report.claim_2_violations.len(),
        margin = RUNNER_NOISE_MARGIN,
        budget = SAMPLE_BUDGET_PER_RECIPE,
    );
}
