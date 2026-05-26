// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Adversarial recipe-evaluator canonical outputs and measurement-derived
//! constants — Phase 2h Round 1 R1-D4 (Family-1 canonical outputs) and
//! Round 3 Pass-3 (substrate-derived constant validation).
//!
//! Per
//! [`docs/design/RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D4 close, the recipe-derived adversarial corpus has a
//! dedicated Family-1 canonical-output array (separate from Phase 2g's
//! [`canonical_outputs`](super::canonical_outputs) random-corpus arrays).
//! This module is the landing site for that array; the array contents
//! land at the implementation PR's C5 commit alongside the recipe
//! corpus itself.
//!
//! Per Round 3 close artifact 1 + M1 substrate discipline
//! ([`docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)),
//! this module also carries the three measurement-derived constants
//! ([`RUNNER_NOISE_MARGIN`], [`CLAIM_2_THRESHOLD`],
//! [`SAMPLE_BUDGET_PER_RECIPE`]) that the
//! [`mode_adversarial_ratio`](super::mode_adversarial_ratio) harness
//! mode (landed at C6) consumes for its Claim 1 hard gate and Claim 2
//! tracking signal. The measurement methodology + results live
//! together per M1 — the methodology side at the linked design doc;
//! the results side as the `pub const` items below.
//!
//! ## C1 disposition (this commit)
//!
//! The constants below are **provisional**: pre-measurement estimates
//! anchored against the Round 1 close framing (R1-D5 for
//! [`CLAIM_2_THRESHOLD`], R1-D6 for [`SAMPLE_BUDGET_PER_RECIPE`]) and
//! against industry baseline for [`RUNNER_NOISE_MARGIN`] per the
//! design doc's §2.3 provisional-value table. The first
//! implementation-PR CI run on `ubuntu-latest` (per
//! [`per_recipe_latency`](../../../rust/shekyl-randomx-differential/tests/per_recipe_latency.rs))
//! produces the measured values; if measurement diverges from the
//! provisional pin by more than [`RUNNER_NOISE_MARGIN`], a substrate
//! finding is recorded per the design doc's §5 R4 reopening criterion
//! and an amendment commit refines the values.
//!
//! Per
//! [`21-reversion-clause-discipline.mdc`](../../../.cursor/rules/21-reversion-clause-discipline.mdc),
//! the provisional pin's reopening criterion is "first measurement
//! disagrees by more than [`RUNNER_NOISE_MARGIN`]" — substrate-
//! anchored, not preference-anchored. The reopening shape is an
//! amendment commit on the implementation branch landing the measured
//! values + a methodology-doc §2.3 update recording the
//! provisional-versus-measured delta.
//!
//! ## Family-1 canonical-output array (deferred to C5)
//!
//! [`FAMILY_1_RECIPE_OUTPUTS`] is declared at C1 as an empty array;
//! the implementation PR's C5 commit populates it with one entry per
//! recipe in the
//! [`adversarial`](https://example.invalid/anchor-pending-c3) module's
//! corpus. Each entry pins the expected SHA-256 of the recipe's
//! evaluator-produced cache bytes per R1-D4's expanded-bytes-SHA
//! discipline (defends against T-A12 recipe substrate tamper + T-A13
//! recipe evaluator divergence per Round 2's §4.5 attack-class
//! split).
//!
//! The empty-at-C1 shape mirrors Phase 2g's `adversarial_corpus.rs`
//! C5a scaffolded-empty disposition: the surface contract is locked
//! at the substrate-defining commit; the contents land alongside the
//! data they pin. Per `15-deletion-and-debt.mdc`, the empty-at-C1
//! shape carries an explicit C5 deletion-target for the empty
//! placeholder.

use sha2::{Digest, Sha256};

/// Per-recipe GitHub-hosted-runner latency-ratio noise margin (R1-D5
/// close; R1-D7 runner-class pin; Round 3 Pass-3 measurement).
///
/// **Provisional value pinned at C1 per
/// [`RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
/// §2.3.** Conservative pre-measurement estimate for GitHub-hosted
/// `ubuntu-latest` runner-class variance based on industry baselines
/// for shared-hypervisor allocation. Per M1 the provisional pin
/// reopens for refinement at the first implementation-PR CI run
/// (substrate-finding-class outcome routes to amendment commit per
/// the design doc's §5 R4 reopening criterion).
///
/// Per R1-D5's Claim 1 hard-gate close: the per-recipe latency-ratio
/// gate is `rust_median / c_median ≤ 5.0 - RUNNER_NOISE_MARGIN`. The
/// margin absorbs single-allocation runner-class noise; a recipe
/// within 1% of the gate gets a single retry per R1-D5's
/// single-retry-noise-filter close before the gate fails.
pub const RUNNER_NOISE_MARGIN: f64 = 0.20;

/// Per-class systematic-regression threshold for Claim 2 tracking
/// signal (R1-D5 close).
///
/// **Provisional value pinned at C1 per
/// [`RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
/// §2.3.** Direct quote from R1-D5 close framing (per-class median
/// ratio `>1.5× corpus_median` is the systematic-regression
/// signal). Pre-measurement value pin; reopens for refinement if
/// the initial recipe set's per-class distribution warrants tighter
/// or looser pinning.
///
/// Per R1-D5's Claim 2 tracking-signal close: this threshold
/// produces a CI warning + nightly investigation routing on
/// violation, not an immediate PR-blocking failure. The tracking
/// shape catches systematic regression as it accumulates rather
/// than blocking on a single recipe's class shifting.
pub const CLAIM_2_THRESHOLD: f64 = 1.5;

/// Per-recipe per-side (Rust + C) timing-sample budget for the
/// per-PR cadence (R1-D6 close).
///
/// **Provisional value pinned at C1 per
/// [`RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
/// §2.3.** Direct quote from R1-D6 close framing. Bounded above by
/// R1-D6's 10-minute per-PR cadence (Pass 4 estimate at Round 3
/// open: 25 recipes × 200 samples × ~100ms = ~8.5 minutes within
/// the 10-min budget with ~1.5-min margin). Pre-measurement value
/// pin; reopens if the measured per-sample latency on
/// `ubuntu-latest` differs from the ~100ms estimate.
///
/// Per R1-D6's cadence-corpus alignment close: this budget pairs
/// with [`RUNNER_NOISE_MARGIN`] to produce a stable Claim 1 hard
/// gate signal — too few samples and runner-class variance
/// dominates the median; too many samples and the per-PR cadence
/// exceeds R1-D6's 10-minute budget. The 100-sample pin is the
/// balance point per the Round 1 framing.
pub const SAMPLE_BUDGET_PER_RECIPE: usize = 100;

/// Runner class against which the constants in this module are
/// calibrated.
///
/// Per Round 1 R1-D7's runner-class close and Round 3 Pass-3
/// measurement methodology §2.1: GitHub-hosted `ubuntu-latest`
/// is the only pre-genesis runner class; self-hosted is deferred.
/// The constants in this module carry runner-class-specific noise
/// characteristics; recalibration is required if the runner class
/// changes (see [`RANDOMX_V2_PHASE2H_MEASUREMENT.md`](../../../docs/design/RANDOMX_V2_PHASE2H_MEASUREMENT.md)
/// §5 R1/R3 reopening criteria).
pub const MEASUREMENT_RUNNER_CLASS: &str = "github-hosted-ubuntu-latest";

/// Number of independent CI runs that informed the measured values
/// in this module.
///
/// **Provisional value pinned at C1: `0`** (the constants above are
/// pre-measurement estimates; no CI run has yet contributed to
/// their derivation). The implementation-PR's first CI run on
/// `ubuntu-latest` increments this to `1`; subsequent runs that
/// inform refinement increment further. Per the methodology doc's
/// §2.2, `RUNNER_NOISE_MARGIN` requires N ≥ 5 independent runs to
/// produce a statistically defensible margin; values committed at
/// `MEASUREMENT_RUN_COUNT < 5` are explicitly provisional per the
/// methodology doc's §2.3 disposition.
pub const MEASUREMENT_RUN_COUNT: usize = 0;

/// Maximum observed per-run variance σ across the measurement
/// runs that informed this module's constants.
///
/// **Provisional value pinned at C1: `0.0`** (no CI run has yet
/// produced variance data). Per the methodology doc's §2.2, the
/// `RUNNER_NOISE_MARGIN = max(σ) × 3` derivation requires real
/// measured variance; the `0.0` placeholder reflects the
/// pre-measurement disposition. The first implementation-PR CI run
/// populates this with the observed σ; the amendment commit that
/// refines [`RUNNER_NOISE_MARGIN`] also updates this value to
/// reflect the measurement basis.
pub const MEASUREMENT_OBSERVED_VARIANCE: f64 = 0.0;

/// Family-1 canonical-output array — recipe-evaluator-produced
/// expanded-bytes SHA-256 pins per R1-D4 (close at this commit;
/// populated at C5 of the implementation plan).
///
/// **Empty at C1 per the C1 disposition** (this commit). C5
/// populates with one entry per recipe in the
/// [`adversarial`](https://example.invalid/anchor-pending-c3)
/// module's corpus; each entry is the SHA-256 of the recipe
/// evaluator's expanded cache bytes per R1-D4's expanded-bytes-SHA
/// discipline.
///
/// Per Round 2 R2-D1 + §4.5.1 close, the canonical-output array
/// extends M1's scope to T-A12 (recipe substrate tamper) and
/// T-A13 (recipe evaluator divergence): a tampered recipe whose
/// expansion differs from the canonical pin fails the canonical
/// assertion; a buggy evaluator that produces drifted output
/// fails likewise.
pub const FAMILY_1_RECIPE_OUTPUTS: &[[u8; 32]] = &[];

/// Count of Family-1 recipe canonical outputs (empty at C1; grows
/// at C5).
pub const FAMILY_1_RECIPE_COUNT: usize = FAMILY_1_RECIPE_OUTPUTS.len();

/// SHA-256 of the empty Family-1 array — the C1 scaffold-pin per
/// the Phase 2g `adversarial_corpus.rs::ADVERSARIAL_CORPUS_SHA256`
/// precedent (empty-scaffold hash asserts no tamper of the empty
/// shape between C1 and C5).
///
/// **Per C1 disposition: this value is the SHA-256 of the
/// `FAMILY_1_RECIPE_OUTPUTS` empty slice** (`SHA-256("") =
/// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
/// At C5, the value is recomputed against the populated array and
/// pinned alongside.
pub const FAMILY_1_RECIPE_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Compute the SHA-256 of the concatenated [`FAMILY_1_RECIPE_OUTPUTS`]
/// array (per-entry bytes streamed in array order).
///
/// Returns the digest as a 32-byte array suitable for byte-equality
/// assertion against [`FAMILY_1_RECIPE_SHA256`]. The C1 disposition
/// (empty array) returns `SHA-256("")`; C5 onwards returns the
/// SHA-256 of the populated array contents.
#[must_use]
pub fn compute_family_1_recipe_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    for entry in FAMILY_1_RECIPE_OUTPUTS {
        hasher.update(entry);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Provisional-constant sanity check (T20a per the §6 test-table
    /// pending Phase 2h §6 substantive content at C10).
    ///
    /// Asserts the C1 provisional values are within their R1-D5 / R1-D6
    /// close framing. If any of these fails, the C1 commit landed
    /// wrong values; amend before extending.
    ///
    /// The `clippy::assertions_on_constants` allow is deliberate: the
    /// test's purpose is to lock the C1 disposition values as
    /// reviewable substrate; the assertions ARE on constants by
    /// design (a refactor that mutates the constants surfaces the
    /// disposition violation here rather than silently propagating).
    /// Per the methodology doc §4 M1 substrate-pairing discipline,
    /// these tests are the substrate-side guard against unreviewed
    /// constant drift.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn c1_provisional_constants_match_round_1_close_framing() {
        assert!(
            RUNNER_NOISE_MARGIN > 0.0 && RUNNER_NOISE_MARGIN < 1.0,
            "RUNNER_NOISE_MARGIN must be a positive fraction less than 1.0; \
             got {RUNNER_NOISE_MARGIN}"
        );
        assert!(
            (CLAIM_2_THRESHOLD - 1.5).abs() < f64::EPSILON,
            "CLAIM_2_THRESHOLD must equal 1.5 per R1-D5 close; got {CLAIM_2_THRESHOLD}"
        );
        assert_eq!(
            SAMPLE_BUDGET_PER_RECIPE, 100,
            "SAMPLE_BUDGET_PER_RECIPE must equal 100 per R1-D6 close"
        );
    }

    /// Asserts the C1 empty-scaffold disposition: Family-1 array is
    /// empty; SHA-256 matches the canonical empty-string hash.
    ///
    /// This is the C1 analog of Phase 2g `adversarial_corpus.rs`'s
    /// T10 empty-scaffold pin (defends against tamper of the empty
    /// shape between C1 and C5).
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn c1_family_1_scaffold_pin() {
        assert_eq!(
            FAMILY_1_RECIPE_COUNT, 0,
            "C1 disposition requires FAMILY_1_RECIPE_OUTPUTS to be empty; \
             got {FAMILY_1_RECIPE_COUNT} entries"
        );
        assert_eq!(
            compute_family_1_recipe_hash(),
            FAMILY_1_RECIPE_SHA256,
            "C1 Family-1 scaffold SHA-256 pin must match SHA-256(\"\")"
        );
    }

    /// Asserts measurement-run-count provisional disposition: C1
    /// commits with zero measurement runs; the constants are
    /// pre-measurement estimates per the methodology doc §2.3.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn c1_measurement_metadata_provisional() {
        assert_eq!(
            MEASUREMENT_RUN_COUNT, 0,
            "C1 disposition: no CI run has yet contributed to the constants"
        );
        assert!(
            (MEASUREMENT_OBSERVED_VARIANCE - 0.0).abs() < f64::EPSILON,
            "C1 disposition: no measured variance data yet"
        );
        assert_eq!(
            MEASUREMENT_RUNNER_CLASS, "github-hosted-ubuntu-latest",
            "Pre-genesis runner class pin per R1-D7 close"
        );
    }
}
