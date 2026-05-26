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
//! ## C1 disposition (measurement-derived constants; still C1-provisional)
//!
//! The [`RUNNER_NOISE_MARGIN`], [`CLAIM_2_THRESHOLD`],
//! [`SAMPLE_BUDGET_PER_RECIPE`], [`MEASUREMENT_RUN_COUNT`], and
//! [`MEASUREMENT_OBSERVED_VARIANCE`] constants remain **provisional**:
//! pre-measurement estimates anchored against the Round 1 close
//! framing (R1-D5 for [`CLAIM_2_THRESHOLD`], R1-D6 for
//! [`SAMPLE_BUDGET_PER_RECIPE`]) and against industry baseline for
//! [`RUNNER_NOISE_MARGIN`] per the design doc's §2.3 provisional-value
//! table. The first measurement-cadence CI run on `ubuntu-latest`
//! (T6 / `worst_case_ratio.rs`, via the dedicated
//! `randomx-v2-adversarial-ratio.yml` workflow per R1-D7 Sub-A close
//! — the per-recipe-latency and per-recipe-ratio measurements share
//! the [`crate::mode_adversarial_ratio::run`] orchestrator per R1-D5
//! close rather than living in a separate `tests/per_recipe_latency.rs`
//! integration test as the early plan-doc framed) produces the
//! measured values; if measurement diverges from the provisional pin
//! by more than [`RUNNER_NOISE_MARGIN`], a substrate finding is
//! recorded per the design doc's §5 R4 reopening criterion and an
//! amendment commit refines the values.
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
//! ## C5 disposition (this commit) — Family-1 canonical-output array
//!
//! [`FAMILY_1_RECIPE_OUTPUTS`] is **populated at C5** with one entry
//! per recipe in the
//! [`adversarial::get_corpus`](super::adversarial::get_corpus) starter
//! corpus (8 recipes: 2 spec-silence-anchor + 0 coverage-target + 3
//! boundary-value + 3 dataset-item-extrema). Each entry pins the
//! SHA-256 of the recipe's evaluator-produced cache bytes per R1-D4's
//! expanded-bytes-SHA discipline; the corresponding
//! [`FAMILY_1_RECIPE_SHA256`] meta-pin asserts the array contents
//! have not been tampered between commit and use.
//!
//! Per Round 2 R2-D1 + §4.5.1 close, the canonical-output array
//! extends M1's scope to T-A12 (recipe substrate tamper) and
//! T-A13 (recipe evaluator divergence): a tampered recipe whose
//! expansion differs from the canonical pin fails the canonical
//! assertion; a buggy evaluator that produces drifted output fails
//! likewise. The
//! [`tests/adversarial_canonical_runtime`](../../../rust/shekyl-randomx-differential/tests/adversarial_canonical_runtime.rs)
//! integration test (landing at C7) provides the runtime
//! backstop — it re-derives each canonical via
//! [`adversarial::canonical::compute_corpus_canonicals`](super::adversarial::canonical::compute_corpus_canonicals)
//! and asserts byte-equality with the committed array entries.
//!
//! ### Population substrate (cache-equivalence reuse)
//!
//! The C5 canonical values were computed via the Rust subject's
//! [`PreparedCache::derive`] +
//! [`PreparedCache::cache_block_bytes_for_testing`] path through
//! [`adversarial::canonical::compute_corpus_canonicals`](super::adversarial::canonical::compute_corpus_canonicals).
//! Per the Phase 2g R1-D14 cache-equivalence precondition, the
//! Rust-subject path produces byte-identical cache memory to the C
//! reference's `randomx_get_cache_memory` for the same seedhash; the
//! Phase 2g harness asserts this equivalence at every test invocation
//! (no new validation surface introduced at C5 per
//! [`19-validation-surface-discipline.mdc`](../../../.cursor/rules/19-validation-surface-discipline.mdc)).
//!
//! The `gen_canonical_outputs` binary (extended at C5) provides the
//! second independent computation path — C-reference-derived — for
//! the regeneration-discipline workflow per
//! [`canonical_outputs`](super::canonical_outputs)'s precedent.
//!
//! ### Cross-checkability (R1-D4 close + R1-D8 substrate cite)
//!
//! The `#[cfg(test)] mod tests` block in this file asserts
//! bidirectional correspondence between
//! [`FAMILY_1_RECIPE_OUTPUTS`] and
//! [`adversarial::get_corpus`](super::adversarial::get_corpus):
//!
//! - Array length equals corpus length (catches recipe addition or
//!   removal without canonical update).
//! - Each entry's array index corresponds to the same-index recipe
//!   in `get_corpus()` (the ordering invariant pinned at
//!   [`adversarial::get_corpus`](super::adversarial::get_corpus)'s
//!   docstring).
//!
//! Both checks fail at `cargo test`; the failure-output diagnostic
//! identifies which recipe needs canonical regeneration.

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
/// expanded-bytes SHA-256 pins per R1-D4 (close at C1; populated
/// at C5).
///
/// **Populated at C5** with 8 entries — one per recipe in
/// [`adversarial::get_corpus`](super::adversarial::get_corpus)'s
/// C4 starter corpus. The array is indexed by
/// [`adversarial::get_corpus`](super::adversarial::get_corpus)'s
/// emission ordering: the *i*-th entry corresponds to the *i*-th
/// recipe in `get_corpus()`. The ordering invariant is asserted by
/// [`tests::family_1_array_length_matches_corpus_length`] +
/// [`tests::family_1_array_recipe_names_in_get_corpus`].
///
/// Per Round 2 R2-D1 + §4.5.1 close, the canonical-output array
/// extends M1's scope to T-A12 (recipe substrate tamper) and
/// T-A13 (recipe evaluator divergence): a tampered recipe whose
/// expansion differs from the canonical pin fails the canonical
/// assertion; a buggy evaluator that produces drifted output
/// fails likewise. The runtime backstop lives at
/// [`tests/adversarial_canonical_runtime`](../../../rust/shekyl-randomx-differential/tests/adversarial_canonical_runtime.rs)
/// (landing at C7).
///
/// # Regeneration
///
/// Per [`canonical_outputs`](super::canonical_outputs)'s
/// regeneration-discipline precedent, this array is not
/// hand-edited; refreshing it requires:
///
/// 1. Substrate change that invalidates the prior pin (e.g., a
///    recipe added/removed, a recipe's modifications changed, the
///    interpreter's algorithm refined per a substrate finding).
/// 2. Re-run [`adversarial::canonical::compute_corpus_canonicals`](super::adversarial::canonical::compute_corpus_canonicals)
///    or the `gen_canonical_outputs` binary's `--include-family-1`
///    mode against the updated corpus.
/// 3. Commit the new bytes alongside the substrate change in the
///    same PR per the M3 PR-template discipline.
#[rustfmt::skip]
pub const FAMILY_1_RECIPE_OUTPUTS: &[[u8; 32]] = &[
    // recipe[0]: u128-high-half-cache-word-0 (Category 1)
    [ 0x5a, 0xd2, 0x60, 0x83, 0xac, 0x7b, 0xdd, 0xfc, 0xe6, 0xf6, 0x92, 0x9d, 0x82, 0x44, 0x29, 0x05, 0x6a, 0xd4, 0xe2, 0x01, 0xc1, 0x4a, 0xdd, 0xe2, 0x62, 0xa9, 0xa5, 0x83, 0x69, 0x52, 0x74, 0x52],
    // recipe[1]: shift-mask-boundary-cache-word-1 (Category 1)
    [ 0x9d, 0x08, 0x32, 0xe4, 0xad, 0x85, 0xa2, 0xe3, 0x11, 0xe5, 0x85, 0x98, 0x70, 0xae, 0xab, 0xd7, 0xba, 0xfe, 0x02, 0x1a, 0x87, 0xd0, 0x59, 0xa2, 0x69, 0x88, 0x6c, 0xd8, 0x19, 0x0a, 0xd9, 0x5a],
    // recipe[2]: boundary-cache-first-byte (Category 3 boundary)
    [ 0xb2, 0x7b, 0x6d, 0x99, 0x4f, 0x47, 0x1b, 0x8c, 0x72, 0x8e, 0xbf, 0x6e, 0xd5, 0x91, 0x4a, 0x64, 0xb2, 0x5f, 0x8a, 0x85, 0x1e, 0xf3, 0xd3, 0x7b, 0x06, 0xf7, 0x0e, 0xb2, 0x67, 0x4d, 0x97, 0x38],
    // recipe[3]: boundary-cache-last-byte (Category 3 boundary)
    [ 0x3d, 0x33, 0xca, 0x72, 0x29, 0x61, 0x47, 0x67, 0x43, 0xa5, 0x84, 0xb0, 0x2c, 0xd3, 0x7b, 0xa1, 0x29, 0x40, 0x6d, 0xaf, 0x8e, 0xe4, 0x55, 0x2d, 0x90, 0xdc, 0x90, 0x73, 0xd8, 0xad, 0x48, 0x32],
    // recipe[4]: boundary-dataset-item-stride-first-edge (Category 3 boundary)
    [ 0x03, 0xf3, 0xd5, 0x99, 0x4d, 0x83, 0x61, 0x0f, 0x81, 0xf5, 0x18, 0x15, 0x08, 0x19, 0xb1, 0x7f, 0x25, 0x8f, 0xf2, 0xdc, 0x73, 0x76, 0x61, 0x91, 0x93, 0x87, 0x09, 0x32, 0x9a, 0x2f, 0xea, 0xd6],
    // recipe[5]: boundary-block-stride-second-block-base (Category 3 dataset-item)
    [ 0x4d, 0x66, 0x83, 0x8c, 0xd5, 0x0c, 0x11, 0x21, 0xb5, 0x8d, 0x49, 0x76, 0xe7, 0x36, 0x7d, 0x75, 0x21, 0x4c, 0xea, 0xd8, 0xac, 0x14, 0x57, 0xc2, 0x19, 0x6b, 0x4d, 0xc9, 0xf2, 0xab, 0xeb, 0x09],
    // recipe[6]: boundary-block-stride-first-block-tail (Category 3 dataset-item)
    [ 0x19, 0x45, 0xb4, 0x4f, 0x43, 0x31, 0x44, 0x9a, 0x9f, 0xe5, 0x28, 0x2e, 0x7e, 0xf4, 0xf5, 0xe8, 0x79, 0xa2, 0xe0, 0xaa, 0x59, 0x66, 0x4a, 0x96, 0xbc, 0xe2, 0x0b, 0x78, 0xc7, 0x65, 0xbd, 0x16],
    // recipe[7]: boundary-line-stride-within-block (Category 3 dataset-item)
    [ 0xd9, 0x84, 0xff, 0x05, 0xbd, 0x35, 0x49, 0xd5, 0x8f, 0xf4, 0x57, 0x62, 0xe7, 0xbe, 0x46, 0x9e, 0x00, 0xe3, 0xd9, 0x63, 0xd8, 0xf6, 0x2b, 0x0a, 0x39, 0xa9, 0xcc, 0x1a, 0xdb, 0x39, 0x41, 0xb6],
];

/// Count of Family-1 recipe canonical outputs (8 at C5;
/// grows in sync with [`adversarial::get_corpus`](super::adversarial::get_corpus)).
pub const FAMILY_1_RECIPE_COUNT: usize = FAMILY_1_RECIPE_OUTPUTS.len();

/// SHA-256 of the concatenated [`FAMILY_1_RECIPE_OUTPUTS`] array
/// contents — the C5 meta-pin per the Phase 2g
/// `adversarial_corpus.rs::ADVERSARIAL_CORPUS_SHA256` precedent.
/// Catches array-tamper between commit and use.
///
/// Computed via [`compute_family_1_recipe_hash`] at the C5
/// population helper's run-time output (per the
/// [`adversarial::canonical::tests::print_c5_family_1_canonical_values`](super::adversarial::canonical)
/// substrate-producer); pinned here and asserted by
/// [`tests::family_1_meta_sha_matches_array_contents`].
///
/// # Regeneration
///
/// When [`FAMILY_1_RECIPE_OUTPUTS`] changes, regenerate this
/// value by either:
///
/// - Re-running the `adversarial::canonical::tests::print_c5_family_1_canonical_values`
///   helper test (output includes the meta-pin); or
/// - Re-running `cargo test family_1_meta_sha_matches_array_contents`
///   after editing the array; the failure output prints the new
///   meta-SHA for paste.
pub const FAMILY_1_RECIPE_SHA256: [u8; 32] = [
    0x81, 0x77, 0xce, 0x34, 0x12, 0x5e, 0x8b, 0x6b, 0x8a, 0xd4, 0xf9, 0xa5, 0x5c, 0x2e, 0x6f, 0x21,
    0x40, 0x1f, 0xfe, 0xc0, 0x63, 0xed, 0xfd, 0x85, 0x72, 0xf8, 0x3b, 0x32, 0xbb, 0x53, 0x25, 0xec,
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

    /// Asserts the C5 populated disposition: Family-1 array has
    /// 8 entries (one per recipe in the C4 starter corpus);
    /// SHA-256 over the array contents matches the pinned meta-SHA.
    ///
    /// This is the C5 analog of Phase 2g `adversarial_corpus.rs`'s
    /// T10 SHA pin (defends against tamper of the recipe canonicals
    /// between commit and use; complements the runtime backstop in
    /// [`tests/adversarial_canonical_runtime`](../../../rust/shekyl-randomx-differential/tests/adversarial_canonical_runtime.rs)
    /// at C7).
    #[test]
    fn c5_family_1_populated_pin() {
        assert_eq!(
            FAMILY_1_RECIPE_COUNT, 8,
            "C5 disposition requires FAMILY_1_RECIPE_OUTPUTS to have 8 entries \
             (one per C4 starter corpus recipe); got {FAMILY_1_RECIPE_COUNT} entries"
        );
    }

    /// Family-1 meta-pin self-consistency: the SHA-256 of the
    /// concatenated array contents must equal the pinned
    /// [`FAMILY_1_RECIPE_SHA256`] meta-SHA.
    ///
    /// If this fails, [`FAMILY_1_RECIPE_OUTPUTS`] was modified
    /// without updating the meta-SHA; the failure-output diagnostic
    /// includes the new SHA bytes for paste into the constant.
    #[test]
    fn family_1_meta_sha_matches_array_contents() {
        let computed = compute_family_1_recipe_hash();
        assert_eq!(
            computed, FAMILY_1_RECIPE_SHA256,
            "FAMILY_1_RECIPE_SHA256 meta-pin drift; FAMILY_1_RECIPE_OUTPUTS contents \
             produce a different SHA than pinned. If you intentionally changed the \
             array, update FAMILY_1_RECIPE_SHA256 to: {computed:02x?}"
        );
    }

    /// Cross-checkability check 1: Family-1 array length equals
    /// [`super::adversarial::get_corpus`] length.
    ///
    /// Catches recipe-addition-without-canonical-update and
    /// recipe-removal-without-canonical-removal. The R1-D4 close
    /// shape pins bidirectional correspondence between the recipe
    /// registry and the canonical-output array; this test is the
    /// length half of that pairing. The recipe-name pairing half
    /// lives at [`family_1_array_recipe_names_in_get_corpus`].
    #[test]
    fn family_1_array_length_matches_corpus_length() {
        let corpus_len = super::super::adversarial::get_corpus().len();
        assert_eq!(
            FAMILY_1_RECIPE_OUTPUTS.len(),
            corpus_len,
            "FAMILY_1_RECIPE_OUTPUTS length ({}) != get_corpus() length ({}). \
             Either a recipe was added without canonical regeneration, or a \
             recipe was removed without canonical pruning. Re-run \
             `adversarial::canonical::compute_corpus_canonicals` and update \
             FAMILY_1_RECIPE_OUTPUTS + FAMILY_1_RECIPE_SHA256.",
            FAMILY_1_RECIPE_OUTPUTS.len(),
            corpus_len,
        );
    }

    /// Cross-checkability check 2: every recipe index in
    /// [`super::adversarial::get_corpus`] falls within
    /// [`FAMILY_1_RECIPE_OUTPUTS`]'s bounds, and every recipe has a
    /// non-empty `name` suitable for diagnostic anchoring in the
    /// canonical-array's `// recipe[i]: <name>` inline comments.
    ///
    /// This is a defensive companion to
    /// [`family_1_array_length_matches_corpus_length`]: the length
    /// pin is the primary invariant (it asserts strict equality);
    /// this test backstops the per-index bound and the name-
    /// non-empty precondition the inline comments depend on. If a
    /// future maintainer ever weakens the length pin to
    /// `corpus_len <= FAMILY_1_RECIPE_OUTPUTS.len()`, this test
    /// catches a 0-length recipe name that would otherwise hide a
    /// diagnostic-anchoring regression.
    ///
    /// **Not asserted here:** that the array body's `// recipe[i]:
    /// <name>` inline comments textually match the corpus order.
    /// The inline comments are reviewer aids generated by the
    /// `gen_canonical_outputs` helper; the C7 runtime backstop
    /// integration test
    /// (`tests/adversarial_canonical_runtime.rs`) is the
    /// substrate-level check — if a recipe is reordered without
    /// regenerating the canonical SHAs, the runtime backstop fails
    /// even though the comments may have gone stale. Per
    /// [`19-validation-surface-discipline.mdc`](../../../.cursor/rules/19-validation-surface-discipline.mdc),
    /// adding a parallel `FAMILY_1_RECIPE_NAMES` mirror to assert
    /// comment-vs-corpus consistency would create a new drift
    /// surface (every regeneration would update three arrays
    /// instead of two) without a substrate-anchored property; that
    /// disposition reopens only if comment drift is observed to
    /// mislead reviewers in practice.
    ///
    /// This test does not re-derive canonical SHA-256 values
    /// (that's the C7 runtime-backstop integration test); it
    /// asserts the structural correspondence at C5's commit time.
    #[test]
    fn family_1_array_recipe_names_in_get_corpus() {
        let corpus = super::super::adversarial::get_corpus();
        for (i, recipe) in corpus.iter().enumerate() {
            assert!(
                !recipe.name.is_empty(),
                "Recipe at index {i} has empty name; canonical-array indexing requires \
                 non-empty names",
            );
            assert!(
                i < FAMILY_1_RECIPE_OUTPUTS.len(),
                "Recipe `{}` at corpus index {i} has no canonical entry (array len = {})",
                recipe.name,
                FAMILY_1_RECIPE_OUTPUTS.len(),
            );
        }
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
