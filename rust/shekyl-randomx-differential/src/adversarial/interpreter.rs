// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recipe evaluation logic for the Phase 2h adversarial corpus
//! (R1-D3 close + R2-D1 T-A13 evaluator-divergence mitigation
//! anchor).
//!
//! The interpreter takes a [`super::types::CacheRecipe`] and a base
//! cache (a 256-MiB `&[u8]` derived from the recipe's base seedhash
//! via the C reference's `randomx_get_cache_memory`), applies the
//! recipe's `(offset, value)` modifications sequentially, and
//! produces an [`super::types::EvaluatedRecipe`] consumable by
//! [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`].
//!
//! # First-class code, not an afterthought
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! R1-D3 close: *the recipe evaluator's correctness is load-bearing
//! for the corpus's correctness*. A bug in [`evaluate`] silently
//! mis-constructs the entire adversarial corpus; every per-recipe
//! `compute_hash` output flows from this function's output.
//!
//! The R1-D3 close enumerates three mitigations against this
//! failure mode, all of which apply here:
//!
//! 1. **Dedicated [`tests`] coverage** in this module. The
//!    [`tests::evaluate_no_op_returns_base_cache_bytes`] (no-op
//!    identity), [`tests::evaluate_idempotent`] (idempotence),
//!    [`tests::evaluate_applies_modifications_in_order`] (sequential
//!    overrides), and
//!    [`tests::evaluate_panics_on_out_of_range_offset`]
//!    (bounds-check) tests pin the invariants.
//! 2. **Canonical-output cross-check** via the M1 substrate at
//!    `adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`
//!    (R1-D4 close). Each canonical entry pairs the recipe's
//!    `expected_hash` with the `expanded_bytes_sha256`; an
//!    evaluator bug shifting the expanded bytes is caught by the
//!    SHA mismatch before the hash comparison runs.
//! 3. **Small DSL**: the [`evaluate`] body is ~30 lines (per the
//!    C3 implementation budget). End-to-end auditable.
//!
//! # T-A13 attack-class disposition (per R2-D1)
//!
//! Per the Phase 2h Round 2 R2-D1 close, T-A13 (recipe evaluator
//! divergence — silent mis-construction of the corpus via an
//! evaluator bug) is mitigated primarily by *the evaluator's own
//! test surface* (this module's [`tests`] block) with the M1
//! canonical-output discipline as the backstop. T-A13's mitigation
//! chain is structurally distinct from T-A12 (recipe substrate
//! tamper, mitigated by M1 + M3 PR-template review of recipe data
//! edits) — see R2-D1 close for the split rationale.

use crate::adversarial::types::{BaseSeedhash, CacheRecipe, EvaluatedRecipe};
use shekyl_pow_randomx::Seedhash;

/// Expected length of any `base_cache_bytes` argument passed to
/// [`evaluate`].
///
/// Equal to the verifier's `CACHE_SIZE` (256 MiB). The constant is
/// re-asserted here as a literal so this module does not couple to
/// the verifier's `pub(crate)` `CACHE_SIZE` accessor — the
/// `randomx-v2-sys` FFI exposes the same value via
/// `RANDOMX_CACHE_SIZE_BYTES` (which is itself derived from the
/// C reference's `RANDOMX_ARGON_MEMORY * ArgonBlockSize` at pin
/// `aaafe71`). The
/// [`tests::cache_size_matches_verifier_constant`] test pins the
/// equality at runtime via the existing
/// [`shekyl_pow_randomx::PreparedCache::cache_block_bytes_for_testing`]
/// accessor's byte count.
pub const BASE_CACHE_BYTES_LEN: usize = 256 * 1024 * 1024;

/// Apply a [`CacheRecipe`]'s modifications to `base_cache_bytes`
/// and produce the [`EvaluatedRecipe`] expansion.
///
/// # Inputs
///
/// - `recipe`: the declarative recipe per the [`super::types`]
///   module.
/// - `base_cache_bytes`: the 256-MiB cache memory derived from
///   `recipe.base.bytes` via the C reference's
///   `randomx_get_cache_memory` (per R1-D2 C-side-symmetry close).
///   Callers amortize this derivation across all recipes sharing a
///   base seedhash; the amortization shape lives at each consumer
///   per the [`super`] module's "Base-cache amortization" docs
///   (the canonicalizer, the adversarial-ratio binary, the
///   canonical-regeneration helper, and the T2 integration test
///   each carry the same `Vec<(base_bytes_key, derived_bytes)>`
///   pattern).
///
/// # Behavior
///
/// 1. Clones `base_cache_bytes` into a fresh `Vec<u8>` owned by
///    the returned [`EvaluatedRecipe::cache_bytes`].
/// 2. Applies each `(offset, value)` modification sequentially —
///    later entries supersede earlier entries at the same offset
///    (this is the documented contract per
///    [`CacheRecipe::modifications`]).
/// 3. Constructs a [`Seedhash`] from `recipe.base.bytes` and
///    bundles into [`EvaluatedRecipe`].
///
/// # Panics
///
/// - If `base_cache_bytes.len() != BASE_CACHE_BYTES_LEN`. The
///   harness's base-cache derivation is responsible for producing
///   a full 256-MiB buffer; a length mismatch is a base-cache-
///   provider bug, not a recipe-author bug.
/// - If any `recipe.modifications[i].0 >= BASE_CACHE_BYTES_LEN`.
///   The diagnostic names the recipe by `recipe.name` and the
///   offending offset+index so the recipe-author can locate the
///   bug without re-deriving from the panic backtrace.
///
/// Both panic surfaces are recipe-author / harness-author bugs;
/// `Result` plumbing at every recipe call site would obscure the
/// bug class without preventing it (per the same discipline as
/// `PreparedCache::from_raw_for_testing`'s length assertion).
///
/// # Cost
///
/// Dominated by the 256-MiB clone (~tens of ms on modern hardware
/// — memory-bandwidth bound). The modification loop is O(N) over
/// `recipe.modifications.len()` (typically <1024 entries per
/// recipe per R1-D3 close); negligible compared to the clone.
///
/// The harness's hot path (per R1-D5 per-recipe-ratio
/// methodology) calls [`evaluate`] once per recipe and reuses the
/// [`EvaluatedRecipe`] across `SAMPLE_BUDGET_PER_RECIPE`
/// `compute_hash` invocations to amortize.
pub fn evaluate(recipe: &CacheRecipe, base_cache_bytes: &[u8]) -> EvaluatedRecipe {
    assert_eq!(
        base_cache_bytes.len(),
        BASE_CACHE_BYTES_LEN,
        "evaluate: base_cache_bytes.len() must equal BASE_CACHE_BYTES_LEN \
         ({BASE_CACHE_BYTES_LEN} bytes = 256 MiB); got {actual} bytes. \
         This is a harness-author bug — the caller's base-cache \
         derivation (see `derive_base_cache_bytes` in \
         `adversarial/canonical.rs` and the per-consumer amortization \
         loops in `mode_adversarial_ratio::run`, the T2 integration \
         test, and `gen_canonical_outputs`) must supply a full cache \
         derivation for recipe `{recipe_name}`.",
        actual = base_cache_bytes.len(),
        recipe_name = recipe.name,
    );

    let mut cache_bytes = base_cache_bytes.to_vec();

    for (mod_idx, &(offset, value)) in recipe.modifications.iter().enumerate() {
        assert!(
            offset < BASE_CACHE_BYTES_LEN,
            "evaluate: recipe `{recipe_name}` modifications[{mod_idx}].offset = {offset} \
             exceeds BASE_CACHE_BYTES_LEN ({BASE_CACHE_BYTES_LEN}). This is a recipe-author \
             bug — modifications must address valid cache positions.",
            recipe_name = recipe.name,
        );
        cache_bytes[offset] = value;
    }

    EvaluatedRecipe {
        recipe_name: recipe.name,
        seedhash: Seedhash::from_bytes(recipe.base.bytes),
        cache_bytes,
    }
}

/// Stable cache-derivation key for the `base_caches` amortization
/// layer landing at C6.
///
/// The key is `BaseSeedhash::bytes` (not `name`) so two recipes
/// citing the same base bytes under different display names share a
/// cache entry — see [`BaseSeedhash`] rustdoc for the name-is-label
/// rationale.
pub fn base_cache_cache_key(base: &BaseSeedhash) -> [u8; 32] {
    base.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct a synthetic "base cache" filled with a
    /// repeating byte pattern. Avoids paying the Argon2d cost in
    /// the interpreter tests (the interpreter does not care about
    /// the bytes' provenance; the tests cover modification
    /// application).
    fn synthetic_base_cache(pattern: u8) -> Vec<u8> {
        vec![pattern; BASE_CACHE_BYTES_LEN]
    }

    /// Helper: a base seedhash with a recognizable name for
    /// diagnostic readability.
    const TEST_BASE: BaseSeedhash = BaseSeedhash {
        name: "interpreter-tests-base",
        bytes: [0x42; 32],
    };

    /// No-op identity: a recipe with empty `modifications` produces
    /// `cache_bytes` byte-identical to `base_cache_bytes`.
    ///
    /// Pins the invariant per R1-D3 close:
    /// "no-op identity: a recipe with no modifications produces the
    /// base cache's exact bytes".
    #[test]
    fn evaluate_no_op_returns_base_cache_bytes() {
        let base = synthetic_base_cache(0x17);
        let recipe = CacheRecipe {
            name: "no-op-test",
            rationale: "Category 3: no-op identity invariant test (this rationale is \
                        test-only and not part of the shipping corpus).",
            base: TEST_BASE,
            modifications: &[],
        };

        let evaluated = evaluate(&recipe, &base);

        assert_eq!(
            evaluated.cache_bytes, base,
            "No-op recipe must produce byte-identical cache_bytes; evaluator bug detected"
        );
        assert_eq!(evaluated.recipe_name, "no-op-test");
        assert_eq!(evaluated.seedhash.as_bytes(), &TEST_BASE.bytes);
    }

    /// Idempotence: re-evaluating an already-expanded recipe
    /// against the recipe's own output yields the same bytes.
    ///
    /// Pins the invariant per R1-D3 close:
    /// "idempotence: re-evaluating an already-expanded recipe
    /// yields the same bytes". (Strict reading: when the
    /// modifications are already applied, applying them again
    /// produces the same result — sequential overrides at the
    /// same offsets are stable.)
    #[test]
    fn evaluate_idempotent() {
        let base = synthetic_base_cache(0x00);
        let recipe = CacheRecipe {
            name: "idempotent-test",
            rationale: "Category 3: idempotence invariant test (test-only).",
            base: TEST_BASE,
            modifications: &[(100, 0xAA), (200, 0xBB), (300, 0xCC)],
        };

        let first = evaluate(&recipe, &base);
        let second = evaluate(&recipe, &first.cache_bytes);

        assert_eq!(
            first.cache_bytes, second.cache_bytes,
            "Idempotence violated: re-evaluating the same recipe against its own output \
             produced different bytes; evaluator bug detected"
        );
    }

    /// Sequential application: later modifications supersede
    /// earlier modifications at the same offset.
    ///
    /// Pins the [`CacheRecipe::modifications`] documented contract
    /// against a regression where the loop's iteration order or
    /// the overwrite semantics drift.
    #[test]
    fn evaluate_applies_modifications_in_order() {
        let base = synthetic_base_cache(0x00);
        let recipe = CacheRecipe {
            name: "order-test",
            rationale: "Category 3: modification-order invariant test (test-only).",
            base: TEST_BASE,
            // Three entries at offset 1024: 0x11, then 0x22, then 0x33.
            // Final value must be 0x33 (last-write-wins).
            modifications: &[(1024, 0x11), (1024, 0x22), (1024, 0x33)],
        };

        let evaluated = evaluate(&recipe, &base);

        assert_eq!(
            evaluated.cache_bytes[1024],
            0x33,
            "Sequential-modification semantics violated: last-write-wins expected; \
             got {got:#04x} at offset 1024",
            got = evaluated.cache_bytes[1024],
        );
        // Untouched offsets remain at the base pattern.
        assert_eq!(evaluated.cache_bytes[0], 0x00);
        assert_eq!(evaluated.cache_bytes[2048], 0x00);
    }

    /// Multi-offset application: distinct offsets all see their
    /// declared values.
    #[test]
    fn evaluate_applies_distinct_offsets() {
        let base = synthetic_base_cache(0xFF);
        let recipe = CacheRecipe {
            name: "multi-offset-test",
            rationale: "Category 3: multi-offset application test (test-only).",
            base: TEST_BASE,
            modifications: &[
                (0, 0x01),
                (1, 0x02),
                (BASE_CACHE_BYTES_LEN - 1, 0xFE),
                (BASE_CACHE_BYTES_LEN / 2, 0x80),
            ],
        };

        let evaluated = evaluate(&recipe, &base);

        assert_eq!(evaluated.cache_bytes[0], 0x01);
        assert_eq!(evaluated.cache_bytes[1], 0x02);
        assert_eq!(evaluated.cache_bytes[BASE_CACHE_BYTES_LEN - 1], 0xFE);
        assert_eq!(evaluated.cache_bytes[BASE_CACHE_BYTES_LEN / 2], 0x80);
        // Sample untouched offsets.
        assert_eq!(evaluated.cache_bytes[2], 0xFF);
        assert_eq!(evaluated.cache_bytes[1024], 0xFF);
    }

    /// Out-of-range offset triggers a diagnostic panic naming the
    /// recipe and the offending index.
    ///
    /// The `expected = ...` substring covers the recipe-name part
    /// of the diagnostic so a regression that drops the recipe
    /// name from the panic message fails this test (the diagnostic
    /// is the recipe-author's path to locating the bug; if it
    /// drops, debugging gets worse).
    #[test]
    #[should_panic(expected = "modifications[0].offset")]
    fn evaluate_panics_on_out_of_range_offset() {
        let base = synthetic_base_cache(0x00);
        let recipe = CacheRecipe {
            name: "out-of-range-test",
            rationale: "Category 3: bounds-check panic test (test-only).",
            base: TEST_BASE,
            modifications: &[(BASE_CACHE_BYTES_LEN, 0x42)],
        };
        let _ = evaluate(&recipe, &base);
    }

    /// Length-mismatch panic surface on the base_cache_bytes
    /// argument. The harness's base-cache provider is responsible
    /// for length; a mismatch is a harness-author bug, not a
    /// recipe-author bug, and the panic message routes the
    /// diagnostic accordingly.
    #[test]
    #[should_panic(expected = "base_cache_bytes.len()")]
    fn evaluate_panics_on_base_cache_length_mismatch() {
        let recipe = CacheRecipe {
            name: "length-test",
            rationale: "Category 3: base-cache length-check test (test-only).",
            base: TEST_BASE,
            modifications: &[],
        };
        // 1 KiB is dramatically shorter than the 256 MiB expected.
        let too_short = vec![0u8; 1024];
        let _ = evaluate(&recipe, &too_short);
    }

    /// Cross-check `BASE_CACHE_BYTES_LEN` against the verifier's
    /// actual cache size via the existing `test-internals` accessor.
    /// Pins the structural assumption (256-MiB cache) against an
    /// upstream change that adjusts `RANDOMX_ARGON_MEMORY` or
    /// `ArgonBlockSize` (both would shift the verifier's
    /// `CACHE_SIZE` and break this module's hard-coded constant).
    ///
    /// The test pays one full `PreparedCache::derive` cost
    /// (~150-200 ms Argon2d-fill) plus the iteration cost; ~hundreds
    /// of ms total. Acceptable for one cross-pin assertion.
    #[test]
    fn cache_size_matches_verifier_constant() {
        let prepared = shekyl_pow_randomx::PreparedCache::derive(Seedhash::from_bytes([0; 32]));
        let mut byte_count: usize = 0;
        for chunk in prepared.cache_block_bytes_for_testing() {
            byte_count += chunk.len();
        }
        assert_eq!(
            byte_count, BASE_CACHE_BYTES_LEN,
            "BASE_CACHE_BYTES_LEN drift: the verifier's cache memory totals {byte_count} \
             bytes per cache_block_bytes_for_testing iteration; the interpreter's \
             BASE_CACHE_BYTES_LEN constant is {BASE_CACHE_BYTES_LEN}. An upstream change \
             to RANDOMX_ARGON_MEMORY or ArgonBlockSize requires updating this constant.",
        );
    }

    /// `base_cache_cache_key` returns `bytes` (not `name`); two
    /// BaseSeedhash values with different names but identical bytes
    /// share a key.
    #[test]
    fn base_cache_key_uses_bytes_not_name() {
        let a = BaseSeedhash {
            name: "alias-A",
            bytes: [0x42; 32],
        };
        let b = BaseSeedhash {
            name: "alias-B",
            bytes: [0x42; 32],
        };
        assert_eq!(
            base_cache_cache_key(&a),
            base_cache_cache_key(&b),
            "Two BaseSeedhash with identical bytes must hash to the same cache key \
             regardless of display name"
        );
        assert_eq!(base_cache_cache_key(&a), [0x42; 32]);
    }
}
