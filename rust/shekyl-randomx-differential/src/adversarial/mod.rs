// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2h adversarial-corpus methodology: recipe types,
//! recipe corpus, and the first-class recipe evaluator (R1-D3
//! close).
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D3 close, this module replaces the historical Phase
//! 2g R7-D4 scaffolded-empty `adversarial_corpus.rs` shape with the
//! recipe-based methodology. The corpus's substrate is now
//! **recipe data** (R1-D3 close): declarative
//! [`types::CacheRecipe`] entries the [`interpreter::evaluate`]
//! function expands into the `(seedhash, cache_bytes)` pairs
//! consumed by
//! [`shekyl_pow_randomx::PreparedCache::from_raw_for_testing`] (the
//! R1-D2 close cache-level test-internals accessor landed at C2).
//!
//! # Module layout (per R1-D3 close)
//!
//! ```text
//! adversarial/
//! ├── mod.rs                      # this file; aggregation surface
//! ├── types.rs                    # CacheRecipe, BaseSeedhash, EvaluatedRecipe
//! ├── interpreter.rs              # evaluate(recipe, base_bytes) -> EvaluatedRecipe
//! └── recipes/                    # per-category corpus (R1-D8)
//!     ├── spec_silence_anchors.rs   # Category 1
//!     ├── coverage_targets.rs       # Category 2
//!     ├── boundary_values.rs        # Category 3
//!     └── dataset_item_extrema.rs   # Category 3
//! ```
//!
//! `adversarial_canonical_outputs.rs` (separate top-level module,
//! landed at Phase 2h C1) carries the Family-1 canonical-output
//! array per R1-D4 close — committed `(declared_seedhash,
//! expanded_bytes_sha256, expected_hash, data)` tuples that pin the
//! corpus's expected verifier output at each fork-pin SHA.
//!
//! Base-cache amortization (the base-seedhash →
//! C-derived-cache-bytes lookup that avoids paying Argon2d once per
//! recipe when multiple recipes share a base) lives **in the
//! consumers** rather than as a dedicated `adversarial/base_caches.rs`
//! module:
//!
//! - [`canonical::compute_corpus_canonicals`] amortizes by
//!   constructing a `Vec<(BaseSeedhash, Vec<u8>)>` keyed by
//!   `base.bytes` during C5 canonical-output generation.
//! - [`crate::mode_adversarial_ratio::run`] amortizes via an
//!   identical `Vec<([u8; 32], Vec<u8>)>` keyed by `base.bytes`
//!   during T6 per-recipe-ratio measurement.
//! - [`crate::bin::gen_canonical_outputs`] amortizes the same way
//!   during the canonical-regeneration helper run.
//! - The T2 integration test
//!   (`tests/adversarial_corpus_byte_equality.rs`) amortizes
//!   identically during byte-equality verification.
//!
//! The four consumers were each written to the same `Vec<(key,
//! bytes)>` shape rather than factoring out a shared helper at C6;
//! per
//! [`15-deletion-and-debt.mdc`](../../../../.cursor/rules/15-deletion-and-debt.mdc)
//! "while-we're-here is the enemy" discipline, the helper extracts
//! when a fifth consumer emerges with a substrate-anchored need (so
//! the shape's invariants — single-pass linear scan, no allocation
//! on hit, `Vec` over `HashMap` to keep deterministic iteration —
//! can be reviewed once rather than re-derived per site).
//!
//! # Phase 2h C3 implementation scope
//!
//! C3 lands:
//!
//! - [`types`] — `BaseSeedhash`, `CacheRecipe`, `EvaluatedRecipe`.
//! - [`interpreter`] — `evaluate(recipe, base_cache_bytes) ->
//!   EvaluatedRecipe`, the `BASE_CACHE_BYTES_LEN` constant, and the
//!   six interpreter-correctness tests (no-op identity, idempotence,
//!   sequential-modification ordering, multi-offset application,
//!   out-of-range panic, length-mismatch panic) per the R1-D3 close
//!   evaluator-correctness mitigation #1.
//! - [`recipes`] (scaffold) — per-category modules with empty
//!   corpus arrays. C4 populates the arrays with 16-30 starter
//!   recipes (R1-D1 close: 50-200 total; C3 lands scaffolds, C4
//!   populates the initial substrate).
//! - [`get_corpus`] — the public aggregation surface. Returns the
//!   four category arrays concatenated in the documented order;
//!   empty at C3 (no recipes populated yet).
//!
//! # Drift-prevention against `lib.rs` §5.7
//!
//! The four sub-modules below are enumerated in the Phase 2h C3
//! implementation plan per
//! [`crate`]'s `§5.7 drift-prevention boundary`. Adding a sub-module
//! outside C3's enumerated scope is grounds for scope-creep
//! rejection per `15-deletion-and-debt.mdc` "while-we're-here is
//! the enemy" discipline.

pub mod canonical;
pub mod interpreter;
pub mod recipes;
pub mod types;

use crate::adversarial::types::CacheRecipe;

/// Return the aggregated adversarial-corpus recipe list.
///
/// # Aggregation order
///
/// Recipes are concatenated in the order
/// `[spec_silence_anchors, coverage_targets, boundary_values,
/// dataset_item_extrema]` — pinned here so the M1 canonical-output
/// array
/// (`crate::adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`)
/// can reference each recipe by its index in this concatenated
/// view. Reordering the category arrays at the call sites in this
/// function (or reordering recipes within a category array) shifts
/// every subsequent index and produces a canonical-output SHA
/// mismatch at the next CI run.
///
/// # Phase 2h C3 state
///
/// All four category arrays are empty scaffolds at C3 (per
/// [`recipes`]); the returned slice is empty. C4 populates 16-30
/// starter recipes; the M1 canonical outputs populate alongside
/// at C5.
///
/// # Why a `Vec<CacheRecipe>` return rather than `&'static [CacheRecipe]`
///
/// Slice concatenation across four `&'static [CacheRecipe]` arrays
/// requires either (a) a const-eval allocation (not yet stable for
/// slice concatenation), (b) a build-script that generates a
/// concatenated const array (build-script cost not justified at
/// C3's scale), or (c) a runtime allocation per call. Option (c)
/// is the C3 disposition; the harness's hot path calls
/// [`get_corpus`] once per CI run and reuses the returned `Vec`,
/// so the allocation cost is paid once per run. If C7+ surfaces
/// per-iteration overhead from the per-call allocation, the
/// disposition reopens with substrate evidence (per
/// [`21-reversion-clause-discipline.mdc`](../../../../.cursor/rules/21-reversion-clause-discipline.mdc)).
pub fn get_corpus() -> Vec<CacheRecipe> {
    let mut corpus = Vec::new();
    corpus.extend_from_slice(recipes::spec_silence_anchors::SPEC_SILENCE_ANCHOR_RECIPES);
    corpus.extend_from_slice(recipes::coverage_targets::COVERAGE_TARGET_RECIPES);
    corpus.extend_from_slice(recipes::boundary_values::BOUNDARY_VALUE_RECIPES);
    corpus.extend_from_slice(recipes::dataset_item_extrema::DATASET_ITEM_EXTREMA_RECIPES);
    corpus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adversarial::interpreter::BASE_CACHE_BYTES_LEN;

    /// Phase 2h C4 starter corpus size pin.
    ///
    /// At C4, the corpus carries:
    /// - 2 `spec_silence_anchors` (Category 1) recipes
    ///   (`u128-high-half-cache-word-0`,
    ///   `shift-mask-boundary-cache-word-1`).
    /// - 0 `coverage_targets` (Category 2) recipes (deferred per
    ///   R1-D1 close Category-2 reopen criterion; coverage-tooling
    ///   reproducibility verification not yet performed).
    /// - 3 `boundary_values` (Category 3) recipes
    ///   (`boundary-cache-first-byte`,
    ///   `boundary-cache-last-byte`,
    ///   `boundary-dataset-item-stride-first-edge`).
    /// - 3 `dataset_item_extrema` (Category 3) recipes
    ///   (`boundary-block-stride-second-block-base`,
    ///   `boundary-block-stride-first-block-tail`,
    ///   `boundary-line-stride-within-block`).
    ///
    /// Total: **8 recipes** at C4.
    ///
    /// Per R1-D1 close: the target full-corpus size is 50-200
    /// entries across all categories. C4's 8-recipe starter set
    /// establishes the methodology end-to-end (each category
    /// represented or explicitly deferred); subsequent commits and
    /// post-genesis FOLLOWUPS expand the corpus toward the R1-D1
    /// target.
    ///
    /// This count is the M1 substrate anchor for the canonical-
    /// output array landing at C5 — `FAMILY_1_RECIPE_OUTPUTS` must
    /// have one entry per `get_corpus()` element with matching
    /// recipe-index ordering per [`get_corpus`]'s aggregation-
    /// order pin.
    #[test]
    fn c4_starter_corpus_size_pin() {
        let corpus = get_corpus();
        assert_eq!(
            corpus.len(),
            8,
            "Phase 2h C4 starter corpus size drift: expected 8 recipes (2 \
             spec_silence + 0 coverage + 3 boundary + 3 dataset_item_extrema); got \
             {got}. If this is intentional (recipe added or removed), update this \
             test's expected count AND the C5 FAMILY_1_RECIPE_OUTPUTS array AND any \
             documentation in this module's `c4_starter_corpus_size_pin` rustdoc.",
            got = corpus.len(),
        );
    }

    /// The aggregation surface compiles and links the four
    /// per-category sub-modules. A test-time invocation of
    /// `get_corpus()` ensures any future refactor that breaks the
    /// `pub mod` declarations or the per-category constant names
    /// is caught at C3's test surface, not at a future-recipe-
    /// addition PR.
    #[test]
    fn get_corpus_links_all_four_category_modules() {
        let _ = get_corpus();
    }

    /// Recipe-data well-formedness: every recipe in the C4 starter
    /// corpus has non-empty `name`, non-empty `rationale`, and
    /// `modifications` whose offsets all lie within
    /// `BASE_CACHE_BYTES_LEN`.
    ///
    /// Catches recipe-author mistakes at test time rather than at
    /// `interpreter::evaluate`'s panic surface — the panic is the
    /// hard backstop, but the test surfaces the bug at PR review
    /// without requiring an interpreter run.
    #[test]
    fn corpus_recipes_are_well_formed() {
        let corpus = get_corpus();
        for recipe in &corpus {
            assert!(!recipe.name.is_empty(), "Recipe `name` must be non-empty",);
            assert!(
                !recipe.rationale.is_empty(),
                "Recipe `{}` rationale must be non-empty (R1-D8 inclusion criterion)",
                recipe.name,
            );
            // Per R1-D8 + R2-D4 M5 citation-validation script, the
            // rationale field must cite a category identifier in the
            // form "Category N: ..." where N is 1, 2, or 3. The
            // syntactic check here catches authoring drift; the C9
            // M5 script provides the mechanical pipeline check.
            assert!(
                recipe.rationale.starts_with("Category 1:")
                    || recipe.rationale.starts_with("Category 2:")
                    || recipe.rationale.starts_with("Category 3:"),
                "Recipe `{}` rationale must start with `Category N:` (N = 1/2/3) per \
                 R1-D8 inclusion criterion + R2-D4 M5 citation-format discipline. \
                 Got rationale prefix: `{}...`",
                recipe.name,
                &recipe.rationale[..recipe.rationale.len().min(40)],
            );
            for (mod_idx, &(offset, _value)) in recipe.modifications.iter().enumerate() {
                assert!(
                    offset < BASE_CACHE_BYTES_LEN,
                    "Recipe `{}` modifications[{}].offset = {} exceeds BASE_CACHE_BYTES_LEN \
                     ({}). Recipe-author bug.",
                    recipe.name,
                    mod_idx,
                    offset,
                    BASE_CACHE_BYTES_LEN,
                );
            }
        }
    }

    /// Recipe-name uniqueness: no two recipes in the C4 starter
    /// corpus share a `name`. Names serve as diagnostic anchors
    /// in failure-output diagnostics and as keys for the M5
    /// citation-validation script's reverse mapping; duplicate
    /// names break both.
    #[test]
    fn corpus_recipe_names_unique() {
        let corpus = get_corpus();
        let mut names: Vec<&str> = corpus.iter().map(|r| r.name).collect();
        let original_len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            original_len,
            "Duplicate recipe names detected in C4 starter corpus; names must be \
             unique for diagnostic + M5-script keying",
        );
    }
}
