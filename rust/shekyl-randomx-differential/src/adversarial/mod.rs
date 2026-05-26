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
//! `base_caches.rs` (planned for Phase 2h C6) carries the
//! amortization layer for the base-seedhash → C-derived-cache-bytes
//! lookup; the harness's hot path consumes
//! [`get_corpus`] + [`interpreter::evaluate`] + the C-side base
//! cache via [`base_caches`] to materialize each recipe once per CI
//! run.
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

    /// At Phase 2h C3, `get_corpus()` returns an empty slice (all
    /// four category arrays are scaffold-empty). C4 will populate
    /// the arrays and this test will need to be updated to assert
    /// the populated count (or split into a test asserting the
    /// shape and a test asserting the count separately).
    #[test]
    fn c3_corpus_is_scaffold_empty() {
        let corpus = get_corpus();
        assert_eq!(
            corpus.len(),
            0,
            "Phase 2h C3 corpus is scaffold-only; populating at C4 requires updating \
             this test to assert the new count. Got {got} recipes; expected 0.",
            got = corpus.len(),
        );
    }

    /// The aggregation surface compiles and links the four
    /// per-category sub-modules. A test-time invocation of
    /// `get_corpus()` ensures any future refactor that breaks the
    /// `pub mod` declarations or the per-category constant names
    /// is caught at C3's test surface, not at C4's first-recipe-
    /// addition PR.
    #[test]
    fn get_corpus_links_all_four_category_modules() {
        // The mere fact that this compiles + runs without panicking
        // pins the linkage. The assertion is structural: we're not
        // checking the corpus's contents (covered by
        // c3_corpus_is_scaffold_empty above), just that the
        // four-module aggregation surface exists.
        let _ = get_corpus();
    }
}
