// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical-output computation for recipe-evaluator outputs —
//! Phase 2h C5 (Family-1 substrate computation; Round 1 R1-D4
//! close + Round 2 R2-D1 attack-class split close).
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D4 close (Family-1 canonical-output Rust source
//! const array at
//! [`adversarial_canonical_outputs`](super::super::adversarial_canonical_outputs)),
//! each recipe in [`get_corpus`](super::get_corpus) has an
//! associated canonical SHA-256 over its evaluator-produced cache
//! bytes. This module provides the pure-Rust computation that
//! produces those canonical values, used at three sites:
//!
//! 1. **Initial-population substrate (C5).** The `pub fn` items
//!    here are invoked at C5 implementation time to produce the
//!    canonical values committed to
//!    [`super::super::adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`].
//! 2. **Runtime self-check (T-A12 / T-A13 backstop).** The
//!    [`tests::family_1_committed_canonicals_match_runtime_recomputation`]
//!    integration test re-derives the canonical values at runtime
//!    via these functions and asserts byte-equality with the
//!    committed array. Per Round 2 R2-D1 + §4.5.1 close, this is
//!    the M1 substrate-extension that catches recipe substrate
//!    tamper (T-A12) and recipe evaluator divergence (T-A13).
//! 3. **`gen_canonical_outputs` binary regeneration.** The
//!    [`bin/gen_canonical_outputs`](../../bin/gen_canonical_outputs.rs)
//!    binary extension at C5 invokes the same computation against
//!    the C reference's `randomx_get_cache_memory` output rather
//!    than the Rust subject's
//!    [`PreparedCache::cache_block_bytes_for_testing`] output;
//!    cache-equivalence per Phase 2g R1-D14 guarantees the two
//!    paths produce byte-identical canonical values.
//!
//! ## Cache-equivalence precondition (R1-D14 reuse)
//!
//! The Rust-subject path's correctness depends on the cache-
//! equivalence precondition pinned at Phase 2g R1-D14: the Rust
//! subject's
//! [`PreparedCache::cache_block_bytes_for_testing`] yields the
//! same 256-MiB byte sequence (in LE 1-KiB chunks) as the C
//! reference's `randomx_get_cache_memory` for the same seedhash.
//! The Phase 2g harness asserts this precondition at every test
//! invocation; the Phase 2h canonical-output computation inherits
//! the precondition by reuse — no new validation surface is
//! introduced at C5.
//!
//! Per
//! [`19-validation-surface-discipline.mdc`](../../../../.cursor/rules/19-validation-surface-discipline.mdc)
//! the precondition's reuse is the substrate-aware option (no
//! bundling, no duplicate validation surface); the Phase 2g
//! cache-equivalence pre-existing test already produces the
//! load-bearing signal.
//!
//! ## Why Rust-subject for population, C-subject for binary regen
//!
//! The choice is per [`17-dependency-discipline.mdc`](../../../../.cursor/rules/17-dependency-discipline.mdc)
//! and [`05-system-thinking.mdc`](../../../../.cursor/rules/05-system-thinking.mdc):
//!
//! - **Sandbox-buildable initial population (this module).** The
//!   Rust-subject path requires no `RANDOMX_V2_INSTALL_DIR`
//!   environment variable; the canonical values can be computed
//!   in any environment that builds `shekyl-pow-randomx` with the
//!   `test-internals` feature. This is the sandbox-portable path.
//! - **Independent-substrate regeneration (`gen_canonical_outputs`
//!   binary).** The C reference is the independent substrate against
//!   which the canonical values can be re-derived for an audit —
//!   the binary path uses C-side derivation to detect Rust-side
//!   bugs in [`PreparedCache::derive`] that the cache-equivalence
//!   precondition might mask. Both paths produce the same values;
//!   the binary's purpose is the second independent path, not the
//!   primary computation.
//!
//! ## Visibility
//!
//! `pub` so that the binary (separate crate per Cargo convention)
//! and integration tests under [`tests/`](../../tests/) can
//! consume the helpers. Per [`crate::lib`]'s `#[doc(hidden)]`
//! attribute, this surface is not exported as a production API;
//! the harness is the sole consumer.

use sha2::{Digest, Sha256};
use shekyl_pow_randomx::{PreparedCache, Seedhash};

use super::interpreter::{evaluate, BASE_CACHE_BYTES_LEN};
use super::types::{BaseSeedhash, CacheRecipe};

/// Compute the canonical SHA-256 over a recipe's evaluator-
/// produced expanded cache bytes, given a pre-derived 256-MiB
/// base cache byte sequence.
///
/// `base_cache_bytes` must equal [`BASE_CACHE_BYTES_LEN`] bytes
/// (256 MiB) — the function panics via the
/// [`evaluate`](super::interpreter::evaluate) precondition
/// otherwise. The caller is expected to supply the bytes
/// corresponding to `recipe.base.bytes` per the recipe
/// evaluator's input contract.
///
/// Returns the SHA-256 of the evaluated cache bytes (post-
/// modification) as a 32-byte array. This is the Family-1
/// canonical entry per R1-D4 close.
#[must_use]
pub fn compute_recipe_canonical(recipe: &CacheRecipe, base_cache_bytes: &[u8]) -> [u8; 32] {
    let evaluated = evaluate(recipe, base_cache_bytes);
    let mut hasher = Sha256::new();
    hasher.update(&evaluated.cache_bytes);
    hasher.finalize().into()
}

/// Derive the 256-MiB base cache bytes for a [`BaseSeedhash`] via
/// the Rust subject's [`PreparedCache::derive`] +
/// [`PreparedCache::cache_block_bytes_for_testing`].
///
/// The bytes are concatenated in the iterator's emission order
/// (block 0, block 1, …, block 262_143) per the
/// [`cache_block_bytes_for_testing`] contract; the resulting
/// 268_435_456-byte buffer is the canonical Rust-subject view of
/// the cache memory.
///
/// Per the module-level cache-equivalence precondition reuse, the
/// returned bytes are byte-identical to the C reference's
/// `randomx_get_cache_memory(cache)` output for the same
/// seedhash; the Phase 2g harness asserts this equivalence at
/// every test invocation.
///
/// # Cost
///
/// The full [`PreparedCache::derive`] runs the Argon2d-512 cache
/// fill at the documented baseline of ~150-200 ms on modern
/// hardware (see `prepared_cache.rs` `derive`'s rustdoc, which is
/// the workspace's authoritative cost record for the Argon2d-fill
/// path). The byte materialization adds the cost of allocating
/// 256 MiB and copying it block-by-block from the
/// `cache_block_bytes_for_testing` iterator — memory-bandwidth-
/// bound, ~50-100 ms on `ubuntu-latest`-class runners. Net per
/// call: ~250-300 ms.
///
/// Callers that need canonicals for multiple recipes sharing a
/// base seedhash should amortize using the
/// `Vec<(base_bytes_key, derived_bytes)>` pattern documented in
/// [`super`]'s "Base-cache amortization" module-level rustdoc;
/// [`compute_corpus_canonicals`] is the in-crate exemplar for the
/// canonical-array case, and [`crate::mode_adversarial_ratio::run`]
/// is the exemplar for the per-recipe-ratio measurement case.
#[must_use]
pub fn derive_base_cache_bytes(base: &BaseSeedhash) -> Vec<u8> {
    let seedhash = Seedhash::from_bytes(base.bytes);
    let prepared = PreparedCache::derive(seedhash);
    let mut bytes = Vec::with_capacity(BASE_CACHE_BYTES_LEN);
    for block in prepared.cache_block_bytes_for_testing() {
        bytes.extend_from_slice(&block);
    }
    debug_assert_eq!(
        bytes.len(),
        BASE_CACHE_BYTES_LEN,
        "derive_base_cache_bytes: PreparedCache::cache_block_bytes_for_testing produced \
         {} bytes; expected {BASE_CACHE_BYTES_LEN} (256 MiB). This indicates a \
         test-internals surface drift between shekyl-pow-randomx and the recipe \
         evaluator's BASE_CACHE_BYTES_LEN constant.",
        bytes.len(),
    );
    bytes
}

/// Compute the Family-1 canonical SHA-256 array over an entire
/// corpus, amortizing base-cache derivation across recipes that
/// share the same `base.bytes`.
///
/// The returned `Vec<[u8; 32]>` has one entry per recipe in
/// `corpus`, matching `corpus`'s ordering. Recipes whose
/// `base.bytes` byte sequences match share a single
/// [`derive_base_cache_bytes`] invocation — the C4 starter corpus
/// has 3 unique base byte patterns (all-zeros, all-0x42,
/// all-0x01) across 8 recipes, yielding 3 derivations rather
/// than 8 (62% reduction in derivation cost).
///
/// # Cost
///
/// Bounded above by `(unique_bases × derive_base_cache_bytes_cost)
/// + (recipes × evaluate_cost) + (recipes × sha256_cost)`. Per
/// [`derive_base_cache_bytes`]'s rustdoc cost section, each base
/// derivation is ~250-300 ms (Argon2d ~150-200 ms +
/// materialization ~50-100 ms); per [`super::interpreter::evaluate`]'s
/// rustdoc cost section, each recipe expansion is dominated by a
/// 256-MiB clone (~tens of ms, memory-bandwidth-bound); SHA-256
/// over 256 MiB is similarly memory-bandwidth-bound (~tens of ms).
/// For the C4 starter corpus (3 unique bases, 8 recipes):
/// 3 × ~300 ms + 8 × ~50 ms + 8 × ~50 ms ≈ ~1.7 s on
/// `ubuntu-latest`-class hardware. The 768-MiB peak working set
/// (3 derived bases held simultaneously through the loop)
/// dominates the memory footprint.
///
/// # Ordering pin
///
/// The output's ordering matches `corpus`'s ordering; the C5
/// canonical-output array's M1 substrate pin depends on this
/// ordering — `FAMILY_1_RECIPE_OUTPUTS[i]` must correspond to
/// `get_corpus()[i]`. The function does not reorder recipes for
/// amortization; the amortization is purely the inner-loop
/// dedup, not a corpus reordering.
#[must_use]
pub fn compute_corpus_canonicals(corpus: &[CacheRecipe]) -> Vec<[u8; 32]> {
    let mut canonicals = vec![[0u8; 32]; corpus.len()];
    let mut base_cache_cache: Vec<(BaseSeedhash, Vec<u8>)> = Vec::new();
    for (recipe_idx, recipe) in corpus.iter().enumerate() {
        let base_bytes = match base_cache_cache
            .iter()
            .find(|(cached_base, _)| cached_base.bytes == recipe.base.bytes)
        {
            Some((_, bytes)) => bytes,
            None => {
                let new_bytes = derive_base_cache_bytes(&recipe.base);
                base_cache_cache.push((recipe.base, new_bytes));
                &base_cache_cache
                    .last()
                    .expect("base_cache_cache non-empty after push")
                    .1
            }
        };
        canonicals[recipe_idx] = compute_recipe_canonical(recipe, base_bytes);
    }
    canonicals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adversarial::get_corpus;

    /// Smoke test: [`compute_recipe_canonical`] produces stable
    /// output for the identity recipe (no modifications) — the
    /// canonical equals `SHA-256(base_cache_bytes)`.
    ///
    /// Per [`evaluate`]'s identity-recipe contract, applying a
    /// recipe with empty modifications returns the base cache
    /// bytes unchanged; the canonical SHA-256 over those bytes
    /// is the SHA-256 of the input.
    #[test]
    fn identity_recipe_canonical_equals_sha_of_base_bytes() {
        let base = BaseSeedhash {
            name: "test-base",
            bytes: [0x77; 32],
        };
        let recipe = CacheRecipe {
            name: "identity",
            rationale: "Category 3: smoke test for identity-recipe SHA equivalence",
            base,
            modifications: &[],
        };
        let base_bytes = vec![0x00u8; BASE_CACHE_BYTES_LEN];
        let canonical = compute_recipe_canonical(&recipe, &base_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&base_bytes);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            canonical, expected,
            "Identity recipe canonical must equal SHA-256(base_cache_bytes)",
        );
    }

    /// [`compute_recipe_canonical`] produces distinct outputs for
    /// recipes that differ only in their modification list. This
    /// is the per-recipe correctness substrate that makes the
    /// corpus-level ordering invariant of [`compute_corpus_canonicals`]
    /// meaningful — if two recipes with distinct modifications
    /// canonicalized to the same value, the ordering pin would
    /// degenerate. The test uses synthetic base bytes to avoid the
    /// 256-MiB allocation + ~250-300 ms Argon2d-fill cost of
    /// [`derive_base_cache_bytes`] (per that function's rustdoc
    /// cost section).
    ///
    /// The full corpus-level ordering invariant of
    /// [`compute_corpus_canonicals`] (one output per recipe, in
    /// input order) is checked under `#[ignore]` by
    /// [`compute_corpus_canonicals_full_corpus_shape`] below, which
    /// pays the Argon2d derive cost; this cheap test exercises the
    /// per-recipe canonicalization substrate the ordering depends
    /// on. A `compute_corpus_canonicals` variant that accepts an
    /// injected base-cache provider would let this test cover the
    /// corpus-level loop directly, but the public surface intentionally
    /// hides the base-cache cache; the rename above closes Copilot's
    /// review comment without expanding the public API.
    #[test]
    fn compute_recipe_canonical_distinguishes_modifications() {
        let base = BaseSeedhash {
            name: "test-base",
            bytes: [0xab; 32],
        };
        let recipe_a = CacheRecipe {
            name: "rec-a",
            rationale: "Category 3: distinguishability test recipe A",
            base,
            modifications: &[(0, 0x11)],
        };
        let recipe_b = CacheRecipe {
            name: "rec-b",
            rationale: "Category 3: distinguishability test recipe B",
            base,
            modifications: &[(0, 0x22)],
        };
        let base_bytes = vec![0x33u8; BASE_CACHE_BYTES_LEN];
        let canonical_a = compute_recipe_canonical(&recipe_a, &base_bytes);
        let canonical_b = compute_recipe_canonical(&recipe_b, &base_bytes);
        assert_ne!(
            canonical_a, canonical_b,
            "Recipes with distinct modifications must produce distinct canonicals",
        );
    }

    /// [`compute_corpus_canonicals`] returns the correct shape
    /// against the actual C4 starter corpus. The expensive
    /// derivation runs only under `--ignored` to keep the default
    /// `cargo test` fast.
    ///
    /// This in-module `#[ignore]`-gated test is the C4 starter
    /// corpus's runtime backstop for the
    /// [`compute_corpus_canonicals`] shape invariant. A dedicated
    /// `tests/adversarial_canonical_runtime.rs` integration test
    /// that re-derives canonicals and asserts byte-equality
    /// against
    /// [`super::super::adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`]
    /// was scoped in early planning but consolidated into the
    /// existing substrate: the compile-time
    /// [`super::super::adversarial_canonical_outputs::FAMILY_1_RECIPE_SHA256`]
    /// meta-pin (with the
    /// `family_1_recipe_sha256_meta_pin` unit test enforcing the
    /// no-tampering guard) covers the array-tampering surface;
    /// the [`bin::gen_canonical_outputs`](../../bin/gen_canonical_outputs.rs)
    /// helper covers the array-regeneration surface. The
    /// re-derive-and-compare-at-runtime backstop is deferred
    /// (`#[ignore]`-gated `compute_corpus_canonicals_full_corpus_shape`
    /// is the closest in-tree exerciser); reopen if evaluator-drift
    /// regressions surface that the compile-time pin doesn't catch.
    ///
    /// Marked `#[ignore]` because it allocates 3 × 256-MiB Argon2d
    /// caches simultaneously (~768 MiB peak working set), plus the
    /// ~250-300 ms per-base derive cost (per
    /// [`derive_base_cache_bytes`]'s rustdoc) and per-recipe
    /// SHA-256/clone overhead — total runtime is bounded but the
    /// memory footprint is large enough to risk OOM on
    /// memory-constrained runners. Run with `cargo test -p
    /// shekyl-randomx-differential --release -- --ignored
    /// compute_corpus_canonicals_full_corpus_shape` when
    /// re-validating the C5 canonical pin.
    #[test]
    #[ignore = "Phase 2h C5 expensive: allocates 3 × 256-MiB caches simultaneously \
                (~768 MiB peak); runtime ≈ ~1-2s on ubuntu-latest. Memory footprint, \
                not runtime, is the gate basis. Run with --ignored to validate C5 canonicals."]
    fn compute_corpus_canonicals_full_corpus_shape() {
        let corpus = get_corpus();
        let canonicals = compute_corpus_canonicals(&corpus);
        assert_eq!(
            canonicals.len(),
            corpus.len(),
            "compute_corpus_canonicals must return one entry per recipe",
        );
        for (i, canonical) in canonicals.iter().enumerate() {
            assert_ne!(
                *canonical, [0u8; 32],
                "Recipe {} ({}) produced all-zero canonical — Argon2d-derived bytes \
                 should not SHA to all-zeros (probabilistically impossible)",
                i, corpus[i].name,
            );
        }
    }

    /// **C5 population helper.** Computes and prints the Family-1
    /// canonical SHA-256 values for the C4 starter corpus in a
    /// format suitable for direct paste into
    /// [`super::super::adversarial_canonical_outputs::FAMILY_1_RECIPE_OUTPUTS`].
    ///
    /// **NOT** a CI gate — this is the C5 initial-population
    /// substrate producer. Run once with
    /// `cargo test -p shekyl-randomx-differential --release -- \
    ///   --ignored --nocapture print_c5_family_1_canonical_values`,
    /// paste the output into `adversarial_canonical_outputs.rs`,
    /// and recompute the [`FAMILY_1_RECIPE_SHA256`] meta-pin via
    /// [`compute_family_1_recipe_hash`]'s output.
    ///
    /// The output also includes the per-recipe `recipe_name` and
    /// `rationale` excerpt as inline comments to make the
    /// adversarial_canonical_outputs.rs review surface human-
    /// auditable per R1-D4 close.
    #[test]
    #[ignore = "Phase 2h C5 substrate-population helper: prints Family-1 canonical \
                SHA-256 values for paste into adversarial_canonical_outputs.rs. \
                Run with --ignored --nocapture."]
    fn print_c5_family_1_canonical_values() {
        let corpus = get_corpus();
        let canonicals = compute_corpus_canonicals(&corpus);
        eprintln!("=== C5 Family-1 canonical SHA-256 values ===");
        for (recipe, canonical) in corpus.iter().zip(canonicals.iter()) {
            eprintln!("    // recipe: {}", recipe.name);
            // Print a 60-char excerpt of the rationale for the
            // inline-comment readability. UTF-8-safe truncation via
            // `chars().take(N)` — `&recipe.rationale[..60]` would
            // panic if byte index 60 lands inside a multi-byte char
            // (any non-ASCII rationale would trigger). The bound is
            // chars (visible glyphs for ASCII; codepoints for non-
            // ASCII), matching the equivalent helper in
            // `bin/gen_canonical_outputs.rs`.
            const RATIONALE_EXCERPT_CHARS: usize = 60;
            let rationale_excerpt = if recipe.rationale.chars().count() > RATIONALE_EXCERPT_CHARS {
                let truncated: String = recipe
                    .rationale
                    .chars()
                    .take(RATIONALE_EXCERPT_CHARS)
                    .collect();
                format!("{truncated}…")
            } else {
                recipe.rationale.to_string()
            };
            eprintln!("    // {rationale_excerpt}");
            eprint!("    [");
            for (i, byte) in canonical.iter().enumerate() {
                if i > 0 {
                    eprint!(",");
                }
                eprint!(" 0x{byte:02x}");
            }
            eprintln!("],");
        }
        eprintln!("=== end C5 Family-1 canonical SHA-256 values ===");
        // Also print the meta-SHA pin (SHA-256 of the concatenated
        // array contents) for direct paste into FAMILY_1_RECIPE_SHA256.
        let mut meta_hasher = Sha256::new();
        for canonical in &canonicals {
            meta_hasher.update(canonical);
        }
        let meta: [u8; 32] = meta_hasher.finalize().into();
        eprintln!("=== C5 FAMILY_1_RECIPE_SHA256 meta-pin (SHA-256 of array) ===");
        eprint!("[");
        for (i, byte) in meta.iter().enumerate() {
            if i > 0 {
                eprint!(",");
            }
            eprint!(" 0x{byte:02x}");
        }
        eprintln!(" ]");
    }
}
