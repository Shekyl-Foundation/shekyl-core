// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`PreparedCache`] — bundle of a derived (crate-private) cache
//! with the [`crate::Seedhash`] it was derived from.
//!
//! # Why bundle
//!
//! Per the Phase 2F plan-doc (`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`)
//! §1.1 Round 2 + §3.1 Round 2 disposition: the verifier crate's
//! threat model treats *which cache is paired with which
//! seedhash* as a consensus-correctness invariant.
//! [`compute_hash`](crate::compute_hash) pre-Round-2 took
//! `(&Cache, &Seedhash, &[u8])` — three independent parameters;
//! a caller passing the *wrong* cache for a given seedhash gets a
//! wrong hash, which the network rejects. Correct for chain
//! integrity, but a footgun the type system can close at zero cost.
//!
//! [`PreparedCache`] bundles the cache and the seedhash it was
//! derived from at construction time
//! ([`PreparedCache::derive`](PreparedCache::derive) is the only
//! public path to a value of this type).
//! [`compute_hash`](crate::compute_hash) takes `&PreparedCache`
//! and reads the seedhash from the bundle, so the consensus-
//! correctness invariant ("the cache used to compute this hash
//! was derived from the seedhash this hash was attributed to")
//! becomes type-enforced rather than convention-enforced. Wrong-
//! cache-for-seedhash becomes unrepresentable.
//!
//! # No `Clone` / `Copy` / `PartialEq`
//!
//! [`PreparedCache`] derives nothing. The wrapped (crate-private)
//! cache is ~256 MiB; cloning would be an extraordinarily
//! expensive operation that no caller wants. Sharing across
//! consumers is handled via [`std::sync::Arc<PreparedCache>`]
//! (the `CacheStore` shape per the same §3.1 Round 2 disposition,
//! landing in Phase 2F commit 2); pointer-equality goes through
//! [`std::sync::Arc::ptr_eq`].
//!
//! Equality semantics (per Phase 2F §1.1 Round 2 post-closure
//! pin #2):
//!
//! - **Seedhash equality** (CacheStore lookup, slot indexing):
//!   `prepared.seedhash() == lookup_key` via [`crate::Seedhash`]'s
//!   derived `PartialEq`.
//! - **Arc identity** (test assertions like "same Arc clone
//!   returned from two `lookup`s"): [`std::sync::Arc::ptr_eq`].
//!
//! Deriving `PartialEq` on `PreparedCache` would either be a
//! structural value-equality (compare the full 256 MiB cache
//! bytes, which no caller wants) or a delegating equality
//! (compare seedhash only, which conflates "same seedhash" with
//! "same `PreparedCache` instance"). Both shapes are wrong; the
//! absence of the impl forces consumers to use the right
//! primitive at the call site.

use crate::cache::Cache;
use crate::seedhash::Seedhash;

/// Bundle of a derived (crate-private) cache with the
/// [`Seedhash`] it was derived from.
///
/// The bundling is enforced at construction
/// ([`PreparedCache::derive`] is the only public path to a value
/// of this type). Consumers can only produce a `PreparedCache`
/// whose inner cache was derived from its `seedhash`.
///
/// See the module rustdoc for the full rationale and the rejected
/// alternatives.
pub struct PreparedCache {
    cache: Cache,
    seedhash: Seedhash,
}

impl PreparedCache {
    /// Derive a [`PreparedCache`] from a [`Seedhash`].
    ///
    /// Internally calls the `pub(crate)` cache-derive primitive
    /// and bundles the result with the input seedhash. The cost
    /// is dominated by the underlying 256-MiB Argon2d fill
    /// (~150–200 ms on modern hardware per the cache-derive
    /// rustdoc); the bundling step itself is free.
    ///
    /// # Determinism
    ///
    /// Inherits the underlying cache-derive primitive's
    /// determinism: same seedhash → byte-identical cache →
    /// byte-identical [`PreparedCache`] (modulo the [`Seedhash`]
    /// field, which is a copy of the input by construction). The
    /// Phase 2c T1 spec-vector test asserts the underlying cache
    /// determinism; this layer adds no new state.
    pub fn derive(seedhash: Seedhash) -> PreparedCache {
        let cache = Cache::derive(&seedhash);
        PreparedCache { cache, seedhash }
    }

    /// Borrow the [`Seedhash`] this [`PreparedCache`] was derived
    /// from.
    ///
    /// The seedhash is the one the caller supplied to
    /// [`PreparedCache::derive`]; [`compute_hash`](crate::compute_hash)
    /// reads it via this accessor rather than taking it as a
    /// separate parameter.
    pub fn seedhash(&self) -> &Seedhash {
        &self.seedhash
    }

    /// In-crate accessor to the inner cache.
    ///
    /// Used by [`compute_hash`](crate::compute_hash)'s body to
    /// drive the dispatch loop and (if a future in-crate consumer
    /// surfaces) by other crate-internal code that needs the inner
    /// cache reference from `&PreparedCache`. Not part of the
    /// public API surface; FFI consumers go through
    /// [`compute_hash`](crate::compute_hash).
    ///
    /// The accessor's existence is the load-bearing structural
    /// property per the Phase 2F plan-doc §1.1 Round 2 post-
    /// closure pin #1: a future contributor wondering "should I
    /// add `prepared.derive_item(...)` as a convenience on
    /// `PreparedCache`?" sees that the established reach-through
    /// shape is `prepared.cache_ref().derive_item(...)` and does
    /// not re-expose the cache's API on `PreparedCache`.
    pub(crate) fn cache_ref(&self) -> &Cache {
        &self.cache
    }

    /// Stream the Argon2d-derived cache memory as 1-KiB little-
    /// endian block chunks.
    ///
    /// **TEST-INFRASTRUCTURE ONLY.** This accessor exists
    /// exclusively to satisfy the Phase 2g Rust/C differential
    /// harness's R1-D14 cache-equivalence precondition; production
    /// consumers MUST NOT enable the `test-internals` feature. The
    /// sole consumer is `shekyl-randomx-differential`.
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2G_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
    /// §3.17 R5-D1 + §5.3.3, the `test-internals` feature carves
    /// out a cfg-gated test-infrastructure surface that is
    /// invisible in default-features builds. The verifier crate's
    /// §5.3.1 production surface is unchanged.
    ///
    /// # Output
    ///
    /// Yields the 262_144 1-KiB blocks of the 256-MiB Argon2d-
    /// derived cache memory in their canonical little-endian byte
    /// serialization (matching the C reference's `load64_native`
    /// reads on little-endian targets, per the uniform LE
    /// convention across the crate). The eight
    /// `SuperscalarProgram`s stored alongside the memory are
    /// *not* yielded — the R1-D14 precondition compares against
    /// the C reference's `randomx_get_cache_memory(cache)` return,
    /// which exposes only the Argon2d-derived `memory` buffer.
    /// The program-side determinism is covered in-crate by the
    /// T1' tests in `cache.rs::#[cfg(test)] mod tests`.
    ///
    /// # Memory budget
    ///
    /// The iterator allocates no heap memory; per-iteration stack
    /// cost is 1 KiB. The harness consumes the iterator by
    /// feeding each chunk into a SHA-256 streaming hasher (per
    /// R1-D14's SHA-256-of-full-cache precondition shape); the
    /// drop-discipline memory budget (~256 MiB per-seedhash peak,
    /// not ~512 MiB) is preserved.
    ///
    /// # Why a visitor, not `&[u8]`
    ///
    /// The verifier's internal cache memory is stored as
    /// `Box<[argon2::Block]>`. A `&[u8]` flat view would require
    /// either (a) `unsafe_code` to reinterpret `&[Block]` as
    /// `&[u8]` (forbidden by the crate's `#![deny(unsafe_code)]`
    /// at `lib.rs:166`), (b) a 256-MiB `Vec<u8>` materialization
    /// (defeats the R1-D14 drop-discipline memory budget by
    /// doubling the per-seedhash peak from ~256 MiB to ~512 MiB),
    /// or (c) a new workspace dependency (`bytemuck`/`zerocopy`)
    /// declined per
    /// [`17-dependency-discipline.mdc`](../../../.cursor/rules/17-dependency-discipline.mdc)'s
    /// no-new-deps-without-justification discipline. The visitor
    /// shape avoids all three: no unsafe, no heap allocation, no
    /// new dep.
    #[cfg(feature = "test-internals")]
    pub fn cache_block_bytes_for_testing(&self) -> impl Iterator<Item = [u8; 1024]> + '_ {
        self.cache.block_bytes_le()
    }

    /// Construct a [`PreparedCache`] from `(seedhash, cache_bytes)`
    /// with the Argon2d-fill step bypassed — the cache memory comes
    /// from `cache_bytes` directly, and `programs` is re-derived from
    /// `seedhash` to preserve spec-faithful dataset-item derivation.
    ///
    /// **TEST-INFRASTRUCTURE ONLY.** This accessor exists exclusively
    /// for the Phase 2h adversarial-corpus recipe evaluator
    /// (`shekyl-randomx-differential::adversarial::interpreter`);
    /// production consumers MUST NOT enable the `test-internals`
    /// feature and MUST go through [`PreparedCache::derive`], which
    /// performs the full Argon2d-512 fill required by the spec. The
    /// sole consumer is `shekyl-randomx-differential` per the
    /// §5.6 sole-binary invariant inherited from Phase 2g
    /// (§5.7 drift-prevention boundary; T14 `cargo metadata`
    /// assertion).
    ///
    /// Per
    /// [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
    /// Round 1 R1-D2 close, this accessor is the cache-level
    /// `test-internals` carve-out the Phase 2h recipe-based corpus
    /// methodology requires: the recipe specifies a `(base_seedhash,
    /// modifications)` pair; the evaluator derives `(base_seedhash,
    /// Argon2d-output)` via the C reference's
    /// `randomx_get_cache_memory` (R1-D2 C-side-symmetry close);
    /// applies the recipe's modifications to the cache bytes; then
    /// wraps the modified bytes into the Rust verifier via this
    /// accessor. The Rust verifier's `compute_hash` then exercises
    /// the recipe's targeted spec-silence path against the modified
    /// cache state.
    ///
    /// # Production-reachability cite (Phase 2h Round 2 R2-D2 / T-A14 Mitigation 2)
    ///
    /// Per Phase 2h Round 2 R2-D2's close, every `*_for_testing`
    /// accessor under the `test-internals` feature gate must carry
    /// a rustdoc production-reachability cite identifying the
    /// substrate property that makes the accessor's inputs
    /// operationally meaningful. The discipline lives in the
    /// PR-template reviewer checklist (R2-D2 Mitigation 1) and the
    /// rustdoc cite is the reviewable substrate (R2-D2 Mitigation
    /// 2); composition makes the production-equivalence principle
    /// enforceable rather than convention-asserted.
    ///
    /// **Cite for this accessor.** Argon2d-512 is the spec-defined
    /// key-derivation function whose image is the full
    /// `CACHE_SIZE`-byte space (256-MiB byte strings); every
    /// possible `cache_bytes` value corresponds to some
    /// hypothetical seedhash-derived state, even if that seedhash
    /// is infeasible to discover (the discovery problem is
    /// equivalent to inverting Argon2d, a one-way function). The
    /// `(seedhash, cache_bytes)` pair this accessor accepts is
    /// thus "operationally equivalent" to two seedhashes: the
    /// `seedhash` parameter drives the `SuperscalarProgram`
    /// derivation (the program-side state the recipe wants to keep
    /// fixed to a known-good base seedhash); a hypothetical
    /// `seedhash*` such that `Argon2d-512(seedhash*) =
    /// cache_bytes` drives the cache-memory state (the memory-side
    /// state the recipe wants to modify to trigger a rare-path).
    /// Production code never constructs cache state with mismatched
    /// `(programs(s1), memory(s2))` for `s1 ≠ s2` — but every byte
    /// of the constructed state IS reachable in production from
    /// SOME pair of (program-seedhash, memory-seedhash) combination.
    ///
    /// **Bundling property broken by construction.** Per the Phase
    /// 2h Round 1 R1-D2 close framing, the `PreparedCache`
    /// bundling property (`prepared.seedhash()` matches the
    /// seedhash whose Argon2d output produced `prepared`'s cache
    /// memory) is **broken by construction** for values returned
    /// by this accessor: `prepared.seedhash()` returns the supplied
    /// `seedhash` (which drives `programs`), not the hypothetical
    /// `seedhash*` whose Argon2d output equals `cache_bytes`. This
    /// is the intentional test-infrastructure carve-out — the
    /// recipe evaluator wants to exercise `compute_hash` against
    /// `(programs(s1), memory(s2))` states that exist only under
    /// the accessor's construction, not under production
    /// derivation. Per Phase 2c §5.11.4 the cache memory is
    /// public-input-only; no secret material is constructible via
    /// the accessor.
    ///
    /// # Length contract
    ///
    /// `cache_bytes.len()` must equal [`crate::cache::CACHE_SIZE`]
    /// (256 MiB = 268_435_456 bytes). The function panics on
    /// mismatch with a diagnostic message via the underlying
    /// [`Cache::from_raw_for_testing`] helper. This is test infra;
    /// length-mismatch is a test-author bug.
    ///
    /// # Cost
    ///
    /// Dominated by the `programs` re-derivation (~few-ms Blake2 +
    /// generate_superscalar). The cache-bytes deserialization is
    /// a single-pass copy through `chunks_exact(1024)` × 262_144
    /// blocks (~hundreds-of-MB/s memory bandwidth bound on modern
    /// hardware). Total cost ≈ 10-50 ms — orders of magnitude
    /// faster than [`PreparedCache::derive`]'s ~150-200 ms
    /// Argon2d-dominated cost. This is the intended use case: the
    /// recipe evaluator pays the full Argon2d cost once (via the
    /// C-side derive in the recipe's base-seedhash setup) and
    /// reuses the derived bytes across multiple recipe modifications
    /// to amortize.
    #[cfg(feature = "test-internals")]
    pub fn from_raw_for_testing(seedhash: Seedhash, cache_bytes: &[u8]) -> PreparedCache {
        let cache = Cache::from_raw_for_testing(&seedhash, cache_bytes);
        PreparedCache { cache, seedhash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `seedhash()` returns the seedhash the consumer passed to
    /// `derive`. Pins the bundling contract end-to-end.
    ///
    /// Note: this test pays one full cache-derive cost
    /// (~150–200 ms, dominated by Argon2d). Acceptable for one
    /// assertion; bulk slot-behavior testing in the (Phase 2F
    /// commit 2) `cache_store.rs#mod tests` uses a `pub(crate)`
    /// test-time cache constructor to avoid paying the cost per
    /// assertion.
    #[test]
    fn seedhash_accessor_returns_input() {
        let input = Seedhash::from_bytes([0x42; 32]);
        let prepared = PreparedCache::derive(input);
        assert_eq!(prepared.seedhash(), &input);
    }

    /// `cache_ref()` returns a reference to the inner cache; the
    /// `pub(crate)` accessor is the documented reach-through path
    /// per the post-closure pin. Compile-time check via
    /// `let _: &Cache = prepared.cache_ref();`.
    #[test]
    fn cache_ref_returns_inner_cache_reference() {
        let prepared = PreparedCache::derive(Seedhash::from_bytes([0x01; 32]));
        let _: &Cache = prepared.cache_ref();
    }

    /// R5-D1 smoke test: `cache_block_bytes_for_testing()` yields
    /// exactly `RANDOMX_ARGON_BLOCKS` (262_144) 1-KiB chunks
    /// totaling `CACHE_SIZE` (256 MiB). Pins the iterator's shape
    /// against accidental future regressions (e.g. a partial
    /// iteration that silently truncates the SHA-256 input under
    /// R1-D14).
    ///
    /// The accessor is feature-gated on `test-internals`; this
    /// test only compiles under `cargo test --features
    /// test-internals` (the same gate the Phase 2g differential
    /// harness uses). Default `cargo test` does not exercise it.
    ///
    /// Determinism of the underlying memory bytes is covered by
    /// the `cache.rs` T1' single-thread / concurrent / interleaved
    /// suite; this test asserts only the iterator's shape (count
    /// + per-chunk length + total bytes).
    #[cfg(feature = "test-internals")]
    #[test]
    fn cache_block_bytes_for_testing_yields_full_cache_in_kib_chunks() {
        use crate::cache::CACHE_SIZE;

        // `RANDOMX_ARGON_BLOCKS` is `pub(crate)` in `argon2d.rs:104`
        // and re-asserted here as a literal so the test does not
        // depend on the constant's accessibility from this module.
        // The literal equals `262_144` per `argon2d.rs:78`
        // (`RANDOMX_ARGON_MEMORY = 262_144`, sourced from
        // `external/randomx-v2/doc/configuration.md` at pin
        // `aaafe71`); `argon2d::tests::constants_match_spec`
        // (`argon2d.rs:185-193`) pins the same value against the
        // same upstream source. The `CACHE_SIZE` assertion below
        // cross-checks this literal against the crate's own
        // `CACHE_SIZE = RANDOMX_ARGON_BLOCKS * Block::SIZE`
        // (`cache.rs:140`).
        const EXPECTED_BLOCKS: usize = 262_144;
        assert_eq!(CACHE_SIZE, EXPECTED_BLOCKS * 1024);

        let prepared = PreparedCache::derive(Seedhash::from_bytes([0x07; 32]));

        let mut total_bytes: usize = 0;
        let mut block_count: usize = 0;
        for block in prepared.cache_block_bytes_for_testing() {
            assert_eq!(
                block.len(),
                1024,
                "cache_block_bytes_for_testing yields 1-KiB chunks per argon2::Block",
            );
            total_bytes += block.len();
            block_count += 1;
        }

        assert_eq!(
            block_count, EXPECTED_BLOCKS,
            "cache_block_bytes_for_testing yields RANDOMX_ARGON_BLOCKS chunks",
        );
        assert_eq!(
            total_bytes, CACHE_SIZE,
            "cache_block_bytes_for_testing yields CACHE_SIZE (256 MiB) total bytes",
        );
    }

    /// Round-trip property: `derive(seedhash)` → extract bytes via
    /// `cache_block_bytes_for_testing()` → reconstruct via
    /// `from_raw_for_testing(seedhash, bytes)` → both prepared caches
    /// produce byte-identical `compute_hash` output for the same data.
    ///
    /// This is the C2 verification of the Phase 2h R1-D2
    /// `from_raw_for_testing` accessor's round-trip correctness: when
    /// the `cache_bytes` input is the actual Argon2d output for the
    /// supplied seedhash, the constructed `PreparedCache` is
    /// functionally equivalent to the production-derived one. The
    /// recipe evaluator's typical path differs (the bytes input
    /// carries recipe modifications), but the round-trip invariant
    /// pins the un-modified baseline — if it fails, the recipe-
    /// modified outputs are also untrustworthy.
    ///
    /// The test is feature-gated on `test-internals` (matches the
    /// accessor's gate); pays two full `Cache::derive` costs
    /// (~300-400 ms total dominated by Argon2d) plus two
    /// `compute_hash` invocations (~100 µs each). Acceptable for one
    /// load-bearing round-trip assertion.
    #[cfg(feature = "test-internals")]
    #[test]
    fn from_raw_for_testing_round_trip_matches_derive() {
        use crate::cache::CACHE_SIZE;

        let seedhash = Seedhash::from_bytes([0x2a; 32]);
        let data = b"phase2h-r1-d2-round-trip-test-input";

        // Production path: derive normally, compute a hash.
        let prepared_derive = PreparedCache::derive(seedhash);
        let hash_derive = crate::compute_hash(&prepared_derive, data);

        // Extract cache bytes via the existing Phase 2g test-internals
        // accessor (cache_block_bytes_for_testing yields LE bytes per
        // Block).
        let mut extracted_bytes: Vec<u8> = Vec::with_capacity(CACHE_SIZE);
        for block in prepared_derive.cache_block_bytes_for_testing() {
            extracted_bytes.extend_from_slice(&block);
        }
        assert_eq!(
            extracted_bytes.len(),
            CACHE_SIZE,
            "Extracted bytes length must equal CACHE_SIZE (256 MiB)",
        );

        // Reconstruction path: from_raw_for_testing wraps the bytes
        // with re-derived programs and compute_hash on the result.
        let prepared_raw = PreparedCache::from_raw_for_testing(seedhash, &extracted_bytes);
        let hash_raw = crate::compute_hash(&prepared_raw, data);

        // Round-trip invariant: both paths produce the same hash.
        // A mismatch indicates either the bytes serialization is not
        // a true inverse (LE byte ordering off) or the program re-
        // derivation diverges from Cache::derive's path.
        assert_eq!(
            hash_derive, hash_raw,
            "Phase 2h R1-D2 round-trip failed: PreparedCache::derive's hash differs from \
             PreparedCache::from_raw_for_testing's hash for the same seedhash + extracted-bytes \
             input. This is either (a) a bug in Cache::from_raw_for_testing's bytes \
             deserialization, (b) a bug in the LE-byte convention asymmetry between \
             block_bytes_le and from_raw_for_testing, or (c) a bug in the program re-derivation \
             path (Blake2Generator + generate_superscalar)."
        );

        // Bundling property surface check: from_raw_for_testing
        // preserves the seedhash() accessor's contract.
        assert_eq!(
            prepared_raw.seedhash(),
            &seedhash,
            "from_raw_for_testing must preserve seedhash() bundling for the supplied seedhash",
        );
    }

    /// Length-mismatch panic surface: `from_raw_for_testing` panics
    /// with a diagnostic when `cache_bytes.len() != CACHE_SIZE`.
    ///
    /// Asserts the panic message is the diagnostic this accessor
    /// surfaces, not a downstream `chunks_exact` or `Box` length
    /// mismatch. Test-author bug discoverability depends on the
    /// panic message naming `CACHE_SIZE`; a regression that swaps
    /// to a generic panic obscures the bug class.
    #[cfg(feature = "test-internals")]
    #[test]
    #[should_panic(expected = "must equal CACHE_SIZE")]
    fn from_raw_for_testing_length_mismatch_panics_with_diagnostic() {
        let seedhash = Seedhash::from_bytes([0; 32]);
        // 1 KiB of zeros is dramatically shorter than the 256 MiB
        // CACHE_SIZE; the assert in Cache::from_raw_for_testing
        // fires first, before any deserialization work.
        let short_bytes = [0u8; 1024];
        let _ = PreparedCache::from_raw_for_testing(seedhash, &short_bytes);
    }
}
