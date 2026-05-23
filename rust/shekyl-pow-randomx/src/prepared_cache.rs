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
}
