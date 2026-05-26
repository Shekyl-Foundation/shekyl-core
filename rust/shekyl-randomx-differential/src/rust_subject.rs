// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Rust verifier "subject under test" wrapper (§5.1.9).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.9, this module
//! owns the harness's only call sites for `PreparedCache::derive` +
//! `compute_hash` — the Phase 2F R3-frozen production public
//! surface of `shekyl-pow-randomx`. Per §5.1.9 + §5.3.1, the
//! hot-path hash-compute call sites in this module carry **no**
//! `test-internals`-gated access; the only `test-internals`
//! consumption in the harness is from `cache_precondition.rs`
//! (§5.1.7), which reaches in through [`RustSubjectSession::prepared`]
//! to call `PreparedCache::cache_block_bytes_for_testing` (§5.3.3).
//!
//! ## Lifecycle (mirrors §5.1.8 C-side)
//!
//! One [`RustSubjectSession`] is constructed per **seedhash** (not
//! per `(seedhash, data)` pair). The contained [`PreparedCache`] is
//! reused for every data value in that seedhash's group; the cache
//! is released by [`Drop`] when the session goes out of scope.
//! This mirrors §5.1.8's C oracle lifecycle (one cache + one VM
//! per seedhash; VM/cache reused across data values) so the two
//! sides' allocator pressure shapes match — the §3.16 R4-D5 deterministic-
//! execution rationale extends here.
//!
//! ## Why a wrapper, not direct `PreparedCache::derive` calls
//!
//! Three reasons:
//!
//! 1. **Lifecycle parity with the C oracle.** Both sides are
//!    constructed from the same `Seedhash` value, expose
//!    `seedhash()`, `compute_hash(data)`, and (for the precondition)
//!    a cache-byte view. The mode modules (C7–C9) construct the two
//!    sides in lockstep without the asymmetry that direct
//!    `PreparedCache::derive` calls would introduce.
//! 2. **Single reach-through point for `cache_block_bytes_for_testing`.**
//!    The `test-internals` accessor is consumed exclusively from
//!    `cache_precondition.rs` via `session.prepared().cache_block_bytes_for_testing()`.
//!    Concentrating the reach-through here makes the §3.17 R5-D1
//!    discipline auditable: any future call to the accessor outside
//!    `cache_precondition.rs` is grounds for §5.7 scope-creep
//!    rejection.
//! 3. **Bisection boundary.** The C4 → C9 commit sequence places
//!    `rust_subject.rs` at C6 alongside `c_oracle.rs`. The mode
//!    modules at C7–C9 then consume the symmetric pair, not the
//!    underlying types directly. A divergence between the two
//!    sides surfaces at the mode-module boundary, not inside the
//!    `PreparedCache` / `randomx-v2-sys` boundaries themselves.

use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

use crate::c_oracle::RANDOMX_HASH_SIZE;

/// One [`PreparedCache`] bound to a specific seedhash for the
/// session's lifetime; the Rust counterpart to
/// [`crate::c_oracle::COracleSession`].
///
/// Construct via [`RustSubjectSession::derive`]; the cache is
/// released when the session is dropped (the verifier crate's
/// `Cache` carries its own `ZeroizeOnDrop` discipline per
/// `shekyl-pow-randomx`'s `cache.rs`).
pub struct RustSubjectSession {
    prepared: PreparedCache,
}

impl RustSubjectSession {
    /// Derive a fresh cache from `seedhash` via
    /// [`PreparedCache::derive`].
    ///
    /// Per §5.1.9's Phase-2F-R3-frozen surface reference, this is
    /// the only `PreparedCache::derive` call site in the harness;
    /// other modules go through this wrapper.
    pub fn derive(seedhash: Seedhash) -> Self {
        Self {
            prepared: PreparedCache::derive(seedhash),
        }
    }

    /// Construct a session whose `PreparedCache` carries the
    /// supplied `cache_bytes` under the declared `seedhash`,
    /// via [`PreparedCache::from_raw_for_testing`] (Phase 2h R1-D2
    /// close).
    ///
    /// Mirrors
    /// [`crate::c_oracle::COracleSession::from_raw_for_testing`]
    /// on the Rust side; both sides run the production hash path
    /// against the recipe-evaluator-crafted cache contents. Used
    /// exclusively by `crate::mode_adversarial_ratio` to construct
    /// paired Rust/C sessions for per-recipe ratio measurement.
    ///
    /// The `test-internals` feature flag is always enabled in the
    /// harness crate's `Cargo.toml` `[dependencies]` entry for
    /// `shekyl-pow-randomx` (the harness is itself a test-only
    /// artifact); production builds of the verifier crate do not
    /// enable it.
    pub fn from_raw_for_testing(seedhash: Seedhash, cache_bytes: &[u8]) -> Self {
        Self {
            prepared: PreparedCache::from_raw_for_testing(seedhash, cache_bytes),
        }
    }

    /// The seedhash this session's cache was derived from.
    ///
    /// Returns the [`Seedhash`] by reference per the verifier
    /// crate's `PreparedCache::seedhash` shape; callers that need
    /// the owned value dereference with `*session.seedhash()` (the
    /// [`Seedhash`] type is `Copy`, so no explicit clone is needed).
    pub fn seedhash(&self) -> &Seedhash {
        self.prepared.seedhash()
    }

    /// Borrow the inner [`PreparedCache`].
    ///
    /// **Internal-to-harness reach-through.** This accessor exists
    /// so [`crate::cache_precondition`] can call
    /// `PreparedCache::cache_block_bytes_for_testing` (§5.3.3,
    /// `test-internals`-gated) without each mode module duplicating
    /// the access. Per §5.7's drift-prevention discipline, no other
    /// module in the harness calls this accessor; the §6.6 T14
    /// crate-invariant grep gate (extended at C10) asserts the
    /// invariant mechanically.
    pub fn prepared(&self) -> &PreparedCache {
        &self.prepared
    }

    /// Compute one Rust-subject RandomX hash of `data` under this
    /// session's `(seedhash, prepared cache)` binding.
    ///
    /// This is the Rust-side oracle for §5.1.10's T1 + T5
    /// byte-equality assertions and §5.1.12's interleaved latency
    /// mode. The C-side counterpart is
    /// [`crate::c_oracle::COracleSession::calculate_hash`].
    pub fn compute_hash(&self, data: &[u8]) -> [u8; RANDOMX_HASH_SIZE] {
        compute_hash(&self.prepared, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `seedhash()` round-trips the value passed to `derive`. Pins
    /// the lifecycle-parity property: both sides (C oracle + Rust
    /// subject) expose the same constructor argument as `seedhash()`,
    /// so mode-module assertions like
    /// `assert_eq!(rust.seedhash(), c.seedhash())` are tautological
    /// when the modules are wired correctly.
    ///
    /// This test pays one full `PreparedCache::derive` cost (~150–
    /// 200 ms in debug; ~5–10 s in release builds dominated by
    /// Argon2d-512). Acceptable for one assertion; bulk-behavior
    /// testing of the verifier's `PreparedCache` lives in
    /// `prepared_cache.rs#mod tests` (which also pays the cost
    /// once).
    #[test]
    fn seedhash_round_trips_through_derive() {
        let input = Seedhash::from_bytes([0x42; 32]);
        let session = RustSubjectSession::derive(input);
        assert_eq!(session.seedhash(), &input);
    }
}
