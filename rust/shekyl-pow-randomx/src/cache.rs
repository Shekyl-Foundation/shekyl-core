// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX v2 [`Cache`] type — 256 MiB Argon2d-derived memory
//! consumed by the per-hash dataset-item reads in `compute_hash`'s
//! execution loop (the free function landed by commit 6 of the same
//! Phase 2c implementation PR).
//!
//! Per
//! [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §2 surface 1 + §5.4 (F4 — `Cache` lands in 2c, not 2e), this module
//! lands across three Phase 2c implementation-PR commits:
//!
//! - **Commit 1 (this commit):** [`Cache`] struct + size constants
//!   ([`CACHE_SIZE`], [`DATASET_ITEM_SIZE`], [`DATASET_ITEM_COUNT`]) +
//!   empty [`Drop`] (review-surface hook per §5.11.4).
//! - **Commit 2:** `Cache::derive` + `pub(crate) Cache::from_raw` + T1
//!   spec-vector test + T1' determinism property test + cache-site
//!   `debug_assert!`s per §5.11.2.
//! - **Commit 3:** `pub(crate) Cache::derive_item` + `pub(crate)
//!   Cache::item_bytes` + T2 spec-vector test + T2' invariance
//!   property test (promotes `superscalar::randomx_reciprocal` to
//!   `pub(crate)` per §4.1 row 6).
//!
//! # Threat-model disposition (per §5.11.4)
//!
//! Cache memory is **public-input-only**: every byte is a
//! deterministic function of `seedhash`, which is itself a block-header
//! field (public by construction). No constant-time discipline applies
//! to access patterns over this memory, and no wipe-on-drop is
//! load-bearing for confidentiality. The empty [`Drop`] impl below
//! exists as a review-surface hook for future field additions, not as
//! a zeroization guarantee.

use argon2::Block;

use crate::argon2d::RANDOMX_ARGON_BLOCKS;

/// Total cache size in bytes.
///
/// `RANDOMX_ARGON_MEMORY * ArgonBlockSize = 262_144 * 1024 =
/// 268_435_456` (256 MiB) per
/// [`external/randomx-v2/src/common.hpp:88`](../../../external/randomx-v2/src/common.hpp)
/// at pin `aaafe71`. The Rust port derives it from the existing
/// [`RANDOMX_ARGON_BLOCKS`] (`= RANDOMX_ARGON_MEMORY`) and
/// [`argon2::Block`]`::SIZE` (`= 1024`) rather than restating the
/// `262_144 * 1024` arithmetic; if either upstream constant changes,
/// the change propagates here automatically.
#[allow(dead_code)] // CLIPPY: read in commit 2 (Cache::derive allocation site).
pub(crate) const CACHE_SIZE: usize = RANDOMX_ARGON_BLOCKS * Block::SIZE;

/// Per-item dataset-read width in bytes.
///
/// `RANDOMX_DATASET_ITEM_SIZE = 64` per
/// [`external/randomx-v2/src/randomx.h:36`](../../../external/randomx-v2/src/randomx.h)
/// at pin `aaafe71`. Each iteration of the spec §4.5.4 execution loop
/// reads exactly this many bytes from the cache (8 native-endian
/// 64-bit registers serialized after 8 chained SuperscalarHash
/// transforms per spec §7.3). Becomes the return-array length of
/// `Cache::derive_item` and `Cache::item_bytes` in commit 3.
#[allow(dead_code)] // CLIPPY: read in commit 3 (derive_item / item_bytes signatures).
pub(crate) const DATASET_ITEM_SIZE: usize = 64;

/// Number of distinct dataset items addressable from the cache.
///
/// `CacheSize / CacheLineSize = 268_435_456 / 64 = 4_194_304` per
/// [`external/randomx-v2/src/common.hpp:85,
/// :88`](../../../external/randomx-v2/src/common.hpp) at pin
/// `aaafe71`. The execution loop addresses items in
/// `0..DATASET_ITEM_COUNT`; commit 3's `derive_item` rejects
/// out-of-range arguments via `debug_assert!` per §5.11.2.
#[allow(dead_code)] // CLIPPY: read in commit 3 (derive_item bounds-check site).
pub(crate) const DATASET_ITEM_COUNT: usize = CACHE_SIZE / DATASET_ITEM_SIZE;

/// RandomX v2 Cache — 256 MiB of Argon2d-derived memory consumed by
/// `compute_hash` via the per-iteration dataset-item read in the spec
/// §4.5.4 execution loop.
///
/// # Construction
///
/// At this commit, [`Cache`] has no constructor. Commit 2 of the
/// Phase 2c implementation PR lands the production constructor
/// `Cache::derive(seedhash: &[u8; 32]) -> Cache` and the test-only
/// `pub(crate) Cache::from_raw(bytes: Vec<u8>) -> Cache`. The `memory`
/// field is intentionally private — callers must go through one of
/// the constructors rather than building a [`Cache`] from a raw
/// `Box<[Block]>`.
///
/// # Public surface
///
/// [`Cache`] is the only `pub` item in this module per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.9 (R2-D3 visibility correction): `derive_item`, `item_bytes`,
/// and `from_raw` are all `pub(crate)` — there is no FFI consumer for
/// them at Phase 2c, and exposing them now would create
/// reviewer-attention surface for properties no caller asserts.
///
/// # Threat-model disposition
///
/// See the module-level docstring for the public-input-only
/// disposition that drives the empty [`Drop`] implementation below.
pub struct Cache {
    /// `RANDOMX_ARGON_BLOCKS` (262_144) [`argon2::Block`]s of 1024
    /// bytes each, totaling [`CACHE_SIZE`] (256 MiB). Allocated as
    /// `Box<[Block]>` so the size is fixed at construction (no
    /// `Vec`-style growth surface) and the resulting `Cache` value is
    /// `Send + Sync`-safe for the eventual Phase 2f `CacheStore`
    /// `Arc<Cache>` shape.
    ///
    /// Field is private; consumers go through `Cache::derive` or
    /// `Cache::from_raw` (both landed in commit 2). Read access from
    /// `derive_item` (commit 3) flows through `Cache::item_bytes`
    /// without exposing the buffer.
    #[allow(dead_code)] // CLIPPY: written by commit 2; read by commit 3.
    memory: Box<[Block]>,
}

impl Drop for Cache {
    /// Empty drop — the 256 MiB `memory` buffer is freed by the
    /// default `Box<[Block]>` destructor; no zeroization is required
    /// because cache memory is public-input-only per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.4.
    ///
    /// # Why the impl exists if it does nothing
    ///
    /// The empty [`Drop`] is the review-surface hook for future field
    /// additions to [`Cache`]: any added field that does carry
    /// secret material lands inside an already-present [`Drop`] body
    /// rather than requiring a future contributor to remember to add
    /// the impl — which is the failure mode that produces the "we
    /// forgot to zeroize" class of bugs
    /// [`35-secure-memory.mdc`](../../../.cursor/rules/35-secure-memory.mdc)
    /// names. Per
    /// [`16-architectural-inheritance.mdc`](../../../.cursor/rules/16-architectural-inheritance.mdc)'s
    /// continuous-discipline corollary, the impl is structurally
    /// cheaper than the dropped-discipline class of bug it preempts.
    fn drop(&mut self) {
        // INTENT: no-op. See impl rustdoc for the public-input-only
        // rationale and the future-field-addition review-surface hook.
    }
}
