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
//! - **Commit 1:** [`Cache`] struct + size constants
//!   ([`CACHE_SIZE`], [`DATASET_ITEM_SIZE`], [`DATASET_ITEM_COUNT`]) +
//!   empty [`Drop`] (review-surface hook per §5.11.4).
//! - **Commit 2 (this commit):** [`Cache::derive`] + the
//!   [`RANDOMX_CACHE_ACCESSES`] constant + the cache-memory allocation
//!   carve-out + the `programs` field on [`Cache`] + cache-site
//!   `debug_assert!`s per §5.11.2 + T1' determinism property test
//!   (`#[cfg(test)] mod tests` per §14 Round 0 R0-D6). T1 spec-vector
//!   test deferred to commit 7 alongside the F6 generator that
//!   produces its fixture; `Cache::from_raw` dropped at impl-time
//!   pre-flight per §14 Round 0 R0-D5.
//! - **Commit 3:** `pub(crate) Cache::derive_item` + `pub(crate)
//!   Cache::item_bytes` + T2' invariance property test (promotes
//!   `superscalar::randomx_reciprocal` to `pub(crate)` per §4.1
//!   row 6); T2 spec-vector test also deferred to commit 7.
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

use core::mem::MaybeUninit;

use argon2::Block;

use crate::argon2d::{fill_cache, RANDOMX_ARGON_BLOCKS};
use crate::blake2_generator::Blake2Generator;
use crate::superscalar::{generate_superscalar, SuperscalarProgram};

/// Number of [`SuperscalarProgram`]s generated per [`Cache`].
///
/// `RANDOMX_CACHE_ACCESSES = 8` per
/// [`external/randomx-v2/src/configuration.h:101`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Each call to [`Cache::derive_item`] (commit 3)
/// chains exactly `RANDOMX_CACHE_ACCESSES` SuperscalarHash transforms
/// over the indexed cache row per spec §7.3.
pub(crate) const RANDOMX_CACHE_ACCESSES: usize = 8;

/// Allocate a zeroed `Box<[Block]>` of the requested length.
///
/// # Why this exists
///
/// Phase 2c's first `#![deny(unsafe_code)]` carve-out per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §1 covenant 7 + §5.11.2: cache memory is allocated as
/// `Box<[Block]>` (fixed at construction; no `Vec`-style growth
/// surface) and zero-initialized before [`fill_cache`] overwrites
/// it. The carve-out is encapsulated in this single helper — one
/// function, one `unsafe` block, no other intrinsic calls or pointer
/// dereferences — so the audit surface is a single grep target and
/// a single review unit. The second carve-out lives in `vm.rs`
/// (commit 4) under the same discipline.
#[allow(unsafe_code)]
fn alloc_zeroed_cache_blocks(len: usize) -> Box<[Block]> {
    let uninit: Box<[MaybeUninit<Block>]> = Box::new_zeroed_slice(len);
    // SAFETY:
    // `argon2::Block` is defined as `pub struct Block([u64; Self::SIZE / 8])`
    // (verified at `argon2-0.5.3/src/block.rs:51`), a transparent wrapper over
    // `[u64; 128]` with no `repr(C)` divergence and no `Drop` impl. All-zeroes
    // is a valid bit pattern for `[u64; 128]` because zero is a valid `u64`.
    // `Box::new_zeroed_slice(len)` allocates `len` Block-sized regions and
    // zero-initializes them per its stabilized contract (Rust 1.82+; current
    // MSRV 1.85); converting `Box<[MaybeUninit<Block>]>` to `Box<[Block]>`
    // via `assume_init` is sound because the zero bit pattern is a valid
    // `Block` value. The length invariant is checked at the caller via the
    // `debug_assert_eq!` in [`Cache::derive`] per §5.11.2.
    unsafe { uninit.assume_init() }
}

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
/// The sole constructor is [`Cache::derive`] (commit 2 of the Phase
/// 2c implementation PR). The fields are intentionally private —
/// callers must go through `derive` rather than building a [`Cache`]
/// from a raw `Box<[Block]>` and a raw program list, which would
/// invite skipping the deterministic `argon2d::fill_cache` +
/// `superscalar::generate_superscalar` steps the verifier depends on.
///
/// # Public surface
///
/// [`Cache`] is the only `pub` item in this module per
/// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
/// §5.9 (R2-D3 visibility correction): `derive_item` and `item_bytes`
/// (commit 3) are `pub(crate)` — there is no FFI consumer for them at
/// Phase 2c, and exposing them now would create reviewer-attention
/// surface for properties no caller asserts. The test-only
/// `Cache::from_raw` was dropped at impl-time pre-flight per §14
/// Round 0 R0-D5; the T1' / T1 tests use the real [`Cache::derive`]
/// path (no test-only shortcut).
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
    /// Field is private; consumers go through [`Cache::derive`] (this
    /// commit) for construction. Read access from `derive_item`
    /// (commit 3) flows through `Cache::item_bytes` without exposing
    /// the buffer.
    #[allow(dead_code)]
    // CLIPPY: written by Cache::derive (commit 2); read by Cache::derive_item (commit 3).
    memory: Box<[Block]>,
    /// The [`RANDOMX_CACHE_ACCESSES`] (= 8) [`SuperscalarProgram`]s
    /// generated from `Blake2Generator::new(seedhash, 0)` per spec
    /// §7.2. Each `derive_item` call chains the 8 programs in sequence
    /// over the indexed cache row to produce the 64-byte dataset item.
    ///
    /// Stored as `Box<[SuperscalarProgram]>` (length 8 by
    /// construction) rather than `Box<[SuperscalarProgram; 8]>` to
    /// keep the inner type ergonomic for iteration; the length
    /// invariant is checked at construction via `debug_assert_eq!`
    /// per §5.11.2.
    #[allow(dead_code)]
    // CLIPPY: written by Cache::derive (commit 2); read by Cache::derive_item (commit 3).
    programs: Box<[SuperscalarProgram]>,
}

impl Cache {
    /// Derive a [`Cache`] from a 32-byte seedhash per spec §7.3.
    ///
    /// Performs the Argon2d-512 memory fill using `seedhash` as the
    /// key (delegated to `argon2d::fill_cache`), then generates the
    /// `RANDOMX_CACHE_ACCESSES` (= 8) `SuperscalarProgram`s that drive
    /// dataset-item derivation in `Cache::derive_item` (landed in
    /// commit 3 of the same Phase 2c implementation PR).
    ///
    /// # Determinism
    ///
    /// Output is a pure function of `seedhash`: the same input always
    /// produces a byte-identical [`Cache`]. The T1' property test in
    /// this file's `#[cfg(test)] mod tests` block asserts this across
    /// a single-thread loop, four concurrent threads, and an
    /// interleaved-seedhash pattern per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1. The T1 spec-vector test (commit 7) further asserts
    /// byte-equality against the C-reference generator output at pin
    /// `aaafe71`.
    ///
    /// # Cost
    ///
    /// Dominated by the 256-MiB Argon2d fill (~200 ms on a modern
    /// x86_64 per Phase 0 §8 budget; PR-gated by
    /// `benches/cache_derive.rs` per §5.8 / §8). Allocations: one
    /// 256-MiB `Box<[Block]>` for the cache memory + one 8-element
    /// `Box<[SuperscalarProgram]>` (~96 KiB) for the programs.
    pub fn derive(seedhash: &[u8; 32]) -> Cache {
        let mut memory = alloc_zeroed_cache_blocks(RANDOMX_ARGON_BLOCKS);

        debug_assert_eq!(
            memory.len(),
            RANDOMX_ARGON_BLOCKS,
            "Cache::derive cache-memory allocation invariant (per RANDOMX_V2_PHASE2C_PLAN.md §5.11.2): \
             `memory.len()` must equal `RANDOMX_ARGON_BLOCKS` ({RANDOMX_ARGON_BLOCKS} blocks = 256 MiB); \
             got {actual}",
            actual = memory.len(),
        );

        fill_cache(seedhash, &mut memory);

        let mut gen = Blake2Generator::new(seedhash, 0);
        let programs: Box<[SuperscalarProgram]> = (0..RANDOMX_CACHE_ACCESSES)
            .map(|_| generate_superscalar(&mut gen))
            .collect();

        debug_assert_eq!(
            programs.len(),
            RANDOMX_CACHE_ACCESSES,
            "Cache::derive program-count invariant (per spec §7.2): \
             `programs.len()` must equal `RANDOMX_CACHE_ACCESSES` ({RANDOMX_CACHE_ACCESSES}); \
             got {actual}",
            actual = programs.len(),
        );

        Cache { memory, programs }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SEEDHASH_A: [u8; 32] = [0x01; 32];
    const SEEDHASH_B: [u8; 32] = [0x02; 32];
    const SEEDHASH_C: [u8; 32] = [0x03; 32];

    /// Byte-equality between two `Cache` values.
    ///
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §14 Round 0 R0-D6 (tests-use-the-
    /// actual-API discipline): the comparison logic lives in test code
    /// using the existing `pub(crate)` field set + the existing
    /// `SuperscalarProgram::size` / `address_register` / `instructions`
    /// accessors. No `pub`-or-`pub(crate)` fingerprint method is added
    /// to [`Cache`] for test purposes; the production API stays
    /// minimal.
    fn caches_equal(a: &Cache, b: &Cache) -> bool {
        if a.memory.len() != b.memory.len() || a.programs.len() != b.programs.len() {
            return false;
        }
        for (x, y) in a.memory.iter().zip(b.memory.iter()) {
            if x.as_ref() != y.as_ref() {
                return false;
            }
        }
        for (px, py) in a.programs.iter().zip(b.programs.iter()) {
            if px.size() != py.size()
                || px.address_register() != py.address_register()
                || px.instructions() != py.instructions()
            {
                return false;
            }
        }
        true
    }

    /// T1' single-thread loop: 100 sequential `Cache::derive` calls on
    /// the same seedhash all produce byte-identical caches. Catches
    /// non-determinism in the derive path — uninitialized-state leak,
    /// allocator-dependent Argon2d ordering, PRNG-state leak across
    /// runs.
    ///
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.11.1 T1' sub-test 1/3.
    #[test]
    fn t1_prime_determinism_single_thread() {
        const ITERATIONS: usize = 100;
        let reference = Cache::derive(&SEEDHASH_A);
        for i in 1..ITERATIONS {
            let candidate = Cache::derive(&SEEDHASH_A);
            assert!(
                caches_equal(&reference, &candidate),
                "Cache::derive(SEEDHASH_A) produced divergent output on iteration {i}",
            );
        }
    }

    /// T1' concurrent threads: 4 threads each call `Cache::derive` 25
    /// times on the same seedhash; assert all 100 outputs match the
    /// single-threaded reference. Catches thread-local or shared-
    /// mutable state leak in the derive path.
    ///
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.11.1 T1' sub-test 2/3.
    #[test]
    fn t1_prime_determinism_concurrent() {
        const THREADS: usize = 4;
        const PER_THREAD: usize = 25;
        let reference = Cache::derive(&SEEDHASH_A);
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(THREADS);
            for _ in 0..THREADS {
                let reference = &reference;
                handles.push(s.spawn(move || {
                    for i in 0..PER_THREAD {
                        let candidate = Cache::derive(&SEEDHASH_A);
                        assert!(
                            caches_equal(reference, &candidate),
                            "Cache::derive(SEEDHASH_A) produced divergent output \
                             in concurrent-thread iteration {i}",
                        );
                    }
                }));
            }
            for h in handles {
                h.join().expect("T1' concurrent worker thread panicked");
            }
        });
    }

    /// T1' interleaved-seedhash: `derive(A)` / `derive(B)` /
    /// `derive(A)` / `derive(C)` / `derive(A)` — assert the three
    /// `derive(A)` outputs are byte-identical. Catches state leak
    /// across `derive(other_seedhash)` boundaries (e.g., a shared
    /// `Blake2Generator` instance, an allocator-scratch buffer not
    /// reset, etc.).
    ///
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.11.1 T1' sub-test 3/3.
    #[test]
    fn t1_prime_determinism_interleaved() {
        let reference_a = Cache::derive(&SEEDHASH_A);
        let _b = Cache::derive(&SEEDHASH_B);
        let candidate_a_1 = Cache::derive(&SEEDHASH_A);
        let _c = Cache::derive(&SEEDHASH_C);
        let candidate_a_2 = Cache::derive(&SEEDHASH_A);

        assert!(
            caches_equal(&reference_a, &candidate_a_1),
            "Cache::derive(SEEDHASH_A) drifted after derive(SEEDHASH_B)",
        );
        assert!(
            caches_equal(&reference_a, &candidate_a_2),
            "Cache::derive(SEEDHASH_A) drifted after derive(SEEDHASH_B) + derive(SEEDHASH_C)",
        );
    }
}
