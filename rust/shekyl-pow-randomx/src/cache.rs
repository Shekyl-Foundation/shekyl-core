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
//! landed across three Phase 2c implementation-PR commits:
//!
//! - **Commit 1** introduced the [`Cache`] struct + size constants
//!   ([`CACHE_SIZE`], [`DATASET_ITEM_SIZE`], [`DATASET_ITEM_COUNT`]) +
//!   empty [`Drop`] (review-surface hook per §5.11.4).
//! - **Commit 2** introduced [`Cache::derive`] + the
//!   [`RANDOMX_CACHE_ACCESSES`] constant + the cache-memory allocation
//!   carve-out + the `programs` field on [`Cache`] + cache-site
//!   `debug_assert!`s per §5.11.2 + the T1' determinism property test
//!   (`#[cfg(test)] mod tests` per §14 Round 0 R0-D6). The T1
//!   spec-vector test was deferred to commit 7 alongside the F6
//!   generator that produces its fixture; `Cache::from_raw` was
//!   dropped at impl-time pre-flight per §14 Round 0 R0-D5.
//! - **Commit 3** introduced `pub(crate) Cache::derive_item` +
//!   `pub(crate) Cache::item_bytes` + the dataset-item spec constants
//!   ([`SUPERSCALAR_MUL_0`], [`SUPERSCALAR_ADD_1`]..[`SUPERSCALAR_ADD_7`]) +
//!   the T2' invariance property test. It also dissolved the
//!   `#[allow(dead_code)]` on `superscalar::execute_superscalar` (this
//!   is the production caller per spec §7.3 step 5). The planned
//!   promotion of `superscalar::randomx_reciprocal` to `pub(crate)`
//!   was withdrawn at impl-time pre-flight per §14 Round 0 R0-D7 —
//!   `cache.rs::derive_item` consumes the reciprocal value
//!   transitively via `execute_superscalar`'s `IMUL_RCP` arm
//!   (`superscalar.rs:1463`), not by direct call. The T2 spec-vector
//!   test was deferred to commit 7 alongside the F6 generator that
//!   produces its fixture.
//! - **Commit 7** added the T1 / T2 spec-vector tests
//!   (`tests` module) and the F6 generator fixtures they consume;
//!   the R0-D11 storage-divergence finding (`SuperscalarProgram`
//!   `IMUL_RCP::imm32` is the raw post-`AesGenerator1R` byte in the
//!   Rust port and the reciprocal-cache index in the C reference) is
//!   resolved in the generator, not here.
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
use crate::superscalar::{execute_superscalar, generate_superscalar, SuperscalarProgram};

/// Number of [`SuperscalarProgram`]s generated per [`Cache`].
///
/// `RANDOMX_CACHE_ACCESSES = 8` per
/// [`external/randomx-v2/src/configuration.h:44`](../../../external/randomx-v2/src/configuration.h)
/// at pin `aaafe71`. Each call to [`Cache::derive_item`] chains
/// exactly `RANDOMX_CACHE_ACCESSES` SuperscalarHash transforms over
/// the indexed cache row per spec §7.3.
pub(crate) const RANDOMX_CACHE_ACCESSES: usize = 8;

/// Spec constants for [`Cache::derive_item`]'s register seed per
/// spec §7.3 step 2 and
/// [`external/randomx-v2/src/dataset.cpp:150-157`](../../../external/randomx-v2/src/dataset.cpp)
/// at pin `aaafe71`. The C reference defines these as `constexpr`
/// `superscalarMul0` / `superscalarAdd1`..`superscalarAdd7` inside
/// the anonymous namespace surrounding `initDatasetItem`; this
/// module mirrors them as `const` with the `SUPERSCALAR_MUL_0` /
/// `SUPERSCALAR_ADD_N` shape per Rust naming conventions. Used
/// only by [`Cache::derive_item`].
pub(crate) const SUPERSCALAR_MUL_0: u64 = 6_364_136_223_846_793_005;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_1: u64 = 9_298_411_001_130_361_340;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_2: u64 = 12_065_312_585_734_608_966;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_3: u64 = 9_306_329_213_124_626_780;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_4: u64 = 5_281_919_268_842_080_866;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_5: u64 = 10_536_153_434_571_861_004;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_6: u64 = 3_398_623_926_847_679_864;
/// See [`SUPERSCALAR_MUL_0`].
pub(crate) const SUPERSCALAR_ADD_7: u64 = 9_549_104_520_008_361_294;

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
pub(crate) const CACHE_SIZE: usize = RANDOMX_ARGON_BLOCKS * Block::SIZE;

/// Per-item dataset-read width in bytes.
///
/// `RANDOMX_DATASET_ITEM_SIZE = 64` per
/// [`external/randomx-v2/src/randomx.h:36`](../../../external/randomx-v2/src/randomx.h)
/// at pin `aaafe71`. Each iteration of the spec §4.5.4 execution loop
/// reads exactly this many bytes from the cache (8 native-endian
/// 64-bit registers serialized after 8 chained SuperscalarHash
/// transforms per spec §7.3). Becomes the return-array length of
/// [`Cache::derive_item`] and [`Cache::item_bytes`].
pub(crate) const DATASET_ITEM_SIZE: usize = 64;

/// Number of cache-line-sized addressable items in the cache.
///
/// `CacheSize / CacheLineSize = 268_435_456 / 64 = 4_194_304` per
/// [`external/randomx-v2/src/common.hpp:85,
/// :88`](../../../external/randomx-v2/src/common.hpp) at pin
/// `aaafe71`. This is the modulus the C reference's `getMixBlock`
/// applies to the u64 register value before computing the cache-line
/// offset (`mask = CacheSize / CacheLineSize - 1` at
/// `dataset.cpp:160`). The constant is a power of two by spec
/// construction (asserted at compile time below), which lets
/// [`Cache::item_bytes`] reduce the modulus to a bitwise `& MASK`.
/// Distinct from the full RandomX dataset size — `Cache::derive_item`
/// accepts any `u64` `item_number` and the cache-line addressing is
/// performed internally on each iteration; no caller-side range
/// check is required.
pub(crate) const DATASET_ITEM_COUNT: usize = CACHE_SIZE / DATASET_ITEM_SIZE;

const _: () = assert!(
    DATASET_ITEM_COUNT.is_power_of_two(),
    "DATASET_ITEM_COUNT must be a power of two so item_bytes can mask with (DATASET_ITEM_COUNT - 1)",
);

/// RandomX v2 Cache — 256 MiB of Argon2d-derived memory consumed by
/// `compute_hash` via the per-iteration dataset-item read in the spec
/// §4.5.4 execution loop.
///
/// # Public construction path: [`crate::PreparedCache`]
///
/// [`Cache`] is `pub(crate)` per
/// [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
/// §1.1 Round 2 substrate correction. The public construction
/// path is [`crate::PreparedCache::derive`], which bundles the
/// derived `Cache` with the [`crate::Seedhash`] it was derived
/// from at the type level. Exposing `Cache` publicly would let
/// callers construct it without the seedhash binding and
/// reintroduce the consensus-correctness footgun the bundling
/// prevents (a caller passing the wrong cache for a given
/// seedhash gets a wrong hash, which the network rejects).
/// Test access is preserved via the
/// `src/*.rs#mod tests` discipline (Phase 2c R0-D6); test code in
/// the same crate sees `pub(crate)` items unchanged.
///
/// # In-crate construction
///
/// The sole constructor is [`Cache::derive`]. The fields are
/// intentionally private — callers must go through `derive`
/// rather than building a [`Cache`] from a raw `Box<[Block]>` and
/// a raw program list, which would invite skipping the
/// deterministic `argon2d::fill_cache` +
/// `superscalar::generate_superscalar` steps the verifier depends
/// on.
///
/// # In-crate accessors
///
/// `Cache::derive_item` and `Cache::item_bytes` are `pub(crate)`
/// — there is no FFI consumer for them at Phase 2c/2f, and
/// exposing them would create reviewer-attention surface for
/// properties no caller asserts. The test-only `Cache::from_raw`
/// was dropped at impl-time pre-flight per Phase 2c §14 Round 0
/// R0-D5; the T1' / T2' / T1 / T2 tests use the real
/// [`Cache::derive`] / `Cache::derive_item` paths (no test-only
/// shortcut).
///
/// # Threat-model disposition
///
/// See the module-level docstring for the public-input-only
/// disposition that drives the empty [`Drop`] implementation below.
pub(crate) struct Cache {
    /// `RANDOMX_ARGON_BLOCKS` (262_144) [`argon2::Block`]s of 1024
    /// bytes each, totaling [`CACHE_SIZE`] (256 MiB). Allocated as
    /// `Box<[Block]>` so the size is fixed at construction (no
    /// `Vec`-style growth surface) and the resulting `Cache` value is
    /// `Send + Sync`-safe for the eventual Phase 2f `CacheStore`
    /// `Arc<Cache>` shape.
    ///
    /// Field is private; consumers go through [`Cache::derive`] for
    /// construction. Read access from [`Cache::derive_item`] flows
    /// through [`Cache::item_bytes`] without exposing the buffer.
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
    /// Dominated by the 256-MiB Argon2d fill. Phase 0 §8 scoped the
    /// budget at ~200 ms on a modern x86_64; the Phase 2c empirical
    /// baseline on the reference machine (i9-11950H, Debian 13) is
    /// **~341 ms median** per `BENCH_RESULTS.md`. Measured by
    /// `benches/cache_derive.rs` as an informational baseline (not a
    /// PR gate at Phase 2c); the budget-vs-measurement reconciliation
    /// is tracked at
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §14 R0-D12. Allocations: one 256-MiB `Box<[Block]>` for the
    /// cache memory + one 8-element `Box<[SuperscalarProgram]>`
    /// (~32 KiB: 8 × ~4 KiB per program per `src/superscalar.rs`
    /// module rustdoc — `512 × 8`-byte instructions + ~16 bytes of
    /// meta per program) for the programs.
    ///
    /// # Visibility
    ///
    /// `pub(crate)` per
    /// [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
    /// §1.1 Round 2. The public construction path is
    /// [`crate::PreparedCache::derive`], which calls this
    /// primitive and bundles the result with the input
    /// [`crate::Seedhash`]. The signature takes `&Seedhash`
    /// rather than `&[u8; 32]` so the type system enforces the
    /// "this byte array is a seedhash, not an output hash"
    /// distinction at every internal call site as well.
    pub(crate) fn derive(seedhash: &crate::Seedhash) -> Cache {
        let bytes = seedhash.as_bytes();
        let mut memory = alloc_zeroed_cache_blocks(RANDOMX_ARGON_BLOCKS);

        debug_assert_eq!(
            memory.len(),
            RANDOMX_ARGON_BLOCKS,
            "Cache::derive cache-memory allocation invariant (per RANDOMX_V2_PHASE2C_PLAN.md §5.11.2): \
             `memory.len()` must equal `RANDOMX_ARGON_BLOCKS` ({RANDOMX_ARGON_BLOCKS} blocks = 256 MiB); \
             got {actual}",
            actual = memory.len(),
        );

        fill_cache(bytes, &mut memory);

        let mut gen = Blake2Generator::new(bytes, 0);
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

    /// Read the 64-byte cache row addressed by `item_number` per
    /// `external/randomx-v2/src/dataset.cpp:159-162 getMixBlock` at
    /// pin `aaafe71`.
    ///
    /// `item_number` is masked to the low `log2(DATASET_ITEM_COUNT)`
    /// bits before addressing (matching the C reference's
    /// `mask = CacheSize / CacheLineSize - 1` modulus), so any `u64`
    /// is accepted — callers are not required to range-check.
    ///
    /// # Layout
    ///
    /// The cache memory is `RANDOMX_ARGON_BLOCKS` (262_144) of
    /// `argon2::Block` (1 KiB each), giving 256 MiB of contiguous
    /// storage organized as `128 × u64` words per block. Each
    /// 64-byte cache line spans 8 contiguous u64 words within a
    /// single block — there are exactly 16 cache lines per block
    /// (`1024 / 64 = 16`), and no line straddles a block boundary.
    /// Returned bytes are the little-endian serialization of those
    /// 8 words, matching the C reference's `load64_native` reads on
    /// little-endian targets and remaining correct on big-endian
    /// targets per the LE convention applied uniformly across the
    /// crate (see `argon2d::tests::blocks_to_le_bytes` for the
    /// established precedent at `argon2d.rs:237`).
    pub(crate) fn item_bytes(&self, item_number: u64) -> [u8; DATASET_ITEM_SIZE] {
        // Mask first as u64 (loses no information; the mask is
        // `DATASET_ITEM_COUNT - 1 = 0x3F_FFFF`, 22 bits), then go
        // u64 → usize via try_from. The try_from is infallible by
        // construction: Rust guarantees `usize >= 16 bits` (and on
        // all Shekyl target platforms `usize >= 32 bits`), and the
        // masked value fits in 22 bits, so it fits in any `usize`
        // the toolchain may produce. The `expect` is a contract
        // assertion against future mask widening, not a runtime
        // possibility under the current mask. This matches the C
        // reference's `getMixBlock` index computation
        // (`(registerValue & mask) / CacheLineSize`, where the mask
        // is the truncation-defining operation; see
        // `external/randomx-v2/src/dataset.cpp:160`) — the cast is
        // a lossless conversion of the already-narrowed value, not
        // a u64 → u32 truncation.
        let masked = item_number & (DATASET_ITEM_COUNT as u64 - 1);
        let line_idx = usize::try_from(masked).expect(
            "(item_number & (DATASET_ITEM_COUNT - 1)) fits in usize by mask construction (22 bits, fits in any Rust-conformant usize >= 16 bits)",
        );
        // Each 1-KiB Block holds 16 cache lines (1024 / 64 = 16) and
        // 128 u64 words (1024 / 8 = 128); 1 cache line = 8 u64 words.
        let block_idx = line_idx >> 4;
        let word_offset = (line_idx & 0xF) << 3;
        let words = &self.memory[block_idx].as_ref()[word_offset..word_offset + 8];

        let mut out = [0u8; DATASET_ITEM_SIZE];
        for (chunk, &word) in out.chunks_exact_mut(8).zip(words.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Derive the 64-byte dataset item at index `item_number` per
    /// spec §7.3 and
    /// `external/randomx-v2/src/dataset.cpp:164-190 initDatasetItem`
    /// at pin `aaafe71`.
    ///
    /// Computes the initial 8-register state from `item_number`
    /// using the [`SUPERSCALAR_MUL_0`] / [`SUPERSCALAR_ADD_1`] ..
    /// [`SUPERSCALAR_ADD_7`] spec constants, then iterates
    /// [`RANDOMX_CACHE_ACCESSES`] (= 8) times:
    ///
    /// 1. Read the cache row addressed by the running register value
    ///    (via [`Cache::item_bytes`]).
    /// 2. Execute `self.programs[i]` over the register array (via
    ///    [`execute_superscalar`]).
    /// 3. XOR the 8 register words with the 8 little-endian-decoded
    ///    cache-row words.
    /// 4. Update the running register value to the program's
    ///    address-register output.
    ///
    /// Returns the little-endian serialization of the final 8-register
    /// state (matching the C reference's `memcpy(out, &rl, 64)` on
    /// little-endian targets; the LE convention is uniform across the
    /// crate per [`Cache::item_bytes`]'s rationale).
    ///
    /// # Reciprocal computation
    ///
    /// The C reference's per-program `executeSuperscalar(rl, prog,
    /// &cache->reciprocalCache)` passes a precomputed
    /// `reciprocalCache` to amortize `IMUL_RCP` reciprocals across
    /// dataset items. The Rust port computes reciprocals on-the-fly
    /// inside [`execute_superscalar`]'s `IMUL_RCP` arm (per the
    /// `superscalar::execute_superscalar` doc-comment; see
    /// `superscalar.rs:1418-1424`); no separate `reciprocalCache`
    /// field exists on [`Cache`] per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.4 ("the Rust port is simpler than C") and §14 Round 0 R0-D7
    /// (the planned promotion of `randomx_reciprocal` to `pub(crate)`
    /// was withdrawn because no direct caller exists in `cache.rs`).
    ///
    /// # Determinism
    ///
    /// Output is a pure function of `(self, item_number)`: every call
    /// with the same arguments returns byte-identical output. The T2'
    /// property test in this file's `#[cfg(test)] mod tests` block
    /// asserts this across interleaved invocations on a shared
    /// [`Cache`] per
    /// [`RANDOMX_V2_PHASE2C_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
    /// §5.11.1. The T2 spec-vector test (commit 7) further asserts
    /// byte-equality against the C-reference generator output at
    /// pin `aaafe71` for the 8-input set `{0, 1, 1023, 1024, 524_287,
    /// 524_288, 2_097_150, 2_097_151}` per §5.6.
    ///
    /// # Production caller
    ///
    /// The sole production caller is `vm::VmState::dataset_read`
    /// (`vm.rs::dataset_read` at line 1427 calls `cache.derive_item`
    /// per spec §7.3 step 5; reachable from the public [`compute_hash`]
    /// transform via `VmState::execute_program`). The entire transitive
    /// chain reached from this function — [`item_bytes`](Cache::item_bytes),
    /// `execute_superscalar` and its internal helpers
    /// (`sign_extend_2s_compl` / `mulh` / `smulh` / `smulh_u64` /
    /// `randomx_reciprocal`), `SuperscalarInstructionType::from_opcode`,
    /// `Instruction::mod_shift`, the eight `SUPERSCALAR_*` spec
    /// constants, the `memory` / `programs` field reads, and the
    /// `CACHE_SIZE` / `DATASET_ITEM_SIZE` / `DATASET_ITEM_COUNT`
    /// constant reads — is reachable-from-`pub` by the same chain;
    /// no `#[allow(dead_code)]` is needed (and adding one would mask
    /// genuine dead-code regressions in the chain).
    pub(crate) fn derive_item(&self, item_number: u64) -> [u8; DATASET_ITEM_SIZE] {
        let mut register_value: u64 = item_number;
        let r0 = item_number.wrapping_add(1).wrapping_mul(SUPERSCALAR_MUL_0);
        let mut rl: [u64; 8] = [
            r0,
            r0 ^ SUPERSCALAR_ADD_1,
            r0 ^ SUPERSCALAR_ADD_2,
            r0 ^ SUPERSCALAR_ADD_3,
            r0 ^ SUPERSCALAR_ADD_4,
            r0 ^ SUPERSCALAR_ADD_5,
            r0 ^ SUPERSCALAR_ADD_6,
            r0 ^ SUPERSCALAR_ADD_7,
        ];

        debug_assert_eq!(
            self.programs.len(),
            RANDOMX_CACHE_ACCESSES,
            "Cache::derive_item program-count invariant (per spec §7.2 + §5.11.2): \
             `self.programs.len()` must equal `RANDOMX_CACHE_ACCESSES` ({RANDOMX_CACHE_ACCESSES}); \
             got {actual}",
            actual = self.programs.len(),
        );

        for program in &self.programs {
            let mix = self.item_bytes(register_value);
            execute_superscalar(program, &mut rl);
            for (reg, chunk) in rl.iter_mut().zip(mix.chunks_exact(8)) {
                let bytes: [u8; 8] = chunk
                    .try_into()
                    .expect("chunks_exact(8) yields [u8; 8] by construction");
                *reg ^= u64::from_le_bytes(bytes);
            }
            let addr = usize::from(program.address_register());
            debug_assert!(
                addr < 8,
                "SuperscalarProgram::address_register must be in 0..8 by generate_superscalar \
                 construction (asserted at superscalar.rs:1644); got {addr}",
            );
            register_value = rl[addr];
        }

        let mut out = [0u8; DATASET_ITEM_SIZE];
        for (chunk, &word) in out.chunks_exact_mut(8).zip(rl.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Stream the Argon2d-derived cache memory as little-endian
    /// 1-KiB block chunks, one per [`argon2::Block`].
    ///
    /// Used exclusively by
    /// [`crate::PreparedCache::cache_block_bytes_for_testing`] (the
    /// `test-internals`-feature-gated public accessor), which the
    /// Phase 2g Rust/C differential harness consumes for the R1-D14
    /// SHA-256 cache-equivalence precondition. See the corresponding
    /// `PreparedCache` rustdoc for the full visitor-shape rationale
    /// (avoiding the `&[Block]` → `&[u8]` reinterpretation that
    /// would require either `unsafe_code`, a 256-MiB heap
    /// materialization, or a new workspace dependency).
    ///
    /// `pub(crate)` per the §5.3.1 "no new production surfaces"
    /// discipline. Gated on the same `test-internals` feature as
    /// the public [`PreparedCache::cache_block_bytes_for_testing`]
    /// accessor so the default-features build (no production
    /// consumer) does not flag the helper as dead code under the
    /// crate's `#[warn(dead_code)]` default lint.
    ///
    /// # Layout
    ///
    /// Each yielded `[u8; 1024]` is the little-endian byte
    /// serialization of one `argon2::Block`'s `[u64; 128]` words,
    /// matching the C reference's `load64_native` reads on
    /// little-endian targets and remaining correct on big-endian
    /// targets per the LE convention applied uniformly across the
    /// crate (see [`Cache::item_bytes`] rationale + the
    /// `argon2d::tests::blocks_to_le_bytes` precedent at
    /// `argon2d.rs:237`).
    ///
    /// # Memory budget
    ///
    /// Iterator yields owned 1-KiB arrays by value; per-iteration
    /// stack cost is 1 KiB and no heap allocation is performed.
    /// The R1-D14 drop-discipline memory budget (~256 MiB peak per
    /// seedhash) is preserved: the harness's SHA-256 streaming
    /// consumer holds at most one chunk at a time.
    ///
    /// # Programs field excluded
    ///
    /// The eight `SuperscalarProgram`s stored alongside the memory
    /// are *not* yielded. The R1-D14 precondition compares against
    /// the C reference's `randomx_get_cache_memory(cache)` return,
    /// which exposes only the Argon2d-derived `memory` buffer (not
    /// the C-side `reciprocalCache` or any program representation).
    /// The cache-derive determinism property (T1' in this file's
    /// `#[cfg(test)] mod tests` block) covers the program side
    /// in-crate; the R1-D14 precondition covers the Argon2d-fill
    /// side cross-implementation. See
    /// [`RANDOMX_V2_PHASE2G_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
    /// §3.17 R5-D1 for the full disposition.
    #[cfg(feature = "test-internals")]
    pub(crate) fn block_bytes_le(&self) -> impl Iterator<Item = [u8; 1024]> + '_ {
        self.memory.iter().map(|block| {
            let mut buf = [0u8; 1024];
            for (chunk, &word) in buf.chunks_exact_mut(8).zip(block.as_ref()) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            buf
        })
    }

    /// Construct a [`Cache`] from `(seedhash, cache_bytes)`,
    /// bypassing Argon2d while still re-deriving the eight
    /// [`SuperscalarProgram`]s from `seedhash`.
    ///
    /// **TEST-INFRASTRUCTURE ONLY.** This is the in-crate
    /// implementation that backs
    /// [`crate::PreparedCache::from_raw_for_testing`]; production
    /// callers MUST go through [`Cache::derive`] /
    /// [`crate::PreparedCache::derive`], which performs the full
    /// Argon2d-512 fill required by the spec. Production-equivalence
    /// for this constructor's `(seedhash, cache_bytes)` pair is
    /// discussed at the [`crate::PreparedCache::from_raw_for_testing`]
    /// rustdoc (the Phase 2h Round 2 R2-D2 / T-A14 cite anchor for
    /// `*_for_testing` accessors).
    ///
    /// # Behavior
    ///
    /// - `programs`: re-derived from `seedhash` via
    ///   [`Blake2Generator`] + [`generate_superscalar`] — identical
    ///   to [`Cache::derive`]'s second half, so the program-side
    ///   determinism is byte-identical to a production-derived
    ///   cache for the same seedhash.
    /// - `memory`: deserialized from `cache_bytes` (256 MiB of
    ///   little-endian `u64` words per the
    ///   [`Cache::block_bytes_le`] inverse), bypassing Argon2d.
    ///   The recipe evaluator at
    ///   `shekyl-randomx-differential::adversarial::interpreter`
    ///   supplies the bytes — typically derived from a base
    ///   seedhash's C-reference cache output with targeted
    ///   modifications applied per the recipe specification per
    ///   Phase 2h R1-D3 close.
    ///
    /// # Length contract
    ///
    /// `cache_bytes.len()` must equal [`CACHE_SIZE`] (256 MiB =
    /// 268_435_456 bytes). The function panics on mismatch with a
    /// diagnostic message — this is test infra, not production;
    /// length-mismatch is a test-author bug and `Result` plumbing
    /// at every recipe call site would obscure the bug class
    /// without preventing it.
    ///
    /// # Visibility
    ///
    /// `pub(crate)` per the §5.3.1 "no new production surfaces"
    /// discipline. The public test-internals accessor is
    /// [`crate::PreparedCache::from_raw_for_testing`].
    #[cfg(feature = "test-internals")]
    pub(crate) fn from_raw_for_testing(seedhash: &crate::Seedhash, cache_bytes: &[u8]) -> Cache {
        assert_eq!(
            cache_bytes.len(),
            CACHE_SIZE,
            "Cache::from_raw_for_testing: `cache_bytes.len()` must equal CACHE_SIZE \
             ({CACHE_SIZE} bytes = 256 MiB); got {actual} bytes. This is a test-author \
             bug — recipes' evaluator must supply exactly CACHE_SIZE bytes of \
             little-endian cache memory.",
            actual = cache_bytes.len(),
        );

        // Deserialize cache_bytes into Box<[Block]>. Each Block is
        // [u64; 128] = 1024 bytes; the byte stream is little-endian
        // u64 words per the LE convention applied uniformly across
        // the crate (matches Cache::block_bytes_le's inverse and the
        // C reference's load64_native reads on little-endian targets).
        // No unsafe required: we allocate Box<[Block]> via the same
        // alloc_zeroed_cache_blocks helper used by Cache::derive
        // (which encapsulates the single Phase 2c unsafe-code carve-
        // out per §1 covenant 7), then overwrite each block's u64
        // words from the bytes.
        let mut memory = alloc_zeroed_cache_blocks(RANDOMX_ARGON_BLOCKS);
        for (block_idx, block_chunk) in cache_bytes.chunks_exact(Block::SIZE).enumerate() {
            // chunks_exact yields exactly RANDOMX_ARGON_BLOCKS chunks
            // by the length assertion above; the .as_mut() conversion
            // is the inverse of block.as_ref() used in block_bytes_le.
            let block_words: &mut [u64] = memory[block_idx].as_mut();
            for (word_slot, word_bytes) in block_words.iter_mut().zip(block_chunk.chunks_exact(8)) {
                // u64::from_le_bytes requires a &[u8; 8]; chunks_exact(8)
                // yields &[u8] of length 8 which must be try_into'd to
                // an array reference. The try_into is infallible by
                // chunks_exact's contract; the expect is contract
                // assertion for future refactor-time safety.
                let array_ref: &[u8; 8] = word_bytes
                    .try_into()
                    .expect("chunks_exact(8) yields slices of length exactly 8 by construction");
                *word_slot = u64::from_le_bytes(*array_ref);
            }
        }

        // Re-derive programs from seedhash identically to Cache::derive
        // (same Blake2Generator seed; same generate_superscalar loop;
        // same RANDOMX_CACHE_ACCESSES count). The recipe evaluator's
        // (seedhash, cache_bytes) pair carries the base seedhash whose
        // programs determine spec-faithful dataset-item derivation;
        // the cache_bytes carry the (possibly modified) cache memory.
        let bytes = seedhash.as_bytes();
        let mut gen = Blake2Generator::new(bytes, 0);
        let programs: Box<[SuperscalarProgram]> = (0..RANDOMX_CACHE_ACCESSES)
            .map(|_| generate_superscalar(&mut gen))
            .collect();

        debug_assert_eq!(
            programs.len(),
            RANDOMX_CACHE_ACCESSES,
            "Cache::from_raw_for_testing program-count invariant: \
             `programs.len()` must equal `RANDOMX_CACHE_ACCESSES` \
             ({RANDOMX_CACHE_ACCESSES}); got {actual}",
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
    use crate::Seedhash;

    /// Test seedhash A — all-`0x01` bytes wrapped in [`Seedhash`]
    /// per Phase 2F §1.1 Round 2 Seedhash-newtype sweep.
    fn seedhash_a() -> Seedhash {
        Seedhash::from_bytes([0x01; 32])
    }

    /// Test seedhash B — all-`0x02` bytes wrapped in [`Seedhash`]
    /// per Phase 2F §1.1 Round 2.
    fn seedhash_b() -> Seedhash {
        Seedhash::from_bytes([0x02; 32])
    }

    /// Test seedhash C — all-`0x03` bytes wrapped in [`Seedhash`]
    /// per Phase 2F §1.1 Round 2.
    fn seedhash_c() -> Seedhash {
        Seedhash::from_bytes([0x03; 32])
    }

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
        let a = seedhash_a();
        let reference = Cache::derive(&a);
        for i in 1..ITERATIONS {
            let candidate = Cache::derive(&a);
            assert!(
                caches_equal(&reference, &candidate),
                "Cache::derive(seedhash_a) produced divergent output on iteration {i}",
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
        let a = seedhash_a();
        let reference = Cache::derive(&a);
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(THREADS);
            for _ in 0..THREADS {
                let reference = &reference;
                handles.push(s.spawn(move || {
                    for i in 0..PER_THREAD {
                        let candidate = Cache::derive(&a);
                        assert!(
                            caches_equal(reference, &candidate),
                            "Cache::derive(seedhash_a) produced divergent output \
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
        let a = seedhash_a();
        let b = seedhash_b();
        let c = seedhash_c();
        let reference_a = Cache::derive(&a);
        let _b = Cache::derive(&b);
        let candidate_a_1 = Cache::derive(&a);
        let _c = Cache::derive(&c);
        let candidate_a_2 = Cache::derive(&a);

        assert!(
            caches_equal(&reference_a, &candidate_a_1),
            "Cache::derive(seedhash_a) drifted after derive(seedhash_b)",
        );
        assert!(
            caches_equal(&reference_a, &candidate_a_2),
            "Cache::derive(seedhash_a) drifted after derive(seedhash_b) + derive(seedhash_c)",
        );
    }

    /// T2' invariance property test for `Cache::derive_item`.
    ///
    /// Derives one `Cache` (shared across all sub-assertions in this
    /// single `#[test]`); records the reference output for each of T2's
    /// 8 item_numbers; then for 10 repetitions, calls
    /// `cache.derive_item(neighbor)` to perturb any hypothetical hidden
    /// state, calls `cache.derive_item(n)` again, and asserts the
    /// output is byte-identical to the reference. Catches cross-call
    /// state pollution inside `derive_item` (e.g., a `&mut [u64; 8]`
    /// register buffer reused without reset, or any interior-mutability
    /// state added in a future refactor).
    ///
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.11.1 T2'a.
    ///
    /// Fixture-free per §14 Round 0 R0-D7 pre-flight pin 7: the
    /// commit-3 version of T2' asserts byte-identity across runs only.
    /// The companion T2 spec-vector test (commit 7) asserts byte-
    /// equality against the C-reference generator output for the same
    /// 8-input set.
    #[test]
    fn t2_prime_invariance_interleaved() {
        const ITEM_NUMBERS: [u64; 8] = [0, 1, 1023, 1024, 524_287, 524_288, 2_097_150, 2_097_151];
        const REPETITIONS: usize = 10;

        let cache = Cache::derive(&seedhash_a());
        let reference: [[u8; DATASET_ITEM_SIZE]; ITEM_NUMBERS.len()] =
            ITEM_NUMBERS.map(|n| cache.derive_item(n));

        for rep in 0..REPETITIONS {
            for (idx, &n) in ITEM_NUMBERS.iter().enumerate() {
                let neighbor = ITEM_NUMBERS[(idx + rep + 1) % ITEM_NUMBERS.len()];
                let _ = cache.derive_item(neighbor);
                let actual = cache.derive_item(n);
                assert_eq!(
                    actual, reference[idx],
                    "Cache::derive_item({n}) drifted at rep {rep} \
                     after derive_item({neighbor})",
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // T1 + T2 spec-vector tests (Phase 2c §5.7 / F7 T1, T2; §9 commit 7).
    //
    // Both vectors were generated by
    // `tests/vectors/reference/_generator/phase2c/gen.cpp` against the
    // v2 RandomX fork at pin
    // `aaafe71322df6602c21a5c72937ac284724ae561` (v2.0.1). The
    // committed `.bin` bytes are bootstrap vectors until Phase 2g
    // lands the live differential harness; see the sibling
    // `.meta.txt` files for per-vector provenance and the Phase 2c
    // generator README for the cross-vector substrate provenance.
    // -----------------------------------------------------------------

    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    /// 32-byte canonical T1/T2/T8 seedhash bytes. Sequential
    /// 0x01..=0x20 bytes; matches `CANONICAL_SEEDHASH` in the
    /// Phase 2c generator (`_generator/phase2c/gen.cpp`). Wrapped
    /// in [`Seedhash`] at the call site via [`canonical_seedhash`].
    const CANONICAL_SEEDHASH_BYTES: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    /// Canonical seedhash as a [`Seedhash`] value for the T1/T2/T8
    /// spec-vector tests. Helper rather than `const` because
    /// [`Seedhash::from_bytes`] is not (yet) `const fn`.
    fn canonical_seedhash() -> Seedhash {
        Seedhash::from_bytes(CANONICAL_SEEDHASH_BYTES)
    }

    /// Feed a single 1 KiB Argon2 cache block into a Blake2b hasher
    /// as 128 little-endian u64 words. Matches the C generator's
    /// `blake2b_update(&st, cache->memory, CacheSize)` call, which
    /// reads the underlying argon2 block bytes verbatim — on the
    /// little-endian targets the Phase 2c plan pins
    /// (`RANDOMX_V2_PHASE2C_PLAN.md` §5.7 portability statement), the
    /// C fork's `block` is also `[u64; 128]` and stores each word
    /// little-endian in memory. The explicit `to_le_bytes` loop
    /// produces the same byte sequence on any host and keeps the
    /// fingerprint reproducible on big-endian audit hosts.
    fn update_blake2b_with_block(hasher: &mut Blake2bVar, block: &Block) {
        for &word in block.as_ref() {
            hasher.update(&word.to_le_bytes());
        }
    }

    /// Feed one SuperscalarProgram into a Blake2b hasher in the wire
    /// format the C generator uses (magic "SSP1", size u16 LE,
    /// address_register u8, reserved u8 = 0, then `size` × 8 bytes
    /// per instruction).
    ///
    /// Mirrors `emit_ss_program_into_blake2b` in
    /// `_generator/phase2c/gen.cpp`. The wire format is documented
    /// in the T1 `.meta.txt` and in the Phase 2c generator README's
    /// "Wire formats" section.
    fn update_blake2b_with_ss_program(hasher: &mut Blake2bVar, prog: &SuperscalarProgram) {
        hasher.update(b"SSP1");

        let size = u16::try_from(prog.size())
            .expect("SuperscalarProgram::size fits in u16 by SUPERSCALAR_MAX_SIZE = 512 invariant");
        hasher.update(&size.to_le_bytes());

        hasher.update(&[prog.address_register()]);
        hasher.update(&[0u8]);

        for instr in prog.instructions() {
            hasher.update(&[instr.opcode, instr.dst, instr.src, instr.mod_]);
            hasher.update(&instr.imm32.to_le_bytes());
        }
    }

    /// T1 spec-vector test: Blake2b-256 over (cache.memory ‖
    /// 8 serialized SuperscalarPrograms) for the canonical seedhash
    /// matches the v2 RandomX fork's byte-for-byte output at pin
    /// `aaafe71`.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/cache/t1_cache_derive_fingerprint.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T1, §9 commit 7.
    #[test]
    fn t1_cache_derive_fingerprint_matches_fork_reference() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/cache/t1_cache_derive_fingerprint.bin");
        assert_eq!(expected.len(), 32, "t1 .bin size invariant");

        let cache = Cache::derive(&canonical_seedhash());
        debug_assert_eq!(cache.memory.len(), RANDOMX_ARGON_BLOCKS);
        debug_assert_eq!(cache.programs.len(), RANDOMX_CACHE_ACCESSES);

        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) accepts 32-byte output");
        for block in &*cache.memory {
            update_blake2b_with_block(&mut hasher, block);
        }
        for prog in &*cache.programs {
            update_blake2b_with_ss_program(&mut hasher, prog);
        }

        let mut actual = [0u8; 32];
        hasher
            .finalize_variable(&mut actual)
            .expect("Blake2bVar finalize succeeds for 32-byte buffer");

        assert_eq!(
            actual,
            <[u8; 32]>::try_from(expected).expect("32-byte vector"),
            "Cache::derive fingerprint diverged from fork pin aaafe71 reference",
        );
    }

    /// T2 spec-vector test: 8 × 64-byte dataset items at the canonical
    /// boundary indices match the v2 RandomX fork's `initDatasetItem`
    /// output byte-for-byte at pin `aaafe71`.
    ///
    /// The 8 indices cover lowest-input (0, 1), 10-bit transition
    /// (1023, 1024), the `DATASET_EXTRA_ITEMS` spec boundary
    /// (524287 = `DATASET_EXTRA_ITEMS` itself / 524288 = one past),
    /// and a 21-bit-magnitude sample (2097150, 2097151 — additional
    /// high-magnitude sample points, NOT a spec boundary). See the
    /// T2 `.meta.txt` for the full per-index rationale.
    ///
    /// Provenance: see sibling
    /// `tests/vectors/reference/cache/t2_cache_derive_item_batch.meta.txt`.
    /// Per RANDOMX_V2_PHASE2C_PLAN.md §5.7 / F7 T2, §9 commit 7.
    #[test]
    fn t2_cache_derive_item_batch_matches_fork_reference() {
        const ITEM_NUMBERS: [u64; 8] = [0, 1, 1023, 1024, 524_287, 524_288, 2_097_150, 2_097_151];
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/cache/t2_cache_derive_item_batch.bin");
        assert_eq!(
            expected.len(),
            ITEM_NUMBERS.len() * DATASET_ITEM_SIZE,
            "t2 .bin size invariant ({} items × {} bytes)",
            ITEM_NUMBERS.len(),
            DATASET_ITEM_SIZE,
        );

        let cache = Cache::derive(&canonical_seedhash());

        for (i, &n) in ITEM_NUMBERS.iter().enumerate() {
            let actual = cache.derive_item(n);
            let expected_slice: &[u8; DATASET_ITEM_SIZE] = expected
                [i * DATASET_ITEM_SIZE..(i + 1) * DATASET_ITEM_SIZE]
                .try_into()
                .expect("DATASET_ITEM_SIZE-byte vector segment");
            assert_eq!(
                &actual, expected_slice,
                "Cache::derive_item({n}) diverged from fork pin aaafe71 reference (vector index {i})",
            );
        }
    }
}
