// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Category 3 recipes: substrate-derived dataset-item-offset
//! extrema and cache-line boundary cases.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D8 close, Category 3 recipes are subdivided into
//! [`super::boundary_values`] (general configuration-constant
//! boundaries) and this module (dataset-item-offset extrema, cache-
//! line boundary edges). Both subdivisions are Category 3 per R1-D8;
//! the split is taxonomic for reviewer ergonomics.
//!
//! # Inclusion criterion (Category 3, dataset-item-extrema subset)
//!
//! A recipe lands in this module only if:
//!
//! 1. The rationale field cites a specific dataset-item-related
//!    constant by file path + line number + symbol name (e.g.,
//!    `cache.rs:151 DATASET_ITEM_SIZE = 64`, `cache.rs:168
//!    DATASET_ITEM_COUNT = CACHE_SIZE / DATASET_ITEM_SIZE`).
//! 2. The recipe's modifications target either:
//!    - A dataset-item-boundary offset (e.g.,
//!      `DATASET_ITEM_SIZE * N - 1`, `DATASET_ITEM_SIZE * N`,
//!      `DATASET_ITEM_SIZE * N + 1` — the bytes immediately
//!      surrounding a 64-byte dataset-item boundary), or
//!    - The first / last byte of the full cache memory (offset 0,
//!      offset `CACHE_SIZE - 1`), or
//!    - The first / last byte of an Argon2d block (offset
//!      `BLOCK_SIZE * N`, `BLOCK_SIZE * N + 1023` — the bytes
//!      immediately surrounding a 1-KiB block boundary).
//! 3. The recipe's `(base, modifications)` shape exercises the
//!    addressing-computation path that the verifier's
//!    `Cache::item_bytes` (cache.rs:348) executes against the
//!    cited constants.
//!
//! # Phase 2h C3 scaffold state
//!
//! Empty at C3 (scaffold-only). C4 populates the array after the
//! substrate-derived constant scan completes; the expected size is
//! 4-8 entries (one per substrate-derived boundary class).

use crate::adversarial::types::{BaseSeedhash, CacheRecipe};

/// Phase 2h C4 starter base seedhash for dataset-item-extrema
/// recipes. All-`0x01` byte pattern; distinct from the
/// boundary_values and spec_silence_anchors module's base
/// seedhashes so each module's recipes pay their own base-cache
/// derivation cost (the C6 `base_caches` amortization layer
/// dedupes when the bytes match across modules).
const BASE_ALL_0X01: BaseSeedhash = BaseSeedhash {
    name: "all-0x01-byte-pattern",
    bytes: [0x01; 32],
};

/// Argon2d block size in bytes; per argon2 crate's `Block::SIZE`
/// constant verified at `argon2-0.5.3/src/block.rs:51` =
/// `[u64; 128]` = 1024 bytes. Re-asserted here as a literal
/// because the `argon2::Block::SIZE` accessor is not in scope at
/// this module.
const BLOCK_SIZE_BYTES: usize = 1024;

/// Category 3 recipe corpus: dataset-item-offset extrema and
/// cache-line boundary cases.
///
/// Phase 2h C4 populates the array with the starter subset
/// covering the Argon2d 1-KiB block boundary. The recipes exercise
/// the cache-bytes-to-block addressing path in `Cache::item_bytes`
/// at the block-stride boundary (cache lines do not straddle
/// blocks per the cache.rs:341 "no line straddles a block
/// boundary" invariant).
pub const DATASET_ITEM_EXTREMA_RECIPES: &[CacheRecipe] = &[
    // Recipe 1: first byte of second Argon2d block.
    //
    // cache.rs:338-341 documents the block-stride invariant: each
    // 1-KiB Block holds 16 cache lines, no line straddles a block
    // boundary. The byte at offset `BLOCK_SIZE * 1` is the base
    // of the second block; modifying it probes the
    // `Cache::item_bytes` block-index computation
    // (cache.rs:370 `let block_idx = line_idx >> 4`) at the
    // second-block boundary against an off-by-one in the
    // line-to-block conversion.
    CacheRecipe {
        name: "boundary-block-stride-second-block-base",
        rationale: "Category 3: cache.rs:338-341 block-stride invariant + cache.rs:370 \
                    `let block_idx = line_idx >> 4`. Cache offset BLOCK_SIZE (= 1024) = \
                    base of second Argon2d block; modification probes the \
                    line-index-to-block-index conversion against an off-by-one at the \
                    block-stride boundary.",
        base: BASE_ALL_0X01,
        modifications: &[(BLOCK_SIZE_BYTES, 0xCC)],
    },
    // Recipe 2: last byte of first Argon2d block.
    //
    // Symmetric to recipe 1: modifying offset `BLOCK_SIZE - 1`
    // probes the last byte of the first block — the byte
    // immediately preceding the second block's base. Together
    // recipes 1 + 2 bracket the first block-stride boundary; any
    // off-by-one in the block-index computation surfaces under
    // one or the other (the C reference's block addressing in
    // `dataset.cpp:159-162 getMixBlock` is the Phase 2g
    // cross-implementation cite at the same boundary).
    CacheRecipe {
        name: "boundary-block-stride-first-block-tail",
        rationale: "Category 3: cache.rs:338-341 block-stride invariant + \
                    dataset.cpp:159-162 getMixBlock cross-implementation cite. Cache \
                    offset (BLOCK_SIZE - 1) = last byte of first Argon2d block; \
                    modification probes the per-block-tail addressing against the C \
                    reference's getMixBlock byte-equality contract.",
        base: BASE_ALL_0X01,
        modifications: &[(BLOCK_SIZE_BYTES - 1, 0xDD)],
    },
    // Recipe 3: cache-line stride boundary within a block.
    //
    // cache.rs:341 documents the per-block layout: 16 cache lines
    // of 64 bytes each within a 1-KiB block. The byte at offset
    // 63 ends the first cache line; offset 64 begins the second.
    // Both bytes are within the first block (cache_lines do not
    // straddle blocks), but the per-line word-offset computation
    // (cache.rs:371 `let word_offset = (line_idx & 0xF) << 3`)
    // mod-reduces the line index to the in-block position. This
    // recipe probes the in-block line-stride boundary, distinct
    // from boundary_values.rs's `boundary-dataset-item-stride-
    // first-edge` recipe which operates on the
    // dataset-item-stride boundary (same byte offset by
    // coincidence — DATASET_ITEM_SIZE = 64 = cache-line stride —
    // but cites the in-block addressing path rather than the
    // dataset-item slicing path).
    CacheRecipe {
        name: "boundary-line-stride-within-block",
        rationale: "Category 3: cache.rs:341 per-block-layout (16 lines × 64 bytes) + \
                    cache.rs:371 `let word_offset = (line_idx & 0xF) << 3`. Cache \
                    offsets 63 + 64 = bytes immediately bracketing the first \
                    cache-line stride boundary within the first block; modification \
                    probes the in-block word-offset mod-reduction (distinct from the \
                    dataset-item-stride probe at boundary_values.rs).",
        base: BASE_ALL_0X01,
        modifications: &[(63, 0xEE), (64, 0xFF)],
    },
];
