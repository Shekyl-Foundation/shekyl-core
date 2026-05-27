// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Category 3 recipes: substrate-derived boundary values from V2
//! configuration constants.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D8 close, Category 3 recipes cite a specific V2
//! configuration constant or boundary value (e.g.,
//! `configuration.h:88 RANDOMX_FREQ_IADD_RS = ...`, `randomx.h:36
//! RANDOMX_DATASET_ITEM_SIZE = 64`). The substrate-derived
//! constant is the recipe's primary evidence of corpus inclusion;
//! the recipe's `(base, modifications)` shape exercises the
//! constant's boundary behavior against the verifier.
//!
//! # Inclusion criterion (Category 3, boundary-values subset)
//!
//! A recipe lands in this module only if:
//!
//! 1. The rationale field cites a specific V2 configuration
//!    constant by file path + line number + symbol name (e.g.,
//!    `external/randomx-v2/src/configuration.h:88 RANDOMX_ARGON_MEMORY`).
//! 2. The cited constant defines a boundary value the recipe
//!    exercises (off-by-one, modulus-equal, modulus-minus-one,
//!    overflow-triggering, underflow-triggering).
//! 3. The recipe's `(base, modifications)` shape is justified by
//!    the constant's boundary semantics rather than by general
//!    randomization.
//!
//! # Distinguished from `dataset_item_extrema`
//!
//! Per R1-D8 close, Category 3 is split into this module
//! (general configuration-constant boundaries) and
//! [`super::dataset_item_extrema`] (dataset-item-offset extrema,
//! cache-line boundaries). The split is taxonomic for reviewer
//! ergonomics; both modules carry Category 3 recipes per R1-D8.
//!
//! # Phase 2h C3 scaffold state
//!
//! Empty at C3 (scaffold-only). C4 populates the array after the
//! substrate-derived constant scan completes; each entry's
//! `rationale` cites a specific V2 configuration constant per the
//! inclusion criterion above. Expected size: a small handful of
//! entries (most boundary behaviors are covered by random-corpus
//! testing; this category is for the specific constants the
//! reviewer can point to).

use crate::adversarial::types::{BaseSeedhash, CacheRecipe};

/// Phase 2h C4 starter base seedhash for boundary-value recipes.
/// All-zeros byte pattern; the canonical "least-perturbing" base
/// for substrate-derived boundary testing.
const BASE_ALL_ZEROS: BaseSeedhash = BaseSeedhash {
    name: "all-zeros",
    bytes: [0x00; 32],
};

/// Argon2d cache memory size in bytes per
/// `configuration.h:32 RANDOMX_ARGON_MEMORY = 262144` × Argon2d
/// block size (1024); equals 256 MiB = 268_435_456 bytes. Matches
/// `crate::adversarial::interpreter::BASE_CACHE_BYTES_LEN`.
const CACHE_SIZE_BYTES: usize = 256 * 1024 * 1024;

/// Category 3 recipe corpus: substrate-derived boundary values.
///
/// Phase 2h C4 populates the array with the starter subset covering
/// the cache-memory edge bytes per
/// `external/randomx-v2/src/configuration.h:32 RANDOMX_ARGON_MEMORY`
/// and per `cache.rs:140 CACHE_SIZE`. The recipes exercise the
/// addressing-computation boundary at the cache-memory's two ends.
pub const BOUNDARY_VALUE_RECIPES: &[CacheRecipe] = &[
    // Recipe 1: first byte of cache memory.
    //
    // configuration.h:32 RANDOMX_ARGON_MEMORY = 262144 (blocks of
    // 1024 bytes) defines the cache-memory size; the first byte is
    // the addressing-origin for every dataset-item read. Modifying
    // offset 0 to 0xFF probes the addressing-computation path at
    // the cache-memory base — any off-by-one in the Rust port's
    // index calculation surfaces as a byte-equality failure under
    // this recipe.
    CacheRecipe {
        name: "boundary-cache-first-byte",
        rationale: "Category 3: configuration.h:32 RANDOMX_ARGON_MEMORY = 262144 + \
                    cache.rs:140 CACHE_SIZE = RANDOMX_ARGON_BLOCKS * Block::SIZE = \
                    256 MiB. Cache offset 0 = addressing origin for every dataset-item \
                    read; modification probes the Rust port's `Cache::item_bytes` \
                    (cache.rs:348) index-computation path at the base of the cache \
                    memory.",
        base: BASE_ALL_ZEROS,
        modifications: &[(0, 0xFF)],
    },
    // Recipe 2: last byte of cache memory.
    //
    // Symmetric to recipe 1: modifying offset `CACHE_SIZE - 1`
    // probes the addressing-computation path at the cache memory's
    // upper boundary. The dataset-item-count mask
    // (cache.rs:170-173: `DATASET_ITEM_COUNT.is_power_of_two()`
    // const_assert) collapses arbitrary u64 register values to the
    // valid item-index range via bitwise `& MASK`; any off-by-one
    // at the mask boundary surfaces as a byte-equality failure.
    CacheRecipe {
        name: "boundary-cache-last-byte",
        rationale: "Category 3: cache.rs:170-173 DATASET_ITEM_COUNT const_assert \
                    (power-of-two) + cache.rs:348 Cache::item_bytes mask boundary cite. \
                    Cache offset (CACHE_SIZE - 1) = last byte of cache memory; \
                    modification probes the index-mask boundary against a u64 register \
                    value reduced via `& (DATASET_ITEM_COUNT - 1)`.",
        base: BASE_ALL_ZEROS,
        modifications: &[(CACHE_SIZE_BYTES - 1, 0xFF)],
    },
    // Recipe 3: dataset-item-aligned boundary at first item.
    //
    // randomx.h:36 RANDOMX_DATASET_ITEM_SIZE = 64 + cache.rs:151
    // DATASET_ITEM_SIZE = 64 define the 64-byte dataset-item
    // stride. The byte immediately preceding the second
    // dataset-item (offset 63) and the byte at the second
    // dataset-item's base (offset 64) bracket the
    // dataset-item-stride boundary. Modifying both probes the
    // Rust port's per-item byte-range slicing in
    // `Cache::item_bytes` (cache.rs:348-379) against an off-by-one
    // at the stride boundary.
    CacheRecipe {
        name: "boundary-dataset-item-stride-first-edge",
        rationale: "Category 3: randomx.h:36 RANDOMX_DATASET_ITEM_SIZE = 64 + \
                    cache.rs:151 DATASET_ITEM_SIZE = 64. Cache offsets 63 + 64 = \
                    bytes immediately bracketing the first dataset-item stride boundary; \
                    modification probes the Rust port's per-item slicing \
                    (cache.rs:372 `&self.memory[block_idx].as_ref()[word_offset..word_offset \
                    + 8]`) against an off-by-one at the stride boundary.",
        base: BASE_ALL_ZEROS,
        modifications: &[(63, 0xAA), (64, 0xBB)],
    },
];
