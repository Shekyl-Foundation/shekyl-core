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

use crate::adversarial::types::CacheRecipe;

/// Category 3 recipe corpus: dataset-item-offset extrema and
/// cache-line boundary cases.
///
/// Empty at Phase 2h C3 (scaffold-only). C4 populates the array
/// per the inclusion criterion in this module's rustdoc.
pub const DATASET_ITEM_EXTREMA_RECIPES: &[CacheRecipe] = &[];
