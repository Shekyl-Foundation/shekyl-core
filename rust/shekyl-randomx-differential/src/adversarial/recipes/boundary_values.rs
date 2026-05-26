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

use crate::adversarial::types::CacheRecipe;

/// Category 3 recipe corpus: substrate-derived boundary values.
///
/// Empty at Phase 2h C3 (scaffold-only). C4 populates the array
/// after the substrate-derived constant scan completes. Each
/// populated entry cites a specific V2 configuration constant in
/// its `rationale` field per the inclusion criterion in this
/// module's rustdoc.
pub const BOUNDARY_VALUE_RECIPES: &[CacheRecipe] = &[];
