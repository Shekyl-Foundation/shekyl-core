// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Category 1 recipes: audit-anchored spec-silence enumeration.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D8 close, Category 1 recipes cite a specific
//! audit-document spec silence, ambiguity, or rare-path enumeration
//! (e.g., `RANDOMX_V2_PHASE2D_PLAN.md §3.4 spec-silence #N`,
//! `RANDOMX_V2_PHASE2C_PLAN.md §X.Y inherited ambiguity`). The
//! recipe's `rationale` field carries the audit-substrate citation
//! as the recipe's primary evidence of corpus inclusion.
//!
//! # Inclusion criterion (Category 1)
//!
//! A recipe lands in this module only if:
//!
//! 1. The rationale field cites an audit-document section by
//!    document path + section anchor (e.g.,
//!    `RANDOMX_V2_PHASE2D_PLAN.md §3.4 spec-silence #3`).
//! 2. The cited document section identifies a specific
//!    spec-silence or ambiguity that the recipe's `(base,
//!    modifications)` shape exercises against the verifier.
//! 3. The recipe's `name` field's kebab-case identifier matches
//!    the spec-silence identifier (e.g., `spec-silence-3-cfround-
//!    boundary`) for grep-anchored M5 citation validation per
//!    R2-D4 close.
//!
//! # Phase 2h C3 scaffold state
//!
//! Empty at C3; populates at C4 alongside the substrate scan
//! (R1-D1 close: audit-anchored spec-silence enumeration primary).
//! The R1-D1 close estimated 50-200 total corpus entries; Category
//! 1 is expected to carry the majority (the substrate scan over
//! Phase 2c/2d audit documents is the primary corpus-generation
//! work).

use crate::adversarial::types::CacheRecipe;

/// Category 1 recipe corpus: audit-anchored spec-silence anchors.
///
/// Empty at Phase 2h C3 (scaffold-only). C4 populates the array
/// after the audit-substrate scan completes; each entry's
/// `rationale` cites a specific audit document section per the
/// inclusion criterion in this module's rustdoc.
///
/// **Drift-prevention.** The array is aggregated into
/// [`crate::adversarial::get_corpus`] in the
/// `[spec_silence_anchors, coverage_targets, boundary_values,
/// dataset_item_extrema]` order pinned at that function. Reordering
/// here without updating the M1 canonical-output array's
/// recipe-index ordering produces a SHA mismatch at the next CI
/// run.
pub const SPEC_SILENCE_ANCHOR_RECIPES: &[CacheRecipe] = &[];
