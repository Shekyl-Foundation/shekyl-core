// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Category 2 recipes: coverage-metric-attested gap targets.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D8 close, Category 2 recipes cite a coverage-metric
//! attestation snapshot identifying a specific rare-path that the
//! corpus's other recipes do not reach. The attestation snapshot is
//! committed alongside the recipe.
//!
//! # Inclusion criterion (Category 2)
//!
//! A recipe lands in this module only if:
//!
//! 1. The rationale field cites a coverage-attestation snapshot
//!    (committed under `docs/design/phase-2h-coverage-snapshots/`
//!    or equivalent path established at C4) identifying the
//!    rare-path the recipe targets.
//! 2. The coverage gap is reproducible: re-running coverage
//!    instrumentation against the corpus minus this recipe
//!    reproduces the cited gap.
//! 3. The recipe's `(base, modifications)` shape exercises the
//!    cited rare-path against the verifier.
//!
//! # Phase 2h C3 scaffold state
//!
//! Empty at C3 (scaffold-only). Coverage-tooling reproducibility
//! against the workspace's pinned toolchain is the gating substrate
//! check (R1-D1 close reopen criterion: "Coverage tooling becomes
//! unreliable or unavailable on the workspace's pinned toolchain;
//! reopen Category 2"). If C4's coverage-tooling exploration
//! demonstrates reproducibility, Category 2 recipes populate; if
//! not, this module ships empty and the reopen criterion records
//! the deferral.

use crate::adversarial::types::CacheRecipe;

/// Category 2 recipe corpus: coverage-metric-attested gap targets.
///
/// Empty at Phase 2h C3 (scaffold-only). Population is conditional
/// on C4's coverage-tooling reproducibility verification per the
/// R1-D1 close Category-2 reopen criterion. Each populated entry
/// pairs the recipe with its coverage-snapshot citation in the
/// `rationale` field.
pub const COVERAGE_TARGET_RECIPES: &[CacheRecipe] = &[];
