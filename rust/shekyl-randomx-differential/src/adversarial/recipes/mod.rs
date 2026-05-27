// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recipe corpus for the Phase 2h adversarial-test methodology.
//!
//! Per
//! [`RANDOMX_V2_PHASE2H_PLAN.md`](../../../../../docs/design/RANDOMX_V2_PHASE2H_PLAN.md)
//! Round 1 R1-D3 close, the corpus is organized by the
//! three-evidence-category structure from R1-D8:
//!
//! - **[`spec_silence_anchors`]** — Category 1 recipes. Each cites
//!   a specific audit-document spec silence (e.g.,
//!   `RANDOMX_V2_PHASE2D_PLAN.md §3.4 spec-silence #N`) that the
//!   recipe exercises against the verifier. The audit-substrate
//!   citation is the recipe's primary evidence of corpus inclusion.
//! - **[`coverage_targets`]** — Category 2 recipes. Each cites a
//!   coverage-metric attestation snapshot identifying a rare-path
//!   the corpus's other recipes do not reach. The snapshot is
//!   committed alongside the recipe per R1-D8 close. (Empty at
//!   C3; populates if coverage tooling at C4 surfaces gaps.)
//! - **[`boundary_values`]** — Category 3 recipes citing a specific
//!   V2 configuration constant or boundary value (e.g.,
//!   `configuration.h:88 RANDOMX_FREQ_IADD_RS = ...`,
//!   `dataset.cpp:160 mask = CacheSize / CacheLineSize - 1`). These
//!   are the substrate-derived recipes per R1-D8's third category.
//! - **[`dataset_item_extrema`]** — Category 3 recipes targeting
//!   the cache-line boundary edges, dataset-item-offset extrema,
//!   and other substrate-derived address constants. Split from
//!   `boundary_values` for taxonomic clarity; both live under
//!   Category 3 per R1-D8.
//!
//! # Module scaffold (Phase 2h C3)
//!
//! C3 lands the directory structure with empty corpus arrays. The
//! initial recipe contents (16-30 recipes per the R1-D1 close
//! sizing 50-200 with C3 landing a starter subset) populate at C4
//! alongside their rationale citations and the M5 citation-format
//! validation script's first run target.
//!
//! Each per-category file at C3 is a scaffold with the
//! `<CATEGORY>_RECIPES: &[CacheRecipe] = &[]` empty array and the
//! per-category rustdoc explaining the inclusion criterion. C4
//! populates the arrays.
//!
//! # `get_corpus` aggregation surface
//!
//! [`super::get_corpus`] (defined in `adversarial/mod.rs`)
//! concatenates the four category arrays into a single
//! `&[CacheRecipe]` for the harness's per-recipe iteration. The
//! aggregation order is `[spec_silence_anchors, coverage_targets,
//! boundary_values, dataset_item_extrema]` — pinned at the
//! [`super::get_corpus`] implementation so the M1 canonical-output
//! array's recipe-index ordering matches.

pub mod boundary_values;
pub mod coverage_targets;
pub mod dataset_item_extrema;
pub mod spec_silence_anchors;
