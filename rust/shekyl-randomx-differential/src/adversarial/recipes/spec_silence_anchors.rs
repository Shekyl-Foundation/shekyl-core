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

use crate::adversarial::types::{BaseSeedhash, CacheRecipe};

/// Phase 2h C4 starter base seedhash for spec-silence-anchor
/// recipes. All-`0x42` byte pattern; reused across multiple recipes
/// to share the C-side base-cache derivation cost via the C6
/// `base_caches` amortization layer.
const BASE_ALL_0X42: BaseSeedhash = BaseSeedhash {
    name: "all-0x42-byte-pattern",
    bytes: [0x42; 32],
};

/// Category 1 recipe corpus: audit-anchored spec-silence anchors.
///
/// Phase 2h C4 populates the array with the starter subset; the
/// full corpus (R1-D1 close target: 50-200 entries across all
/// categories) grows incrementally as subsequent commits surface
/// audit-substrate citations.
///
/// **Drift-prevention.** The array is aggregated into
/// [`crate::adversarial::get_corpus`] in the
/// `[spec_silence_anchors, coverage_targets, boundary_values,
/// dataset_item_extrema]` order pinned at that function. Reordering
/// here without updating the M1 canonical-output array's
/// recipe-index ordering produces a SHA mismatch at the next CI
/// run.
pub const SPEC_SILENCE_ANCHOR_RECIPES: &[CacheRecipe] = &[
    // Recipe 1: u128-high-half audit anchor.
    //
    // RANDOMX_V2_PHASE2D_PLAN.md §3.4 + R1-D4 audit table identify
    // IMULH_R / IMULH_M / ISMULH_R / ISMULH_M / IMUL_RCP as the
    // five opcodes consuming a u128 high-half computation path. The
    // C reference's `mulh` / `smulh_u64` helpers at
    // superscalar.rs:1495-1519 are byte-equality-checked against
    // the Rust port's per-opcode handlers in Phase 2d. The cache
    // memory at offset 0 carries the first 8 little-endian u64
    // word of the first Argon2d-derived block, which the spec's
    // §7.3 dataset-item derivation chains through SuperscalarHash
    // before feeding the result into the VM register that drives
    // the u128 multiplication. Modifying offset 0 changes the
    // input to the first dataset-item computation; any divergence
    // between the Rust and C high-half computation paths surfaces
    // as a `compute_hash` byte-equality failure under this recipe.
    CacheRecipe {
        name: "u128-high-half-cache-word-0",
        rationale: "Category 1: RANDOMX_V2_PHASE2D_PLAN.md §3.4 + R1-D4 audit-table cite. \
                    Cache offset 0 = first u64 word of first Argon2d block; modification \
                    drives a divergent SuperscalarHash output into the dataset-item path \
                    feeding the five u128-high-half opcodes (IMULH_R/M, ISMULH_R/M, \
                    IMUL_RCP) per R1-D4 disposition class M.",
        base: BASE_ALL_0X42,
        modifications: &[
            // High byte of first u64 word: 0x80 sets the high bit,
            // forcing signed/unsigned interpretation divergence in
            // any downstream signed-mul path. C reference's
            // smulh_u64 (superscalar.rs:1506-1519) sign-extends;
            // the Rust port's `smulh` mirror is the byte-equality
            // anchor under this recipe.
            (7, 0x80),
        ],
    },
    // Recipe 2: shift-mask boundary anchor (IROR / IROL / CFROUND).
    //
    // RANDOMX_V2_PHASE2D_PLAN.md §3.4 + R1-D4 audit table identify
    // IROR_R / IROL_R / CFROUND with disposition class **G** —
    // guarded by `src & 63` shift mask. The mask collapses the
    // full u64 shift amount to the low 6 bits, matching the C
    // reference's portable helper at instructions_portable.cpp.
    // The dataset-item path's u64 words feed into the shift source
    // register; cache content at the second u64 word (offset 8)
    // affects the shift amount for the first iteration after the
    // dataset-item read. Modifying offset 8 to 0xFF in the high
    // bits exercises the shift-mask boundary against a u64 shift
    // value at the high-bit-set extreme.
    CacheRecipe {
        name: "shift-mask-boundary-cache-word-1",
        rationale: "Category 1: RANDOMX_V2_PHASE2D_PLAN.md §3.4 + R1-D4 audit-table cite \
                    for IROR_R / IROL_R / CFROUND shift-mask disposition class G. \
                    Cache offset 8 = second u64 word of first Argon2d block; high-bit-set \
                    modification (0xFF in word's top byte) probes the shift-mask boundary \
                    against a near-u64::MAX shift source value, exercising the `src & 63` \
                    guard against the C reference's portable helper at \
                    instructions_portable.cpp.",
        base: BASE_ALL_0X42,
        modifications: &[
            // High byte of second u64 word: 0xFF saturates the
            // shift-source's high bits; the `& 63` mask should
            // produce the same result as the C reference regardless.
            (15, 0xFF),
        ],
    },
];
