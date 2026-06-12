// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Subtree-aligned segment math for the CT-1 `LeafStore` hot path.
//!
//! Segment boundaries, freeze eligibility, and `R_k` extraction mirror the
//! CT-0 gate harness (`rust/shekyl-fcmp/tests/curve_tree_freeze.rs`) and are
//! pinned in `docs/design/CT1_ROUND1_PINS.md`.

use shekyl_fcmp::tree::{
    layer_is_selene, try_build_layers, HELIOS_CHUNK_WIDTH, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};
use shekyl_oxide::DEFAULT_LOCK_WINDOW;

/// Sub-root layer index `j` for segment boundaries (provisional; §7.2.2).
pub const SEGMENT_LAYER_J: u8 = 2;

/// Same numeric value as `ARCHIVAL_REORG_DEPTH_BLOCKS` (720). Hardcoded until
/// PHASE_2B codegen; see `docs/FOLLOWUPS.md`.
pub const SEGMENT_FREEZE_REORG_MARGIN_BLOCKS: u64 = 720;

/// Output maturity / spendable age in blocks (`CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`).
pub const SPENDABLE_AGE_BLOCKS: u64 = DEFAULT_LOCK_WINDOW as u64;

/// Dense segment identifier (`SegmentId` 0 covers tree positions `[0, E)`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SegmentId(pub u32);

crate::types::redb_delegated_key!(SegmentId, u32, "shekyl_curve_tree::SegmentId");

/// Outputs covered by one node at sub-root layer `j` (= segment size `E`).
#[must_use]
pub fn outputs_per_node(j: u8) -> usize {
    let mut e = SELENE_CHUNK_WIDTH;
    for layer in 1..=usize::from(j) {
        let layer = u8::try_from(layer).expect("tree layer fits u8");
        e *= if layer_is_selene(layer) {
            SELENE_CHUNK_WIDTH
        } else {
            HELIOS_CHUNK_WIDTH
        };
    }
    e
}

/// Leaves per segment at the pinned layer `j`.
#[must_use]
pub fn leaves_per_segment() -> usize {
    outputs_per_node(SEGMENT_LAYER_J)
}

/// Height-based freeze gate (`CT1_ROUND1_PINS.md`).
#[must_use]
pub fn segment_freeze_eligible(tip_height: u64, end_block_height: u64) -> bool {
    tip_height.saturating_sub(end_block_height)
        >= SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS
}

/// Recompute segment `k`'s sub-root `R_k` from its `E` leaf scalars.
pub fn extract_r_k(leaf_scalars: &[[u8; 32]]) -> [u8; 32] {
    try_extract_r_k(leaf_scalars).expect("valid leaf scalars")
}

/// Fallible [`extract_r_k`] for persisted bytes on the CT-1 store path.
pub fn try_extract_r_k(leaf_scalars: &[[u8; 32]]) -> Option<[u8; 32]> {
    let layers = try_build_layers(leaf_scalars)?;
    layers
        .get(usize::from(SEGMENT_LAYER_J))
        .and_then(|layer| layer.first().copied())
}

/// Flatten `LeafEntry`-style 128-byte leaves into Selene scalars for `build_layers`.
#[must_use]
pub fn leaf_bytes_to_scalars(leaves: &[[u8; 128]]) -> Vec<[u8; 32]> {
    // Each 128-byte leaf yields exactly `SCALARS_PER_LEAF` (4) 32-byte scalars;
    // `LEAF_CHUNK_SCALARS` is per Selene *chunk* and would over-reserve by
    // `SELENE_CHUNK_WIDTH`x on large leaf sets.
    let mut scalars = Vec::with_capacity(leaves.len() * SCALARS_PER_LEAF);
    for leaf in leaves {
        for chunk in leaf.chunks_exact(32) {
            let mut s = [0u8; 32];
            s.copy_from_slice(chunk);
            scalars.push(s);
        }
    }
    scalars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_per_node_matches_ct0_harness() {
        assert_eq!(outputs_per_node(0), SELENE_CHUNK_WIDTH);
        assert_eq!(outputs_per_node(1), SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH);
        assert_eq!(
            outputs_per_node(2),
            SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH * SELENE_CHUNK_WIDTH
        );
    }

    #[test]
    fn freeze_gate_requires_height_burial() {
        let margin = SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;
        assert!(!segment_freeze_eligible(margin - 1, 0));
        assert!(segment_freeze_eligible(margin, 0));
        assert!(!segment_freeze_eligible(margin, 1));
    }
}
