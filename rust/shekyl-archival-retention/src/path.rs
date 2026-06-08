// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Merkle opening verification to a frozen segment sub-root `R_k`.
//!
//! Replays `shekyl-fcmp::tree` grow rules through sibling branches to `R_k`,
//! matching the layer discipline of `shekyl-curve-tree::AssembledPath` but
//! terminating at the segment root (gate-2 §5.1).

use crate::error::VerifyError;
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, layer_is_selene, selene_hash_init,
    selene_point_to_helios_scalar, SCALARS_PER_LEAF,
};

const ZERO: [u8; 32] = [0u8; 32];

/// Sibling branches from a segment leaf to frozen sub-root `R_k`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentPathOpening {
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    pub c2_layers: Vec<Vec<[u8; 32]>>,
}

impl SegmentPathOpening {
    /// `c1.len() + c2.len() + 1` (leaf layer included), per gate-2 §5.1.
    #[must_use]
    pub fn segment_path_depth(&self) -> u32 {
        u32::try_from(self.c1_layers.len() + self.c2_layers.len() + 1)
            .expect("segment path depth fits u32")
    }
}

/// Hash a Selene leaf-layer node from the flattened `{O.x, I.x, C.x, h_pqc}`
/// scalars of every output in the chunk (CT-4 / `assemble_kat` parity).
fn leaf_node_from_layer_scalars(scalars: &[[u8; 32]]) -> [u8; 32] {
    hash_grow_selene(&selene_hash_init(), 0, &ZERO, scalars)
        .expect("valid leaf-layer scalars hash to a Selene node")
}

/// Re-hash branch chunks from layer 1 upward; top hash is the sub-root.
fn recompute_subroot(path: &SegmentPathOpening) -> [u8; 32] {
    let depth = path.segment_path_depth();
    let mut c1 = path.c1_layers.iter();
    let mut c2 = path.c2_layers.iter();
    let mut root = None;
    for layer in 1..depth {
        let layer = u8::try_from(layer).expect("segment path layer fits u8");
        let point = if layer_is_selene(layer) {
            let chunk = c1.next().expect("c1 branch for Selene layer");
            hash_grow_selene(&selene_hash_init(), 0, &ZERO, chunk).expect("selene node")
        } else {
            let chunk = c2.next().expect("c2 branch for Helios layer");
            hash_grow_helios(&helios_hash_init(), 0, &ZERO, chunk).expect("helios node")
        };
        root = Some(point);
    }
    root.expect("segment path depth >= 2 yields at least one branch layer")
}

/// Returns true when `leaf_bytes` equals one output's four scalars inside
/// `leaf_layer_scalars`.
fn leaf_bytes_in_layer(leaf_bytes: &[u8; 128], leaf_layer_scalars: &[[u8; 32]]) -> bool {
    if !leaf_layer_scalars.len().is_multiple_of(SCALARS_PER_LEAF) {
        return false;
    }
    let outputs = leaf_layer_scalars.len() / SCALARS_PER_LEAF;
    (0..outputs).any(|i| {
        let start = i * SCALARS_PER_LEAF;
        let mut packed = [0u8; 128];
        for j in 0..SCALARS_PER_LEAF {
            packed[j * 32..(j + 1) * 32].copy_from_slice(&leaf_layer_scalars[start + j]);
        }
        packed == *leaf_bytes
    })
}

/// `VerifyPath(leaf_bytes, path, R_k)` from gate-2 §5.3 step 7.
///
/// `leaf_layer_scalars` is the Selene leaf-layer chunk containing the
/// challenged output (`4 × chunk_width` scalars). Consensus derives it from
/// segment leaf store at the challenged index's parent node; the vin carries
/// only the challenged `leaf_bytes` (128 bytes).
pub fn verify_segment_path(
    leaf_bytes: &[u8; 128],
    leaf_layer_scalars: &[[u8; 32]],
    path: &SegmentPathOpening,
    rk: &[u8; 32],
) -> Result<(), VerifyError> {
    let depth = path.segment_path_depth();
    if depth < 2 {
        return Err(VerifyError::PathTooShallow);
    }

    if !leaf_bytes_in_layer(leaf_bytes, leaf_layer_scalars) {
        return Err(VerifyError::LeafNotInOpening);
    }

    let leaf_point = leaf_node_from_layer_scalars(leaf_layer_scalars);
    let leaf_x = selene_point_to_helios_scalar(&leaf_point)
        .expect("leaf Selene node yields Helios child scalar");
    let first_helios = path.c2_layers.first().ok_or(VerifyError::PathTooShallow)?;
    if !first_helios.contains(&leaf_x) {
        return Err(VerifyError::LeafNotInOpening);
    }

    if recompute_subroot(path) != *rk {
        return Err(VerifyError::SubrootMismatch);
    }
    Ok(())
}

/// Gate-2 §5.3 step 4: challenged index must match epoch derivation.
pub fn verify_leaf_index(
    leaf_index_in_segment: u32,
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
    segment_leaf_count: u64,
) -> Result<(), VerifyError> {
    let expected = crate::challenge::challenge_leaf_index(
        p_id,
        shard_id,
        settlement_epoch,
        segment_leaf_count,
    );
    if leaf_index_in_segment != expected {
        return Err(VerifyError::LeafIndexMismatch {
            got: leaf_index_in_segment,
            expected,
        });
    }
    Ok(())
}
