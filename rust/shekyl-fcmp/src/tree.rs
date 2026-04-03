// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Curve tree operations: grow, trim, root computation.
//!
//! These functions wrap the upstream FCMP++ hash operations for the
//! Helios/Selene curve tower and are called from C++ via FFI during
//! `add_block` / `pop_block`.

use crate::leaf::ShekylLeaf;

/// Result of a hash-grow operation (appending new outputs to the tree).
#[derive(Clone, Debug)]
pub struct HashGrowResult {
    /// Updated layer hashes, indexed by `(layer_idx, chunk_idx)`.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after growth.
    pub new_root: [u8; 32],
}

/// Result of a hash-trim operation (removing outputs during reorg).
#[derive(Clone, Debug)]
pub struct HashTrimResult {
    /// Updated layer hashes after trimming.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after trimming.
    pub new_root: [u8; 32],
}

/// A single node update in the tree.
#[derive(Clone, Debug)]
pub struct LayerUpdate {
    pub layer_idx: u8,
    pub chunk_idx: u64,
    pub hash: [u8; 32],
}

/// Marker for tree operations dispatched through FFI.
pub enum TreeOp {
    Grow,
    Trim,
}

/// Convert Shekyl 4-scalar leaves into the format expected by the upstream
/// FCMP++ tree hash functions.
///
/// Each leaf's 4 scalars are passed to the curve tree's leaf-layer hash.
/// The upstream expects 3 scalars `{O.x, I.x, C.x}`; our extension adds
/// `H(pqc_pk)` as the 4th. The actual hash-into-tree is deferred until
/// the upstream crate supports 4-scalar leaves (Phase 1h circuit mod).
///
/// For now, this function serializes leaves into the byte format that the
/// FFI layer will pass to the C++ LMDB storage layer.
pub fn leaves_to_bytes(leaves: &[ShekylLeaf]) -> Vec<u8> {
    let mut out = Vec::with_capacity(leaves.len() * ShekylLeaf::SIZE);
    for leaf in leaves {
        out.extend_from_slice(&leaf.to_bytes());
    }
    out
}

/// Compute the expected proof size for a given number of inputs and tree depth.
///
/// Delegates to upstream `FcmpPlusPlus::proof_size` plus overhead for the
/// 4th scalar PQC commitment per input.
pub fn proof_size(num_inputs: usize, tree_depth: usize) -> usize {
    // Upstream proof size: (inputs * (3*32 + 12*32)) + FCMP_proof_size(inputs, layers)
    // Additional overhead for 4th scalar commitment per input: 32 bytes each.
    // The exact formula depends on the upstream's proof_size function.
    // Placeholder: upstream_size + 32 * num_inputs for the PQC commitment scalars.
    let upstream_estimate = (num_inputs * ((3 * 32) + (12 * 32)))
        + fcmp_proof_size_estimate(num_inputs, tree_depth);
    upstream_estimate + (32 * num_inputs)
}

/// Estimate the FCMP component proof size based on input count and tree layers.
///
/// The actual computation requires the upstream GBP proof size formula.
/// This estimate is based on the documented ~2.5-4 KB per input baseline.
fn fcmp_proof_size_estimate(num_inputs: usize, layers: usize) -> usize {
    // GBP proof: ~(2 * log2(n) + 9) * 32 bytes per layer level
    // With typical branching factor 256 and ~20 layers, and sharing across inputs:
    // Base: ~2560 bytes for 1 input, scaling sub-linearly.
    // This is a conservative estimate; actual value comes from upstream at runtime.
    let base_per_input = 2560;
    let layer_overhead = layers * 64;
    (base_per_input * num_inputs) + layer_overhead
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::PqcLeafScalar;

    #[test]
    fn leaves_to_bytes_roundtrip() {
        let leaves = vec![
            ShekylLeaf {
                o_x: [1u8; 32],
                i_x: [2u8; 32],
                c_x: [3u8; 32],
                h_pqc: PqcLeafScalar([4u8; 32]),
            },
            ShekylLeaf {
                o_x: [5u8; 32],
                i_x: [6u8; 32],
                c_x: [7u8; 32],
                h_pqc: PqcLeafScalar([8u8; 32]),
            },
        ];
        let bytes = leaves_to_bytes(&leaves);
        assert_eq!(bytes.len(), 2 * ShekylLeaf::SIZE);

        let restored_0 = ShekylLeaf::from_bytes(bytes[..128].try_into().unwrap());
        let restored_1 = ShekylLeaf::from_bytes(bytes[128..256].try_into().unwrap());
        assert_eq!(leaves[0], restored_0);
        assert_eq!(leaves[1], restored_1);
    }

    #[test]
    fn proof_size_grows_with_inputs() {
        let s1 = proof_size(1, 20);
        let s2 = proof_size(2, 20);
        let s8 = proof_size(8, 20);
        assert!(s2 > s1);
        assert!(s8 > s2);
    }
}
