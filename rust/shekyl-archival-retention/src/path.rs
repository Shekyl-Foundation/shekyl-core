// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Merkle opening verification to a frozen segment sub-root `R_k`.
//!
//! Replays `shekyl-fcmp::tree` grow rules through sibling branches to `R_k`,
//! matching the layer discipline of `shekyl-curve-tree::AssembledPath` but
//! terminating at the segment root (gate-2 §5.1).
//!
//! # Mechanism status (2026-08-11): this is the RETIRED sampled-leaf mode
//!
//! **The sampled-leaf opening, kept by the format round as SUPPLEMENTARY
//! consensus-checkable evidence.** An earlier version of this header said the
//! module was superseded wholesale by derived assignment and would delete with
//! the format round. The format round (`ARCHIVAL_RESPONSE_FORMAT.md`, RF-D8,
//! ruled 2026-08-20) examined that and **kept the opening**, for a reason the
//! earlier note did not weigh:
//!
//! Every other element of a pass record depends on witness honesty. The
//! witness claims it fetched the whole shard and recomputed `R_k`; nothing on
//! chain checks that claim, so a witness colluding with `P` can manufacture a
//! pass with `P` holding zero bytes. **The opening is the one element
//! consensus verifies independently of the witness**: `P` must produce a valid
//! path for a leaf index it cannot choose, against a root it cannot supply
//! (both verifier-derived), and every node checks it at admission. It raises
//! the floor from "P may hold nothing" to "P must hold at least the challenged
//! leaf and its path" -- weak, cheaply outsourced, but non-zero, and the only
//! component that survives total witness collusion. That is what
//! ~1,920 B/record buys.
//!
//! Whole-shard fetching by the witness (`shekyl_curve_tree::recompute_segment_r_k`)
//! remains the **mechanism**; `ARCHIVAL_CHALLENGE_MECHANISM.md` §5.6's finding
//! that sampled-leaf is insufficient as a *standalone* mechanism stands, and
//! says nothing against an opening carried additively on top. Accordingly
//! [`crate::challenge::challenge_leaf_index`] comes **off** §2's deletion
//! surface: it is the verifier-side derivation the opening is checked against.
//!
//! **Everything the verifier can derive, it derives** (RF-D6/RF-D8): `R_k`
//! from its frozen-segment record, the leaf index from `challenge_leaf_index`,
//! and the challenged leaf's bytes from the leaf chunk it already reads. None
//! of those travel on the wire; the prover supplies only the branch layers.

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

/// The challenged leaf's 128 bytes, selected from the verifier's own leaf
/// chunk at the derived offset.
///
/// Replaces a transported `leaf_bytes` (RF-D8): the verifier must read the
/// whole chunk to verify at all, so it already holds the challenged leaf, and a
/// wire copy was a prover-supplied value the verifier had to check against its
/// own data -- the class RF-D6 removed. Selecting by offset is also STRONGER
/// than the old check, which only asked whether the supplied bytes matched
/// *some* leaf in the chunk and never bound them to the challenged index.
///
/// Returns `None` if the offset is outside the chunk.
#[must_use]
pub fn challenged_leaf_bytes(
    leaf_layer_scalars: &[[u8; 32]],
    leaf_offset_in_chunk: usize,
) -> Option<[u8; 128]> {
    if !leaf_layer_scalars.len().is_multiple_of(SCALARS_PER_LEAF) {
        return None;
    }
    let start = leaf_offset_in_chunk.checked_mul(SCALARS_PER_LEAF)?;
    let scalars = leaf_layer_scalars.get(start..start.checked_add(SCALARS_PER_LEAF)?)?;
    let mut packed = [0u8; 128];
    for (j, scalar) in scalars.iter().enumerate() {
        packed[j * 32..(j + 1) * 32].copy_from_slice(scalar);
    }
    Some(packed)
}

/// `VerifyPath(path, R_k)` from gate-2 §5.3 step 7, over verifier-held inputs.
///
/// `leaf_layer_scalars` is the Selene leaf-layer chunk containing the
/// challenged output (`4 × chunk_width` scalars), read by consensus from its
/// own leaf store; `leaf_offset_in_chunk` is where the derived challenge index
/// falls inside it. The vin carries neither -- only the branch layers in
/// `path` are the prover's.
pub fn verify_segment_path(
    leaf_layer_scalars: &[[u8; 32]],
    leaf_offset_in_chunk: usize,
    path: &SegmentPathOpening,
    rk: &[u8; 32],
) -> Result<(), VerifyError> {
    let depth = path.segment_path_depth();
    if depth < 2 {
        return Err(VerifyError::PathTooShallow);
    }

    if challenged_leaf_bytes(leaf_layer_scalars, leaf_offset_in_chunk).is_none() {
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

// `verify_leaf_index` was DELETED by RF-D6. It compared a wire-transported
// `leaf_index_in_segment` against `challenge_leaf_index`; the index is no
// longer transported, so there is nothing to compare -- the verifier derives
// it and uses it directly (path verification, signature preimage). A check
// whose only possible input is the value it would check against is not a
// check.
