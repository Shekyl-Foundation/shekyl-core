// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Curve tree operations: grow, trim, root computation.
//!
//! These functions wrap the upstream FCMP++ Pedersen hash operations for the
//! Helios/Selene curve tower. The C++ LMDB layer manages the tree structure;
//! Rust provides the cryptographic hash primitives via FFI.
//!
//! ## Tree topology
//!
//! - Layer 0 (leaf): Selene. Each chunk hashes `SCALARS_PER_LEAF * SELENE_CHUNK_WIDTH`
//!   Selene scalars into a Selene point.
//! - Odd layers: Helios. Children are x-coordinates of Selene points from the layer below.
//! - Even layers (>0): Selene. Children are x-coordinates of Helios points from the layer below.
//! - Root: the single point at the topmost layer.

use crate::leaf::ShekylLeaf;

use ciphersuite::{
    group::{ff::PrimeField, GroupEncoding},
    Ciphersuite,
};
use ec_divisors::DivisorCurve;
use helioselene::{Helios, Selene};
use monero_fcmp_plus_plus::fcmps;
use monero_generators::{HELIOS_HASH_INIT, SELENE_HASH_INIT};

/// Number of scalars per output in the leaf layer.
/// Shekyl uses 4-scalar leaves: {O.x, I.x, C.x, H(pqc_pk)}.
pub const SCALARS_PER_LEAF: usize = 4;

/// Number of outputs per leaf-layer chunk (C1/Selene branching factor).
pub const SELENE_CHUNK_WIDTH: usize = fcmps::LAYER_ONE_LEN;

/// Number of children per Helios-layer chunk.
pub const HELIOS_CHUNK_WIDTH: usize = fcmps::LAYER_TWO_LEN;

/// Total leaf scalars per leaf-layer chunk.
pub const LEAF_CHUNK_SCALARS: usize = SCALARS_PER_LEAF * SELENE_CHUNK_WIDTH;

/// Result of a hash-grow operation (appending new outputs to the tree).
#[derive(Clone, Debug)]
pub struct HashGrowResult {
    /// Updated layer hashes, indexed by `(layer_idx, chunk_idx)`.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after growth (serialized point, 32 bytes).
    pub new_root: [u8; 32],
}

/// Result of a hash-trim operation (removing outputs during reorg).
#[derive(Clone, Debug)]
pub struct HashTrimResult {
    /// Updated layer hashes after trimming.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after trimming (serialized point, 32 bytes).
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

// ---------------------------------------------------------------------------
// Selene hash operations (leaf layer + even internal layers)
// ---------------------------------------------------------------------------

/// Incrementally add children to an existing Selene chunk hash.
///
/// - `existing_hash`: Current chunk hash (serialized Selene point). Use
///   `selene_hash_init()` for a new (empty) chunk.
/// - `offset`: Position in the chunk where new children start.
/// - `existing_child_at_offset`: The old scalar at `offset` (use 32 zero bytes
///   if this is a fresh position).
/// - `new_children`: Slice of new Selene scalars (32 bytes each).
///
/// Returns the updated Selene point (32 bytes), or `None` on failure.
pub fn hash_grow_selene(
    existing_hash: &[u8; 32],
    offset: usize,
    existing_child_at_offset: &[u8; 32],
    new_children: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let generators = &monero_fcmp_plus_plus::SELENE_FCMP_GENERATORS.generators;
    let existing = <Selene as Ciphersuite>::G::from_bytes(existing_hash.into());
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let old_child = deserialize_selene_scalar(existing_child_at_offset)?;
    let children: Vec<<Selene as Ciphersuite>::F> = new_children
        .iter()
        .map(|b| deserialize_selene_scalar(b))
        .collect::<Option<Vec<_>>>()?;

    let result = fcmps::tree::hash_grow::<Selene>(
        generators,
        existing,
        offset,
        old_child,
        &children,
    )?;

    Some(result.to_bytes().into())
}

/// Trim children from an existing Selene chunk hash.
pub fn hash_trim_selene(
    existing_hash: &[u8; 32],
    offset: usize,
    children_to_remove: &[[u8; 32]],
    child_to_grow_back: &[u8; 32],
) -> Option<[u8; 32]> {
    let generators = &monero_fcmp_plus_plus::SELENE_FCMP_GENERATORS.generators;
    let existing = <Selene as Ciphersuite>::G::from_bytes(existing_hash.into());
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let children: Vec<<Selene as Ciphersuite>::F> = children_to_remove
        .iter()
        .map(|b| deserialize_selene_scalar(b))
        .collect::<Option<Vec<_>>>()?;
    let grow_back = deserialize_selene_scalar(child_to_grow_back)?;

    let result = fcmps::tree::hash_trim::<Selene>(
        generators,
        existing,
        offset,
        &children,
        grow_back,
    )?;

    Some(result.to_bytes().into())
}

// ---------------------------------------------------------------------------
// Helios hash operations (odd internal layers)
// ---------------------------------------------------------------------------

/// Incrementally add children to an existing Helios chunk hash.
pub fn hash_grow_helios(
    existing_hash: &[u8; 32],
    offset: usize,
    existing_child_at_offset: &[u8; 32],
    new_children: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let generators = &monero_fcmp_plus_plus::HELIOS_FCMP_GENERATORS.generators;
    let existing = <Helios as Ciphersuite>::G::from_bytes(existing_hash.into());
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let old_child = deserialize_helios_scalar(existing_child_at_offset)?;
    let children: Vec<<Helios as Ciphersuite>::F> = new_children
        .iter()
        .map(|b| deserialize_helios_scalar(b))
        .collect::<Option<Vec<_>>>()?;

    let result = fcmps::tree::hash_grow::<Helios>(
        generators,
        existing,
        offset,
        old_child,
        &children,
    )?;

    Some(result.to_bytes().into())
}

/// Trim children from an existing Helios chunk hash.
pub fn hash_trim_helios(
    existing_hash: &[u8; 32],
    offset: usize,
    children_to_remove: &[[u8; 32]],
    child_to_grow_back: &[u8; 32],
) -> Option<[u8; 32]> {
    let generators = &monero_fcmp_plus_plus::HELIOS_FCMP_GENERATORS.generators;
    let existing = <Helios as Ciphersuite>::G::from_bytes(existing_hash.into());
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let children: Vec<<Helios as Ciphersuite>::F> = children_to_remove
        .iter()
        .map(|b| deserialize_helios_scalar(b))
        .collect::<Option<Vec<_>>>()?;
    let grow_back = deserialize_helios_scalar(child_to_grow_back)?;

    let result = fcmps::tree::hash_trim::<Helios>(
        generators,
        existing,
        offset,
        &children,
        grow_back,
    )?;

    Some(result.to_bytes().into())
}

// ---------------------------------------------------------------------------
// Point-to-cycle-scalar conversions
// ---------------------------------------------------------------------------

/// Extract the x-coordinate of a Selene point as a Helios scalar.
///
/// In the Helios/Selene curve cycle, Selene point coordinates are Helios
/// field elements. This conversion feeds Selene layer hashes into the
/// next Helios layer as children.
pub fn selene_point_to_helios_scalar(selene_point: &[u8; 32]) -> Option<[u8; 32]> {
    let point = <Selene as Ciphersuite>::G::from_bytes(selene_point.into());
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = <<Selene as Ciphersuite>::G as DivisorCurve>::to_xy(point.unwrap())?;
    Some(x.to_repr().into())
}

/// Extract the x-coordinate of a Helios point as a Selene scalar.
pub fn helios_point_to_selene_scalar(helios_point: &[u8; 32]) -> Option<[u8; 32]> {
    let point = <Helios as Ciphersuite>::G::from_bytes(helios_point.into());
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = <<Helios as Ciphersuite>::G as DivisorCurve>::to_xy(point.unwrap())?;
    Some(x.to_repr().into())
}

// ---------------------------------------------------------------------------
// Hash initialization points
// ---------------------------------------------------------------------------

/// Get the Selene hash initialization point (used for empty chunks).
pub fn selene_hash_init() -> [u8; 32] {
    SELENE_HASH_INIT.to_bytes().into()
}

/// Get the Helios hash initialization point (used for empty chunks).
pub fn helios_hash_init() -> [u8; 32] {
    HELIOS_HASH_INIT.to_bytes().into()
}

// ---------------------------------------------------------------------------
// Ed25519 → Selene scalar conversion (leaf construction)
// ---------------------------------------------------------------------------

/// Convert a compressed Ed25519 point to a Selene scalar (Wei25519 x-coordinate).
///
/// The Helios/Selene curve tower is constructed so that Ed25519's base field
/// GF(2^255-19) equals the Selene scalar field. This function decompresses
/// the point, maps it to short Weierstrass form (Wei25519), and returns the
/// x-coordinate as a 32-byte Selene scalar.
pub fn ed25519_point_to_selene_scalar(compressed: &[u8; 32]) -> Option<[u8; 32]> {
    use dalek_ff_group::EdwardsPoint as DfgEdwardsPoint;

    let point = <DfgEdwardsPoint as GroupEncoding>::from_bytes(compressed.into());
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = DfgEdwardsPoint::to_xy(point.unwrap())?;
    Some(x.to_repr().into())
}

/// Construct a 128-byte curve tree leaf from an output's public key and commitment.
///
/// Computes Hp(O) (Monero's hash-to-curve), then extracts the Wei25519
/// x-coordinates of O, Hp(O), and C. The 4th scalar (H(pqc_pk)) is set to
/// zero until PQC keys are included in the output format (Phase 3+).
pub fn construct_leaf(output_key: &[u8; 32], commitment: &[u8; 32]) -> Option<[u8; 128]> {
    let hp_point = monero_generators::biased_hash_to_point(*output_key);
    let hp_bytes: [u8; 32] = hp_point.compress().to_bytes();

    let o_x = ed25519_point_to_selene_scalar(output_key)?;
    let i_x = ed25519_point_to_selene_scalar(&hp_bytes)?;
    let c_x = ed25519_point_to_selene_scalar(commitment)?;

    let mut leaf = [0u8; 128];
    leaf[0..32].copy_from_slice(&o_x);
    leaf[32..64].copy_from_slice(&i_x);
    leaf[64..96].copy_from_slice(&c_x);
    // leaf[96..128] = H(pqc_pk).  Currently zero because PQC public keys are
    // not yet committed per-output.  When Phase 3 adds per-output PQC keys,
    // this scalar will hold the hash of the PQC public key.  NOTE: all leaves
    // stored before that activation will have H(pqc_pk)=0.  A full tree
    // rebuild (or migration) will be required at activation to replace zeros
    // with actual PQC key hashes for historical outputs.
    Some(leaf)
}

// ---------------------------------------------------------------------------
// Leaf helpers
// ---------------------------------------------------------------------------

/// Convert Shekyl 4-scalar leaves into serialized byte format for LMDB storage.
pub fn leaves_to_bytes(leaves: &[ShekylLeaf]) -> Vec<u8> {
    let mut out = Vec::with_capacity(leaves.len() * ShekylLeaf::SIZE);
    for leaf in leaves {
        out.extend_from_slice(&leaf.to_bytes());
    }
    out
}

/// Compute the expected proof size for a given number of inputs and tree depth.
pub fn proof_size(num_inputs: usize, tree_depth: usize) -> usize {
    use monero_fcmp_plus_plus::fcmps::Fcmp;
    type ShekylFcmp = Fcmp<monero_fcmp_plus_plus::Curves>;
    ShekylFcmp::proof_size(num_inputs, tree_depth)
}

/// Return the chunk width (branching factor) for a given layer.
///
/// Layer 0 is the leaf layer: each chunk holds `SELENE_CHUNK_WIDTH` outputs
/// (i.e. `LEAF_CHUNK_SCALARS` individual Selene scalars).
/// Even non-leaf layers (Selene) use `SELENE_CHUNK_WIDTH`.
/// Odd layers (Helios) use `HELIOS_CHUNK_WIDTH`.
pub fn chunk_width(layer: u8) -> usize {
    if layer == 0 {
        SELENE_CHUNK_WIDTH
    } else if layer % 2 == 0 {
        SELENE_CHUNK_WIDTH
    } else {
        HELIOS_CHUNK_WIDTH
    }
}

/// Returns true if the given layer uses Selene (even layers), false for Helios (odd layers).
pub fn layer_is_selene(layer: u8) -> bool {
    layer % 2 == 0
}

// ---------------------------------------------------------------------------
// Scalar deserialization helpers
// ---------------------------------------------------------------------------

fn deserialize_selene_scalar(bytes: &[u8; 32]) -> Option<<Selene as Ciphersuite>::F> {
    let repr = <Selene as Ciphersuite>::F::from_repr((*bytes).into());
    if bool::from(repr.is_some()) {
        Some(repr.unwrap())
    } else {
        None
    }
}

fn deserialize_helios_scalar(bytes: &[u8; 32]) -> Option<<Helios as Ciphersuite>::F> {
    let repr = <Helios as Ciphersuite>::F::from_repr((*bytes).into());
    if bool::from(repr.is_some()) {
        Some(repr.unwrap())
    } else {
        None
    }
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
    fn hash_init_points_are_nonzero() {
        let s = selene_hash_init();
        let h = helios_hash_init();
        assert_ne!(s, [0u8; 32]);
        assert_ne!(h, [0u8; 32]);
        assert_ne!(s, h);
    }

    #[test]
    fn hash_grow_selene_single_scalar() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;

        let result = hash_grow_selene(&init, 0, &zero, &[scalar]);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_ne!(hash, init);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn hash_grow_helios_single_scalar() {
        let init = helios_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;

        let result = hash_grow_helios(&init, 0, &zero, &[scalar]);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_ne!(hash, init);
    }

    #[test]
    fn selene_to_helios_roundtrip_nonidentity() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut s = [0u8; 32];
        s[0] = 42;

        let selene_point = hash_grow_selene(&init, 0, &zero, &[s]).unwrap();
        let helios_scalar = selene_point_to_helios_scalar(&selene_point);
        assert!(helios_scalar.is_some());
        let hs = helios_scalar.unwrap();
        assert_ne!(hs, [0u8; 32]);
    }

    #[test]
    fn proof_size_uses_upstream() {
        let s1 = proof_size(1, 8);
        let s2 = proof_size(2, 8);
        assert!(s1 > 0);
        assert!(s2 > s1);
    }

    #[test]
    fn chunk_widths_correct() {
        assert_eq!(chunk_width(0), SELENE_CHUNK_WIDTH);
        assert_eq!(chunk_width(1), HELIOS_CHUNK_WIDTH);
        assert_eq!(chunk_width(2), SELENE_CHUNK_WIDTH);
        assert_eq!(chunk_width(3), HELIOS_CHUNK_WIDTH);
    }
}
