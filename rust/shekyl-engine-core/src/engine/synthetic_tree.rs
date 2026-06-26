// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Depth-parametric synthetic FCMP++ tree fixtures (§3.0.5 / PF7).
//!
//! **Test-only since CT-5c.** Production assembles real membership paths via
//! the curve-tree client; these synthetic, depth-controlled fixtures survive
//! only for the non-daemon test surfaces that need them (the tx-weight KAT and
//! the `local_keys` signing KATs) — the A4 reversion clause of
//! `docs/design/CT5C_ASSEMBLER_CUTOVER.md`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::EdwardsPoint;
use shekyl_tx_builder::LeafEntry;

/// Synthetic `h_pqc` bytes for a leaf entry.
#[must_use]
pub(crate) fn synthetic_h_pqc_bytes(seed: u64) -> [u8; 32] {
    use ciphersuite::group::ff::PrimeField;
    let mut buf = [0u8; 64];
    buf[..8].copy_from_slice(&seed.to_le_bytes());
    buf[32..40].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let h_pqc_field = dalek_ff_group::FieldElement::wide_reduce(buf);
    h_pqc_field.to_repr()
}

/// Selene single-leaf-chunk tree root for `tree_depth = 1` (M3c-via-C recipe).
///
/// Root = `SELENE_HASH_INIT + multiexp(generators, [O.x, I.x, C.x, h_pqc] per leaf)`.
#[must_use]
pub(crate) fn selene_single_chunk_tree_root(leaf_chunk: &[LeafEntry]) -> [u8; 32] {
    use ciphersuite::{
        group::{ff::PrimeField, GroupEncoding},
        Ciphersuite,
    };
    use dalek_ff_group::EdwardsPoint as DfgEdwardsPoint;
    use ec_divisors::DivisorCurve;
    use helioselene::Selene;
    use multiexp::multiexp_vartime;
    use shekyl_curve_generators::SELENE_HASH_INIT;
    use shekyl_fcmp_proofs::SELENE_FCMP_GENERATORS;

    let leaves: Vec<(EdwardsPoint, EdwardsPoint, EdwardsPoint, [u8; 32])> = leaf_chunk
        .iter()
        .map(|e| {
            let o = CompressedEdwardsY(e.output_key)
                .decompress()
                .expect("output_key is on-curve");
            let i = CompressedEdwardsY(e.key_image_gen)
                .decompress()
                .expect("key_image_gen is on-curve");
            let c = CompressedEdwardsY(e.commitment)
                .decompress()
                .expect("commitment is on-curve");
            (o, i, c, e.h_pqc)
        })
        .collect();

    let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
    let needed = leaves.len() * 4;
    assert!(
        generators.len() >= needed,
        "SELENE_FCMP_GENERATORS.g_bold_slice() has {} entries; \
         single-leaf-chunk tree-root construction needs {} (4 per leaf, \
         {} leaves).",
        generators.len(),
        needed,
        leaves.len(),
    );
    let mut terms: Vec<(<Selene as ciphersuite::Ciphersuite>::F, _)> = Vec::with_capacity(needed);

    let mut g_idx = 0usize;
    for (o, i, c, h_pqc) in &leaves {
        let o_dfg = DfgEdwardsPoint(*o);
        let i_dfg = DfgEdwardsPoint(*i);
        let c_dfg = DfgEdwardsPoint(*c);
        terms.push((
            <DfgEdwardsPoint as DivisorCurve>::to_xy(o_dfg)
                .expect("output_key is on-curve")
                .0,
            generators[g_idx],
        ));
        g_idx += 1;
        terms.push((
            <DfgEdwardsPoint as DivisorCurve>::to_xy(i_dfg)
                .expect("key_image_gen is on-curve")
                .0,
            generators[g_idx],
        ));
        g_idx += 1;
        terms.push((
            <DfgEdwardsPoint as DivisorCurve>::to_xy(c_dfg)
                .expect("commitment is on-curve")
                .0,
            generators[g_idx],
        ));
        g_idx += 1;
        let h_pqc_field: <Selene as Ciphersuite>::F =
            Option::from(<Selene as Ciphersuite>::F::from_repr(*h_pqc))
                .expect("h_pqc bytes must be canonical Selene scalar");
        terms.push((h_pqc_field, generators[g_idx]));
        g_idx += 1;
    }

    let root_point: <Selene as ciphersuite::Ciphersuite>::G =
        *SELENE_HASH_INIT + multiexp_vartime(&terms);
    root_point.to_bytes()
}

/// `(c1_layers, c2_layers, tree_root)` for a depth-consistent synthetic path.
type SyntheticPath = (Vec<Vec<[u8; 32]>>, Vec<Vec<[u8; 32]>>, [u8; 32]);

/// A depth-consistent **single-path** synthetic tree over `leaf_chunk` (PF7):
/// the branch layers (`c1`, `c2`) and `tree_root` for a tree whose every layer
/// above the leaf holds exactly one node — the path node — hashed upward to the
/// target `depth`.
///
/// Unlike the pre-CT-5c placeholder branches (which did not hash to the
/// single-chunk root, so the FCMP++ prover rejected them above depth 1 —
/// `InconsistentWitness`, the PF7 block), this is a genuine consistent witness
/// at **any** depth without an astronomically large tree: the leaf chunk hashes
/// to a Selene node (layer 0), whose x-coord is the sole child in the layer-1
/// Helios branch, whose node's x-coord is the sole child in the layer-2 Selene
/// branch, and so on to the root. The prover pads each branch to the layer width
/// (Selene 38 / Helios 18) exactly as for a full tree, so the measured proof
/// size equals a real tree's at the same `(n_in, depth)`.
///
/// Returns `(c1_layers, c2_layers, tree_root)`, shared by every input of the tx
/// (the inputs all sit in the one leaf chunk). Branch index 0 (tree layer 1) is
/// C2 (Helios), alternating upward, matching `shekyl_curve_tree::assemble_path`
/// and the prover's "curve_2_layers populated before curve_1_layers".
#[must_use]
pub(crate) fn consistent_synthetic_path(leaf_chunk: &[LeafEntry], depth: u8) -> SyntheticPath {
    use shekyl_fcmp::tree::{
        hash_grow_helios, hash_grow_selene, helios_hash_init, helios_point_to_selene_scalar,
        layer_is_selene, selene_hash_init, selene_point_to_helios_scalar,
    };
    const ZERO: [u8; 32] = [0u8; 32];

    // Layer 0: the Selene leaf node (same recipe the prover hashes the leaf
    // chunk to, and the depth-1 root).
    let mut node = selene_single_chunk_tree_root(leaf_chunk);
    let mut c1_layers: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut c2_layers: Vec<Vec<[u8; 32]>> = Vec::new();

    for layer in 1..depth {
        if layer_is_selene(layer) {
            // Even layer (Selene node): its sole child is the Helios node below;
            // its x-coord as a Selene scalar is the branch.
            let scalar = helios_point_to_selene_scalar(&node).expect("helios->selene");
            node = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &[scalar]).expect("selene node");
            c1_layers.push(vec![scalar]);
        } else {
            // Odd layer (Helios node): its sole child is the Selene node below.
            let scalar = selene_point_to_helios_scalar(&node).expect("selene->helios");
            node = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &[scalar]).expect("helios node");
            c2_layers.push(vec![scalar]);
        }
    }

    (c1_layers, c2_layers, node)
}
