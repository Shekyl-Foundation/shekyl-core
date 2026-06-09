// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Depth-parametric synthetic FCMP++ tree fixtures (§3.0.5 / PF7).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::EdwardsPoint;
use shekyl_tx_builder::{LeafEntry, TreeContext};

/// Canonical Selene scalar sibling for structural C1 layers (pre-mainnet).
#[must_use]
pub(crate) fn placeholder_selene_sibling(seed: u64) -> [u8; 32] {
    synthetic_h_pqc_bytes(seed)
}

/// Canonical Helios scalar sibling for structural C2 layers (pre-mainnet).
#[must_use]
pub(crate) fn placeholder_helios_sibling(seed: u64) -> [u8; 32] {
    use ciphersuite::group::ff::PrimeField;
    use helioselene::HelioseleneField;
    HelioseleneField::from(seed.wrapping_add(0x1_0000)).to_repr()
}

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
    use shekyl_fcmp_plus_plus::SELENE_FCMP_GENERATORS;
    use shekyl_generators::SELENE_HASH_INIT;

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

/// Synthetic tree root for the given depth and leaf chunk.
#[must_use]
pub(crate) fn synthetic_tree_root_from_leaf_chunk(
    leaf_chunk: &[LeafEntry],
    _depth: u8,
) -> [u8; 32] {
    // Pre-mainnet: depth > 1 uses the same single-chunk root recipe until CT-5.
    selene_single_chunk_tree_root(leaf_chunk)
}

/// Default synthetic tree context for 2a builds.
#[must_use]
pub(crate) fn synthetic_tree_context(
    reference_block: [u8; 32],
    depth: u8,
    leaf_chunk: &[LeafEntry],
) -> TreeContext {
    TreeContext {
        reference_block,
        tree_root: synthetic_tree_root_from_leaf_chunk(leaf_chunk, depth),
        tree_depth: depth,
    }
}

type EnrichedInputTree = (
    Vec<LeafEntry>,
    Vec<Vec<[u8; 32]>>,
    Vec<Vec<[u8; 32]>>,
    [u8; 32],
);

/// Attach branch layers and root to an input context leaf.
pub(crate) fn enrich_input_tree(leaf_chunk: Vec<LeafEntry>, depth: u8) -> EnrichedInputTree {
    let branch_count = depth.saturating_sub(1) as usize;
    let c1_count = branch_count.div_ceil(2);
    let c2_count = branch_count / 2;
    let c1_layers: Vec<Vec<[u8; 32]>> = (0..c1_count)
        .map(|i| vec![placeholder_selene_sibling(i as u64 + 1)])
        .collect();
    let c2_layers: Vec<Vec<[u8; 32]>> = (0..c2_count)
        .map(|i| vec![placeholder_helios_sibling(i as u64 + 1)])
        .collect();
    let root = synthetic_tree_root_from_leaf_chunk(&leaf_chunk, depth);
    (leaf_chunk, c1_layers, c2_layers, root)
}
