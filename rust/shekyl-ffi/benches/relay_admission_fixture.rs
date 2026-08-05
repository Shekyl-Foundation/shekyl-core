// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixture for the §72 admission-verification benches.
//!
//! Included by both `relay_admission_verify.rs` (wall clock, the `hop` input)
//! and `relay_admission_verify_iai.rs` (instruction counts, the drift gate) via
//! `#[path]`, so the two instruments measure **the same workload** — which is
//! the only thing that makes the gate meaningful about the number.
//!
//! Not a `tests/common`-style helper: bench targets are separate compilation
//! units, so a shared module is the only way to keep one definition.

#![allow(dead_code)]

use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use dalek_ff_group::{EdwardsPoint, Scalar};
use ec_divisors::DivisorCurve;
use helioselene::Selene;
use multiexp::multiexp_vartime;
use rand_core::OsRng;
use shekyl_curve_generators::{SELENE_HASH_INIT, T};
use shekyl_fcmp::leaf::PqcLeafScalar;
use shekyl_fcmp::proof::{prove, BranchLayer, ProveInput};
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, helios_point_to_selene_scalar,
    selene_hash_init, selene_point_to_helios_scalar,
};
use shekyl_fcmp_proofs::SELENE_FCMP_GENERATORS;

use shekyl_ffi::ct_balance_ffi::shekyl_check_commitment_masks;
use shekyl_ffi::shekyl_fcmp_verify;

/// `shekyl_fcmp_verify` / `shekyl_check_commitment_masks` both use `0` for
/// success; the XOR below is `0` only when both succeeded.
pub const ADMISSION_OK: u8 = 0;

/// Everything `blockchain.cpp` hands the admission calls for one transaction.
pub struct AdmissionFixture {
    pub proof: Vec<u8>,
    pub key_images_flat: Vec<u8>,
    pub pseudo_outs_flat: Vec<u8>,
    pub pqc_hashes_flat: Vec<u8>,
    pub tree_root: [u8; 32],
    pub tree_depth: u8,
    pub signable_tx_hash: [u8; 32],
    /// Output commitment masks — `rv.outPk`, the axis `check_commitment_masks`
    /// walks.
    pub masks_flat: Vec<u8>,
}

/// Build a verifiable `n_in`-input, `n_out`-output admission fixture.
///
/// All inputs share one depth-1 leaf chunk, so the tree root is a single
/// multiexp over the chunk's `4 × n_in` leaf scalars. That is the smallest
/// tree that admits `n_in` inputs, which keeps the sweep measuring **input
/// count** rather than tree depth — a second axis that would otherwise ride
/// along and produce F-7's confound (§69.2).
/// How the spent outputs sit in the curve tree.
///
/// **This is the fixture caveat §76.1 flagged, made measurable.** The input
/// axis was first swept with every input in ONE leaf chunk — the right control
/// for isolating input count from tree depth, but not what production
/// presents: real spends are scattered, so each lands in its own chunk with
/// its own path. Since `f`'s per-input term is built from this marginal, the
/// layout has to be measured rather than assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChunkLayout {
    /// All inputs adjacent in one leaf chunk — the §72 control.
    Shared,
    /// One input per leaf chunk, `n` siblings at the Helios layer — production
    /// topology for unrelated spends.
    Spread,
}

pub fn build_fixture(
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    layout: ChunkLayout,
) -> AdmissionFixture {
    assert!(
        layout == ChunkLayout::Shared || tree_depth >= 2,
        "Spread needs the Helios layer to hold the sibling chunks; depth 1 has none"
    );
    assert!(
        (1..=7).contains(&tree_depth),
        "depth 1 is sub-production; 2 is the production minimum; 3..=7 are the \
         capacity tiers (§72) and are PROJECTIONS -- synthesized trees under \
         genesis-era conditions, not measurements of a tree that exists"
    );
    let signable_tx_hash = [0xABu8; 32];

    let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
    assert!(
        generators.len() >= 4 * n_in,
        "leaf chunk needs 4 generators per input; have {} for n_in={n_in}",
        generators.len()
    );

    let mut xs = Vec::with_capacity(n_in);
    let mut ys = Vec::with_capacity(n_in);
    let mut os = Vec::with_capacity(n_in);
    let mut is = Vec::with_capacity(n_in);
    let mut cs = Vec::with_capacity(n_in);
    let mut h_pqcs = Vec::with_capacity(n_in);

    for _ in 0..n_in {
        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let o = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
        let i = EdwardsPoint::random(&mut OsRng);
        let c = EdwardsPoint::random(&mut OsRng);
        let h = <Selene as Ciphersuite>::F::random(&mut OsRng);
        xs.push(x);
        ys.push(y);
        os.push(o);
        is.push(i);
        cs.push(c);
        h_pqcs.push(h);
    }

    // Per-layout leaf construction.
    //
    // Shared: one chunk holding all `n_in` outputs, so the root is a single
    // multiexp over `4 * n_in` leaf scalars and every input's path is the same.
    //
    // Spread: `n_in` chunks of one output each, so the Helios layer carries
    // `n_in` siblings and each input walks a distinct path — the arrangement a
    // wallet spending unrelated outputs actually produces.
    let leaf_selene_for = |idxs: &[usize]| -> <Selene as Ciphersuite>::G {
        let mut terms = Vec::with_capacity(4 * idxs.len());
        for (slot, &idx) in idxs.iter().enumerate() {
            terms.push((
                <EdwardsPoint as DivisorCurve>::to_xy(os[idx]).unwrap().0,
                generators[4 * slot],
            ));
            terms.push((
                <EdwardsPoint as DivisorCurve>::to_xy(is[idx]).unwrap().0,
                generators[4 * slot + 1],
            ));
            terms.push((
                <EdwardsPoint as DivisorCurve>::to_xy(cs[idx]).unwrap().0,
                generators[4 * slot + 2],
            ));
            terms.push((h_pqcs[idx], generators[4 * slot + 3]));
        }
        *SELENE_HASH_INIT + multiexp_vartime(&terms)
    };

    let all: Vec<usize> = (0..n_in).collect();

    // Depth 1 roots at the leaf layer, which PRODUCTION NEVER DOES:
    // `tree.rs` states a non-empty tree yields depth >= 2, because a single
    // layer-0 node is promoted into a layer-1 Helios root rather than returned
    // bare. Depth 1 is kept only as the sub-production floor the first sweep
    // measured; depth 2 is the shallowest tree a live chain can present.
    // Walk the alternating tree to `tree_depth`. `tree.rs`: layer 0 is the
    // Selene leaf, odd layers are Helios over the x-coords of the Selene points
    // below, even layers > 0 are Selene over the x-coords of the Helios points
    // below. Each layer above the leaf contributes a 1-wide branch chunk on its
    // own curve, which is what `prove` walks.
    //
    // Depths 3..=7 are PROJECTIONS: they synthesize the capacity tiers (§72)
    // under genesis-era conditions rather than measuring a tree that exists.
    // Labelled here as well as at the table (§81.2) so the number carries its
    // status wherever it is read.
    let (tree_root, c1_layers, c2_layers, per_input_chunk): (
        [u8; 32],
        Vec<BranchLayer>,
        Vec<BranchLayer>,
        Vec<Vec<usize>>,
    ) = if tree_depth == 1 {
        (
            leaf_selene_for(&all).to_bytes(),
            Vec::new(),
            Vec::new(),
            vec![all.clone(); n_in],
        )
    } else {
        let chunks: Vec<Vec<usize>> = match layout {
            ChunkLayout::Shared => vec![all.clone()],
            ChunkLayout::Spread => all.iter().map(|&i| vec![i]).collect(),
        };
        let owner: Vec<Vec<usize>> = match layout {
            ChunkLayout::Shared => vec![all.clone(); n_in],
            ChunkLayout::Spread => all.iter().map(|&i| vec![i]).collect(),
        };

        // Layer 1 (Helios) over the leaf chunk(s).
        let l1_children: Vec<[u8; 32]> = chunks
            .iter()
            .map(|c| {
                selene_point_to_helios_scalar(&leaf_selene_for(c).to_bytes())
                    .expect("selene->helios conversion")
            })
            .collect();
        let mut point = hash_grow_helios(&helios_hash_init(), 0, &[0u8; 32], &l1_children)
            .expect("layer-1 Helios node");
        let mut c1: Vec<BranchLayer> = Vec::new();
        let mut c2: Vec<BranchLayer> = vec![BranchLayer {
            siblings: l1_children,
        }];

        // Layers 2..tree_depth-1, alternating Selene / Helios.
        for layer in 2..tree_depth {
            if layer % 2 == 0 {
                let child =
                    helios_point_to_selene_scalar(&point).expect("helios->selene conversion");
                point = hash_grow_selene(&selene_hash_init(), 0, &[0u8; 32], &[child])
                    .expect("Selene node");
                c1.push(BranchLayer {
                    siblings: vec![child],
                });
            } else {
                let child =
                    selene_point_to_helios_scalar(&point).expect("selene->helios conversion");
                point = hash_grow_helios(&helios_hash_init(), 0, &[0u8; 32], &[child])
                    .expect("Helios node");
                c2.push(BranchLayer {
                    siblings: vec![child],
                });
            }
        }

        (point, c1, c2, owner)
    };

    let all_h_pqc: Vec<[u8; 32]> = h_pqcs.iter().map(PrimeField::to_repr).collect();

    let inputs: Vec<ProveInput> = (0..n_in)
        .map(|i| ProveInput {
            output_key: os[i].to_bytes(),
            key_image_gen: is[i].to_bytes(),
            commitment: cs[i].to_bytes(),
            h_pqc: PqcLeafScalar(all_h_pqc[i]),
            spend_key_x: xs[i].to_repr(),
            spend_key_y: ys[i].to_repr(),
            commitment_mask: Scalar::random(&mut OsRng).to_repr(),
            pseudo_out_blind: Scalar::random(&mut OsRng).to_repr(),
            leaf_chunk_outputs: per_input_chunk[i]
                .iter()
                .map(|&j| (os[j].to_bytes(), is[j].to_bytes(), cs[j].to_bytes()))
                .collect(),
            leaf_chunk_h_pqc: per_input_chunk[i].iter().map(|&j| all_h_pqc[j]).collect(),
            c1_branch_layers: c1_layers.clone(),
            c2_branch_layers: c2_layers.clone(),
        })
        .collect();

    let result =
        prove(&inputs, &tree_root, tree_depth, signable_tx_hash).expect("fixture proof must build");

    let mut key_images_flat = Vec::with_capacity(32 * n_in);
    for i in 0..n_in {
        key_images_flat.extend_from_slice(&(is[i] * xs[i]).to_bytes());
    }

    let mut pseudo_outs_flat = Vec::with_capacity(32 * n_in);
    for po in &result.pseudo_outs {
        pseudo_outs_flat.extend_from_slice(po);
    }

    let mut pqc_hashes_flat = Vec::with_capacity(32 * n_in);
    for h in &all_h_pqc {
        pqc_hashes_flat.extend_from_slice(h);
    }

    // Output commitments: valid prime-order points, which is exactly what
    // `check_commitment_masks` is paid to confirm.
    let mut masks_flat = Vec::with_capacity(32 * n_out);
    for _ in 0..n_out {
        masks_flat.extend_from_slice(&EdwardsPoint::random(&mut OsRng).to_bytes());
    }

    AdmissionFixture {
        proof: result.proof.data,
        key_images_flat,
        pseudo_outs_flat,
        pqc_hashes_flat,
        tree_root,
        tree_depth,
        signable_tx_hash,
        masks_flat,
    }
}

/// The admission sequence, in `blockchain.cpp`'s order.
///
/// Returned rather than discarded so the optimiser cannot delete the work —
/// the fixture-drop artifact that made an earlier bench measure `zeroize`
/// instead of its workload.
pub fn admission_verify(f: &AdmissionFixture, n_in: usize, n_out: usize) -> u8 {
    let masks_rc =
        unsafe { shekyl_check_commitment_masks(f.masks_flat.as_ptr(), n_out, std::ptr::null(), 0) };

    let verify_rc = unsafe {
        shekyl_fcmp_verify(
            f.proof.as_ptr(),
            f.proof.len(),
            f.key_images_flat.as_ptr(),
            n_in,
            f.pseudo_outs_flat.as_ptr(),
            n_in,
            f.pqc_hashes_flat.as_ptr(),
            n_in,
            f.tree_root.as_ptr(),
            f.tree_depth,
            f.signable_tx_hash.as_ptr(),
        )
    };

    masks_rc ^ verify_rc
}
