// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixture for the §72 admission-verification benches: the masks
//! and the FCMP++ proof.
//!
//! `relay_admission_verify` (wall clock, the `hop` input's masks-and-proof
//! term) times this module's pair over 64 cells. The drift gate,
//! `relay_admission_verify_iai`, times the door's whole sequence
//! ([`crate::door`]), whose masks and proof are this module's fixture and
//! bodies. The GAP-7 connect fixture ([`crate::connect`]) builds on it too.
//!
//! # What the fixture is, and what it is not
//!
//! The proof is real — [`prove_with_rng`] over a tree synthesized here — and
//! [`admission_verify`] runs the verification bodies the pool door runs:
//! the mask check and the membership check behind
//! `shekyl_chain_rules::judge_slot_stateless` at `TxSlot::Lone`. This crate
//! calls those bodies. It does not call `judge_slot_stateless`, and it does
//! not depend on `shekyl-chain-rules`. The fixture is **not** a
//! consensus-valid transaction: the proof is made over a constant signable
//! hash, not `Transaction::tx_signable(network)`; each input's key scalar
//! `k` is drawn at random rather than derived from a revealed hybrid public
//! key (`PqcKeyScalar::from_pqc_public_key`); and there is no transaction
//! around it for `tx_form` to judge. Building one at the synthetic depths
//! 3..=7 would need the wallet builder's coordination
//! (`shekyl-tx-builder`), which draws from `OsRng` and so cannot give the
//! drift gate a byte-identical fixture.

use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use dalek_ff_group::{EdwardsPoint, Scalar};
use ec_divisors::DivisorCurve;
use helioselene::Selene;
use multiexp::multiexp_vartime;
use rand_core::{CryptoRng, RngCore};
use shekyl_ct_balance::{check_commitment_masks, MaskSubject, OutputPointsError};
use shekyl_curve_generators::{PQC_LEAF_COMMITMENT_G_K, PQC_LEAF_COMMITMENT_J};
use shekyl_curve_generators::{SELENE_HASH_INIT, T};
use shekyl_fcmp::proof::{
    prove_with_rng, verify, BranchLayer, KeyImage, ProveInput, ShekylFcmpProof, VerifyError,
};
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, helios_point_to_selene_scalar,
    selene_hash_init, selene_point_to_helios_scalar,
};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_fcmp_proofs::SELENE_FCMP_GENERATORS;
use shekyl_types::{CurveTreeRoot, TxSignableHash};

/// Both admission checks' results, kept apart.
///
/// The two bodies fail in different types — the mask rule's
/// [`OutputPointsError`] and the proof's [`VerifyError`] (or `Ok(false)`) — so
/// they are carried side by side rather than folded. A fold into one flag
/// loses *which* check refused, and a fold that can cancel loses *that* one
/// refused; either way the sweep could time the rejection path while its
/// self-witness assert passes. [`AdmissionStatus::verified`] is true for one
/// state only, and the `Debug` form names the refusing check when the assert
/// fires.
#[derive(Debug)]
pub struct AdmissionStatus {
    /// CEN-H17's body over the outputs' commitment masks.
    pub masks: Result<(), OutputPointsError>,
    /// CEN-I15's body over the proof.
    pub membership: Result<bool, VerifyError>,
}

impl AdmissionStatus {
    /// Both checks accepted — the only status a fixture the benches time may
    /// have.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.masks.is_ok() && matches!(self.membership, Ok(true))
    }
}

/// Everything the pool door's verification bodies read for one transaction.
pub struct AdmissionFixture {
    pub proof: Vec<u8>,
    pub key_images: Vec<KeyImage>,
    pub pseudo_outs: Vec<[u8; 32]>,
    pub pqc_keys: Vec<PqcKeyScalar>,
    pub tree_root: CurveTreeRoot,
    /// The proof's layer count (`declared tree_depth + 1` on the wire).
    pub tree_depth: u8,
    pub signable_tx_hash: TxSignableHash,
    /// Output commitment masks — `base.commitments`, the axis CEN-H17 walks.
    pub masks_flat: Vec<u8>,
    /// The shape this fixture WAS BUILT AT, carried so the admission call
    /// cannot be handed a different one: a caller-supplied shape that the
    /// fixture does not hold is a rejection, i.e. a silent measurement of the
    /// reject path rather than an error.
    pub n_in: usize,
    pub n_out: usize,
}

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

/// Build a verifiable `n_in`-input, `n_out`-output admission fixture.
///
/// Under [`ChunkLayout::Shared`] all inputs sit in one leaf chunk, so the leaf
/// layer is a single multiexp over `4 × n_in` scalars and every input walks the
/// same path — the control that keeps the sweep measuring **input count**
/// rather than tree depth, a second axis that would otherwise ride along and
/// produce F-7's confound (§69.2). [`ChunkLayout::Spread`] is the production
/// topology; see the enum.
///
/// All randomness — the fixture inputs **and** the FCMP++ proof (via
/// [`prove_with_rng`]) — is drawn from `rng`. The wall-clock bench passes
/// `OsRng`; the instruction-count bench passes a seeded RNG so the fixture is
/// byte-identical run-to-run and the drift gate's Callgrind counts are stable.
pub fn build_fixture<R: RngCore + CryptoRng>(
    rng: &mut R,
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
    // PL-D3 leaf commitments: k, r, CM = k*G_k + r*J; the leaf's 4th scalar is
    // CM.x and the verifier's per-input value is k.
    let mut ks: Vec<Scalar> = Vec::with_capacity(n_in);
    let mut rs: Vec<Scalar> = Vec::with_capacity(n_in);
    let mut cms: Vec<EdwardsPoint> = Vec::with_capacity(n_in);
    let mut cm_xs = Vec::with_capacity(n_in);

    for _ in 0..n_in {
        let x = Scalar::random(&mut *rng);
        let y = Scalar::random(&mut *rng);
        let o = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
        let i = EdwardsPoint::random(&mut *rng);
        let c = EdwardsPoint::random(&mut *rng);
        let k = Scalar::random(&mut *rng);
        let r = Scalar::random(&mut *rng);
        let cm = (EdwardsPoint(*PQC_LEAF_COMMITMENT_G_K) * k)
            + (EdwardsPoint(*PQC_LEAF_COMMITMENT_J) * r);
        let h = <EdwardsPoint as DivisorCurve>::to_xy(cm)
            .expect("CM is not the identity")
            .0;
        ks.push(k);
        rs.push(r);
        cms.push(cm);
        xs.push(x);
        ys.push(y);
        os.push(o);
        is.push(i);
        cs.push(c);
        cm_xs.push(h);
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
            terms.push((cm_xs[idx], generators[4 * slot + 3]));
        }
        *SELENE_HASH_INIT + multiexp_vartime(&terms)
    };

    let all: Vec<usize> = (0..n_in).collect();

    // Depth 1 roots at the leaf layer, which PRODUCTION NEVER DOES:
    // `tree.rs` states a non-empty tree yields depth >= 2, because a single
    // layer-0 node is promoted into a layer-1 Helios root rather than returned
    // bare. Depth 1 is kept only as the sub-production floor the first sweep
    // measured; depth 2 is the shallowest tree a live chain can present.
    // The walk is local rather than a call into `shekyl-engine-core`'s
    // `synthetic_tree` helpers, and deliberately: those are `pub(crate)`, they
    // build wallet-side `LeafEntry` trees, and they have no notion of the
    // multi-chunk `Spread` layout this sweep exists to measure. Widening a
    // production crate's visibility to serve a bench is the worse trade. What
    // IS shared is shared: the hashes and curve conversions below are
    // `shekyl_fcmp::tree`'s own, so the layer convention has one owner.
    //
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
            if layer.is_multiple_of(2) {
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

    let all_cm_x: Vec<[u8; 32]> = cm_xs.iter().map(PrimeField::to_repr).collect();

    let inputs: Vec<ProveInput> = (0..n_in)
        .map(|i| ProveInput {
            output_key: os[i].to_bytes(),
            key_image_gen: is[i].to_bytes(),
            commitment: cs[i].to_bytes(),
            pqc_leaf_commitment: cms[i].to_bytes(),
            pqc_leaf_blind: rs[i].to_repr(),
            spend_key_x: xs[i].to_repr(),
            spend_key_y: ys[i].to_repr(),
            commitment_mask: Scalar::random(&mut *rng).to_repr(),
            pseudo_out_blind: Scalar::random(&mut *rng).to_repr(),
            leaf_chunk_outputs: per_input_chunk[i]
                .iter()
                .map(|&j| (os[j].to_bytes(), is[j].to_bytes(), cs[j].to_bytes()))
                .collect(),
            leaf_chunk_cm_x: per_input_chunk[i].iter().map(|&j| all_cm_x[j]).collect(),
            c1_branch_layers: c1_layers.clone(),
            c2_branch_layers: c2_layers.clone(),
        })
        .collect();

    let tree_root = CurveTreeRoot::from_bytes(tree_root);
    let signable_tx_hash = TxSignableHash::from_bytes(signable_tx_hash);
    let result = prove_with_rng(&mut *rng, &inputs, &tree_root, tree_depth, signable_tx_hash)
        .expect("fixture proof must build");

    let key_images: Vec<KeyImage> = (0..n_in)
        .map(|i| KeyImage::from_canonical_bytes((is[i] * xs[i]).to_bytes()))
        .collect();

    // `k` from its canonical encoding, the boundary constructor; the door
    // derives it from the revealed hybrid public key instead (see the module
    // docs), which this fixture has no transaction to carry.
    let pqc_keys: Vec<PqcKeyScalar> = ks
        .iter()
        .map(|k| PqcKeyScalar::from_canonical_bytes(k.to_repr()).expect("k is a reduced scalar"))
        .collect();

    // Output commitments: valid prime-order points, which is exactly what
    // CEN-H17 is paid to confirm.
    let mut masks_flat = Vec::with_capacity(32 * n_out);
    for _ in 0..n_out {
        masks_flat.extend_from_slice(&EdwardsPoint::random(&mut *rng).to_bytes());
    }

    AdmissionFixture {
        proof: result.proof.data,
        key_images,
        pseudo_outs: result.pseudo_outs,
        pqc_keys,
        tree_root,
        tree_depth,
        signable_tx_hash,
        masks_flat,
        n_in,
        n_out,
    }
}

/// The admission checks this fixture can carry, in the pool door's order.
///
/// `shekyl_chain_rules::judge_slot_stateless` runs `tx_form` (CEN-H17's
/// mask rule among its rows), then the signatures (CEN-I17/I18), then the
/// proof (CEN-I15), then — at `TxSlot::Lone` — the range proof as a batch of
/// one (CEN-H19). This calls the bodies of H17 and I15, in that order:
/// [`check_commitment_masks`] under [`MaskSubject::Spend`], and
/// [`verify`] with the arguments I15 marshals (`layers` = the declared depth
/// plus one). The signature and range-proof terms are not in this pair:
/// [`crate::door::door_verify`] runs all four in the door's order, and the
/// GAP-7 connect bench times each beside it.
///
/// The shape comes from the fixture, not from the caller, so the pair cannot
/// disagree. The status is returned rather than discarded so the optimiser
/// cannot delete the work — and both results are returned, not folded, so the
/// callers' `assert!(…verified())` is a real self-witness (see
/// [`AdmissionStatus`]).
pub fn admission_verify(f: &AdmissionFixture) -> AdmissionStatus {
    let masks = masks_check(f);
    let membership = membership_verify(f);
    AdmissionStatus { masks, membership }
}

/// CEN-H17's body over the fixture's output masks: what `tx_form` runs on a
/// spend ([`check_commitment_masks`] under [`MaskSubject::Spend`]).
pub fn masks_check(f: &AdmissionFixture) -> Result<(), OutputPointsError> {
    check_commitment_masks(&f.masks_flat, f.n_out, MaskSubject::Spend)
}

/// CEN-I15's body over the fixture's proof: [`verify`] with the arguments
/// `I15::verify` marshals (the proof bytes owned by a [`ShekylFcmpProof`], as
/// I15 clones them out of the prunable region).
pub fn membership_verify(f: &AdmissionFixture) -> Result<bool, VerifyError> {
    let proof = ShekylFcmpProof {
        data: f.proof.clone(),
        num_inputs: u32::try_from(f.n_in).expect("n_in <= MAX_INPUTS"),
        tree_depth: f.tree_depth,
    };
    verify(
        &proof,
        &f.key_images,
        &f.pseudo_outs,
        &f.pqc_keys,
        &f.tree_root,
        f.tree_depth,
        f.signable_tx_hash,
    )
}
