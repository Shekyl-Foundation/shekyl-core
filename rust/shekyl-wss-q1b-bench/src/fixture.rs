// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corpus: leaves, trees, paths, and the `ProveInput`s the denominator is
//! measured on.
//!
//! ## Two path provenances, and why both exist
//!
//! The denominator is the prover invocation at a stated **depth**, and §6.3.2
//! row 4 puts the production target at ~6 layers. A *dense* depth-6 tree needs
//! [`crate::corpus::min_leaves_for_depth`]`(6)` = 17 778 529 leaves — about
//! 2.3 GB of leaf scalars before a single layer is allocated, on a board the
//! rig pins at 8 GB. Building one to time a prover would be hostile, and it is
//! also unnecessary: `proof::prove` takes `tree_depth` directly and the circuit
//! pads each chunk to the layer width, so a path with one real child per layer
//! should cost what a full one costs.
//!
//! *Should*. That claim is load-bearing for the whole approach, so the harness
//! **proves it rather than citing the padding comment** — see
//! [`control_experiment`]. The control is run at a depth where both arms are
//! cheap, and it holds sparsity as the only variable: same depth, dense path
//! versus sparse path. Comparing a sparse depth-6 path against a dense depth-4
//! one — as this harness's opening brief proposed — varies depth *and*
//! sparsity at once and could not attribute a difference to either.
//!
//! ## What the leaf values are
//!
//! Only the 38 leaves of the spent leaf's own chunk need to be real outputs
//! with openable secrets; every other leaf in the tree is only ever a scalar
//! fed to `hash_grow`. Those are filled by repeating the real chunk's scalars.
//! Hash cost is identical for any valid scalar, so the replay measurement is
//! unaffected — and the alternative, generating millions of independent curve
//! points, would spend the measurement's whole budget on corpus construction.

use ciphersuite::group::{ff::PrimeField, Group, GroupEncoding};
use dalek_ff_group::{EdwardsPoint, Scalar};
use rand_core::OsRng;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf;
use shekyl_curve_generators::T;
use shekyl_fcmp::leaf::{PqcKeyScalar, PqcLeafScalar};
use shekyl_fcmp::proof::{self, BranchLayer, KeyImage, ProveInput};
use shekyl_fcmp::tree::{
    build_layers, chunk_width, ed25519_point_to_selene_scalar, hash_grow_helios, hash_grow_selene,
    helios_hash_init, helios_point_to_selene_scalar, key_image_generator, layer_is_selene,
    selene_hash_init, selene_point_to_helios_scalar, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};

const ZERO: [u8; 32] = [0u8; 32];

/// One leaf of the spent output's chunk, with the material a `ProveInput`
/// needs.
#[derive(Clone)]
pub struct ChunkLeaf {
    /// Compressed Ed25519 output key `O`.
    pub output_key: [u8; 32],
    /// `I = Hp(O)`.
    pub key_image_gen: [u8; 32],
    /// Compressed Pedersen commitment `C`.
    pub commitment: [u8; 32],
    /// `CM.x`, the 4th leaf scalar.
    pub cm_x: [u8; 32],
    /// `CM` itself.
    pub pqc_commitment: [u8; 32],
    /// `CM`'s blind.
    pub pqc_blind: [u8; 32],
    /// Spend secret `x`.
    pub spend_key_x: [u8; 32],
    /// SAL secret `y`.
    pub spend_key_y: [u8; 32],
    /// Commitment mask `z`.
    pub commitment_mask: [u8; 32],
    /// `k = H_l(hybrid_pk)` — the verifier's opening input, kept so the
    /// harness's own `verify` round-trip is constructible without a second
    /// derivation path. Carried as the type, not as bytes: its canonical-
    /// encoding invariant is the reason the field inside it is private.
    pub pqc_key_scalar: PqcKeyScalar,
}

impl ChunkLeaf {
    /// The four Selene scalars this leaf contributes to the tree, in leaf
    /// order (`O.x`, `I.x`, `C.x`, `CM.x`) — the layout
    /// `shekyl_curve_tree`'s `construct_leaf` persists and `assemble.rs` reads
    /// `cm_x` back out of at `[96..128]`.
    #[must_use]
    pub fn scalars(&self) -> Option<[[u8; 32]; SCALARS_PER_LEAF]> {
        Some([
            ed25519_point_to_selene_scalar(&self.output_key)?,
            ed25519_point_to_selene_scalar(&self.key_image_gen)?,
            ed25519_point_to_selene_scalar(&self.commitment)?,
            self.cm_x,
        ])
    }
}

/// A leaf population plus the real chunk the spend is taken from.
pub struct Corpus {
    /// Every leaf scalar in the tree, in tree order.
    pub leaf_scalars: Vec<[u8; 32]>,
    /// The real leaves occupying chunk 0.
    pub chunk: Vec<ChunkLeaf>,
    /// Which entry of [`Corpus::chunk`] is spent.
    pub spent_index: usize,
    /// Leaves in the tree.
    pub leaves: u64,
}

/// A membership path as the prover consumes it.
#[derive(Clone)]
pub struct Path {
    /// Selene branch layers.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios branch layers.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
    /// The root point.
    pub tree_root: [u8; 32],
    /// `c1_layers.len() + c2_layers.len() + 1`.
    pub tree_depth: u8,
}

/// Build a leaf population of `leaves` leaves.
///
/// # Panics
/// If the derived curve points are not convertible, which would mean the
/// production derivation produced an inadmissible leaf.
#[must_use]
pub fn build_corpus(leaves: u64, seed: u8) -> Corpus {
    let chunk = build_real_chunk(seed);
    let chunk_scalars: Vec<[u8; 32]> = chunk
        .iter()
        .flat_map(|l| l.scalars().expect("derived leaf converts to scalars"))
        .collect();

    let total_scalars = (leaves as usize) * SCALARS_PER_LEAF;
    let mut leaf_scalars = Vec::with_capacity(total_scalars);
    while leaf_scalars.len() < total_scalars {
        let take = (total_scalars - leaf_scalars.len()).min(chunk_scalars.len());
        leaf_scalars.extend_from_slice(&chunk_scalars[..take]);
    }

    Corpus {
        leaf_scalars,
        chunk,
        spent_index: 0,
        leaves,
    }
}

/// The replay proxy: hash the window's leaves into a tree.
///
/// **Stated direction of error, per term** (§6.3.4 wants the model, not the
/// word "bound"):
///
/// - **Leaf-layer hashing is exact.** Every window leaf is hashed into its
///   Selene chunk exactly once here and exactly once in a frontier advance.
///   This term dominates by roughly the leaf-chunk width (38×).
/// - **Upper-layer work is under-modelled.** A window tree is 3–4 layers, so
///   this propagates 2–3 layers where a real advance at depth 6 propagates ~6.
/// - **Net: an upper bound**, because `build_layers` rehashes *every* upper
///   node from scratch while a frontier advance touches only the rightmost
///   node per layer — a saving far larger than the missing layers cost.
#[must_use]
pub fn replay(corpus: &Corpus) -> Vec<Vec<[u8; 32]>> {
    build_layers(&corpus.leaf_scalars)
}

/// Read a dense path off built layers — the same walk `assemble.rs` performs.
#[must_use]
pub fn read_off_path(layers: &[Vec<[u8; 32]>], leaf_pos: usize) -> Path {
    let depth = u8::try_from(layers.len()).expect("curve-tree depth fits u8");
    let mut c1_layers = Vec::new();
    let mut c2_layers = Vec::new();
    let mut child_node_idx = leaf_pos / SELENE_CHUNK_WIDTH;
    for layer in 1..depth {
        let width = chunk_width(layer);
        let node_idx = child_node_idx / width;
        let prev = &layers[usize::from(layer) - 1];
        let start = node_idx * width;
        let end = (start + width).min(prev.len());
        if layer_is_selene(layer) {
            c1_layers.push(
                prev[start..end]
                    .iter()
                    .map(|p| helios_point_to_selene_scalar(p).expect("helios->selene"))
                    .collect(),
            );
        } else {
            c2_layers.push(
                prev[start..end]
                    .iter()
                    .map(|p| selene_point_to_helios_scalar(p).expect("selene->helios"))
                    .collect(),
            );
        }
        child_node_idx = node_idx;
    }
    Path {
        c1_layers,
        c2_layers,
        tree_root: *layers
            .last()
            .expect("non-empty tree")
            .first()
            .expect("root"),
        tree_depth: depth,
    }
}

/// Synthesize a path to `tree_depth` with one real child per internal layer.
///
/// The root this returns is a genuine hash of the chain below it — the prover
/// and the verifier both see a well-formed tree. What makes it *synthetic* is
/// only that no chain produced it. Nothing about the circuit's cost depends on
/// that, which is the claim [`control_experiment`] checks.
///
/// # Panics
/// If a hash-grow or point conversion fails, which for valid leaf scalars is a
/// logic error rather than an input condition.
#[must_use]
pub fn synth_sparse_path(corpus: &Corpus, tree_depth: u8) -> Path {
    let leaf_chunk_scalars: Vec<[u8; 32]> = corpus
        .chunk
        .iter()
        .flat_map(|l| l.scalars().expect("derived leaf converts to scalars"))
        .collect();
    let mut node =
        hash_grow_selene(&selene_hash_init(), 0, &ZERO, &leaf_chunk_scalars).expect("leaf chunk");

    let mut c1_layers = Vec::new();
    let mut c2_layers = Vec::new();
    for layer in 1..tree_depth {
        if layer_is_selene(layer) {
            let child = helios_point_to_selene_scalar(&node).expect("helios->selene");
            c1_layers.push(vec![child]);
            node = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &[child]).expect("selene grow");
        } else {
            let child = selene_point_to_helios_scalar(&node).expect("selene->helios");
            c2_layers.push(vec![child]);
            node = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &[child]).expect("helios grow");
        }
    }
    Path {
        c1_layers,
        c2_layers,
        tree_root: node,
        tree_depth,
    }
}

/// Build the `ProveInput`s for the canonical shape against `path`.
///
/// Every input spends a distinct leaf of the same chunk, which is what a
/// 2-in transaction from one wallet ordinarily looks like.
#[must_use]
pub fn prove_inputs(corpus: &Corpus, path: &Path, n_in: usize) -> Vec<ProveInput> {
    let leaf_chunk_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = corpus
        .chunk
        .iter()
        .map(|l| (l.output_key, l.key_image_gen, l.commitment))
        .collect();
    let leaf_chunk_cm_x: Vec<[u8; 32]> = corpus.chunk.iter().map(|l| l.cm_x).collect();
    let c1: Vec<BranchLayer> = path
        .c1_layers
        .iter()
        .map(|s| BranchLayer {
            siblings: s.clone(),
        })
        .collect();
    let c2: Vec<BranchLayer> = path
        .c2_layers
        .iter()
        .map(|s| BranchLayer {
            siblings: s.clone(),
        })
        .collect();

    (0..n_in)
        .map(|i| {
            let leaf = &corpus.chunk[(corpus.spent_index + i) % corpus.chunk.len()];
            ProveInput {
                output_key: leaf.output_key,
                key_image_gen: leaf.key_image_gen,
                commitment: leaf.commitment,
                pqc_leaf_commitment: leaf.pqc_commitment,
                pqc_leaf_blind: leaf.pqc_blind,
                spend_key_x: leaf.spend_key_x,
                spend_key_y: leaf.spend_key_y,
                commitment_mask: leaf.commitment_mask,
                // Independent of the mask on purpose: the prover's commitment
                // rerandomization is `r_c = a - z`, so `a == z` is a zero
                // blinding factor and `prove` refuses it
                // (`ProveError::ScalarDecompositionFailed`). In production
                // `sign.rs` constrains the last input's blind for balance and
                // randomizes the rest; the harness does not build a balanced
                // transaction, so every input gets a fresh blind.
                pseudo_out_blind: Scalar::random(&mut OsRng).to_repr(),
                leaf_chunk_outputs: leaf_chunk_outputs.clone(),
                leaf_chunk_cm_x: leaf_chunk_cm_x.clone(),
                c1_branch_layers: c1.clone(),
                c2_branch_layers: c2.clone(),
            }
        })
        .collect()
}

/// The key image `L = I · x` for one leaf — the verifier's per-input handle.
///
/// # Panics
/// If the leaf's own secrets do not decode, which would mean the fixture built
/// an output it cannot spend.
#[must_use]
pub fn key_image(leaf: &ChunkLeaf) -> KeyImage {
    let x = Scalar::from_repr(leaf.spend_key_x).expect("fixture spend key is canonical");
    let i = EdwardsPoint::from_bytes(&leaf.key_image_gen).expect("fixture key-image generator");
    KeyImage::from_canonical_bytes((i * x).to_bytes())
}

/// Prove, then **verify**, one canonical-shape spend.
///
/// The bench contract (`WSS_Q1B_BENCH_SPEC.md` §3.6) says every measured
/// `Path` round-trips through `proof::verify`. Until this existed that was
/// true only of the unit tests: both binaries set `paths_verified: true` from
/// `prove`'s `Ok`, which records that the prover *returned*, not that what it
/// returned is coherent with the root.
///
/// **Deliberately not called inside a timed series.** `verify` is real work
/// (~35 ms per input) and the denominator is defined as the prover invocation
/// alone, so folding it in would inflate the figure the 15 % arm is taken
/// against — the same boundary violation that rules out driving
/// `sign_transaction`. Call it once, outside the timer, to establish the
/// artifacts are real; time `prove_only` separately.
///
/// **What this establishes, and what it does not:** `verify` takes the root as
/// an *input*, so a self-consistent wrong tree verifies. This proves the path
/// and the prover are coherent with each other, not that the tree matches
/// consensus — that is CT-2's reconstruct-root KAT's claim.
///
/// # Errors
/// Propagates the prover's error; a proof that fails verification returns
/// `Ok(false)`.
pub fn prove_and_verify(
    corpus: &Corpus,
    path: &Path,
    n_in: usize,
    signable_tx_hash: [u8; 32],
) -> Result<bool, proof::ProveError> {
    let inputs = prove_inputs(corpus, path, n_in);
    let result = prove_only(&inputs, path, signable_tx_hash)?;
    let images: Vec<KeyImage> = (0..n_in)
        .map(|i| key_image(&corpus.chunk[(corpus.spent_index + i) % corpus.chunk.len()]))
        .collect();
    let keys: Vec<PqcKeyScalar> = (0..n_in)
        .map(|i| corpus.chunk[(corpus.spent_index + i) % corpus.chunk.len()].pqc_key_scalar)
        .collect();
    Ok(proof::verify(
        &result.proof,
        &images,
        &result.pseudo_outs,
        &keys,
        &path.tree_root,
        path.tree_depth,
        signable_tx_hash,
    )
    .unwrap_or(false))
}

/// Invoke the prover — **the denominator, and nothing else**.
///
/// This is `shekyl_fcmp::proof::prove`, the same function
/// `shekyl-tx-builder/src/sign.rs:171` calls. Driving the measurement through
/// `sign_transaction` instead would fold the Bulletproof+ range proof
/// (`sign.rs:113`) and the PQC signing into the denominator, inflating it and
/// silently loosening the 15 % arm — the boundary violation §6.3.4 draws the
/// seam to prevent.
///
/// # Errors
/// Propagates the prover's own error.
pub fn prove_only(
    inputs: &[ProveInput],
    path: &Path,
    signable_tx_hash: [u8; 32],
) -> Result<proof::ProveResult, proof::ProveError> {
    proof::prove(inputs, &path.tree_root, path.tree_depth, signable_tx_hash)
}

fn build_real_chunk(seed: u8) -> Vec<ChunkLeaf> {
    (0..SELENE_CHUNK_WIDTH)
        .map(|i| build_real_leaf(seed, i as u64))
        .collect()
}

fn build_real_leaf(seed: u8, index: u64) -> ChunkLeaf {
    let mut combined = [0u8; 64];
    combined[0] = seed;
    combined[1..9].copy_from_slice(&index.to_le_bytes());
    let pqc = derive_pqc_leaf(&combined, index).expect("production PQC leaf derivation");
    let pqc_pk = derive_pqc_public_key(&combined, index).expect("production PQC public key");
    let pqc_key_scalar = PqcKeyScalar::from_pqc_public_key(pqc_pk.as_ref());
    // `CM` itself, not the `0x07` entry: the entry is `CM || record`, and only
    // the point is the leaf's 4th-scalar source.
    let pqc_commitment = pqc.point;
    let cm_x = PqcLeafScalar::from_commitment_point(&pqc_commitment)
        .expect("derived commitment is a point")
        .0;
    let spend = derive_spend();
    ChunkLeaf {
        key_image_gen: key_image_generator(&spend.output_key),
        output_key: spend.output_key,
        commitment: spend.commitment,
        cm_x,
        pqc_commitment,
        pqc_blind: pqc.blind,
        spend_key_x: spend.spend_key_x,
        spend_key_y: spend.spend_key_y,
        commitment_mask: spend.commitment_mask,
        pqc_key_scalar,
    }
}

/// One spendable output's public points and the secrets that open them.
struct SpendMaterial {
    output_key: [u8; 32],
    spend_key_x: [u8; 32],
    spend_key_y: [u8; 32],
    commitment: [u8; 32],
    commitment_mask: [u8; 32],
}

/// Build one spendable output: `O = xG + yT`, and a Pedersen commitment.
///
/// The secrets are random rather than derived from `seed`/`index`: the corpus's
/// *values* never enter a timing, only its *shape* does, and a deterministic
/// scalar derivation here would be a second key-derivation implementation
/// beside the wallet's for no gain.
fn derive_spend() -> SpendMaterial {
    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);
    let o = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
    let z = Scalar::random(&mut OsRng);
    let c = EdwardsPoint::random(&mut OsRng);
    SpendMaterial {
        output_key: o.to_bytes(),
        spend_key_x: x.to_repr(),
        spend_key_y: y.to_repr(),
        commitment: c.to_bytes(),
        commitment_mask: z.to_repr(),
    }
}

/// The control experiment: **same depth, sparse versus dense**.
///
/// Holds sparsity as the only variable, which is what makes a difference
/// attributable to it. Run at a depth where a dense tree is cheap; the result
/// licenses (or refuses) the sparse path at depths where one is not.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ControlExperiment {
    /// The depth both arms were proved at.
    pub tree_depth: u8,
    /// Leaves the dense arm's tree held.
    pub dense_leaves: u64,
    /// Dense-arm prover seconds.
    pub dense_s: f64,
    /// Sparse-arm prover seconds.
    pub sparse_s: f64,
    /// `|sparse - dense| / dense`, as a percentage.
    pub divergence_pct: f64,
    /// Whether the divergence is within tolerance.
    pub sparse_equals_dense: bool,
    /// Whether both arms' proofs verified.
    pub both_verified: bool,
}

#[cfg(test)]
#[path = "fixture_tests.rs"]
mod tests;
