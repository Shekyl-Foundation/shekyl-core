// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

// A membership proof over a tree the fuzz input builds, checked against the
// root a block header would carry.
//
// The spent output is real and fixed: its secrets come from the production
// per-output derivation (`derive_output_secrets`, `derive_pqc_leaf`,
// `derive_pqc_public_key`) over a fixed combined secret, and the spend key
// `b` from a fixed seed, so `O = (ho + b)·G + y·T` opens. Everything around
// it is fuzz input: the output's amount, how many sibling outputs share its
// leaf chunk and where it sits among them, each sibling's points and leaf
// scalar, the tree's depth, every upper layer's siblings and the position of
// the path's node among them, the signable hash, and a second root and hash
// to verify against. Missing input bytes read as zero, so every input builds
// a tree; the empty input is a one-leaf tree at depth 1.
//
// The oracle:
// - a tree the hashes accept is a tree the prover proves over, and its
//   proof verifies against that root, at that depth, over that hash;
// - the same proof never verifies against another root or another hash.
//
// The harness it replaces handed the prover an output key of `[1; 32]`,
// which is not a point, so every input stopped at the prover's first check.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::Scalar;
use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::derivation::{derive_output_secrets, derive_pqc_public_key};
use shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf;
use shekyl_curve_generators::{biased_hash_to_point, H, T};
use shekyl_fcmp::leaf::{PqcKeyScalar, PqcLeafScalar};
use shekyl_fcmp::proof::{prove, verify, BranchLayer, KeyImage, ProveInput};
use shekyl_fcmp::tree::{
    chunk_width, hash_grow_helios, hash_grow_selene,
    helios_hash_init, helios_point_to_selene_scalar, key_image_generator, layer_is_selene,
    leaf_from_chunk_entry, selene_hash_init, selene_point_to_helios_scalar, SELENE_CHUNK_WIDTH,
};
use shekyl_types::{CurveTreeRoot, TxSignableHash};

/// The combined secret the spent output's secrets are derived from. Fixed, so
/// every run proves the same output; never a live wallet's.
const COMBINED_SS: [u8; 64] = [0x5a; 64];
/// The spent output's index under [`COMBINED_SS`].
const OUTPUT_INDEX: u64 = 0;
/// The spend key `b`'s seed, reduced to a scalar.
const SPEND_KEY_SEED: [u8; 32] = [0x3c; 32];
/// The pseudo-out blind. It must differ from the commitment mask `z`, or the
/// rerandomization `a - z` is zero and the prover refuses it.
const PSEUDO_OUT_BLIND: [u8; 32] = [0x07; 32];
/// Deepest tree built. Production trees are 2 layers or more; depth 1 (a root
/// at the leaf layer) is kept because the prover accepts it.
const MAX_DEPTH: u8 = 4;

const ZERO: [u8; 32] = [0u8; 32];

/// The fuzz input as a stream; reads past its end are zeros.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for b in &mut out {
            *b = self.byte();
        }
        out
    }

    fn u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        for b in &mut out {
            *b = self.byte();
        }
        u64::from_le_bytes(out)
    }
}

/// The spent output: its public points and the secrets that open them.
struct Spent {
    output_key: [u8; 32],
    key_image_gen: [u8; 32],
    pqc_leaf_commitment: [u8; 32],
    pqc_leaf_blind: [u8; 32],
    cm_x: [u8; 32],
    pqc_key: PqcKeyScalar,
    x: Scalar,
    y: Scalar,
    z: Scalar,
}

/// Derived once: the PQC key derivation is an ML-DSA key generation.
fn spent() -> &'static Spent {
    static SPENT: std::sync::OnceLock<Spent> = std::sync::OnceLock::new();
    SPENT.get_or_init(derive_spent)
}

fn derive_spent() -> Spent {
    let secrets = derive_output_secrets(&COMBINED_SS, OUTPUT_INDEX);
    let ho = Scalar::from_bytes_mod_order(secrets.ho);
    let y = Scalar::from_bytes_mod_order(secrets.y);
    let z = Scalar::from_bytes_mod_order(secrets.z);
    let b = Scalar::from_bytes_mod_order(SPEND_KEY_SEED);
    let x = ho + b;
    let output_key = (ED25519_BASEPOINT_POINT * x + *T * y).compress().to_bytes();
    let pqc = derive_pqc_leaf(&COMBINED_SS, OUTPUT_INDEX).expect("production PQC leaf");
    let pqc_pk = derive_pqc_public_key(&COMBINED_SS, OUTPUT_INDEX).expect("production PQC key");
    let cm_x = PqcLeafScalar::from_commitment_point(&pqc.point)
        .expect("a derived commitment is a point")
        .0;
    Spent {
        key_image_gen: key_image_generator(&output_key),
        output_key,
        pqc_leaf_commitment: pqc.point,
        pqc_leaf_blind: pqc.blind,
        cm_x,
        pqc_key: PqcKeyScalar::from_pqc_public_key(&pqc_pk),
        x,
        y,
        z,
    }
}

fuzz_target!(|data: &[u8]| {
    let s = spent();
    let mut input = Input(data);

    let tree_depth = 1 + input.byte() % MAX_DEPTH;
    let signable_tx_hash = TxSignableHash::from_bytes(input.bytes32());
    let other_root = input.bytes32();
    let other_hash = input.bytes32();

    // The spent output's commitment, over a fuzz-chosen amount.
    let amount = input.u64();
    let commitment = (ED25519_BASEPOINT_POINT * s.z + *H * Scalar::from(amount))
        .compress()
        .to_bytes();

    // The leaf chunk: the spent output among up to 37 siblings, each a pair of
    // hashed-to points and a raw fourth scalar.
    let siblings = usize::from(input.byte()) % SELENE_CHUNK_WIDTH;
    let position = usize::from(input.byte()) % (siblings + 1);
    let mut chunk_outputs = Vec::with_capacity(siblings + 1);
    let mut chunk_cm_x = Vec::with_capacity(siblings + 1);
    for _ in 0..siblings {
        let o = biased_hash_to_point(input.bytes32()).compress().to_bytes();
        let c = biased_hash_to_point(input.bytes32()).compress().to_bytes();
        chunk_outputs.push((o, key_image_generator(&o), c));
        chunk_cm_x.push(input.bytes32());
    }
    chunk_outputs.insert(position, (s.output_key, s.key_image_gen, commitment));
    chunk_cm_x.insert(position, s.cm_x);

    let mut leaf_scalars = Vec::with_capacity(4 * chunk_outputs.len());
    for ((o, i, c), cm_x) in chunk_outputs.iter().zip(&chunk_cm_x) {
        // Every point here decompresses (hashed-to, or the spent output's
        // own), so this refuses nothing yet; it is the served-chunk path.
        let Some(leaf) = leaf_from_chunk_entry(o, i, c, cm_x) else {
            return;
        };
        for scalar in leaf.chunks_exact(32) {
            leaf_scalars.push(<[u8; 32]>::try_from(scalar).expect("32-byte chunk"));
        }
    }
    // A raw fourth scalar outside the field is refused here.
    let Some(mut node) = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &leaf_scalars) else {
        return;
    };

    // Each layer above the leaf: the path's child among fuzz-chosen siblings.
    let mut c1_branch_layers = Vec::new();
    let mut c2_branch_layers = Vec::new();
    for layer in 1..tree_depth {
        let width = chunk_width(layer);
        let siblings = usize::from(input.byte()) % width;
        let position = usize::from(input.byte()) % (siblings + 1);
        let mut children: Vec<[u8; 32]> = (0..siblings).map(|_| input.bytes32()).collect();
        if layer_is_selene(layer) {
            let child = helios_point_to_selene_scalar(&node).expect("a grown node converts");
            children.insert(position, child);
            let Some(grown) = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &children) else {
                return;
            };
            node = grown;
            c1_branch_layers.push(BranchLayer { siblings: children });
        } else {
            let child = selene_point_to_helios_scalar(&node).expect("a grown node converts");
            children.insert(position, child);
            let Some(grown) = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &children) else {
                return;
            };
            node = grown;
            c2_branch_layers.push(BranchLayer { siblings: children });
        }
    }
    let tree_root = CurveTreeRoot::from_bytes(node);

    let prove_input = ProveInput {
        output_key: s.output_key,
        key_image_gen: s.key_image_gen,
        commitment,
        pqc_leaf_commitment: s.pqc_leaf_commitment,
        pqc_leaf_blind: s.pqc_leaf_blind,
        spend_key_x: s.x.to_bytes(),
        spend_key_y: s.y.to_bytes(),
        commitment_mask: s.z.to_bytes(),
        pseudo_out_blind: PSEUDO_OUT_BLIND,
        leaf_chunk_outputs: chunk_outputs,
        leaf_chunk_cm_x: chunk_cm_x,
        c1_branch_layers,
        c2_branch_layers,
    };
    let proved = match prove(&[prove_input], &tree_root, tree_depth, signable_tx_hash) {
        Ok(p) => p,
        Err(e) => panic!("the prover refused a tree the hashes accept, at depth {tree_depth}: {e}"),
    };

    let key_image_gen = CompressedEdwardsY(s.key_image_gen)
        .decompress()
        .expect("I = Hp(O) is a point");
    let key_images = [KeyImage::from_canonical_bytes(
        (key_image_gen * s.x).compress().to_bytes(),
    )];
    let pqc_keys = [s.pqc_key];
    let verifies = |root: &CurveTreeRoot, hash: TxSignableHash| {
        verify(
            &proved.proof,
            &key_images,
            &proved.pseudo_outs,
            &pqc_keys,
            root,
            tree_depth,
            hash,
        )
    };

    match verifies(&tree_root, signable_tx_hash) {
        Ok(true) => {}
        other => panic!("a proof over the tree failed to verify against its root: {other:?}"),
    }
    let other_root = CurveTreeRoot::from_bytes(other_root);
    if other_root != tree_root {
        if let Ok(true) = verifies(&other_root, signable_tx_hash) {
            panic!("the proof verified against a root other than the tree's");
        }
    }
    let other_hash = TxSignableHash::from_bytes(other_hash);
    if other_hash != signable_tx_hash {
        if let Ok(true) = verifies(&tree_root, other_hash) {
            panic!("the proof verified over a hash other than the one it proved");
        }
    }
});
