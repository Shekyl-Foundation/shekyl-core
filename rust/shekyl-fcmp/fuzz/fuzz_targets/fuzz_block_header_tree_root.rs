// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

// The verifier against the root a block header carries: one valid proof,
// and every way the verify-time inputs can differ from what it proved.
//
// The proof is built once, before the first input, over a small real tree
// and from a seeded generator, so every run fuzzes the same proof. The
// spent output is real: its secrets come from the production per-output
// derivation (`derive_output_secrets`, `derive_pqc_leaf`,
// `derive_pqc_public_key`) over a fixed combined secret, and its spend key
// `b` from a fixed seed, so `O = (ho + b)·G + y·T` opens. Its leaf chunk
// holds three sibling outputs, and the tree is two layers deep, the
// shallowest a live chain presents.
//
// The fuzz input chooses which of the verify-time inputs to replace, and
// with what: the root, the depth, the signable hash, the key image, and
// the proof's bytes (cut short, extended, or with bytes flipped).
//
// The oracle: the proof verifies when every one of those equals what was
// proved, and never otherwise.
//
// The harness this replaces proved a fresh tree on every input, about 9 s
// an input under the address sanitizer, a few dozen inputs in the nightly
// run's five minutes. The harness before that handed the prover an output
// key of `[1; 32]`, which is not a point, and so proved nothing.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::Scalar;
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shekyl_crypto_pq::derivation::{derive_output_secrets, derive_pqc_public_key};
use shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf;
use shekyl_curve_generators::{biased_hash_to_point, H, T};
use shekyl_fcmp::leaf::{PqcKeyScalar, PqcLeafScalar};
use shekyl_fcmp::proof::{
    prove_with_rng, verify, BranchLayer, KeyImage, ProveInput, ShekylFcmpProof,
};
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, key_image_generator,
    leaf_from_chunk_entry, selene_hash_init, selene_point_to_helios_scalar,
};
use shekyl_types::{CurveTreeRoot, TxSignableHash};

/// The combined secret the outputs' secrets are derived from. Fixed, so
/// every run proves the same tree; never a live wallet's.
const COMBINED_SS: [u8; 64] = [0x5a; 64];
/// The spend key `b`'s seed, reduced to a scalar.
const SPEND_KEY_SEED: [u8; 32] = [0x3c; 32];
/// The seed of the generator the proof's blinds are drawn from.
const PROOF_SEED: [u8; 32] = [0x2b; 32];
/// The pseudo-out blind. It must differ from the commitment mask `z`, or the
/// rerandomization `a - z` is zero and the prover refuses it.
const PSEUDO_OUT_BLIND: [u8; 32] = [0x07; 32];
/// The spent output's amount.
const AMOUNT: u64 = 1_000_000;
/// Sibling outputs beside the spent one in its leaf chunk.
const SIBLINGS: u64 = 3;
/// Layers: the leaf layer and one Helios layer above it.
const TREE_DEPTH: u8 = 2;
/// The signable hash the proof is made over.
const SIGNABLE_TX_HASH: [u8; 32] = [0xab; 32];

const ZERO: [u8; 32] = [0u8; 32];

/// What was proved, and the proof.
struct Proved {
    proof: ShekylFcmpProof,
    pseudo_outs: Vec<[u8; 32]>,
    pqc_key: PqcKeyScalar,
    key_image: [u8; 32],
    root: [u8; 32],
}

fn proved() -> &'static Proved {
    static PROVED: std::sync::OnceLock<Proved> = std::sync::OnceLock::new();
    PROVED.get_or_init(prove_once)
}

/// One leaf of the chunk: `(O, I, C)` and its fourth scalar `CM.x`.
fn leaf(output_key: [u8; 32], commitment: [u8; 32], index: u64) -> (([u8; 32], [u8; 32], [u8; 32]), [u8; 32]) {
    let pqc = derive_pqc_leaf(&COMBINED_SS, index).expect("production PQC leaf");
    let cm_x = PqcLeafScalar::from_commitment_point(&pqc.point)
        .expect("a derived commitment is a point")
        .0;
    ((output_key, key_image_generator(&output_key), commitment), cm_x)
}

fn prove_once() -> Proved {
    let secrets = derive_output_secrets(&COMBINED_SS, 0);
    let x = Scalar::from_bytes_mod_order(secrets.ho) + Scalar::from_bytes_mod_order(SPEND_KEY_SEED);
    let y = Scalar::from_bytes_mod_order(secrets.y);
    let z = Scalar::from_bytes_mod_order(secrets.z);
    let output_key = (ED25519_BASEPOINT_POINT * x + *T * y).compress().to_bytes();
    let commitment = (ED25519_BASEPOINT_POINT * z + *H * Scalar::from(AMOUNT))
        .compress()
        .to_bytes();
    let pqc = derive_pqc_leaf(&COMBINED_SS, 0).expect("production PQC leaf");
    let pqc_pk = derive_pqc_public_key(&COMBINED_SS, 0).expect("production PQC key");

    // The chunk: the spent output, then its siblings.
    let mut chunk = vec![leaf(output_key, commitment, 0)];
    for index in 1..=SIBLINGS {
        let seed = [u8::try_from(index).expect("few siblings"); 32];
        let mut other = seed;
        other[0] ^= 0x80;
        chunk.push(leaf(
            biased_hash_to_point(seed).compress().to_bytes(),
            biased_hash_to_point(other).compress().to_bytes(),
            index,
        ));
    }
    let mut scalars = Vec::new();
    for ((o, i, c), cm_x) in &chunk {
        let leaf = leaf_from_chunk_entry(o, i, c, cm_x).expect("every point decompresses");
        scalars.extend(leaf.chunks_exact(32).map(|s| <[u8; 32]>::try_from(s).expect("32 bytes")));
    }
    let leaf_node = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &scalars).expect("the leaf chunk");
    let child = selene_point_to_helios_scalar(&leaf_node).expect("a grown node converts");
    let root = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &[child]).expect("the root");

    let input = ProveInput {
        output_key,
        key_image_gen: chunk[0].0 .1,
        commitment,
        pqc_leaf_commitment: pqc.point,
        pqc_leaf_blind: pqc.blind,
        spend_key_x: x.to_bytes(),
        spend_key_y: y.to_bytes(),
        commitment_mask: z.to_bytes(),
        pseudo_out_blind: PSEUDO_OUT_BLIND,
        leaf_chunk_outputs: chunk.iter().map(|(points, _)| *points).collect(),
        leaf_chunk_cm_x: chunk.iter().map(|(_, cm_x)| *cm_x).collect(),
        c1_branch_layers: vec![],
        c2_branch_layers: vec![BranchLayer { siblings: vec![child] }],
    };
    let mut rng = ChaCha20Rng::from_seed(PROOF_SEED);
    let result = prove_with_rng(
        &mut rng,
        &[input],
        &CurveTreeRoot::from_bytes(root),
        TREE_DEPTH,
        TxSignableHash::from_bytes(SIGNABLE_TX_HASH),
    )
    .expect("the fixed tree proves");
    let key_image_gen = CompressedEdwardsY(chunk[0].0 .1)
        .decompress()
        .expect("I = Hp(O) is a point");
    let proved = Proved {
        proof: result.proof,
        pseudo_outs: result.pseudo_outs,
        pqc_key: PqcKeyScalar::from_pqc_public_key(&pqc_pk),
        key_image: (key_image_gen * x).compress().to_bytes(),
        root,
    };
    assert!(
        matches!(
            check(&proved, &proved.proof.data, proved.root, TREE_DEPTH, SIGNABLE_TX_HASH, proved.key_image),
            Ok(true)
        ),
        "the fixed proof does not verify as made"
    );
    proved
}

fn check(
    p: &Proved,
    data: &[u8],
    root: [u8; 32],
    depth: u8,
    hash: [u8; 32],
    key_image: [u8; 32],
) -> Result<bool, shekyl_fcmp::proof::VerifyError> {
    verify(
        &ShekylFcmpProof {
            data: data.to_vec(),
            num_inputs: p.proof.num_inputs,
            tree_depth: p.proof.tree_depth,
        },
        &[KeyImage::from_canonical_bytes(key_image)],
        &p.pseudo_outs,
        &[p.pqc_key],
        &CurveTreeRoot::from_bytes(root),
        depth,
        TxSignableHash::from_bytes(hash),
    )
}

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

    fn u16(&mut self) -> usize {
        usize::from(u16::from_le_bytes([self.byte(), self.byte()]))
    }
}

fuzz_target!(|data: &[u8]| {
    let p = proved();
    let mut input = Input(data);

    // Which inputs to replace: one bit each.
    let replace = input.byte();
    let root = if replace & 0x01 != 0 { input.bytes32() } else { p.root };
    let depth = if replace & 0x02 != 0 { input.byte() } else { TREE_DEPTH };
    let hash = if replace & 0x04 != 0 { input.bytes32() } else { SIGNABLE_TX_HASH };
    let key_image = if replace & 0x08 != 0 { input.bytes32() } else { p.key_image };

    let mut proof = p.proof.data.clone();
    if replace & 0x10 != 0 {
        // A new length: shorter cuts the proof, longer extends it with the
        // next input bytes (zeros past the input's end).
        let len = input.u16();
        if len <= proof.len() {
            proof.truncate(len);
        } else {
            for _ in proof.len()..len {
                proof.push(input.byte());
            }
        }
    }
    if replace & 0x20 != 0 && !proof.is_empty() {
        // The rest of the input: (offset, mask) pairs flipping proof bytes.
        while input.0.len() >= 3 {
            let at = input.u16() % proof.len();
            proof[at] ^= input.byte();
        }
    }

    let unchanged = root == p.root
        && depth == TREE_DEPTH
        && hash == SIGNABLE_TX_HASH
        && key_image == p.key_image
        && proof == p.proof.data;
    let verified = check(p, &proof, root, depth, hash, key_image);
    if unchanged {
        assert!(matches!(verified, Ok(true)), "the proof as made failed to verify: {verified:?}");
    } else {
        assert!(
            !matches!(verified, Ok(true)),
            "the proof verified with an input it was not made over (replaced {replace:#04x})"
        );
    }
});
