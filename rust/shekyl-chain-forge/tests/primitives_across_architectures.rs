// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seeded primitives a forged chain's bytes rest on, pinned so that an
//! aarch64 build is held to the x86_64 build's answers
//! (`CHAIN_FORGE.md` §5.2, the cross-architecture item).
//!
//! A forged chain compares across architectures only if every primitive
//! under it gives the same bytes from the same seed on both. Two of them
//! are where that could fail: FN-DSA's signer computes in floating point,
//! and a persona's receipt key comes from `HybridEd25519FnDsa::keypair_from_seeds`,
//! which a join commits. The forge's determinism check compares the whole
//! small plan on both architectures; this test names the primitive when a
//! comparison fails, and runs in seconds where the plan takes minutes.
//!
//! Each answer is the SHA-256 of the primitive's canonical bytes, pinned
//! from an x86_64 build. The determinism workflow runs this test on both
//! of its architectures.

use curve25519_dalek::Scalar;
use rand_chacha::rand_core::SeedableRng;
use shekyl_crypto_pq::account::Network;
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_BUNDLE,
};

fn sha256(bytes: &[u8]) -> String {
    shekyl_chain_forge::sha256_hex(bytes)
}

/// A persona's keys derived under regtest's name from a fixed master: the
/// ML-DSA identity and bond keys and the FN-DSA receipt key.
#[test]
fn a_personas_keys_are_the_same_on_every_architecture() {
    let keys = derive_archival_p_keys(&[0x51; 64], Network::Regtest, 3).expect("derives");
    let mut public = Vec::new();
    public.extend_from_slice(&keys.hybrid_sign_pk.to_canonical_bytes().expect("encodes"));
    public.extend_from_slice(&keys.bond_spend_pk.to_canonical_bytes().expect("encodes"));
    public.extend_from_slice(&keys.receipt_sign_pk.to_canonical_bytes());
    assert_eq!(sha256(&public), PERSONA_KEYS);
}

/// FN-DSA keygen from two seeds and a seeded FN-DSA signature: the witness
/// key and its bundle signature, the receipt key and a receipt.
#[test]
fn a_seeded_fn_dsa_signature_is_the_same_on_every_architecture() {
    let (public, secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&[0x61; 32], &[0x3B; 32]).expect("keygen");
    let witness = HybridEd25519FnDsa
        .sign_with_rng_seed(
            &secret,
            SCHEME_DOMAIN_WITNESS_BUNDLE,
            b"commitment",
            &[7; 32],
        )
        .expect("signs");
    let receipt = HybridEd25519FnDsa
        .sign_with_rng_seed(&secret, SCHEME_DOMAIN_RECEIPT, b"transcript", &[8; 32])
        .expect("signs");
    let mut bytes = public.to_canonical_bytes();
    bytes.extend_from_slice(&witness.to_canonical_bytes());
    bytes.extend_from_slice(&receipt.to_canonical_bytes());
    assert_eq!(sha256(&bytes), FN_DSA);
}

/// A seeded ML-DSA hybrid signature under a persona's identity key.
#[test]
fn a_seeded_ml_dsa_signature_is_the_same_on_every_architecture() {
    let keys = derive_archival_p_keys(&[0x52; 64], Network::Regtest, 1).expect("derives");
    let signature = HybridEd25519MlDsa
        .sign_with_ml_dsa_seed(
            &keys.hybrid_sign_sk,
            b"shekyl/chain-forge/probe",
            b"message",
            &[9; 32],
        )
        .expect("signs");
    assert_eq!(
        sha256(&signature.to_canonical_bytes().expect("encodes")),
        ML_DSA
    );
}

/// A Bulletproofs+ range proof over two commitments from a seeded stream.
#[test]
fn a_seeded_range_proof_is_the_same_on_every_architecture() {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x0B; 32]);
    let commitments = vec![
        shekyl_curve_primitives::Commitment::new(Scalar::from(11u64), 1_000_000),
        shekyl_curve_primitives::Commitment::new(Scalar::from(13u64), 2_500_000),
    ];
    let proof =
        shekyl_bulletproofs::Bulletproof::prove_plus(&mut rng, commitments).expect("proves");
    assert_eq!(sha256(&proof.serialize()), RANGE_PROOF);
}

const PERSONA_KEYS: &str = "00a7bd392fa2688a4d609c2d5d538a7451947df4c28ea15b7abdff0cde94053a";
const FN_DSA: &str = "560d837d8e2293ee024367cadd4d469c8c80b0c7a6431e817a21c755d28204d9";
const ML_DSA: &str = "33594cbf8812b8cb06497c2c5dafb5732ea50f7a08b08c1d67a9ad12f1829dea";
const RANGE_PROOF: &str = "ceeafcba3a1dc80f662573babfe11217f23348f99ab7a9be829c7df741b0930b";
