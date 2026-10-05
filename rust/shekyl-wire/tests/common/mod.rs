// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared helpers for the wire crate's integration tests.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_wire::tx_extra::{
    conforming_pqc_leaf_blob, serialize, TxExtraField, HYBRID_KEM_CT_BYTES,
};

/// A minimal spendable wallet: an Ed25519 spend keypair (`b`, `B = b*G`) plus a
/// hybrid X25519 + ML-KEM-768 KEM keypair. The typed (non-FFI) analogue of the
/// wallet in `shekyl-ffi`'s `signing_round_trip` test.
// Each integration-test binary compiles this module separately; binaries
// that never build a wallet would otherwise flag these items dead.
#[allow(dead_code)]
pub struct Wallet {
    /// Spend secret `b`.
    pub spend_secret: [u8; 32],
    /// Spend public `B = b*G` (compressed Ed25519).
    pub spend_public: [u8; 32],
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub ml_kem_ek: Vec<u8>,
    pub ml_kem_dk: Vec<u8>,
}

#[allow(dead_code)]
pub fn random_wallet(rng: &mut ChaCha20Rng) -> Wallet {
    let b = Scalar::random(rng);
    let spend_public = (ED25519_BASEPOINT_POINT * b).compress().to_bytes();
    let (pk, sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    Wallet {
        spend_secret: b.to_bytes(),
        spend_public,
        x25519_pk: pk.x25519,
        x25519_sk: sk.x25519,
        ml_kem_ek: pk.ml_kem,
        // `HybridKemSecretKey` is `ZeroizeOnDrop`; its `Vec` field can't be
        // moved out, so clone the decapsulation key into the test wallet.
        ml_kem_dk: sk.ml_kem.clone(),
    }
}

/// The `tx_extra` every transaction with outputs must carry (CEN-I19,
/// `GENESIS_TX_WIRE_FORMAT.md` §9.6a): exactly one `0x06` of `1120·n` bytes and
/// one `0x07` of `64·n`, and neither when `n == 0`.
///
/// The shape rule reads counts and lengths only, so the payload bytes are
/// arbitrary filler — a fixture needs a *valid* transaction in every respect
/// except the one thing its test is about, and before this rule existed these
/// fixtures were quietly building transactions consensus would reject.
// Each integration-test binary compiles this module separately; binaries
// that don't build a conforming extra would otherwise flag this dead.
#[allow(dead_code)]
#[must_use]
pub fn conforming_pqc_extra(n_outputs: usize) -> Vec<u8> {
    if n_outputs == 0 {
        return Vec::new();
    }
    serialize(&[
        TxExtraField::PqcKemCiphertext(vec![0x6a; HYBRID_KEM_CT_BYTES * n_outputs]),
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n_outputs)),
    ])
    .expect("conforming PQC tx_extra serializes")
}
