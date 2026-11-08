// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`verify_receipt_transcript`]: the scheme-3 check over the pass
//! transcript, and its separation from the identity key's check.

use super::*;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_RECEIPT,
    SCHEME_DOMAIN_WITNESS_BUNDLE,
};
use shekyl_types::BlockHeight;

const NONCE: [u8; PASS_NONCE_LEN] = [0x11; PASS_NONCE_LEN];
const ANCHOR: BlockHeight = BlockHeight::from_raw(1_000);
const ANCHOR_HASH: [u8; PASS_ANCHOR_HASH_LEN] = [0x22; PASS_ANCHOR_HASH_LEN];
const SHARD: u64 = 7;
const DIGEST: [u8; PASS_DELIVERY_DIGEST_LEN] = [0x5a; PASS_DELIVERY_DIGEST_LEN];

fn transcript() -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    pass_countersignature_message(
        crate::pass_anchor::PassStream::Economy,
        &NONCE,
        ANCHOR,
        &ANCHOR_HASH,
        SHARD,
        &DIGEST,
    )
}

fn receipt_keypair(
    seed: u8,
) -> (
    FnDsaHybridPublicKey,
    shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSecretKey,
) {
    HybridEd25519FnDsa::keypair_from_seeds(&[seed; 32], &[seed.wrapping_add(1); 32])
        .expect("keygen")
}

fn verify(
    public: &FnDsaHybridPublicKey,
    signature: &FnDsaHybridSignature,
) -> Result<(), PassCountersignatureError> {
    verify_receipt_transcript(
        public,
        crate::pass_anchor::PassStream::Economy,
        &NONCE,
        ANCHOR,
        &ANCHOR_HASH,
        SHARD,
        &DIGEST,
        signature,
    )
}

#[test]
fn a_receipt_over_the_transcript_verifies_and_binds_every_field() {
    let (public, secret) = receipt_keypair(7);
    let signature = HybridEd25519FnDsa
        .sign(&secret, SCHEME_DOMAIN_RECEIPT, &transcript())
        .expect("sign");
    verify(&public, &signature).expect("verifies");

    let refused = Err(PassCountersignatureError::InvalidSignature);
    // Another key.
    assert_eq!(verify(&receipt_keypair(9).0, &signature), refused);
    // Each transcript field, moved by one.
    assert_eq!(
        verify_receipt_transcript(
            &public,
            crate::pass_anchor::PassStream::Economy,
            &[0x12; PASS_NONCE_LEN],
            ANCHOR,
            &ANCHOR_HASH,
            SHARD,
            &DIGEST,
            &signature
        ),
        refused
    );
    assert_eq!(
        verify_receipt_transcript(
            &public,
            crate::pass_anchor::PassStream::Economy,
            &NONCE,
            BlockHeight::from_raw(1_001),
            &ANCHOR_HASH,
            SHARD,
            &DIGEST,
            &signature
        ),
        refused
    );
    assert_eq!(
        verify_receipt_transcript(
            &public,
            crate::pass_anchor::PassStream::Economy,
            &NONCE,
            ANCHOR,
            &[0x23; PASS_ANCHOR_HASH_LEN],
            SHARD,
            &DIGEST,
            &signature
        ),
        refused
    );
    assert_eq!(
        verify_receipt_transcript(
            &public,
            crate::pass_anchor::PassStream::Economy,
            &NONCE,
            ANCHOR,
            &ANCHOR_HASH,
            SHARD + 1,
            &DIGEST,
            &signature
        ),
        refused
    );
    assert_eq!(
        verify_receipt_transcript(
            &public,
            crate::pass_anchor::PassStream::Economy,
            &NONCE,
            ANCHOR,
            &ANCHOR_HASH,
            SHARD,
            &[0x5b; PASS_DELIVERY_DIGEST_LEN],
            &signature
        ),
        refused
    );
}

/// The domain is the receipt's. The same key over the same transcript under
/// the identity key's domain, or under the other scheme-3 surface's, is not
/// a receipt.
#[test]
fn a_signature_under_another_domain_is_not_a_receipt() {
    let (public, secret) = receipt_keypair(7);
    for domain in [SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_WITNESS_BUNDLE] {
        let signature = HybridEd25519FnDsa
            .sign(&secret, domain, &transcript())
            .expect("sign");
        assert_eq!(
            verify(&public, &signature),
            Err(PassCountersignatureError::InvalidSignature)
        );
    }
}

/// The two checks do not accept each other's objects. The types refuse it
/// first — an identity signature is not a `FnDsaHybridSignature` — so what
/// is held here is the bytes: an identity signature's canonical encoding
/// does not parse as a receipt, and a receipt's does not parse as an
/// identity signature.
#[test]
fn an_identity_signature_is_not_a_receipt_and_a_receipt_is_not_one() {
    let (identity_public, identity_secret) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keygen");
    let identity = HybridEd25519MlDsa
        .sign(&identity_secret, SCHEME_DOMAIN_ATTESTATION, &transcript())
        .expect("sign");
    verify_pass_transcript(
        &identity_public,
        crate::pass_anchor::PassStream::Economy,
        &NONCE,
        ANCHOR,
        &ANCHOR_HASH,
        SHARD,
        &DIGEST,
        &identity,
    )
    .expect("control: the identity check accepts its own");

    let (_, receipt_secret) = receipt_keypair(7);
    let receipt = HybridEd25519FnDsa
        .sign(&receipt_secret, SCHEME_DOMAIN_RECEIPT, &transcript())
        .expect("sign");

    assert!(FnDsaHybridSignature::from_canonical_bytes(
        &identity.to_canonical_bytes().expect("canonical")
    )
    .is_err());
    assert!(HybridSignature::from_canonical_bytes(&receipt.to_canonical_bytes()).is_err());
}
