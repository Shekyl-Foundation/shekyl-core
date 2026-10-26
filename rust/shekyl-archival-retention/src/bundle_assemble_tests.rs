// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production assembler, held beside the byte vectors.

use super::*;

/// The production assembler: the reference names the body it returns,
/// the signature it asked for is over the commitment of the kept part and
/// the records, and it verifies under the witness domain and no other.
/// Red edit: sign the commitment of the kept part alone, or under
/// `SCHEME_DOMAIN_RECEIPT` — the verification below fails.
#[test]
fn an_assembled_bundle_is_signed_over_its_commitment_under_the_witness_domain() {
    use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSignature, HybridEd25519FnDsa};
    use shekyl_crypto_pq::signature::{
        SignatureScheme as _, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_BUNDLE,
    };

    let (public, secret) =
        HybridEd25519FnDsa::keypair_from_seeds(&[0x41; 32], &[0x42; 32]).expect("keygen");
    let public_bytes: [u8; BUNDLE_WITNESS_KEY_LEN] = public
        .to_canonical_bytes()
        .try_into()
        .expect("the canonical key length");
    let kept = kept_at(BlockHeight::from_raw(900), 9, &[0b0000_0101, 0]);
    let records = [record(1), record(2)];
    let mut asked = None;
    let (reference, body) = assemble_bundle(&kept, &records, &public_bytes, |commitment| {
        asked = Some(*commitment);
        sign_bundle_commitment(&secret, commitment)
    })
    .expect("the key signs");

    assert_eq!(reference.kept(), &kept);
    assert_eq!(reference.prunable_hash(), &body.prunable_hash());
    assert_eq!(body.witness_public_key(), &public_bytes);
    assert_eq!(body.records().collect::<Vec<_>>(), records.to_vec());
    let commitment = kept.commitment(body.records_bytes());
    assert_eq!(asked, Some(commitment));
    let signature =
        FnDsaHybridSignature::from_canonical_bytes(body.witness_signature()).expect("canonical");
    HybridEd25519FnDsa
        .verify(
            &public,
            SCHEME_DOMAIN_WITNESS_BUNDLE,
            &commitment,
            &signature,
        )
        .expect("the witness domain verifies");
    assert!(HybridEd25519FnDsa
        .verify(&public, SCHEME_DOMAIN_RECEIPT, &commitment, &signature)
        .is_err());

    let refused: Result<_, &str> =
        assemble_bundle(&kept, &records, &public_bytes, |_| Err("no signer"));
    assert_eq!(refused.unwrap_err(), "no signer");
}
