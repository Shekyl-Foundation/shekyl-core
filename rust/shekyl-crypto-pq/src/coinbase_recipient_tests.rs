// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

/// The first 32-byte encoding, `[y, 0, ..]`, that is no curve point.
fn not_a_point() -> [u8; 32] {
    (2u8..=255)
        .map(|y| {
            let mut bytes = [0u8; 32];
            bytes[0] = y;
            bytes
        })
        .find(|bytes| {
            curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
                .decompress()
                .is_none()
        })
        .expect("about half of all encodings are not points")
}

#[test]
fn a_coinbase_pays_a_wallets_keys_and_its_x25519_is_the_wallets() {
    let seed = [0x99u8; MASTER_SEED_BYTES];
    let blob = rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();
    assert_eq!(
        coinbase_recipient(
            blob.spend_pk.as_canonical_bytes(),
            blob.view_pk.as_canonical_bytes(),
            &blob.ml_kem_ek,
        ),
        Ok(blob.x25519_pk)
    );
}

/// Each of the C++ decode's checks, one key at a time.
#[test]
fn a_coinbase_recipient_is_refused_for_each_bad_key() {
    let seed = [0x99u8; MASTER_SEED_BYTES];
    let blob = rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();
    let spend = *blob.spend_pk.as_canonical_bytes();
    let view = *blob.view_pk.as_canonical_bytes();
    assert_eq!(
        coinbase_recipient(&not_a_point(), &view, &blob.ml_kem_ek),
        Err(RecipientRefused::SpendKeyNotAPoint)
    );
    assert_eq!(
        coinbase_recipient(&spend, &not_a_point(), &blob.ml_kem_ek),
        Err(RecipientRefused::ViewKeyNotAPoint)
    );
    assert_eq!(
        coinbase_recipient(&spend, &view, &[0xff; ML_KEM_768_EK_LEN]),
        Err(RecipientRefused::KemKeyMalformed)
    );
    assert_eq!(
        coinbase_recipient(&spend, &view, &blob.ml_kem_ek[1..]),
        Err(RecipientRefused::KemKeyMalformed)
    );
}
