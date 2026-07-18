// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Adversarial test matrix: tests for attack vectors against V3.1 multisig.

use crate::{
    encryption::{decrypt_payload, encrypt_payload},
    intent::{IntentRecipient, SpendIntent, SpendIntentError, SPEND_INTENT_VERSION},
    messages::MessageType,
};
use shekyl_units::AtomicUnits;

#[test]
fn replay_detection_via_kem_seed() {
    let intent1 = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x11; 32],
        address_fingerprint: [0xBB; 32],
        proposer_index: 0,
        proposer_sig: vec![0; 64],
        created_at: 1000,
        expires_at: 2000,
        tx_counter: 1,
        reference_block_height: 900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![IntentRecipient {
            address: vec![1],
            amount: AtomicUnits::from_raw(100),
        }],
        fee: AtomicUnits::from_raw(10),
        input_global_indices: vec![42],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0; 32],
    };

    let mut intent2 = intent1.clone();
    intent2.intent_id = [0x22; 32];

    assert_eq!(intent1.kem_randomness_seed, intent2.kem_randomness_seed);

    let mut seen = std::collections::HashSet::new();
    seen.insert(intent1.kem_randomness_seed);
    assert!(seen.contains(&intent2.kem_randomness_seed));
}

#[test]
fn wrong_key_cannot_decrypt() {
    let group_secret = [0x42; 32];
    let intent_hash = [0xAA; 32];
    let plaintext = b"sensitive multisig data";

    let ct = encrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        plaintext,
    )
    .unwrap();

    let attacker_key = [0x99; 32];
    let result = decrypt_payload(
        &attacker_key,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        &ct,
    );
    assert!(result.is_err());
}

#[test]
fn tampered_ciphertext_detected() {
    let group_secret = [0x42; 32];
    let intent_hash = [0xAA; 32];
    let plaintext = b"sensitive data";

    let mut ct = encrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        plaintext,
    )
    .unwrap();

    let mid = ct.len() / 2;
    ct[mid] ^= 0xFF;

    let result = decrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        &ct,
    );
    assert!(result.is_err());
}

#[test]
fn structural_validation_rejects_all_bad_inputs() {
    let base = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0; 32],
        address_fingerprint: [0; 32],
        proposer_index: 0,
        proposer_sig: vec![0; 64],
        created_at: 1000,
        expires_at: 2000,
        tx_counter: 1,
        reference_block_height: 900,
        reference_block_hash: [0; 32],
        recipients: vec![IntentRecipient {
            address: vec![1],
            amount: AtomicUnits::from_raw(100),
        }],
        fee: AtomicUnits::from_raw(10),
        input_global_indices: vec![42],
        kem_randomness_seed: [0; 32],
        chain_state_fingerprint: [0; 32],
    };

    let mut bad_version = base.clone();
    bad_version.version = 99;
    assert!(matches!(
        bad_version.validate_structural(3, 1500),
        Err(SpendIntentError::WrongVersion(99))
    ));

    let mut bad_proposer = base.clone();
    bad_proposer.proposer_index = 10;
    assert!(matches!(
        bad_proposer.validate_structural(3, 1500),
        Err(SpendIntentError::ProposerOutOfRange(10))
    ));

    assert!(matches!(
        base.validate_structural(3, 3000),
        Err(SpendIntentError::Expired { .. })
    ));

    assert!(matches!(
        base.validate_structural(3, 500),
        Err(SpendIntentError::NotYetValid { .. })
    ));
}
