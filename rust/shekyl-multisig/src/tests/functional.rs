// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Functional test matrix: happy-path and edge-case coverage for
//! the V3.1 multisig protocol flow.

use crate::{
    encryption::{decrypt_payload, encrypt_payload},
    intent::{ChainStateFingerprint, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION},
    messages::{DecryptedPayload, MessageType, MultisigEnvelope, ENVELOPE_VERSION},
};
use shekyl_units::AtomicUnits;

#[test]
fn intent_roundtrip_through_encryption() {
    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x11; 32],
        group_id: [0x22; 32],
        proposer_index: 0,
        proposer_sig: vec![0xAA; 64],
        created_at: 1000,
        expires_at: 2000,
        tx_counter: 1,
        reference_block_height: 900,
        reference_block_hash: [0x33; 32],
        recipients: vec![IntentRecipient {
            address: vec![1, 2, 3],
            amount: AtomicUnits::from_raw(500),
        }],
        fee: AtomicUnits::from_raw(10),
        input_global_indices: vec![42],
        kem_randomness_seed: [0x44; 32],
        chain_state_fingerprint: [0x55; 32],
    };

    let group_secret = [0x99; 32];
    let intent_hash = intent.intent_hash().unwrap();

    let payload = DecryptedPayload {
        message_type: MessageType::SpendIntent,
        body: intent.to_canonical_bytes().unwrap(),
    };
    let plaintext = payload.encode();

    let ct = encrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        &plaintext,
    )
    .unwrap();

    let pt = decrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        &ct,
    )
    .unwrap();

    let decoded = DecryptedPayload::decode(&pt).unwrap();
    assert_eq!(decoded.message_type, MessageType::SpendIntent);
    assert_eq!(decoded.body, intent.to_canonical_bytes().unwrap());
}

#[test]
fn envelope_wraps_encrypted_payload() {
    let group_secret = [0x42; 32];
    let intent_hash = [0xBB; 32];
    let plaintext = b"test payload content";

    let ct = encrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SignatureShare,
        1,
        0,
        plaintext,
    )
    .unwrap();

    let envelope = MultisigEnvelope {
        version: ENVELOPE_VERSION,
        group_id: [0xAA; 32],
        intent_hash,
        sender_index: 1,
        sender_sig: vec![0; 64],
        encrypted_payload: ct.clone(),
    };

    let bytes = envelope.to_bytes().unwrap();
    let parsed = MultisigEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.encrypted_payload, ct);

    let pt = decrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::SignatureShare,
        1,
        0,
        &parsed.encrypted_payload,
    )
    .unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn chain_state_fingerprint_includes_all_fields() {
    let fp1 = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![
            AtomicUnits::from_raw(10),
            AtomicUnits::from_raw(20),
            AtomicUnits::from_raw(30),
        ],
    };

    let h1 = fp1.compute();

    let fp2 = ChainStateFingerprint {
        input_global_indices: vec![1, 2, 4],
        ..ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![1, 2, 4],
            input_eligible_heights: vec![100, 200, 300],
            input_amounts: vec![
                AtomicUnits::from_raw(10),
                AtomicUnits::from_raw(20),
                AtomicUnits::from_raw(30),
            ],
        }
    };
    assert_ne!(h1, fp2.compute());

    let fp3 = ChainStateFingerprint {
        reference_block_hash: [0xBB; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![
            AtomicUnits::from_raw(10),
            AtomicUnits::from_raw(20),
            AtomicUnits::from_raw(30),
        ],
    };
    assert_ne!(h1, fp3.compute());
}
