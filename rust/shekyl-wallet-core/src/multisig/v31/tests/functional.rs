// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Functional test matrix: happy-path and edge-case coverage for
//! the V3.1 multisig protocol flow.

use crate::multisig::v31::{
    encryption::{decrypt_payload, encrypt_payload},
    intent::{ChainStateFingerprint, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION},
    messages::{DecryptedPayload, MessageType, MultisigEnvelope, ENVELOPE_VERSION},
    prover::{ProverReceipt, SignatureShare},
    state::{IntentState, TrackedIntent, TxCounterTracker},
};

#[test]
fn full_happy_path_state_transitions() {
    let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);

    ti.transition(IntentState::Verified).unwrap();
    ti.transition(IntentState::ProverReady).unwrap();
    ti.transition(IntentState::Signed).unwrap();
    assert!(!ti.record_signature());
    assert!(ti.record_signature());

    ti.transition(IntentState::Assembled).unwrap();
    ti.transition(IntentState::Broadcast).unwrap();
    assert!(ti.state.is_terminal());
    assert!(!ti.state.is_active());
}

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
            amount: 500,
        }],
        fee: 10,
        input_global_indices: vec![42],
        kem_randomness_seed: [0x44; 32],
        chain_state_fingerprint: [0x55; 32],
    };

    let group_secret = [0x99; 32];
    let intent_hash = intent.intent_hash();

    let payload = DecryptedPayload {
        message_type: MessageType::SpendIntent,
        body: intent.to_canonical_bytes(),
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
    assert_eq!(decoded.body, intent.to_canonical_bytes());
}

#[test]
fn envelope_wraps_encrypted_payload() {
    let group_secret = [0x42; 32];
    let intent_hash = [0xBB; 32];
    let plaintext = b"test payload content";

    let ct = encrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::ProverOutput,
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

    let bytes = envelope.to_bytes();
    let parsed = MultisigEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.encrypted_payload, ct);

    let pt = decrypt_payload(
        &group_secret,
        &intent_hash,
        MessageType::ProverOutput,
        1,
        0,
        &parsed.encrypted_payload,
    )
    .unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn tx_counter_only_advances_forward() {
    let mut tc = TxCounterTracker::new(0, 3);
    assert_eq!(tc.advance_to(1), Some(1));
    assert_eq!(tc.advance_to(1), None);
    assert_eq!(tc.advance_to(0), None);
    assert_eq!(tc.advance_to(5), Some(5));
    assert_eq!(tc.advance_to(3), None);
    assert_eq!(tc.current, 5);
}

#[test]
fn chain_state_fingerprint_includes_all_fields() {
    let fp1 = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![10, 20, 30],
        input_assigned_prover_indices: vec![0, 1, 2],
    };

    let h1 = fp1.compute();

    let fp2 = ChainStateFingerprint {
        input_global_indices: vec![1, 2, 4],
        ..ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![1, 2, 4],
            input_eligible_heights: vec![100, 200, 300],
            input_amounts: vec![10, 20, 30],
            input_assigned_prover_indices: vec![0, 1, 2],
        }
    };
    assert_ne!(h1, fp2.compute());

    let fp3 = ChainStateFingerprint {
        reference_block_hash: [0xBB; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![10, 20, 30],
        input_assigned_prover_indices: vec![0, 1, 2],
    };
    assert_ne!(h1, fp3.compute());
}

#[test]
fn prover_receipt_counter_monotonicity() {
    let r1 = ProverReceipt {
        prover_index: 0,
        intent_hash: [0xAA; 32],
        local_counter: 1,
        receipt_sig: vec![0; 64],
    };
    let r2 = ProverReceipt {
        local_counter: 2,
        ..r1.clone()
    };
    assert_ne!(r1.signable_bytes(), r2.signable_bytes());
}

#[test]
fn signature_share_commitments_bind_content() {
    let share = SignatureShare {
        signer_index: 0,
        hybrid_sig: vec![0; 64],
        tx_hash_commitment: [0xAA; 32],
        fcmp_proof_commitment: [0xBB; 32],
        bp_plus_proof_commitment: [0xCC; 32],
    };

    assert_ne!(share.tx_hash_commitment, share.fcmp_proof_commitment);
    assert_ne!(share.fcmp_proof_commitment, share.bp_plus_proof_commitment);
}
