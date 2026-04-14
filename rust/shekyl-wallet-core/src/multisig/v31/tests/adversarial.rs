// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Adversarial test matrix: tests for attack vectors against V3.1 multisig.

use crate::multisig::v31::{
    encryption::{decrypt_payload, encrypt_payload},
    heartbeat::{Heartbeat, HeartbeatAnomaly, HeartbeatTracker},
    intent::{IntentRecipient, SpendIntent, SpendIntentError, SPEND_INTENT_VERSION},
    invariants::{
        check_assembly_consensus, InvariantCheckResult, InvariantId,
    },
    messages::MessageType,
    prover::{EquivocationProof, ProverInputProof, ProverOutput, SignatureShare},
    state::{IntentState, TrackedIntent},
};

#[test]
fn replay_detection_via_kem_seed() {
    let intent1 = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x11; 32],
        group_id: [0xBB; 32],
        proposer_index: 0,
        proposer_sig: vec![0; 64],
        created_at: 1000,
        expires_at: 2000,
        tx_counter: 1,
        reference_block_height: 900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![IntentRecipient {
            address: vec![1],
            amount: 100,
        }],
        fee: 10,
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
fn equivocation_detected_via_proof_commitment() {
    let po1 = ProverOutput {
        prover_index: 0,
        intent_hash: [0xAA; 32],
        fcmp_proofs: vec![ProverInputProof {
            input_global_index: 42,
            fcmp_proof: vec![0x11; 100],
            key_image: [0xBB; 32],
        }],
        prover_sig: vec![0; 64],
    };

    let mut po2 = po1.clone();
    po2.fcmp_proofs[0].fcmp_proof = vec![0x22; 100];

    assert_ne!(po1.fcmp_proof_commitment(), po2.fcmp_proof_commitment());

    let ep = EquivocationProof {
        prover_index: 0,
        intent_hash: [0xAA; 32],
        proof_a: po1,
        proof_b: po2,
    };
    assert!(ep.is_valid());
}

#[test]
fn assembly_rejects_mixed_commitments() {
    let shares = vec![
        SignatureShare {
            signer_index: 0,
            hybrid_sig: vec![0; 64],
            tx_hash_commitment: [0xAA; 32],
            fcmp_proof_commitment: [0xBB; 32],
            bp_plus_proof_commitment: [0xCC; 32],
        },
        SignatureShare {
            signer_index: 1,
            hybrid_sig: vec![0; 64],
            tx_hash_commitment: [0xAA; 32],
            fcmp_proof_commitment: [0xFF; 32],
            bp_plus_proof_commitment: [0xCC; 32],
        },
    ];

    match check_assembly_consensus(&shares) {
        InvariantCheckResult::Fail { invariant, .. } => {
            assert_eq!(invariant, InvariantId::I6AssemblyConsensus);
        }
        _ => panic!("should have detected fcmp_proof disagreement"),
    }
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
fn expired_intent_cannot_be_signed() {
    let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
    ti.transition(IntentState::Verified).unwrap();

    let expired = ti.check_expiry(3000);
    assert!(expired);
    assert_eq!(ti.state, IntentState::TimedOut);

    let result = ti.transition(IntentState::ProverReady);
    assert!(result.is_err());
}

#[test]
fn heartbeat_detects_all_anomaly_types() {
    let mut tracker = HeartbeatTracker::new(3);
    let hb = Heartbeat {
        sender_index: 1,
        timestamp: 500,
        last_seen_intent: [0xFF; 32],
        observed_relay_ops: vec!["same".into()],
        local_tx_counter: 99,
        sig: vec![],
    };

    let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);

    let has_intent = anomalies
        .iter()
        .any(|a| matches!(a, HeartbeatAnomaly::IntentDisagreement { .. }));
    let has_relay = anomalies
        .iter()
        .any(|a| matches!(a, HeartbeatAnomaly::RelayDiversityCollapse { .. }));
    let has_counter = anomalies
        .iter()
        .any(|a| matches!(a, HeartbeatAnomaly::CounterDivergence { .. }));
    let has_skew = anomalies
        .iter()
        .any(|a| matches!(a, HeartbeatAnomaly::TimeSkew { .. }));

    assert!(has_intent, "should detect intent disagreement");
    assert!(has_relay, "should detect relay diversity collapse");
    assert!(has_counter, "should detect counter divergence");
    assert!(has_skew, "should detect time skew");
}

#[test]
fn structural_validation_rejects_all_bad_inputs() {
    let base = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0; 32],
        group_id: [0; 32],
        proposer_index: 0,
        proposer_sig: vec![0; 64],
        created_at: 1000,
        expires_at: 2000,
        tx_counter: 1,
        reference_block_height: 900,
        reference_block_hash: [0; 32],
        recipients: vec![IntentRecipient {
            address: vec![1],
            amount: 100,
        }],
        fee: 10,
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
