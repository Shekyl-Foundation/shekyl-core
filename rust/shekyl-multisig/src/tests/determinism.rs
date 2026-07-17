// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Cross-platform determinism canary tests.
//!
//! These tests pin byte-exact outputs for critical derivation functions.
//! If any of these fail on a new platform, it means the V3.1 multisig
//! protocol would produce incompatible results across platforms —
//! a consensus-breaking bug.

use crate::{
    encryption::derive_message_key,
    intent::{ChainStateFingerprint, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION},
    messages::MessageType,
};
use shekyl_units::AtomicUnits;

#[test]
fn intent_hash_canary() {
    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x42; 32],
        address_fingerprint: [0xBB; 32],
        proposer_index: 0,
        proposer_sig: vec![0xAA; 64],
        created_at: 1000000,
        expires_at: 1086400,
        tx_counter: 1,
        reference_block_height: 999900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![IntentRecipient {
            address: vec![0x01, 0x02, 0x03, 0x04],
            amount: AtomicUnits::from_raw(1_000_000_000),
        }],
        fee: AtomicUnits::from_raw(1_000_000),
        input_global_indices: vec![12345],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0xEE; 32],
    };

    let hash = intent.intent_hash().unwrap();

    assert_eq!(
        &hash[..4],
        &[0x7e, 0x3e, 0x50, 0x43],
        "intent_hash prefix diverged — cross-platform determinism broken"
    );
}

#[test]
fn chain_state_fingerprint_canary() {
    let fp = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: vec![100, 200, 300],
        input_eligible_heights: vec![900, 910, 920],
        input_amounts: vec![
            AtomicUnits::from_raw(1_000_000),
            AtomicUnits::from_raw(2_000_000),
            AtomicUnits::from_raw(3_000_000),
        ],
    };

    let hash = fp.compute();

    // Regenerated under MS-5: the `input_assigned_prover_indices` term was
    // excised from the fingerprint preimage with the Option-D prover lineage,
    // so the pinned prefix changed from the pre-E′ value.
    assert_eq!(
        &hash[..4],
        &[0x65, 0x09, 0xdc, 0x17],
        "chain_state_fingerprint prefix diverged — cross-platform determinism broken"
    );
}

#[test]
fn message_key_derivation_canary() {
    let group_secret = [0x42; 32];
    let intent_hash = [0xAA; 32];

    let key = derive_message_key(&group_secret, &intent_hash, MessageType::SpendIntent, 0).unwrap();

    assert_eq!(
        &key[..4],
        &[0x6d, 0xbd, 0xa3, 0xaf],
        "message_key derivation diverged — cross-platform determinism broken"
    );
}

#[test]
fn canonical_serialization_length_canary() {
    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0; 32],
        address_fingerprint: [0; 32],
        proposer_index: 0,
        proposer_sig: vec![0; 64],
        created_at: 0,
        expires_at: 0,
        tx_counter: 0,
        reference_block_height: 0,
        reference_block_hash: [0; 32],
        recipients: vec![],
        fee: AtomicUnits::ZERO,
        input_global_indices: vec![],
        kem_randomness_seed: [0; 32],
        chain_state_fingerprint: [0; 32],
    };

    let bytes = intent.to_canonical_bytes().unwrap();

    assert_eq!(
        bytes.len(),
        278,
        "canonical serialization length changed — wire format broken"
    );
}
