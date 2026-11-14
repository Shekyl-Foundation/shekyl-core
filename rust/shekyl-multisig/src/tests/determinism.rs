// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Byte-exact pins for the multisig formats every member must reproduce.
//! A failure here means two members' wallets would disagree on what they
//! sign: refuse the change, or bump the format with a recorded reason.

use crate::intent::{ChainStateFingerprint, IntentRecipient, SpendIntent};
use serde_json::Value;
use shekyl_units::AtomicUnits;

const INTENT_VECTORS: &str = include_str!("../../../../docs/test_vectors/MULTISIG_INTENT_V2.json");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

fn u64_of(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

fn u8_of(v: &Value) -> u8 {
    u8::try_from(u64_of(v)).unwrap()
}

fn intent_of(v: &Value) -> SpendIntent {
    SpendIntent {
        version: u8_of(&v["version"]),
        intent_id: hex32(&v["intent_id"]),
        address_fingerprint: hex32(&v["address_fingerprint"]),
        proposer_index: u8_of(&v["proposer_index"]),
        signers: v["signers"].as_array().unwrap().iter().map(u8_of).collect(),
        responder_index: u8_of(&v["responder_index"]),
        created_at: u64_of(&v["created_at"]),
        reference_block_height: u64_of(&v["reference_block_height"]),
        reference_block_hash: hex32(&v["reference_block_hash"]),
        recipients: v["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| IntentRecipient {
                address: hex(r["address"].as_str().unwrap()),
                amount: AtomicUnits::from_raw(u64_of(&r["amount"])),
            })
            .collect(),
        fee: AtomicUnits::from_raw(u64_of(&v["fee"])),
        input_global_indices: v["input_global_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(u64_of)
            .collect(),
        kem_randomness_seed: hex32(&v["kem_randomness_seed"]),
        chain_state_fingerprint: hex32(&v["chain_state_fingerprint"]),
    }
}

/// The intent's canonical bytes and hash, against the Python oracle
/// (`scripts/kat/multisig_intent_oracle.py`, written from the spec). The
/// vectors define the bytes; do not regenerate them to make this pass.
#[test]
fn intent_v2_vectors() {
    let file: Value = serde_json::from_str(INTENT_VECTORS).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty(), "the vector file pins no intent");
    for v in vectors {
        let intent = intent_of(v);
        let name = v["name"].as_str().unwrap();
        assert_eq!(
            intent.to_canonical_bytes().unwrap(),
            hex(v["canonical"].as_str().unwrap()),
            "{name}: canonical bytes"
        );
        assert_eq!(
            intent.intent_hash().unwrap(),
            hex32(&v["intent_hash"]),
            "{name}: intent_hash"
        );
    }
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
