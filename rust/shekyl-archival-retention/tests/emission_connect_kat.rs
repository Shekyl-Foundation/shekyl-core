// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C-1 connect-arm KAT fixture (`REWARD_EMISSION_E3_GATING_ROUND.md` §9.5
//! item 7): a structurally-valid `txin_archival_reward_emission` wire blob
//! plus the extraction outputs (`P_canonical_id`, `settlement_epochs`) the
//! C++ connect dispatch obtains through `shekyl_archival_emission_vin_extract`.
//!
//! The connect arm never verifies — verify ran at `check_tx_inputs` — so the
//! fixture carries deterministic length-canonical filler for the pubkeys and
//! signatures (the extract path parses structure and hashes `P_pubkey`; it
//! performs no cryptographic checks). Determinism keeps the fixture
//! regeneration byte-identical, unlike the keypair-generating verify KATs.
//!
//! Regenerate fixture:
//! `cargo test -p shekyl-archival-retention regenerate_emission_connect_fixture -- --ignored --nocapture`

use std::io::Cursor;

use serde_json::{json, Value};
use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin, HoldingsDescriptor, HoldingsKind,
    MembershipOnlyBacking, ShardSet, ShardWorkEntry, WorkEpochClaim,
    VIN_TYPE_ARCHIVAL_REWARD_EMISSION,
};
use shekyl_crypto_pq::derivation::hash_pqc_public_key;
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

const EMISSION_CONNECT_KAT: &str = include_str!("fixtures/emission_connect_kat_v1.json");

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Deterministic structurally-valid vin: two claimed epochs, one shard,
/// canonical-length filler keys/sigs. Mirrors `validate()`'s invariants
/// (strictly increasing epochs, aligned work claims, positive amounts).
///
/// The epochs are the lowest claimable pair ({1, 2}, settled at tip epoch 3)
/// so the real-LMDB connect/pop round-trip KAT
/// (`tests/unit_tests/archival_substrate_lmdb.cpp`) only has to append
/// ~3 settlement epochs of blocks to make them claimable at connect.
fn build_connect_vin() -> ArchivalRewardEmissionVin {
    const SHARD: u64 = 7;
    let epochs = [1u64, 2];
    let backing_pubkey = vec![0x22u8; SINGLE_KEY_CANONICAL_LEN];
    let pqc_pk_hash = hash_pqc_public_key(&backing_pubkey);
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0x11; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![SHARD]).unwrap(),
        },
        settlement_epochs: epochs.to_vec(),
        work_claim: epochs
            .iter()
            .map(|&epoch| WorkEpochClaim {
                epoch,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: SHARD,
                    serve_credit_bit: true,
                    scarcity_micro: 250,
                }],
            })
            .collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0xAB; 64],
            pseudo_out: [0x33; 32],
            pqc_pk_hash,
            backing_pubkey,
            tree_depth: 3,
        },
        reward_amount_plain: vec![500, 700],
        auth_backing: vec![0x44; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0x55; SINGLE_SIG_CANONICAL_LEN],
    }
}

fn build_connect_document() -> Value {
    let vin = build_connect_vin();
    vin.validate().expect("fixture vin is structurally valid");
    let wire = vin.serialize().expect("canonical wire");
    let p_id = p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey).to_bytes();
    json!({
        "format_version": 1,
        "description": "C-1 connect-arm extraction KAT: wire blob + shekyl_archival_emission_vin_extract outputs",
        "emission_vin": {
            "wire_hex": encode_hex(&wire),
            "p_canonical_id_hex": encode_hex(&p_id),
            "settlement_epochs": vin.settlement_epochs,
            "reward_amount_plain": vin.reward_amount_plain,
        },
    })
}

#[test]
#[ignore = "writes tests/fixtures/emission_connect_kat_v1.json"]
fn regenerate_emission_connect_fixture() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/emission_connect_kat_v1.json");
    let doc = build_connect_document();
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());
}

/// The pinned fixture reproduces from source (deterministic builder) and its
/// recorded extraction outputs match a fresh parse of the wire bytes — the
/// same parse `shekyl_archival_emission_vin_extract` performs.
#[test]
fn emission_connect_kat_vectors() {
    let kat: Value = serde_json::from_str(EMISSION_CONNECT_KAT).expect("kat json");
    assert_eq!(kat["format_version"].as_u64(), Some(1));
    assert_eq!(
        &kat,
        &build_connect_document(),
        "fixture drifted from the deterministic builder — regenerate"
    );

    let vin_section = &kat["emission_vin"];
    let wire = decode_hex(vin_section["wire_hex"].as_str().expect("wire hex"));
    assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_REWARD_EMISSION);

    let parsed = ArchivalRewardEmissionVin::read(&mut Cursor::new(&wire)).expect("wire parses");
    let expected_epochs: Vec<u64> = vin_section["settlement_epochs"]
        .as_array()
        .expect("epochs array")
        .iter()
        .map(|v| v.as_u64().expect("epoch u64"))
        .collect();
    assert_eq!(parsed.settlement_epochs, expected_epochs);
    assert_eq!(
        encode_hex(&p_canonical_id_from_hybrid_pubkey(&parsed.p_pubkey).to_bytes()),
        vin_section["p_canonical_id_hex"].as_str().expect("pid hex")
    );
}
