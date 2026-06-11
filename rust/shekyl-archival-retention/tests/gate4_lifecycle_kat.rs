// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Gate-4 §8 phase-1 lifecycle KAT (join → serve `E_first`, bonded-aggregation audit).
//!
//! Regenerate fixture:
//! `cargo test -p shekyl-archival-retention regenerate_gate4_lifecycle_fixture -- --ignored --nocapture`

use std::io::Cursor;

use serde_json::{json, Value};
use shekyl_archival_retention::{
    bond_floor, challenge_fire_height, challenge_seal_height, p_canonical_id_from_hybrid_pubkey,
    r_market_count, serve_credit_epoch_ok, sigma_work_milli, verify_conservation_snapshot,
    verify_join_market_bond_post, verify_leaf_index, verify_segment_path, ArchivalBondPostVin,
    ArchivalServeCreditResponse, BadInterval, BandedCurveParams, BondPostError, BondPostKind,
    ConservationError, ConservationSnapshot, HoldingsDescriptor, HoldingsKind, ServeCreditRow,
    ARCHIVAL_BOND_FLOOR_ATOMIC, SETTLEMENT_EPOCH_BLOCKS, VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme};

const GATE2_KAT: &str = include_str!("fixtures/gate2_serve_credit_kat_v1.json");
const GATE4_KAT: &str = include_str!("fixtures/gate4_lifecycle_kat_v1.json");

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

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    assert_eq!(v.len(), 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn settlement_epoch_open_height(e: u64) -> u64 {
    e.saturating_mul(SETTLEMENT_EPOCH_BLOCKS)
}

fn build_gate4_document() -> Value {
    let gate2: Value = serde_json::from_str(GATE2_KAT).expect("gate2 json");
    let integration = &gate2["integration"];
    let hybrid_pk_hex = integration["bond_hybrid_pubkey_hex"]
        .as_str()
        .expect("integration pk");
    let hybrid_pk_bytes = decode_hex(hybrid_pk_hex);
    let p_id = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);

    let join_vin = ArchivalBondPostVin {
        hybrid_public_key: hybrid_pk_bytes,
        p_canonical_id: p_id,
        post_kind: BondPostKind::JoinMarket,
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![integration["shard_id"].as_u64().expect("shard")],
        },
        bonded_total_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
        bond_credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
        bond_debit: 0,
    };
    verify_join_market_bond_post(&join_vin, false).expect("join vin valid");

    json!({
        "format_version": 1,
        "description": "Gate-4 §8 phase-1: join bond-post, serve at E_first, bonded-aggregation KAT.",
        "join": {
            "wire_hex": encode_hex(&join_vin.serialize().expect("join wire")),
            "p_canonical_id_hex": encode_hex(&p_id),
            "bond_credit": ARCHIVAL_BOND_FLOOR_ATOMIC,
            "join_settlement_epoch": integration["join_settlement_epoch"].as_u64().expect("join epoch"),
        },
        "serve_e_first": integration.clone(),
        "negative_serve_at_e_join": {
            "settlement_epoch": 0,
            "join_settlement_epoch": 0,
        },
        "conservation_after_join": {
            "total_bonded_atomic": ARCHIVAL_BOND_FLOOR_ATOMIC,
            "per_p_bonded": [ARCHIVAL_BOND_FLOOR_ATOMIC],
        },
        "emission": {
            "description": "Phase-2: consensus_state replay pin (ARCHIVAL_CONSENSUS_STATE §3.3–§4.5).",
            "settlement_epoch": 10,
            "shard_id": 42,
            "expected": {
                "r_market": 1,
                "sigma_work_milli": 4000
            },
            "per_p_work_milli": [4000, 0, 12000],
            "market_mask": [true, false, false],
            "curve": {
                "plateau_work_milli": 16000,
                "plateau_value_milli": 8000
            },
            "serve_credit_rows": [
                {
                    "p_id_hex": "01",
                    "shard_id": 42,
                    "serve_credit": true,
                    "join_epoch": 0,
                    "bad_intervals": [],
                    "foundation": false
                },
                {
                    "p_id_hex": "02",
                    "shard_id": 42,
                    "serve_credit": false,
                    "join_epoch": 0,
                    "bad_intervals": [],
                    "foundation": false
                },
                {
                    "p_id_hex": "03",
                    "shard_id": 42,
                    "serve_credit": true,
                    "join_epoch": 0,
                    "bad_intervals": [{ "start": 8, "end_exclusive": u64::MAX }],
                    "foundation": false
                }
            ]
        },
    })
}

fn gate4_emission_phase2_vectors(emission: &Value) {
    let curve = BandedCurveParams {
        plateau_work_milli: emission["curve"]["plateau_work_milli"]
            .as_u64()
            .expect("plateau_work"),
        plateau_value_milli: emission["curve"]["plateau_value_milli"]
            .as_u64()
            .expect("plateau_value"),
    };
    let e = emission["settlement_epoch"].as_u64().expect("epoch");
    let shard = emission["shard_id"].as_u64().expect("shard");

    let rows: Vec<ServeCreditRow> = emission["serve_credit_rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            let bad: Vec<BadInterval> = r["bad_intervals"]
                .as_array()
                .map(|ivs| {
                    ivs.iter()
                        .map(|iv| BadInterval {
                            start_epoch: iv["start"].as_u64().unwrap_or(0),
                            end_exclusive: iv["end_exclusive"].as_u64().unwrap_or(u64::MAX),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut p_id = [0u8; 32];
            let hex = r["p_id_hex"].as_str().unwrap_or("00");
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            p_id[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
            ServeCreditRow {
                p_id,
                shard_id: r["shard_id"].as_u64().unwrap_or(shard),
                serve_credit: r["serve_credit"].as_bool().unwrap_or(false),
                join_settlement_epoch: r["join_epoch"].as_u64().unwrap_or(0),
                bad_intervals: bad,
                is_foundation: r["foundation"].as_bool().unwrap_or(false),
            }
        })
        .collect();

    let expected = &emission["expected"];
    assert_eq!(
        r_market_count(&rows, shard, e),
        expected["r_market"].as_u64().expect("r_market")
    );

    let works: Vec<u64> = emission["per_p_work_milli"]
        .as_array()
        .expect("works")
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    let mask: Vec<bool> = emission["market_mask"]
        .as_array()
        .expect("mask")
        .iter()
        .map(|v| v.as_bool().unwrap())
        .collect();
    assert_eq!(
        sigma_work_milli(&works, &curve, &mask),
        expected["sigma_work_milli"].as_u64().expect("sigma")
    );
}

#[test]
#[ignore = "writes tests/fixtures/gate4_lifecycle_kat_v1.json"]
fn regenerate_gate4_lifecycle_fixture() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/gate4_lifecycle_kat_v1.json");
    let doc = build_gate4_document();
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());
}

#[test]
fn gate4_lifecycle_kat_vectors() {
    let kat: Value = serde_json::from_str(GATE4_KAT).expect("gate4 json");
    assert_eq!(kat["format_version"].as_u64(), Some(1));
    let emission = &kat["emission"];
    assert!(emission.is_object());
    gate4_emission_phase2_vectors(emission);

    let join = &kat["join"];
    let join_wire = decode_hex(join["wire_hex"].as_str().expect("join wire"));
    assert_eq!(
        join_wire[0],
        shekyl_archival_retention::VIN_TYPE_ARCHIVAL_BOND_POST
    );
    let mut cursor = Cursor::new(&join_wire[1..]);
    let join_vin =
        ArchivalBondPostVin::read_payload_exact(&mut cursor).expect("parse join bond-post");
    verify_join_market_bond_post(&join_vin, false).expect("join verify");
    assert_eq!(
        bond_floor(&join_vin.holdings),
        join["bond_credit"].as_u64().expect("bond_credit")
    );

    let neg = &kat["negative_serve_at_e_join"];
    assert!(!serve_credit_epoch_ok(
        neg["settlement_epoch"].as_u64().expect("E"),
        neg["join_settlement_epoch"].as_u64().expect("E_join"),
    ));

    let serve = &kat["serve_e_first"];
    let join_epoch = serve["join_settlement_epoch"].as_u64().expect("join epoch");
    let settlement_epoch = serve["settlement_epoch"]
        .as_u64()
        .expect("settlement epoch");
    assert!(serve_credit_epoch_ok(settlement_epoch, join_epoch));
    assert_eq!(settlement_epoch, join_epoch + 1);

    let serve_wire = decode_hex(serve["wire_hex"].as_str().expect("serve wire"));
    assert_eq!(serve_wire[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);
    let mut serve_cursor = Cursor::new(&serve_wire[1..]);
    let parsed = ArchivalServeCreditResponse::read_payload(&mut serve_cursor).expect("serve parse");
    let int_pk = HybridPublicKey::from_canonical_bytes(&decode_hex(
        serve["bond_hybrid_pubkey_hex"].as_str().expect("pk"),
    ))
    .expect("pk");
    let sig_bytes = parsed
        .hybrid_signature
        .to_canonical_bytes()
        .expect("sig bytes");
    let sig = shekyl_crypto_pq::signature::HybridSignature::from_canonical_bytes(&sig_bytes)
        .expect("sig");
    assert!(HybridEd25519MlDsa
        .verify(&int_pk, &parsed.signature_preimage(), &sig)
        .expect("hybrid verify"));

    let segment_leaf_count = serve["segment_leaf_count"].as_u64().expect("segment count");
    verify_leaf_index(
        parsed.leaf_index_in_segment,
        &parsed.p_canonical_id,
        parsed.shard_id,
        parsed.settlement_epoch,
        segment_leaf_count,
    )
    .expect("leaf index");

    let layer_scalars: Vec<[u8; 32]> = decode_hex(
        serve["leaf_layer_scalars_hex"]
            .as_str()
            .expect("layer scalars"),
    )
    .chunks_exact(32)
    .map(|c| {
        let mut s = [0u8; 32];
        s.copy_from_slice(c);
        s
    })
    .collect();

    verify_segment_path(
        &parsed.leaf_bytes,
        &layer_scalars,
        &parsed.path,
        &parsed.segment_subroot_rk,
    )
    .expect("path verify");

    let h_open = settlement_epoch_open_height(settlement_epoch);
    let h_close = h_open + SETTLEMENT_EPOCH_BLOCKS - 1;
    let seal_hash = decode_hex32(serve["block_hash_at_seal_hex"].as_str().expect("seal hash"));
    assert_eq!(
        challenge_seal_height(h_open),
        serve["h_seal"].as_u64().expect("h_seal")
    );
    assert_eq!(
        challenge_fire_height(
            h_open,
            h_close,
            &seal_hash,
            &parsed.p_canonical_id,
            parsed.shard_id,
            parsed.settlement_epoch,
        ),
        serve["h_fire"].as_u64().expect("h_fire")
    );

    let cons = &kat["conservation_after_join"];
    let per_p: Vec<u64> = cons["per_p_bonded"]
        .as_array()
        .expect("per_p")
        .iter()
        .map(|v| v.as_u64().expect("u64"))
        .collect();
    let snapshot = ConservationSnapshot {
        total_bonded_atomic: cons["total_bonded_atomic"].as_u64().expect("total"),
        per_p_bonded: &per_p,
        already_generated: None,
        circulating: None,
        burned: None,
    };
    verify_conservation_snapshot(&snapshot).expect("bonded aggregation");
    assert_eq!(
        snapshot.total_bonded_atomic,
        join["bond_credit"].as_u64().expect("credit")
    );
}

#[test]
fn gate4_join_rejects_both_bond_terms() {
    let kat: Value = serde_json::from_str(GATE4_KAT).expect("gate4 json");
    let join_wire = decode_hex(kat["join"]["wire_hex"].as_str().expect("join wire"));
    let mut cursor = Cursor::new(&join_wire[1..]);
    let mut join_vin =
        ArchivalBondPostVin::read_payload_exact(&mut cursor).expect("parse join bond-post");
    join_vin.bond_debit = join_vin.bond_credit;
    assert_eq!(
        verify_join_market_bond_post(&join_vin, false),
        Err(BondPostError::BothTermsNonzero)
    );
}

#[test]
fn gate4_conservation_rejects_aggregation_mismatch() {
    let kat: Value = serde_json::from_str(GATE4_KAT).expect("gate4 json");
    let cons = &kat["conservation_after_join"];
    let per_p: Vec<u64> = cons["per_p_bonded"]
        .as_array()
        .expect("per_p")
        .iter()
        .map(|v| v.as_u64().expect("u64"))
        .collect();
    let snapshot = ConservationSnapshot {
        total_bonded_atomic: cons["total_bonded_atomic"].as_u64().expect("total") + 1,
        per_p_bonded: &per_p,
        already_generated: None,
        circulating: None,
        burned: None,
    };
    assert_eq!(
        verify_conservation_snapshot(&snapshot),
        Err(ConservationError::BondedAggregationMismatch {
            total: snapshot.total_bonded_atomic,
            sum: per_p.iter().sum(),
        })
    );
}

#[test]
fn gate4_join_wire_p_id_matches_recomputed_pubkey() {
    let kat: Value = serde_json::from_str(GATE4_KAT).expect("gate4 json");
    let serve = &kat["serve_e_first"];
    let pk_bytes = decode_hex(serve["bond_hybrid_pubkey_hex"].as_str().expect("hybrid pk"));
    let expected = decode_hex32(kat["join"]["p_canonical_id_hex"].as_str().expect("p_id"));
    assert_eq!(p_canonical_id_from_hybrid_pubkey(&pk_bytes), expected);
}
