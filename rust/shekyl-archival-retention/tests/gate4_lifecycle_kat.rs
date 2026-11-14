// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Gate-4 §8 phase-1 lifecycle KAT: the join, its floor and its bonded
//! aggregation, and the phase-2 emission replay.
//!
//! Regenerate fixture (armed — cite the decision-log entry that authorizes it):
//! `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-archival-retention regenerate_gate4_lifecycle_fixture -- --ignored --nocapture`

use std::io::Cursor;

use serde_json::{json, Value};
use shekyl_archival_retention::{
    bond_floor, p_canonical_id_from_hybrid_pubkey, r_market_count, sigma_work_milli,
    verify_conservation_snapshot, verify_join_market_bond_post, ArchivalBondPostVin, BadInterval,
    BondPostError, ConservationError, ConservationSnapshot, HoldingsDescriptor, HoldingsKind,
    ServeCreditRow, ShardSet, ARCHIVAL_BOND_FLOOR_ATOMIC, ENDPOINT_BYTES,
    HYBRID_PUBKEY_CANONICAL_BYTES,
};

/// The persona's identity key: a canonical-length pattern. The KAT pins the
/// join's wire shape and its record commit, not key validity.
const PERSONA_KEY_BYTE: u8 = 0xA1;
/// The shard the join holds.
const JOIN_SHARD: u64 = 7;
/// The settlement epoch the join connects in.
const JOIN_EPOCH: u64 = 0;
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

fn build_gate4_document() -> Value {
    let hybrid_pk_bytes = vec![PERSONA_KEY_BYTE; HYBRID_PUBKEY_CANONICAL_BYTES];
    let p_id = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes).to_bytes();
    // The GF-1 debit authorizer (§9.11, JoinMarket-coupled). A deterministic
    // canonical-length pattern — the KAT pins wire shape and record commit,
    // not key validity; the C++ integration auth KAT references this hex.
    let bond_spend_pk = vec![0xB5u8; hybrid_pk_bytes.len()];

    let join_vin = ArchivalBondPostVin::join_market(
        hybrid_pk_bytes,
        p_id,
        bond_spend_pk.clone(),
        shekyl_archival_retention::ReceiptSignPk::from_bytes(
            [0x5C; shekyl_archival_retention::RECEIPT_SIGN_PK_LEN],
        ),
        [0x0Eu8; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![JOIN_SHARD]).unwrap(),
        },
        ARCHIVAL_BOND_FLOOR_ATOMIC,
    );
    verify_join_market_bond_post(&join_vin, false).expect("join vin valid");

    json!({
        "format_version": 1,
        "description": "Gate-4 §8 phase-1: the join bond-post, its floor and the bonded-aggregation audit; phase-2: the consensus-state emission replay.",
        "join": {
            "wire_hex": encode_hex(&join_vin.serialize().expect("join wire")),
            "p_canonical_id_hex": encode_hex(&p_id),
            "bond_spend_pk_hex": encode_hex(&bond_spend_pk),
            "bond_credit": ARCHIVAL_BOND_FLOOR_ATOMIC,
            "join_settlement_epoch": JOIN_EPOCH,
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
            "serve_credit_rows": [
                {
                    "p_id_hex": "01",
                    "shard_id": 42,
                    "serve_credit": true,
                    "join_epoch": 0,
                    "bad_intervals": []
                },
                {
                    "p_id_hex": "02",
                    "shard_id": 42,
                    "serve_credit": false,
                    "join_epoch": 0,
                    "bad_intervals": []
                },
                {
                    "p_id_hex": "03",
                    "shard_id": 42,
                    "serve_credit": true,
                    "join_epoch": 0,
                    "bad_intervals": [{ "start": 8, "end_exclusive": u64::MAX }]
                }
            ]
        },
    })
}

fn gate4_emission_phase2_vectors(emission: &Value) {
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
        sigma_work_milli(&works, &mask),
        expected["sigma_work_milli"].as_u64().expect("sigma")
    );
}

/// The JoinMarket this KAT judges, and why it is not the fixture's.
///
/// `gate4_lifecycle_kat_v1.json`'s `join.wire_hex` is a **keyless**
/// JoinMarket (`post_kind` 0). That kind is retired (2026-10-12, ruling on
/// PR #1046; `FN_DSA_HYBRID.md` `FND-19`): the receipt key is mandatory and
/// the byte is refused at parse. The fixture is not regenerated here,
/// because `tests/unit_tests/archival_bond_post_integration.cpp` parses the
/// same `join` object with the C++ decoder, which knows kind 0 and cannot
/// read kind 5 — a regenerated fixture would fail that file at its loader.
/// So the pinned bytes are held to one thing, that they are refused as the
/// retired kind, and the join the rest of this KAT judges is the one
/// [`build_gate4_document`] builds today: the same persona, bond-spend key,
/// endpoint, shard and floor, with a receipt key. Everything else in the
/// fixture — the conservation, the negative epoch, the emission — is still
/// read from the pinned file.
fn join_wire_of_record(kat: &Value) -> Vec<u8> {
    let pinned = decode_hex(kat["join"]["wire_hex"].as_str().expect("join wire"));
    assert_eq!(
        pinned[0],
        shekyl_archival_retention::VIN_TYPE_ARCHIVAL_BOND_POST
    );
    // The pinned join is the one the builder makes: a fixture that drifted
    // from the constants above fails here, not in a leg that reads it.
    let rebuilt = build_gate4_document();
    assert_eq!(
        rebuilt["join"], kat["join"],
        "the pinned join is the rebuilt one"
    );
    pinned
}

#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regenerate_gate4_lifecycle_fixture() {
    // The fixture is a self-pinned tripwire (rule 50): the shared guard
    // refuses to move it without a docs/V3_WALLET_DECISION_LOG.md citation.
    let decision =
        shekyl_crypto_pq::test_support::regen_decision_or_refuse("the gate-4 lifecycle fixture");
    eprintln!("regenerating the gate-4 lifecycle fixture under decision: {decision}");
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
    let join_wire = join_wire_of_record(&kat);
    assert_eq!(
        join_wire[0],
        shekyl_archival_retention::VIN_TYPE_ARCHIVAL_BOND_POST
    );
    let mut cursor = Cursor::new(&join_wire[1..]);
    let join_vin =
        ArchivalBondPostVin::read_payload_exact(&mut cursor).expect("parse join bond-post");
    verify_join_market_bond_post(&join_vin, false).expect("join verify");
    assert_eq!(
        bond_floor(
            &join_vin.holdings,
            &shekyl_archival_retention::ArchivalParams::SHIPPED
        ),
        join["bond_credit"].as_u64().expect("bond_credit")
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
    let join_wire = join_wire_of_record(&kat);
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
    let join_wire = join_wire_of_record(&kat);
    let join_vin = ArchivalBondPostVin::read_payload_exact(&mut Cursor::new(&join_wire[1..]))
        .expect("parse join bond-post");
    let pk_bytes = join_vin.hybrid_public_key;
    let expected = decode_hex32(kat["join"]["p_canonical_id_hex"].as_str().expect("p_id"));
    assert_eq!(
        p_canonical_id_from_hybrid_pubkey(&pk_bytes).to_bytes(),
        expected
    );
}
