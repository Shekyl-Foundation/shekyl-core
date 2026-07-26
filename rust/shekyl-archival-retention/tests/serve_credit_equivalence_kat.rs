// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standing serve-credit equivalence KAT — the Rust leg
//! (`ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md` §5).
//!
//! Runs the three decision mirrors (`serve_credit_decisions`) over the shared
//! fixture `serve_credit_equivalence_kat_v1.json` and asserts **verdict and
//! reason** for every vector. The C++ leg
//! (`tests/unit_tests/archival_serve_credit_equivalence.cpp`) drives the live
//! `check_archival_serve_credit_input` over the same vectors' `cpp_setup`
//! seeded-state mutations and asserts the `bool` verdict only — the §5
//! leg-responsibility split: the reason column here is authored by source
//! inspection at the fixture's `substrate_commit`, never parsed from C++
//! logs.
//!
//! Mirror-only vectors (`cpp_reachable: false`) cover branches that are
//! defensive dead code through the live call path (fire-height guard, vin
//! re-serialize failure, wrong/empty wire tag); their reason assertions still
//! pin the mirror's ordering fidelity.

use std::collections::BTreeSet;

use shekyl_archival_retention::challenge::challenge_fire_height;
use shekyl_archival_retention::serve_credit_decisions::{
    serve_credit_block_key, serve_credit_block_unique, serve_credit_gate_decision,
    serve_credit_key_be, serve_credit_preblock_duplicate, BlockUniqueVerdict, GateReject,
    GateVerdict, ServeCreditGateInputs, SERVE_CREDIT_KEY_LEN,
};

const KAT: &str = include_str!("fixtures/serve_credit_equivalence_kat_v1.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(KAT).expect("fixture parses")
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    let bytes = hex_bytes(v);
    bytes.as_slice().try_into().expect("32-byte hex")
}

fn hex_bytes(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Base-with-overrides field resolution: the vector's `overrides` map wins,
/// the `base` object supplies the rest.
struct VectorInputs<'a> {
    base: &'a serde_json::Value,
    overrides: &'a serde_json::Value,
}

impl VectorInputs<'_> {
    fn get(&self, field: &str) -> &serde_json::Value {
        let overridden = &self.overrides[field];
        if overridden.is_null() && !self.overrides.as_object().unwrap().contains_key(field) {
            &self.base[field]
        } else {
            overridden
        }
    }

    fn u64(&self, field: &str) -> u64 {
        self.get(field).as_u64().unwrap_or_else(|| {
            panic!("field {field} must be u64");
        })
    }

    fn bool(&self, field: &str) -> bool {
        self.get(field)
            .as_bool()
            .unwrap_or_else(|| panic!("field {field} must be bool"))
    }

    fn usize_array(&self, field: &str) -> Vec<usize> {
        self.get(field)
            .as_array()
            .unwrap_or_else(|| panic!("field {field} must be an array"))
            .iter()
            .map(|v| usize::try_from(v.as_u64().expect("count")).expect("usize"))
            .collect()
    }
}

fn reason_from_name(name: &str) -> GateReject {
    match name {
        "PathLayerCountExceedsBound" => GateReject::PathLayerCountExceedsBound,
        "C1BranchScalarCountExceedsBound" => GateReject::C1BranchScalarCountExceedsBound,
        "C2BranchScalarCountExceedsBound" => GateReject::C2BranchScalarCountExceedsBound,
        "DuplicatePreBlock" => GateReject::DuplicatePreBlock,
        "BondSubstrateMissing" => GateReject::BondSubstrateMissing,
        "EpochBeforeEFirst" => GateReject::EpochBeforeEFirst,
        "NotGoodThrough" => GateReject::NotGoodThrough,
        "PastCreditDeadline" => GateReject::PastCreditDeadline,
        "SealBlockNotYetCommitted" => GateReject::SealBlockNotYetCommitted,
        "SealHashUnavailable" => GateReject::SealHashUnavailable,
        "FireHeightDerivationFailed" => GateReject::FireHeightDerivationFailed,
        "ShardNotHeldAtFire" => GateReject::ShardNotHeldAtFire,
        "ShardRegistryUnavailableAtFire" => GateReject::ShardRegistryUnavailableAtFire,
        "LeafIndexOutOfSegmentRange" => GateReject::LeafIndexOutOfSegmentRange,
        "LeafChunkReadFailed" => GateReject::LeafChunkReadFailed,
        "VinSerializeFailed" => GateReject::VinSerializeFailed,
        "UnexpectedVinWireTag" => GateReject::UnexpectedVinWireTag,
        "FfiVerifyFailed" => GateReject::FfiVerifyFailed,
        other => panic!("unknown expected_reason {other}"),
    }
}

/// The fixture's `h_fire` pin must equal the shared Rust derivation the C++
/// calls through the FFI — a cross-language tripwire on the fire-height
/// operands before any gate vector runs.
#[test]
fn base_fire_height_matches_shared_derivation() {
    let doc = fixture();
    let base = &doc["gate"]["base"];
    let derived = challenge_fire_height(
        base["h_open"].as_u64().unwrap(),
        base["h_close"].as_u64().unwrap(),
        &hex32(&base["seal_hash_hex"]),
        &hex32(&base["p_canonical_id_hex"]),
        base["shard_id"].as_u64().unwrap(),
        base["settlement_epoch"].as_u64().unwrap(),
    );
    assert_eq!(derived, base["h_fire"].as_u64().unwrap());
}

#[test]
fn gate_vectors_verdict_and_reason() {
    let doc = fixture();
    let base = &doc["gate"]["base"];
    let vectors = doc["gate"]["vectors"].as_array().expect("gate vectors");
    assert!(!vectors.is_empty());

    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id");
        let v = VectorInputs {
            base,
            overrides: &vector["overrides"],
        };

        let c1 = v.usize_array("c1_branch_scalar_counts");
        let c2 = v.usize_array("c2_branch_scalar_counts");
        let seal_hash = if v.bool("seal_hash_available") {
            Some(hex32(v.get("seal_hash_hex")))
        } else {
            None
        };
        let wire_first_byte = {
            let raw = v.get("wire_first_byte");
            if raw.is_null() {
                None
            } else {
                Some(u8::try_from(raw.as_u64().expect("byte")).expect("u8"))
            }
        };

        let inputs = ServeCreditGateInputs {
            p_canonical_id: hex32(v.get("p_canonical_id_hex")),
            shard_id: v.u64("shard_id"),
            settlement_epoch: v.u64("settlement_epoch"),
            c1_branch_scalar_counts: &c1,
            c2_branch_scalar_counts: &c2,
            preblock_present: v.bool("preblock_present"),
            bond_substrate_present: v.bool("bond_substrate_present"),
            join_epoch: v.u64("join_epoch"),
            good_through: v.bool("good_through"),
            current_height: v.u64("current_height"),
            h_open: v.u64("h_open"),
            h_close: v.u64("h_close"),
            seal_hash,
            held_at_fire: v.bool("held_at_fire"),
            registry_present_at_fire: v.bool("registry_present_at_fire"),
            leaf_index_in_segment: v.u64("leaf_index_in_segment"),
            leaf_chunk_ok: v.bool("leaf_chunk_ok"),
            wire_serialize_ok: v.bool("wire_serialize_ok"),
            wire_first_byte,
            verify_ok: v.bool("verify_ok"),
        };

        let verdict = serve_credit_gate_decision(&inputs);
        let expected_verdict = vector["expected_verdict"].as_bool().expect("verdict");
        assert_eq!(verdict.accepted(), expected_verdict, "vector {id}: verdict");

        match vector["expected_reason"].as_str() {
            None => assert_eq!(verdict, GateVerdict::Accept, "vector {id}: accept"),
            Some(name) => assert_eq!(
                verdict,
                GateVerdict::Reject(reason_from_name(name)),
                "vector {id}: reason"
            ),
        }
    }
}

#[test]
fn dedup_vectors_verdict_and_key_pin() {
    let doc = fixture();
    for vector in doc["dedup"]["vectors"].as_array().expect("dedup vectors") {
        let id = vector["id"].as_str().expect("id");
        let p = hex32(&vector["p_canonical_id_hex"]);
        let shard_id = vector["shard_id"].as_u64().unwrap();
        let epoch = vector["settlement_epoch"].as_u64().unwrap();

        let key = serve_credit_key_be(&p, shard_id, epoch);
        assert_eq!(
            key.to_vec(),
            hex_bytes(&vector["expected_key_be_hex"]),
            "vector {id}: BE key bytes"
        );

        let preblock: BTreeSet<[u8; SERVE_CREDIT_KEY_LEN]> = vector["preblock_keys_hex"]
            .as_array()
            .expect("preblock keys")
            .iter()
            .map(|k| hex_bytes(k).as_slice().try_into().expect("48-byte key"))
            .collect();
        assert_eq!(
            serve_credit_preblock_duplicate(&preblock, &p, shard_id, epoch),
            vector["expected_duplicate"].as_bool().unwrap(),
            "vector {id}: duplicate verdict"
        );
    }
}

#[test]
fn block_unique_vectors_verdict_and_key_pin() {
    let doc = fixture();
    for vector in doc["block_unique"]["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().expect("id");
        let triples: Vec<([u8; 32], u64, u64)> = vector["triples"]
            .as_array()
            .expect("triples")
            .iter()
            .map(|t| {
                (
                    hex32(&t[0]),
                    t[1].as_u64().expect("shard"),
                    t[2].as_u64().expect("epoch"),
                )
            })
            .collect();

        let verdict = serve_credit_block_unique(&triples);
        match vector["expected"].as_str().expect("expected") {
            "unique" => assert_eq!(verdict, BlockUniqueVerdict::Unique, "vector {id}"),
            "duplicate_at" => {
                let index =
                    usize::try_from(vector["duplicate_index"].as_u64().expect("index")).unwrap();
                assert_eq!(
                    verdict,
                    BlockUniqueVerdict::DuplicateAt { index },
                    "vector {id}"
                );
            }
            other => panic!("unknown expected kind {other}"),
        }

        if let Some(pin) = vector["expected_first_key_be_hex"].as_str() {
            let (p, shard_id, epoch) = triples[0];
            assert_eq!(
                serve_credit_block_key(&p, shard_id, epoch).to_vec(),
                hex_bytes(&serde_json::Value::String(pin.to_owned())),
                "vector {id}: unified BE key bytes"
            );
        }
    }
}

/// SCE-1 executable record, post-unify: the two decision paths (D-SC-A
/// persistent, D-SC-C block-level) key the same logical `(P, shard, E)`
/// triple with the *same* bytes — the unify commit re-pointed D-SC-C onto
/// `ArchivalServeCreditKey` (audit doc §6). `expect_equal` is now `true` and
/// load-bearing: a reintroduced encoding split fails here.
#[test]
fn sce1_key_encoding_crosscheck() {
    let doc = fixture();
    let x = &doc["sce1_crosscheck"];
    let p = hex32(&x["p_canonical_id_hex"]);
    let shard_id = x["shard_id"].as_u64().unwrap();
    let epoch = x["settlement_epoch"].as_u64().unwrap();

    let key_be = serve_credit_key_be(&p, shard_id, epoch);
    let key_block = serve_credit_block_key(&p, shard_id, epoch);
    assert_eq!(key_be.to_vec(), hex_bytes(&x["key_be_hex"]));
    assert_eq!(key_block.to_vec(), hex_bytes(&x["key_block_hex"]));

    let expect_equal = x["expect_equal"].as_bool().expect("expect_equal");
    assert_eq!(
        key_be == key_block,
        expect_equal,
        "SCE-1 pin: the unified A/C key encoding must not re-split"
    );
}
