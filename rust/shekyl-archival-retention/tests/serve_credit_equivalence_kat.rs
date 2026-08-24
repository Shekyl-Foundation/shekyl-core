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
}

fn reason_from_name(name: &str) -> GateReject {
    match name {
        "VinUnparseable" => GateReject::VinUnparseable,
        "PrunedRecordSizeOutOfBounds" => GateReject::PrunedRecordSizeOutOfBounds,
        "DuplicatePreBlock" => GateReject::DuplicatePreBlock,
        "BondSubstrateMissing" => GateReject::BondSubstrateMissing,
        "EpochBeforeEFirst" => GateReject::EpochBeforeEFirst,
        "NotGoodThrough" => GateReject::NotGoodThrough,
        "PastCreditDeadline" => GateReject::PastCreditDeadline,
        "SealBlockNotYetCommitted" => GateReject::SealBlockNotYetCommitted,
        "SealHashUnavailable" => GateReject::SealHashUnavailable,
        "ShardNotHeldAtFire" => GateReject::ShardNotHeldAtFire,
        "ShardRegistryUnavailableAtFire" => GateReject::ShardRegistryUnavailableAtFire,
        "LeafIndexDerivationRefused" => GateReject::LeafIndexDerivationRefused,
        "LeafIndexOutOfSegmentRange" => GateReject::LeafIndexOutOfSegmentRange,
        "LeafChunkReadFailed" => GateReject::LeafChunkReadFailed,
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

        let seal_hash = if v.bool("seal_hash_available") {
            Some(hex32(v.get("seal_hash_hex")))
        } else {
            None
        };

        let inputs = ServeCreditGateInputs {
            p_canonical_id: hex32(v.get("p_canonical_id_hex")),
            shard_id: v.u64("shard_id"),
            settlement_epoch: v.u64("settlement_epoch"),
            vin_parsed: v.bool("vin_parsed"),
            pruned_record_in_bounds: v.bool("pruned_record_in_bounds"),
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
            segment_leaf_count: v.u64("segment_leaf_count"),
            // `PC-D3`. Read from the fixture rather than defaulted so both
            // legs are fed the SAME bytes for this input -- see
            // `prev_block_hash_is_fed_from_the_fixture_not_defaulted` for why
            // that is not something these vectors can otherwise detect.
            prev_block_hash: hex32(v.get("prev_block_hash_hex")),
            leaf_chunk_ok: v.bool("leaf_chunk_ok"),
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

// ---------------------------------------------------------------------------
// Regen writer (FOLLOWUP 2026-08-10: "serve-credit equivalence fixture needs a
// regen writer") — the gate-4 pattern: re-derive the gate-2-mirrored substrate
// mechanically, preserve the hand-authored columns.
// ---------------------------------------------------------------------------

/// Replace the value of the FIRST occurrence of `"key": <number>` in `doc`.
/// The first occurrence of every mirrored scalar lives in `gate.base` (the
/// vectors' overrides come later in the document), so first-match is the
/// base-targeted edit that leaves override values untouched.
fn replace_first_scalar(doc: &str, key: &str, new_value: u64) -> String {
    let needle = format!("\"{key}\": ");
    let start = doc
        .find(&needle)
        .unwrap_or_else(|| panic!("no {key} field"))
        + needle.len();
    let end = start
        + doc[start..]
            .find(|c: char| !c.is_ascii_digit())
            .expect("number terminator");
    assert!(
        doc[start..end].chars().all(|c| c.is_ascii_digit()) && start < end,
        "{key} is not a bare number"
    );
    format!("{}{}{}", &doc[..start], new_value, &doc[end..])
}

/// Rewrite `serve_credit_equivalence_kat_v1.json`'s gate-2-mirrored substrate
/// from `gate2_serve_credit_kat_v1.json` — run after any gate-2 regen. The
/// rewrite is **textual** on purpose: only the mechanical mirrors move (the
/// `gate.base` scalars and every p_id-prefixed key encoding), and the
/// hand-authored columns (`expected_verdict`, `expected_reason`, `overrides`,
/// `cpp_setup`, notes, `substrate_commit`) plus the document's layout are
/// preserved byte-for-byte. Re-author the reason column (and bump
/// `substrate_commit`) only when the C++ substrate itself changes (§5).
#[test]
#[ignore = "rewrites tests/fixtures/serve_credit_equivalence_kat_v1.json from the gate-2 substrate"]
fn regenerate_equivalence_fixture_from_gate2() {
    use shekyl_archival_retention::wire::ArchivalServeCreditResponse;

    let gate2: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/gate2_serve_credit_kat_v1.json"))
            .expect("gate2 fixture parses");
    let integ = &gate2["integration"];
    let mut doc = KAT.to_owned();

    let old_pid = fixture()["gate"]["base"]["p_canonical_id_hex"]
        .as_str()
        .expect("old p_id")
        .to_owned();
    let new_pid = integ["p_canonical_id_hex"]
        .as_str()
        .expect("new p_id")
        .to_owned();
    assert_eq!(old_pid.len(), 64);
    assert_eq!(new_pid.len(), 64);

    // Every occurrence of the old p_id is a gate-2 mirror: the base field and
    // the dedup/block-unique key encodings, which are `p_id ‖ shard ‖ epoch`
    // words — a prefix swap re-derives them exactly.
    doc = doc.replace(&old_pid, &new_pid);

    // `PC-D3`: the base must mirror gate-2's integration block, or the two
    // legs derive the challenged index from different blocks.
    let old_prev = fixture()["gate"]["base"]["prev_block_hash_hex"]
        .as_str()
        .expect("old prev block hash")
        .to_owned();
    let new_prev = integ["prev_block_hash_hex"]
        .as_str()
        .expect("gate-2 prev block hash")
        .to_owned();
    assert_eq!(old_prev.len(), 64);
    assert_eq!(new_prev.len(), 64);
    doc = doc.replace(&old_prev, &new_prev);

    // The integration wire is the parse-authoritative source for the leaf
    // index the base mirrors (and for the path shape asserted below).
    let wire = hex_bytes(&integ["wire_hex"]);
    // Parse-only assertion: the kept half must still parse. Nothing below
    // reads it -- the index is the fixture's recorded derivation and the path
    // is on the pruned half (RF-D1/RF-D6).
    let _kept =
        ArchivalServeCreditResponse::read(&mut wire.as_slice()).expect("integration wire parses");

    for (key, value) in [
        ("h_open", integ["h_open"].as_u64().expect("h_open")),
        ("h_close", integ["h_close"].as_u64().expect("h_close")),
        ("h_seal", integ["h_seal"].as_u64().expect("h_seal")),
        ("h_fire", integ["h_fire"].as_u64().expect("h_fire")),
        (
            "current_height",
            integ["current_height"].as_u64().expect("current_height"),
        ),
        // RF-D6: the index is no longer on the wire; the gate-2 fixture records
        // the verifier's derived value, which is what the base mirrors.
        (
            "leaf_index_in_segment",
            integ["leaf_index_in_segment"]
                .as_u64()
                .expect("recorded index"),
        ),
    ] {
        doc = replace_first_scalar(&doc, key, value);
    }

    // (The base no longer mirrors the path shape: the path is inside the pruned
    // record, which C++ does not read, so its bounds are no longer gate steps.)
    let reparsed: serde_json::Value = serde_json::from_str(&doc).expect("rewritten doc parses");
    let _ = &reparsed;
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/serve_credit_equivalence_kat_v1.json");
    std::fs::write(&path, doc).expect("write");
    eprintln!("wrote {}", path.display());
}
