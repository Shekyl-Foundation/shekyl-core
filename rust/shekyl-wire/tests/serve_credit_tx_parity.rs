// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-language byte-parity KAT for the serve-credit TRANSACTION (RF-D1 /
//! RF-D9, `ARCHIVAL_RESPONSE_FORMAT.md` §3.5).
//!
//! Until this file, the serve-credit shape had never round-tripped in C++ at
//! all (RF-D9), and this crate's own comment deferred its live-oracle parity
//! to "when those post-genesis blobs are capturable". This is that parity,
//! established for the first time rather than restored:
//!
//! - the two blobs come from the gate-2 fixture (`wire_hex` = the kept vin,
//!   `pruned_hex` = the pruned record), whose interiors are the retention
//!   codec's;
//! - this crate builds the whole transaction around them and serializes it
//!   with the Rust oracle of the C++ wire;
//! - the bytes are pinned in `tests/fixtures/serve_credit_tx_parity_v1.json`;
//! - `tests/unit_tests/archival_serve_credit_integration.cpp` builds the SAME
//!   transaction from the same blobs, serializes it with the C++ serializer,
//!   and asserts byte-equality with the pin -- and parses the pin back.
//!
//! A divergence anywhere in the fee-only ct encoding, the empty-`pqc_auths`
//! rule, or the pruned-record framing fails one side against the other.

use std::path::PathBuf;

use serde_json::Value;
use shekyl_types::{ArchivalLength, BlockHash, PrunableHash};
use shekyl_wire::{Ct, CtBase, Input, Prunable, Transaction, TxPrefix};

const GATE2_FIXTURE: &str =
    "../shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json";
const PARITY_FIXTURE: &str = "tests/fixtures/serve_credit_tx_parity_v1.json";

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex length {} is odd; fixture is malformed",
        s.len()
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_str(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn manifest(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The serve-credit transaction around the fixture's two blobs: one vin, no
/// outputs, fee 0, empty `pqc_auths`, and a prunable region holding nothing
/// but the pruned record -- exactly what consensus requires of the shape
/// (`tx_verification_utils.cpp:117-124`).
fn build_tx(kept: Vec<u8>, pruned: Vec<u8>) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ServeCredit {
                canonical_bytes: kept,
            }],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
            base: CtBase {
                enc_amounts: vec![],
                enc_labels: vec![],
                commitments: vec![],
            },
            pqc_auths: vec![],
            prunable: Some(Prunable {
                bulletproofs: vec![],
                tree_depth: 0,
                fcmp_proof: vec![],
                pseudo_outs: vec![],
                serve_credit_pruned: vec![pruned],
            }),
        },
    }
}

fn gate2_integration_blobs() -> (Vec<u8>, Vec<u8>) {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest(GATE2_FIXTURE)).expect("gate-2"))
            .expect("gate-2 json");
    let integ = &doc["integration"];
    (
        hex_bytes(integ["wire_hex"].as_str().expect("wire_hex")),
        hex_bytes(integ["pruned_hex"].as_str().expect("pruned_hex")),
    )
}

#[test]
#[ignore = "writes tests/fixtures/serve_credit_tx_parity_v1.json"]
fn regenerate_serve_credit_tx_parity_fixture() {
    let (kept, pruned) = gate2_integration_blobs();
    let tx = build_tx(kept.clone(), pruned.clone());
    tx.validate().expect("the parity tx must validate");
    let doc = serde_json::json!({
        "format_version": 2,
        "description": "Serve-credit full-transaction byte-parity KAT (RF-D1/RF-D9; SHT-Q2). Blobs are the gate-2 integration section's; tx_hex is shekyl-wire's serialization of the transaction built around them; archival_len is its prunable region's bytes (it has no pqc_auths), which the txid binds. The C++ leg (archival_serve_credit_integration.cpp) must serialize the same transaction to these bytes, parse them back, and reproduce the hash.",
        "kept_wire_hex": hex_str(&kept),
        "pruned_hex": hex_str(&pruned),
        "tx_hex": hex_str(tx.serialize()),
        "archival_len": tx.archival_len().to_raw(),
        "tx_hash_hex": hex_str(tx.hash()),
    });
    std::fs::write(
        manifest(PARITY_FIXTURE),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write");
}

#[test]
fn serve_credit_tx_serializes_to_the_pinned_bytes() {
    let pin: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest(PARITY_FIXTURE)).expect("parity fixture"),
    )
    .expect("parity json");
    let (kept, pruned) = gate2_integration_blobs();
    assert_eq!(
        hex_str(&kept),
        pin["kept_wire_hex"].as_str().unwrap(),
        "gate-2 blobs moved under the parity pin: regenerate both"
    );
    assert_eq!(hex_str(&pruned), pin["pruned_hex"].as_str().unwrap());

    let tx = build_tx(kept.clone(), pruned.clone());
    tx.validate().expect("validate");
    let bytes = tx.serialize();
    assert_eq!(hex_str(&bytes), pin["tx_hex"].as_str().unwrap(), "tx bytes");
    assert_eq!(
        hex_str(tx.hash()),
        pin["tx_hash_hex"].as_str().unwrap(),
        "tx hash"
    );

    // And the bytes re-parse to the same transaction.
    let back = Transaction::from_bytes(&bytes).expect("parse");
    assert_eq!(back, tx);

    // The PRUNED identity on the arm with no `pqc_auths` component: the
    // prunable region is the full form's tail after the pruned prefix, and
    // mixing its digest and the archival length back in via
    // `hash_with_supplied_prunable` must reproduce the pinned hash — the same
    // recomputation the engine performs on a pruned reply, against the txid
    // the C++ leg also asserts (same fixture). With no `pqc_auths`, the
    // archival length is the region's own length. The spend arm has its own
    // pin (`pruned_tx_hash_parity_v1.json`).
    let pruned_form = {
        let mut t = build_tx(kept, pruned);
        let Ct::Fcmp { prunable, .. } = &mut t.ct else {
            unreachable!("build_tx is Fcmp by construction");
        };
        *prunable = None;
        t.serialize()
    };
    assert!(
        bytes.starts_with(&pruned_form),
        "the pruned form must be a prefix of the full form"
    );
    let region = &bytes[pruned_form.len()..];
    let digest = shekyl_crypto_hash::keccak256(region);
    let archival_len =
        ArchivalLength::from_raw(pin["archival_len"].as_u64().expect("archival_len"));
    assert_eq!(
        archival_len.to_raw(),
        u64::try_from(region.len()).expect("fits"),
        "a serve-credit transaction's archival length is its prunable region"
    );
    assert_eq!(tx.archival_len(), archival_len, "measured archival length");

    // The mix, spelled out here instead of asked of the mixer. Four words —
    // this form has no `pqc_auths` component: the digests of the prefix, the
    // ct base and the prunable region, then the length as a little-endian
    // `u64` in a zeroed word.
    let mut ct_section = Vec::new();
    tx.ct.write(&mut ct_section).expect("Vec write");
    let (prefix, ct) = bytes.split_at(bytes.len() - ct_section.len());
    let base = &ct[..ct.len() - region.len()];
    let mut length_word = [0u8; 32];
    length_word[..8].copy_from_slice(&archival_len.to_raw().to_le_bytes());
    let preimage = [
        shekyl_crypto_hash::keccak256(prefix),
        shekyl_crypto_hash::keccak256(base),
        digest,
        length_word,
    ]
    .concat();
    assert_eq!(
        preimage.len(),
        4 * 32,
        "a serve-credit txid mixes four words"
    );
    assert_eq!(
        hex_str(shekyl_crypto_hash::keccak256(&preimage)),
        pin["tx_hash_hex"].as_str().unwrap(),
        "the txid is not the four-word mix"
    );

    assert_eq!(
        hex_str(tx.hash_with_supplied_prunable(PrunableHash::from_bytes(digest), archival_len)),
        pin["tx_hash_hex"].as_str().unwrap(),
        "pruned identity (supplied digest and length) diverged from the pinned hash"
    );
}
