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

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
            reference_block: [0u8; 32],
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
        "format_version": 1,
        "description": "Serve-credit full-transaction byte-parity KAT (RF-D1/RF-D9). Blobs are the gate-2 integration section's; tx_hex is shekyl-wire's serialization of the transaction built around them. The C++ leg (archival_serve_credit_integration.cpp) must serialize the same transaction to these bytes and parse them back.",
        "kept_wire_hex": hex_str(&kept),
        "pruned_hex": hex_str(&pruned),
        "tx_hex": hex_str(&tx.serialize()),
        "tx_hash_hex": hex_str(&tx.hash()),
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
        hex_str(&tx.hash()),
        pin["tx_hash_hex"].as_str().unwrap(),
        "tx hash"
    );

    // And the bytes re-parse to the same transaction.
    let back = Transaction::from_bytes(&bytes).expect("parse");
    assert_eq!(back, tx);

    // The PRUNED identity on the 3-part (empty-`pqc_auths`) arm: the prunable
    // region is the full form's tail after the pruned prefix, and mixing its
    // digest back in via `hash_with_supplied_prunable` must reproduce the
    // pinned hash — the same recomputation the engine performs on a pruned
    // reply, against the txid the C++ leg also asserts
    // (`get_pruned_transaction_hash`, same fixture). The 4-part spend arm has
    // its own pin (`pruned_tx_hash_parity_v1.json`).
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
    let digest = shekyl_crypto_hash::keccak256(&bytes[pruned_form.len()..]);
    assert_eq!(
        hex_str(&tx.hash_with_supplied_prunable(digest)),
        pin["tx_hash_hex"].as_str().unwrap(),
        "pruned identity (supplied digest) diverged from the pinned hash"
    );
}
