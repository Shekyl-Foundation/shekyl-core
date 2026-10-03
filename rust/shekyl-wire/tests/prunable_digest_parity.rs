// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-language pin for the **prunable digest**, on a body of every
//! transaction class.
//!
//! The prunable digest is a txid operand that also travels on its own: the
//! daemon stores it (`txs_prunable_hash`) and serves it beside a pruned body,
//! and a wallet mixes it into the txid it checks that body against. It has
//! one definition, [`shekyl_wire::prunable_hash_of`]. The C++ daemon owns no
//! hash of it: `calculate_transaction_prunable_hash` finds the range and
//! calls that function over FFI (`shekyl_tx_prunable_hash`).
//!
//! What can still go wrong is **which bytes** each side takes to be the
//! prunable range, and that differs by class — a coinbase has none, a
//! serve-credit transaction's is pass records and no proofs, a bond post's
//! and an emission claim's follow different inputs. So the pin is per class:
//!
//! - this crate derives each body's digest and pins it in
//!   `tests/fixtures/prunable_digest_parity_v1.json`;
//! - `tests/unit_tests/prunable_digest_parity.cpp` parses the same bytes with
//!   the C++ parser and asserts `get_transaction_prunable_hash` — the range
//!   the C++ serializer cut, hashed by this crate — gives the same value,
//!   from the blob and from a fresh serialization.
//!
//! The bodies are not new: eight are the daemon-accepted transactions of
//! `pqc_signing_preimage_v1.json`, read from that fixture by name, and the
//! ninth is the coinbase of `vectors/regtest_coinbase_h1.block`.
//!
//! **The pinned values have an oracle that is neither side's current code.**
//! The signing-preimage fixture's payloads were captured from the C++
//! assembly before it was deleted, and each payload carries
//! `keccak256(prunable)` right after the pruned segment. Every pinned digest
//! of a body with a payload is held to those 32 bytes; the coinbase's is held
//! to `keccak256("")` written out.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use shekyl_wire::{prunable_hash_of, Block, Input, Transaction};

const FIXTURE: &str = "tests/fixtures/prunable_digest_parity_v1.json";
const BODIES: &str = "tests/fixtures/pqc_signing_preimage_v1.json";

/// `keccak256("")`: the digest of a body with no prunable region.
const KECCAK_OF_NOTHING: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

const DESCRIPTION: &str = "Prunable digest of one body per transaction class. \
     prunable_hash_hex = keccak256 of the body's prunable region (shekyl-wire \
     prunable_hash_of), which is keccak256 of nothing for a coinbase. An entry \
     with tx_hex carries its own bytes; an entry without takes them from the \
     transaction of the same name in pqc_signing_preimage_v1.json. The C++ leg \
     (tests/unit_tests/prunable_digest_parity.cpp) parses the same bytes and \
     asserts get_transaction_prunable_hash returns the same value.";

fn hex_str(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn manifest(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(manifest(rel)).expect("fixture")).expect("json")
}

/// The class a body's inputs put it in, by the same partition the consensus
/// validator derives (`shekyl-chain-rules`, `TxClass`): the archival arms
/// first, since each rides with fee spends.
fn class_of(tx: &Transaction) -> &'static str {
    let inputs = &tx.prefix.inputs;
    if inputs.iter().any(|i| matches!(i, Input::Gen(_))) {
        "coinbase"
    } else if inputs.iter().any(|i| matches!(i, Input::BondPost(_))) {
        "bond-post"
    } else if inputs
        .iter()
        .any(|i| matches!(i, Input::ArchivalRewardEmission { .. }))
    {
        "emission"
    } else if inputs
        .iter()
        .all(|i| matches!(i, Input::ServeCredit { .. }))
    {
        "serve-credit-only"
    } else {
        "spend"
    }
}

/// One pinned body.
struct Subject {
    name: String,
    /// The bytes, and whether the parity fixture has to carry them itself.
    bytes: Vec<u8>,
    inline: bool,
    /// `keccak256(prunable)` from a source that is not today's code, when
    /// there is one.
    oracle: Option<String>,
}

/// The nine bodies: the coinbase, then the signing-preimage fixture's eight
/// in its order.
fn subjects() -> Vec<Subject> {
    let block = Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h1.block"))
        .expect("block vector");
    let mut subjects = vec![Subject {
        name: "coinbase-regtest-h1".to_owned(),
        bytes: block.miner_transaction.serialize(),
        inline: true,
        oracle: Some(KECCAK_OF_NOTHING.to_owned()),
    }];
    for entry in json(BODIES)["transactions"]
        .as_array()
        .expect("transactions")
    {
        let bytes = hex_bytes(entry["tx_hex"].as_str().expect("tx_hex"));
        let tx = Transaction::from_bytes(&bytes).expect("a captured body parses");
        // payload(i) = pruned segment ‖ keccak256(prunable) ‖ …, so the 32
        // bytes after the pruned segment are the C++ assembly's digest.
        let pruned_len = tx.write_segments().expect("segments").pruned.len();
        let oracle = entry["payloads_hex"]
            .as_array()
            .expect("payloads_hex")
            .first()
            .map(|payload| {
                let payload = payload.as_str().expect("payload hex");
                payload[2 * pruned_len..2 * (pruned_len + 32)].to_owned()
            });
        subjects.push(Subject {
            name: entry["name"].as_str().expect("name").to_owned(),
            bytes,
            inline: false,
            oracle,
        });
    }
    subjects
}

/// Regenerate the pin. Run when a body or the digest's definition changes:
/// `cargo test -p shekyl-wire --test prunable_digest_parity -- --ignored`.
#[test]
#[ignore = "writes tests/fixtures/prunable_digest_parity_v1.json"]
fn regenerate_prunable_digest_parity_fixture() {
    let entries: Vec<Value> = subjects()
        .into_iter()
        .map(|s| {
            let tx = Transaction::from_bytes(&s.bytes).expect("parses");
            let mut entry = serde_json::json!({
                "name": s.name,
                "class": class_of(&tx),
                "prunable_hash_hex": hex_str(tx.prunable_hash()),
            });
            if s.inline {
                entry["tx_hex"] = Value::String(hex_str(&s.bytes));
            }
            entry
        })
        .collect();
    let doc = serde_json::json!({
        "format_version": 1,
        "description": DESCRIPTION,
        "transactions": entries,
    });
    std::fs::write(
        manifest(FIXTURE),
        serde_json::to_string_pretty(&doc).expect("json") + "\n",
    )
    .expect("write");
}

#[test]
fn every_class_has_a_pinned_prunable_digest_and_it_is_the_regions() {
    let pin = json(FIXTURE);
    assert_eq!(pin["description"].as_str(), Some(DESCRIPTION));
    let pinned = pin["transactions"].as_array().expect("transactions");
    let subjects = subjects();
    assert_eq!(pinned.len(), subjects.len(), "every subject is pinned");

    let mut classes = BTreeSet::new();
    let mut held_to_an_oracle = 0;
    for (entry, subject) in pinned.iter().zip(&subjects) {
        let name = subject.name.as_str();
        assert_eq!(entry["name"].as_str(), Some(name), "subject order");
        // An inline entry's bytes are the subject's; a referenced one has none.
        assert_eq!(
            entry["tx_hex"].as_str().map(hex_bytes),
            subject.inline.then(|| subject.bytes.clone()),
            "{name}: where the bytes live"
        );

        let tx = Transaction::from_bytes(&subject.bytes).expect("parses");
        assert_eq!(
            tx.serialize(),
            subject.bytes,
            "{name}: the bytes round-trip"
        );
        assert_eq!(
            entry["class"].as_str(),
            Some(class_of(&tx)),
            "{name}: class"
        );
        classes.insert(class_of(&tx));

        let pinned_digest = entry["prunable_hash_hex"].as_str().expect("digest");
        assert_eq!(hex_str(tx.prunable_hash()), pinned_digest, "{name}");

        // The digest is of the region and of nothing else: the bytes after
        // the pruned segment and the tx-level pqc_auths, cut from the wire.
        let segments = tx.write_segments().expect("segments");
        let region = &subject.bytes[segments.pruned.len() + segments.pqc_auths.len()..];
        assert_eq!(region, segments.prunable.as_slice(), "{name}: the region");
        assert_eq!(hex_str(prunable_hash_of(region)), pinned_digest, "{name}");

        if let Some(oracle) = &subject.oracle {
            assert_eq!(pinned_digest, oracle, "{name}: the independent oracle");
            held_to_an_oracle += 1;
        }
    }

    // Every class the validator partitions transactions into, and no pin
    // that rests only on the function under test except the one shape with
    // no signing payload to carry an oracle.
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        [
            "bond-post",
            "coinbase",
            "emission",
            "serve-credit-only",
            "spend"
        ]
    );
    assert_eq!(
        held_to_an_oracle,
        subjects.len() - 1,
        "all but the serve-credit form, which has no signing payload"
    );
}
