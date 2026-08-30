// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-language KAT for the **pruned transaction identity** — the 4-part
//! FCMP++/PQC spend arm of `Transaction::hash_with_supplied_prunable` against
//! C++ `get_pruned_transaction_hash` (RK-4c; `GENESIS_TX_WIRE_FORMAT.md` §11).
//!
//! Until this file, every in-tree test that touched the pruned identity
//! derived its expected txid by calling the function under test, so a
//! component-order or arm-selection error would leave every Rust fixture and
//! every check agreeing on the same wrong value — green tests, while a real
//! daemon's every pruned reply fails `parse_tx_batch`'s "a label is not an
//! identity" refusal. This pin breaks that circle:
//!
//! - this crate builds a structurally canonical PQC spend (zeroed proof
//!   bytes; commitments are the Ed25519 basepoint so the C++ parse's
//!   `expand_transaction_1` can decompress them), serializes the full and
//!   the pruned form, and pins bytes + prunable digest + txid in
//!   `tests/fixtures/pruned_tx_hash_parity_v1.json`;
//! - `tests/unit_tests/pruned_tx_hash_parity.cpp` builds the SAME
//!   transaction, and asserts the C++ production serializer reproduces the
//!   bytes, `get_transaction_hash` / `get_pruned_transaction_hash` reproduce
//!   the txid, `calculate_transaction_prunable_hash` reproduces the digest,
//!   and `serialize_base` (the framing `get_pruned_tx_blob` serves) equals
//!   the pinned pruned bytes.
//!
//! A wrong branch anywhere in `hash_with_prunable` — transposed components, a
//! misclassified `has_pqc`, a miscounted auth segment — fails one language
//! against the other instead of agreeing with itself.
//!
//! The **live-oracle** spend KAT (a daemon-accepted spend captured off a
//! running node) remains deferred on its named blocker — the FCMP++ spend
//! path has not yet produced a daemon-accepted transaction to capture
//! (`docs/FOLLOWUPS.md`). This pin is the struct-derived half: it binds the
//! two implementations to each other, not yet to a chain.

use std::path::PathBuf;

use serde_json::Value;
use shekyl_crypto_hash::keccak256;
use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix};

const PARITY_FIXTURE: &str = "tests/fixtures/pruned_tx_hash_parity_v1.json";

/// The compressed Ed25519 basepoint. `expand_transaction_1` multiplies each
/// output commitment by `INV_EIGHT` on parse, which requires a decompressable
/// point — arbitrary bytes fail the C++ leg before any hash is compared.
const BASEPOINT: [u8; 32] = {
    let mut k = [0x66u8; 32];
    k[0] = 0x58;
    k
};

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// The prunable region of the KAT spend, built separately so its serialized
/// bytes (the digest's preimage) are observable to the regenerator.
fn kat_prunable() -> Prunable {
    Prunable {
        serve_credit_pruned: Vec::new(),
        bulletproofs: vec![BpPlus {
            a: [0; 32],
            a1: [0; 32],
            b: [0; 32],
            r1: [0; 32],
            s1: [0; 32],
            d1: [0; 32],
            // L.len() == 7 → capacity 2 amounts, matching the two outputs the
            // anti-deanonymization minimum requires.
            l: vec![[0; 32]; 7],
            r: vec![[0; 32]; 7],
        }],
        tree_depth: 1,
        fcmp_proof: vec![0u8; 8],
        pseudo_outs: vec![[0; 32]],
    }
}

/// A structurally canonical v3 PQC spend: one `ToKey` input, two outputs, one
/// hybrid auth per input, the prunable section of [`kat_prunable`]. Proof
/// bytes are zeroed placeholders — both legs parse and hash, neither verifies
/// proof math, so the KAT pins the *derivation*, not a valid spend.
fn build_tx(with_prunable: bool) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x42u8; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [1u8; 32],
                    view_tag: 0,
                },
                Output {
                    amount: 0,
                    key: [3u8; 32],
                    view_tag: 1,
                },
            ],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0u8; 32],
            base: CtBase {
                enc_amounts: vec![[0u8; 9], [0u8; 9]],
                enc_labels: vec![[0u8; 9], [0u8; 9]],
                commitments: vec![BASEPOINT, BASEPOINT],
            },
            pqc_auths: vec![PqcAuth {
                auth_version: 1,
                scheme_id: 1,
                flags: 0,
                hybrid_public_key: vec![0u8; PQC_HYBRID_SINGLE_KEY_LEN],
                hybrid_signature: vec![0u8; PQC_HYBRID_SINGLE_SIG_LEN],
            }],
            prunable: with_prunable.then(kat_prunable),
        },
    }
}

/// `keccak256` of the prunable region's bytes — derived as the full form's
/// tail after the pruned prefix, which is the same positional identity the
/// C++ blob path hashes (`tx_prunable_region_sole_occupant.cpp` pins that the
/// region has exactly one occupant, so the tail IS `Prunable::write`).
fn prunable_digest() -> [u8; 32] {
    let full = build_tx(true).serialize();
    let pruned_len = build_tx(false).serialize().len();
    keccak256(&full[pruned_len..])
}

#[test]
#[ignore = "writes tests/fixtures/pruned_tx_hash_parity_v1.json"]
fn regenerate_pruned_tx_hash_parity_fixture() {
    let tx = build_tx(true);
    tx.validate().expect("the parity tx must validate");
    let digest = prunable_digest();
    // The two derivations must already agree in Rust before either is pinned:
    // the pruned identity with the true digest supplied IS the txid.
    assert_eq!(tx.hash(), tx.hash_with_supplied_prunable(digest));
    let doc = serde_json::json!({
        "format_version": 1,
        "description": "Pruned-identity KAT for the 4-part FCMP++/PQC spend arm \
         (RK-4c). tx_hex is shekyl-wire's serialization of the spend; pruned_hex \
         its pruned form (the serialize_base framing get_pruned_tx_blob serves); \
         prunable_hash_hex = keccak256 of the prunable region; tx_hash_hex the \
         txid. The C++ leg (pruned_tx_hash_parity.cpp) must reproduce all four \
         with its production serializer and hash functions.",
        "tx_hex": hex_str(&tx.serialize()),
        "pruned_hex": hex_str(&build_tx(false).serialize()),
        "prunable_hash_hex": hex_str(&digest),
        "tx_hash_hex": hex_str(&tx.hash()),
    });
    std::fs::write(
        manifest(PARITY_FIXTURE),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write");
}

#[test]
fn pruned_spend_identity_matches_the_pinned_oracle() {
    let pin: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest(PARITY_FIXTURE)).expect("parity fixture"),
    )
    .expect("parity json");
    let tx_hex = pin["tx_hex"].as_str().expect("tx_hex");
    let pruned_hex = pin["pruned_hex"].as_str().expect("pruned_hex");
    let prunable_hash_hex = pin["prunable_hash_hex"]
        .as_str()
        .expect("prunable_hash_hex");
    let tx_hash_hex = pin["tx_hash_hex"].as_str().expect("tx_hash_hex");

    // The construction still serializes and hashes to the pinned bytes.
    let tx = build_tx(true);
    tx.validate().expect("validate");
    assert_eq!(hex_str(&tx.serialize()), tx_hex, "full tx bytes");
    assert_eq!(hex_str(&tx.hash()), tx_hash_hex, "txid");
    assert_eq!(
        hex_str(&prunable_digest()),
        prunable_hash_hex,
        "prunable digest"
    );

    // The pruned form is the full form's prefix — the split identity the
    // daemon's storage (`txs_pruned` + `txs_pqc_auths`) reassembles and
    // serves as `pruned_as_hex`.
    assert!(
        tx_hex.starts_with(pruned_hex),
        "the pruned form must be a prefix of the full form"
    );

    // The bound surface: parse the pinned pruned bytes through the same
    // entry the engine's `parse_pruned_tx` uses, then mix the supplied
    // digest — the recomputed identity must be the pinned txid. This is the
    // exact recomputation `parse_tx_batch` performs against an untrusted
    // daemon's reply.
    let pruned = Transaction::from_bytes(&hex_bytes(pruned_hex)).expect("pruned parse");
    pruned
        .validate_context_free_pruned()
        .expect("the served pruned form must pass the engine's shape gate");
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hex_bytes(prunable_hash_hex));
    assert_eq!(
        hex_str(&pruned.hash_with_supplied_prunable(digest)),
        tx_hash_hex,
        "pruned identity (supplied digest) diverged from the pinned txid"
    );
}
