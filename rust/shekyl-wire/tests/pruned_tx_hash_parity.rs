// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-language KAT for the **transaction identity** of the FCMP++/PQC
//! spend arm — the full body, the pruned form
//! (`Transaction::hash_with_supplied_prunable`) and the skeleton — against the
//! C++ daemon's one txid entry (RK-4c; `SHT-Q2`; `GENESIS_TX_WIRE_FORMAT.md`
//! §11).
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
//!   the pruned form, and pins bytes + prunable digest + archival length +
//!   txid in `tests/fixtures/pruned_tx_hash_parity_v1.json`;
//! - `tests/unit_tests/pruned_tx_hash_parity.cpp` builds the SAME
//!   transaction, and asserts the C++ production serializer reproduces the
//!   bytes, `get_transaction_hash` — which hands the body's segments to this
//!   crate's mixer over FFI — reproduces the txid,
//!   `calculate_transaction_prunable_hash` reproduces the digest, and
//!   `serialize_base` (the framing `get_pruned_tx_blob` serves) equals the
//!   pinned pruned bytes.
//!
//! What the two languages hold each other to changed with `SHT-Q2`. There is
//! one mixer, so C++ no longer derives the mix a second time; it pins what
//! decides which bytes reach it — the serializer's bytes and the three
//! offsets it cuts them at. A misclassified `has_pqc` or a miscounted auth
//! segment on that side still fails against this pin. The mix itself —
//! component order, arity, the length word — is held here, by a derivation
//! spelled out in the test instead of asked of the mixer.
//!
//! The **live-oracle** spend KAT (`live_oracle_spend_v1.json`) is the other
//! half of this file: bytes a running `shekyld` accepted and connected,
//! captured by `e2e_fcmp_spend_accepted_by_daemon`. Note the distinction
//! against the sibling comments in `fcmp_spend_e2e.rs` and
//! `fcmp_spend_roundtrip.rs`, which say the **C++** spend path never produced
//! one: that is still true, and is a different claim. The synthetic pin binds
//! the two implementations to each other; the live pin binds both to a chain.

mod common;
use common::conforming_pqc_extra;

use std::path::PathBuf;

use serde_json::Value;
use shekyl_crypto_hash::keccak256;
use shekyl_types::{ArchivalLength, BlockHash, PrunableHash};
use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix};

const PARITY_FIXTURE: &str = "tests/fixtures/pruned_tx_hash_parity_v1.json";

/// The live-oracle sibling: daemon-accepted bytes. Deliberately a *separate*
/// fixture from [`PARITY_FIXTURE`] — that one is hand-built, deterministic and
/// reproducible with nothing but a checkout; this one requires a built daemon
/// and a live run. Neither subsumes the other, and consolidating them would
/// trade one property away for the other.
const LIVE_ORACLE_FIXTURE: &str = "tests/fixtures/live_oracle_spend_v1.json";

/// The pinned transaction's output count, which its `tx_extra` must match
/// (CEN-I19: one `0x06` of `1120·n`, one `0x07` of `64·n`).
const N_OUT: usize = 2;

/// The compressed Ed25519 basepoint. `expand_transaction_1` multiplies each
/// output commitment by `INV_EIGHT` on parse, which requires a decompressable
/// point — arbitrary bytes fail the C++ leg before any hash is compared.
const BASEPOINT: [u8; 32] = {
    let mut k = [0x66u8; 32];
    k[0] = 0x58;
    k
};

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
            extra: conforming_pqc_extra(N_OUT),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
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
    // the pruned identity with the true digest and length supplied IS the
    // txid.
    assert_eq!(
        tx.hash(),
        tx.hash_with_supplied_prunable(PrunableHash::from_bytes(digest), tx.archival_len())
    );
    let doc = serde_json::json!({
        "format_version": 2,
        "description": "Identity KAT for the FCMP++/PQC spend arm (RK-4c; \
         SHT-Q2). tx_hex is shekyl-wire's serialization of the spend; pruned_hex \
         its pruned form (the serialize_base framing get_pruned_tx_blob serves); \
         prunable_hash_hex = keccak256 of the prunable region; archival_len = the \
         bytes of the prunable region plus the pqc_auths segment, which the txid \
         binds; tx_hash_hex the txid. The C++ leg (pruned_tx_hash_parity.cpp) \
         must reproduce the bytes, the digest and the txid with its production \
         serializer and its one txid entry.",
        "tx_hex": hex_str(tx.serialize()),
        "pruned_hex": hex_str(build_tx(false).serialize()),
        "prunable_hash_hex": hex_str(digest),
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
    let archival_len =
        ArchivalLength::from_raw(pin["archival_len"].as_u64().expect("archival_len"));

    // The construction still serializes and hashes to the pinned bytes.
    let tx = build_tx(true);
    tx.validate().expect("validate");
    assert_eq!(hex_str(tx.serialize()), tx_hex, "full tx bytes");
    assert_eq!(hex_str(tx.hash()), tx_hash_hex, "txid");
    // The pinned length is the two discardable segments' bytes, counted here
    // from the segments and not from the function under test.
    let segments = tx.write_segments().expect("segments");
    assert_eq!(
        archival_len.to_raw(),
        u64::try_from(segments.pqc_auths.len() + segments.prunable.len()).expect("fits"),
        "the pinned archival length is |pqc_auths| + |prunable|"
    );
    assert_eq!(tx.archival_len(), archival_len, "measured archival length");
    assert_eq!(
        hex_str(prunable_digest()),
        prunable_hash_hex,
        "prunable digest"
    );

    // The mix, spelled out here instead of asked of the mixer. Five words:
    // the digests of the prefix, the ct base, the count-prefixed `pqc_auths`
    // and the prunable region, then the length — a `u64`, little-endian, in
    // a zeroed word. C++ no longer derives this a second time (it calls the
    // Rust mixer), so this is the derivation that stands beside it.
    let full = tx.serialize();
    let mut ct_section = Vec::new();
    tx.ct.write(&mut ct_section).expect("Vec write");
    let (prefix, ct) = full.split_at(full.len() - ct_section.len());
    let base_len = ct.len() - segments.pqc_auths.len() - segments.prunable.len();
    let (base, discardable) = ct.split_at(base_len);
    let (auths, prunable) = discardable.split_at(segments.pqc_auths.len());
    let counted_auths = [&[0x01u8][..], auths].concat(); // varint(1): one authorization
    let mut length_word = [0u8; 32];
    length_word[..8].copy_from_slice(&archival_len.to_raw().to_le_bytes());
    let preimage = [
        keccak256(prefix),
        keccak256(base),
        keccak256(&counted_auths),
        keccak256(prunable),
        length_word,
    ]
    .concat();
    assert_eq!(preimage.len(), 5 * 32, "a spend's txid mixes five words");
    assert_eq!(
        hex_str(keccak256(&preimage)),
        tx_hash_hex,
        "the txid is not the five-word mix"
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
        hex_str(pruned.hash_with_supplied_prunable(PrunableHash::from_bytes(digest), archival_len)),
        tx_hash_hex,
        "pruned identity (supplied digest and length) diverged from the pinned txid"
    );

    // The length is bound: the same body and digest under any other length
    // are another identity, so a daemon cannot serve a pruned body with a
    // length of its choosing (`SHT-Q2`). One byte either way, and zero.
    for lied in [archival_len.to_raw() - 1, archival_len.to_raw() + 1, 0] {
        assert_ne!(
            hex_str(pruned.hash_with_supplied_prunable(
                PrunableHash::from_bytes(digest),
                ArchivalLength::from_raw(lied)
            )),
            tx_hash_hex,
            "a supplied length of {lied} must not reproduce the txid"
        );
    }
}

/// `PDM-Q-F26`: the txid's **third component** and the **skeleton**
/// reconstruction (`DAEMON_REDB_STORE.md` §7.7 item 2), pinned to the same
/// oracle txid as the pruned form above.
///
/// A node that discards `pqc_auths` after verification (`PDM-Q6` item 2)
/// holds a body with *neither* discardable region. It cannot recompute the
/// txid from that body — `hash()` would read the empty `pqc_auths` as "3-part"
/// and return an identity no spend has — so it reconstructs from the two
/// stored digests. This pins that reconstruction to the pinned txid, and pins
/// the third component's derivation (`keccak256(varint(count) ‖ auths)`) as
/// the value the full-body path used, so the store's column and the txid
/// cannot drift apart.
#[test]
fn skeleton_identity_reconstructs_the_pinned_txid_from_both_stored_digests() {
    let pin: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest(PARITY_FIXTURE)).expect("parity fixture"),
    )
    .expect("parity json");
    let tx_hash_hex = pin["tx_hash_hex"].as_str().expect("tx_hash_hex");

    let tx = build_tx(true);
    let parts = tx.txid_parts();
    let pqc_auth = parts
        .pqc_auth_hash
        .expect("a spend's txid is 4-part, so its third component exists");
    let prunable = parts.prunable_hash;
    assert_eq!(
        parts.hash,
        tx.hash(),
        "txid_parts.hash is hash(), not a second construction"
    );

    // The third component is the hash the txid was built over, independently
    // derived here so the accessor cannot drift from `hash()`: the count
    // varint the C++ vector serializer emits, then the stored `txs_pqc_auths`
    // segment bytes — which is why the segment's own keccak is NOT the
    // component (no count).
    let segments = tx.write_segments().expect("segments");
    let mut auth_buf = vec![1u8]; // varint(1): build_tx carries one auth
    auth_buf.extend_from_slice(&segments.pqc_auths);
    assert_eq!(
        pqc_auth.to_bytes(),
        keccak256(&auth_buf),
        "third component derivation"
    );
    assert_ne!(
        pqc_auth.to_bytes(),
        keccak256(&segments.pqc_auths),
        "the stored segment's hash is not the txid component"
    );

    // The skeleton: prefix + base only. The malformed "empty pqc_auths, first
    // input a spend" shape is exactly what a discarding node holds, and it
    // must hash 4-part when told the component's value.
    let mut skeleton = tx.clone();
    if let Ct::Fcmp {
        pqc_auths,
        prunable,
        ..
    } = &mut skeleton.ct
    {
        pqc_auths.clear();
        *prunable = None;
    }
    assert_ne!(
        hex_str(skeleton.hash()),
        tx_hash_hex,
        "a skeleton hashed as a body is the wrong identity — the reason this API exists"
    );
    let archival_len = parts.archival_len;
    assert_eq!(
        hex_str(skeleton.hash_with_supplied_components(Some(pqc_auth), prunable, archival_len)),
        tx_hash_hex,
        "skeleton identity (digests and length supplied) diverged from the pinned txid"
    );
    // The skeleton's own measurement is not the transaction's: with both
    // regions gone it reads zero, which is why the length is a stored row.
    assert_eq!(skeleton.archival_len(), ArchivalLength::ZERO);
    assert_ne!(
        hex_str(skeleton.hash_with_supplied_components(
            Some(pqc_auth),
            prunable,
            skeleton.archival_len()
        )),
        tx_hash_hex,
        "a skeleton's recomputed length is not the accepted transaction's"
    );
    // One construction: the full-body and supplied paths are its special
    // cases and agree on the same body.
    assert_eq!(
        tx.hash_with_supplied_components(Some(pqc_auth), prunable, archival_len),
        tx.hash()
    );
    assert_eq!(
        tx.hash_with_supplied_prunable(prunable, archival_len),
        tx.hash()
    );
}

/// The **live-oracle** half: bytes a running `shekyld` accepted and connected.
///
/// This is the property the sibling pin above cannot have. `build_tx` authors a
/// transaction to a shape *we* believe consensus takes, and both languages then
/// agree with us — which is worth having, and is exactly what fails silently if
/// the belief is wrong. PR #630 is the precedent: the pinned bytes encoded a
/// transaction with outputs and an empty `tx_extra`, a shape no builder can
/// produce and admission rejects, so the pin fixed cross-language agreement on
/// bytes the network would never carry.
///
/// These bytes carry a daemon's signature on that question. They were built by
/// the production `Engine`, submitted to a real node, accepted by its consensus
/// verify, and connected in a block — recorded, with the accepting daemon's own
/// version string, by `e2e_fcmp_spend_accepted_by_daemon`.
///
/// The fixture records only the bytes and the txid. Every other identity is
/// *derived* here and in the C++ leg by each language's production code: a
/// fixture that also recorded the prunable digest could disagree with itself,
/// and would pin a value the capturing run never independently checked.
#[test]
fn live_oracle_spend_identity_matches_the_accepted_bytes() {
    let pin: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest(LIVE_ORACLE_FIXTURE)).expect("live-oracle fixture"),
    )
    .expect("live-oracle json");

    let tx_hex = pin["tx_hex"].as_str().expect("tx_hex");
    let tx_hash_hex = pin["tx_hash_hex"].as_str().expect("tx_hash_hex");

    // Rule 47: assert the subject exists before asserting about it. An empty or
    // truncated capture would otherwise parse-and-compare its way to a green.
    let bytes = hex_bytes(tx_hex);
    assert!(
        bytes.len() > 1024,
        "the captured spend is {} bytes, which is too small to be an FCMP++ \
         spend — the fixture is truncated or was written by a failed capture",
        bytes.len()
    );
    assert!(
        !pin["accepted_by_daemon_version"]
            .as_str()
            .expect("accepted_by_daemon_version")
            .is_empty(),
        "the capture must name the daemon that accepted it"
    );

    // The daemon-accepted bytes parse through the production deserializer.
    let tx = Transaction::from_bytes(&bytes).expect("daemon-accepted bytes must parse");

    // Round-trip: re-serializing the parsed form reproduces them exactly. This
    // is what breaks if the serializer drifts away from what the chain took.
    assert_eq!(
        hex_str(tx.serialize()),
        tx_hex,
        "re-serializing the accepted spend changed its bytes"
    );

    // And the identity the daemon indexed it under.
    assert_eq!(
        hex_str(tx.hash()),
        tx_hash_hex,
        "txid recomputed from the accepted bytes differs from the one the \
         daemon accepted"
    );

    // The bound surface this file exists for: pruned identity with the digest
    // and the length supplied is the txid, now over bytes consensus admitted.
    // Same recomputation as the synthetic sibling above.
    let pruned_form = {
        let mut t = tx.clone();
        let Ct::Fcmp { prunable, .. } = &mut t.ct else {
            panic!("the captured spend must be an FCMP++ spend");
        };
        *prunable = None;
        t.serialize()
    };
    assert!(
        bytes.starts_with(&pruned_form),
        "the pruned form must be a prefix of the full form"
    );
    let digest = keccak256(&bytes[pruned_form.len()..]);
    assert_eq!(
        hex_str(
            tx.hash_with_supplied_prunable(PrunableHash::from_bytes(digest), tx.archival_len())
        ),
        tx_hash_hex,
        "pruned identity (supplied digest and length) diverged from the accepted txid"
    );
}
