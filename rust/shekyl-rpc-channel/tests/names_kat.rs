// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Known-answer tests for the channel's two derivations. The third, the
//! rendezvous name, is `shekyl-rpc-rendezvous`'s, tested there against the
//! same vectors.
//!
//! The vectors in `docs/test_vectors/RPC_CHANNEL_NAMES_V1/` come from
//! `generate.py` beside them, which carries its own cSHAKE256 and shares no
//! code with this crate. These tests check the crate against the vectors,
//! never the other way round.

use serde_json::Value;
use shekyl_rpc_channel::{
    prologue, static_fingerprint, NetworkId, CHANNEL_DST, MLKEM768_EK_LEN, NETWORK_ID_LEN,
    PROLOGUE_LEN, X25519_PUBLIC_LEN,
};

const VECTORS: &str = include_str!("../../../docs/test_vectors/RPC_CHANNEL_NAMES_V1/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors.json parses")
}

/// A section of the vector file, which must hold at least one case: a test
/// that iterates an empty list passes while checking nothing.
fn section<'a>(root: &'a Value, name: &str) -> &'a Vec<Value> {
    let cases = root[name]
        .as_array()
        .unwrap_or_else(|| panic!("section {name} is missing"));
    assert!(!cases.is_empty(), "section {name} is empty");
    cases
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{case}: no string field {field}"))
}

fn bytes<const N: usize>(case: &Value, field: &str) -> [u8; N] {
    let raw = hex::decode(text(case, field)).expect("hex field decodes");
    raw.try_into()
        .unwrap_or_else(|_| panic!("{field} is not {N} bytes"))
}

#[test]
fn prologue_matches_the_vectors() {
    let root = vectors();
    for case in section(&root, "prologue") {
        let network_id: NetworkId = bytes(case, "network_id_hex");
        let got = prologue(&network_id);
        assert_eq!(
            hex::encode(got),
            text(&case["expected"], "prologue_hex"),
            "{}",
            text(case, "id")
        );
    }
}

#[test]
fn static_fingerprint_matches_the_vectors() {
    let root = vectors();
    for case in section(&root, "static_fingerprint") {
        let x25519: [u8; X25519_PUBLIC_LEN] = bytes(case, "x25519_public_hex");
        let ek: [u8; MLKEM768_EK_LEN] = bytes(case, "mlkem768_ek_hex");
        let got = static_fingerprint(&x25519, &ek);
        assert_eq!(
            hex::encode(got.as_bytes()),
            text(&case["expected"], "fingerprint_hex"),
            "{}",
            text(case, "id")
        );
    }
}

/// This crate restates two lengths it does not own. Each is held equal to
/// its owner's, so a change there fails here.
#[test]
fn restated_lengths_match_their_owners() {
    let id: shekyl_p2p_transport::NetworkId = [0; NETWORK_ID_LEN];
    let _: &NetworkId = &id;
    assert_eq!(MLKEM768_EK_LEN, shekyl_crypto_pq::kem::ML_KEM_768_EK_LEN);
    assert_eq!(PROLOGUE_LEN, CHANNEL_DST.len() + NETWORK_ID_LEN);
}
