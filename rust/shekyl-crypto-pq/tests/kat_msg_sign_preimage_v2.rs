// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The message-signing preimage, wire layout version 2:
//! `frame("shekyl/msg-sign-v2", network_id, [u64_le(mode), segment,
//! message])`, the id the network's 16-byte genesis-derived id at position 0
//! (`NETWORK_IDENTITY.md` NI-F2; `WALLET_MESSAGE_SIGNING.md` SM-R-3; the
//! signing envelope §2.1, §2.6).
//!
//! Corpus: `docs/test_vectors/MSG_SIGN_PREIMAGE_V2.json`. Oracle: every
//! preimage and every network id in it is computed by
//! `scripts/kat/msg_sign_preimage_oracle.py` (stdlib Keccak, cSHAKE256 and
//! the envelope's `frame`, anchored on hashlib's SHAKE256, NIST SP 800-185's
//! cSHAKE256 samples and the recorded ids), which CI runs in
//! `docs-gates.yml`. The file is that script's output (`--write`); this test
//! holds the Rust to it.

use serde::Deserialize;
use shekyl_address::Network;
use shekyl_crypto_pq::message_signing::{
    message_preimage, MSG_SIG_LAYOUT_VERSION, MSG_SIG_MODE_SPEND,
};
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("../../../docs/test_vectors/MSG_SIGN_PREIMAGE_V2.json");

#[derive(Deserialize)]
struct Vectors {
    sig_format_version: u8,
    mode: u8,
    network_ids: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    segment_hex: String,
    message_hex: String,
    preimage_by_network: BTreeMap<String, String>,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("the vector file parses")
}

/// Every network's row in the file, matched to the table by name: a network
/// the file lacks, or a name the table lacks, fails here.
fn by_network(map: &BTreeMap<String, String>) -> Vec<(Network, &str)> {
    assert_eq!(map.len(), Network::ALL.len(), "one entry per network");
    Network::ALL
        .into_iter()
        .map(|net| {
            let hex = map
                .get(net.name())
                .unwrap_or_else(|| panic!("{net}: no entry in the vector file"));
            (net, hex.as_str())
        })
        .collect()
}

#[test]
fn the_file_is_this_layout() {
    let v = vectors();
    assert_eq!(v.sig_format_version, MSG_SIG_LAYOUT_VERSION);
    assert_eq!(v.mode, MSG_SIG_MODE_SPEND);
    assert!(!v.cases.is_empty(), "the file has no case (rule 47)");
}

#[test]
fn the_oracles_network_ids_are_the_tables() {
    for (net, hex) in by_network(&vectors().network_ids) {
        assert_eq!(hex::encode(net.network_id()), hex, "{net}");
    }
}

#[test]
fn every_preimage_is_the_oracles() {
    for case in vectors().cases {
        let segment = hex::decode(&case.segment_hex).expect("segment hex");
        let message = hex::decode(&case.message_hex).expect("message hex");
        let mut seen = Vec::new();
        for (net, hex) in by_network(&case.preimage_by_network) {
            let got = message_preimage(net, &segment, &message);
            assert_eq!(hex::encode(got), hex, "{}: {net}", case.name);
            seen.push(got);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            Network::ALL.len(),
            "{}: two networks share a preimage",
            case.name
        );
    }
}
