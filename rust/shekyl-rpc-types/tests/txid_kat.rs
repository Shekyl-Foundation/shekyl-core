// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frozen-hex txid KAT (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.4 / §10
//! item 1, last leg).
//!
//! The submit path has one txid authority question: does the engine-side
//! `shekyl-wire` txid equal C++ `get_transaction_hash` over the same blob?
//! §3.4 answers it three ways — this build-time KAT, the commit shim's
//! release-mode runtime equality check, and (via F24/F33) the
//! certificate-blob binding that rides on the same equality. This test is
//! the build-time leg: the pinned txids below were captured **from the C++
//! daemon** (see `vectors/README.md` for the provenance chain); Rust
//! recomputes over the identical bytes and must agree, making "which txid is
//! authoritative" moot by construction.
//!
//! Placed in this crate (not `shekyl-wire`, which carries the same identity
//! inside its block-level KAT) because the *contract* is what needs the
//! pin: PR-2's crate is the freeze surface, and this KAT freezes alongside
//! the wire types it protects.

use shekyl_wire::Transaction;

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// (blob, daemon-captured txid) pairs. The txid hex is copied from
/// `shekyl-wire/tests/vectors/regtest_coinbase_hashes.json` — C++
/// `get_transaction_hash` output — never recomputed on the Rust side.
/// Blobs are the miner txs extracted from the matching
/// `regtest_coinbase_h{0,1}.block` vectors (re-extract with
/// `cargo test -p shekyl-wire --test emit_miner_tx -- --ignored --nocapture`
/// after any wire-vector re-capture).
const ORACLE_CORPUS: [(&[u8], &str); 2] = [
    (
        include_bytes!("vectors/regtest_coinbase_h0.tx"),
        // mainnet genesis miner_tx (regtest h0 shares GENESIS_TX)
        "2382d899d4d746e0ad2dba8a0b27d9fcb174d2a06a208112082cd12d20b91077",
    ),
    (
        include_bytes!("vectors/regtest_coinbase_h1.tx"),
        "97e22afe01b92e8aa2e08902f22b538a80adc6ef0b940e077aee92e4ec2955e6",
    ),
];

#[test]
fn engine_txid_equals_cpp_get_transaction_hash_over_oracle_blobs() {
    for (i, (blob, cpp_txid)) in ORACLE_CORPUS.iter().enumerate() {
        let tx = Transaction::from_bytes(blob)
            .unwrap_or_else(|e| panic!("oracle blob {i} must parse: {e}"));
        assert_eq!(
            hex32(&tx.hash()),
            *cpp_txid,
            "oracle blob {i}: shekyl-wire txid diverged from C++ get_transaction_hash — \
             the §3.4 txid authority equivalence is broken"
        );
    }
}

#[test]
fn oracle_blobs_reserialize_byte_identically() {
    // The runtime leg of §3.4 hashes the *received* blob on both sides; the
    // KAT's validity therefore requires the parse→serialize round-trip to be
    // byte-identical (otherwise the Rust hash would be over different bytes
    // than the pinned C++ hash was).
    for (i, (blob, _)) in ORACLE_CORPUS.iter().enumerate() {
        let tx = Transaction::from_bytes(blob)
            .unwrap_or_else(|e| panic!("oracle blob {i} must parse: {e}"));
        assert_eq!(
            tx.serialize().as_slice(),
            *blob,
            "oracle blob {i}: reserialization must be byte-identical"
        );
    }
}
