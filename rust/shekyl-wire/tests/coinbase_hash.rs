// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live-oracle hash KAT (GENESIS_TX_WIRE_FORMAT.md §11).
//!
//! `Block::hash()` and the coinbase `Transaction::hash()` must equal the C++
//! daemon's `block_header.hash` / `miner_tx_hash` for the same blobs. This is the
//! gold-standard validation of the cn_fast_hash component hashing (3-part coinbase
//! tx hash + the `V(len)`-prefixed block-hash preimage + the single-leaf tree
//! hash) — byte-identical to consensus.
//!
//! The expected hashes are loaded from `vectors/regtest_coinbase_hashes.json` — the
//! **single source of truth**, captured alongside the blobs by
//! `vectors/capture_coinbase.py`. Regenerate the JSON and the `*.block` blobs
//! together; nothing here is hand-copied, so the vectors can't drift out of sync.
//!
//! Regenerated for the credit-wire cutover (2026-08-04): the `block_header` gained
//! `attestation_root` (`ARCHIVAL_CREDIT_WIRE.md` §3), moving every block hash, so
//! all three heights were recaptured. Genesis (h0) is deterministic and equals
//! `mining_parity`'s mainnet genesis id; h1/h2 are mined regtest blocks.
//!
//! Mining address note: `capture_coinbase.py` mines to a **freshly derived
//! current-format** regtest address (`vectors/regtest_mining_recipients.json`,
//! reproducible via `shekyl-crypto-pq`'s `emit_regtest_addr` test), NOT the
//! genesis treasury address in `shekyl-dev`. The latter is a **pre-#327 stale
//! format** — its classical segment is 65 bytes (`version‖spend‖view`) where the
//! current decoder expects 81 (the 16-byte `ek_bind` tag from #327), so
//! `get_account_address_from_str` rejects it and `generateblocks` could not mine.
//! (The genesis block itself is unaffected: `GENESIS_TX` was baked from those
//! addresses when they were current, and the daemon parses the pre-baked coinbase,
//! not the address.) Regenerating the canonical genesis recipients is a separate,
//! genesis-scoped concern.

use shekyl_wire::Block;

/// The empty-set archival attestation root — `attestation_root(&[])`, pinned in
/// `shekyl-archival-retention`'s `attestation_wire_kat.rs` (ROOT_EMPTY_EXPECT_HEX).
/// The daemon's genesis header must carry exactly this (genesis has no attestation
/// records), tying the C++ `generate_genesis_block` constant to the Rust root
/// derivation through the shared pin — the cross-language check the FFI slice will
/// later make a live differential.
const GENESIS_EMPTY_ATTESTATION_ROOT: &str =
    "32b1bcd9532f6f0cad787eeeb126c307cdd6c9712b914fd6ba087d6a36bb7bf2";

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn coinbase_block_and_tx_hashes_match_the_daemon() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("vectors/regtest_coinbase_hashes.json"))
            .expect("parse regtest_coinbase_hashes.json");

    let corpus: [(u64, &[u8]); 3] = [
        (0, include_bytes!("vectors/regtest_coinbase_h0.block")),
        (1, include_bytes!("vectors/regtest_coinbase_h1.block")),
        (2, include_bytes!("vectors/regtest_coinbase_h2.block")),
    ];

    for (height, blob) in corpus {
        let want = &expected[height.to_string()];
        let block_hash = want["block_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("height {height}: no block_hash in JSON vectors"));
        let miner_tx_hash = want["miner_tx_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("height {height}: no miner_tx_hash in JSON vectors"));

        let block =
            Block::from_bytes(blob).unwrap_or_else(|e| panic!("height {height}: parse: {e}"));
        assert_eq!(
            hex32(&block.miner_transaction.hash()),
            miner_tx_hash,
            "height {height}: miner tx hash (3-part cn_fast_hash) must match the daemon"
        );
        assert_eq!(
            hex32(&block.hash()),
            block_hash,
            "height {height}: block hash (cn_fast_hash of V(len)·preimage) must match the daemon"
        );
        // Genesis commits the valid empty-set attestation root, not null_hash —
        // the C++ generate_genesis_block constant must equal Rust's attestation_root(&[]).
        if height == 0 {
            assert_eq!(
                hex32(&block.header.attestation_root),
                GENESIS_EMPTY_ATTESTATION_ROOT,
                "genesis attestation_root must be attestation_root(&[]), not null_hash"
            );
        }
    }
}
