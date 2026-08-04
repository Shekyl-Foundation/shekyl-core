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
//! Empty-set invariant: every captured height (no pass records yet) must carry
//! `empty_attestation_root()` — live-derived from `shekyl-archival-retention`, not
//! a hand-copied pin — so C++ `empty_attestation_root()` / constructor default and
//! Rust agree without a third hex constant.
//!
//! Mining address note: `capture_coinbase.py` mines to a freshly derived
//! current-format regtest fixture address (`vectors/regtest_mining_recipients.json`),
//! NOT the genesis treasury — a vector concern, not the treasury allocation; see
//! `vectors/README.md` for the full rationale.

use shekyl_archival_retention::empty_attestation_root;
use shekyl_wire::Block;

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

    let empty_root = empty_attestation_root();

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
        // Every height in this corpus has no pass records, so the header must
        // commit the empty-set root — not null_hash. Ties C++ constructor default /
        // create_block_template to Rust empty_attestation_root() without a hex pin.
        assert_eq!(
            block.header.attestation_root, empty_root,
            "height {height}: attestation_root must be empty_attestation_root(), not null_hash"
        );
    }
}
