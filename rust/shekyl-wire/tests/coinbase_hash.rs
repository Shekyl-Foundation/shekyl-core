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
//! Expected values are from `vectors/regtest_coinbase_hashes.json`, captured with
//! the blobs by `vectors/capture_coinbase.py`. Regenerate both together; if a
//! re-capture changes the blobs, update the hex below to match the new JSON.

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
    // (height, blob, block_hash, miner_tx_hash)
    let corpus: [(u64, &[u8], &str, &str); 3] = [
        (
            0,
            include_bytes!("vectors/regtest_coinbase_h0.block"),
            "1e1366b3028d45f5b8a9de8fb3a7119be1f73456fdecd7d7380681e08b8bf7dc",
            "251ac0405141958fe2018119dae1e1a45720523bf3487d2f0a985f1563bd4467",
        ),
        (
            1,
            include_bytes!("vectors/regtest_coinbase_h1.block"),
            "f857a1223a78a18b7f569ad9d3265afe411e529a9dda79ca0504247fd97b0c0a",
            "20a70e36efc2a1c2d0c561ab0f22d8453e0684671c966494955216d20bd56ca2",
        ),
        (
            2,
            include_bytes!("vectors/regtest_coinbase_h2.block"),
            "f729d7c83bbea7c4a7ac5fc5804b12e9be22ed1a5ad578344299d2f64b0d7ad3",
            "9eb0103593c80329e82bc6e105c2f3dc51924768911110f225b93f08a586a9c3",
        ),
    ];

    for (height, blob, block_hash, miner_tx_hash) in corpus {
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
    }
}
