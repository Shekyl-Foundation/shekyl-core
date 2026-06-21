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
            "919f8db5a0696c4969af09755c1acc42ae95e4ec573cab0a095c2e7849a144c4",
            "e8718621fa0e3fec9fda9251caaa1b19ceaef76f56ed00126412dc60e6dc0ed7",
        ),
        (
            1,
            include_bytes!("vectors/regtest_coinbase_h1.block"),
            "ae72bd571a5743e3da52be06e0d10c103839e60a7cb9d8b8eb7cf5db0d160407",
            "6eb4e78a369270447c1a4416bcebc0fd7bf1b9b8de1976962ad87313c8adc52e",
        ),
        (
            2,
            include_bytes!("vectors/regtest_coinbase_h2.block"),
            "ea49456f385d778d1c4361a2b31d611e61b1a880be59745a129725a3899846a1",
            "082554ef382283f6076865c2adec727265fa9efdaccaa91ee461c38f65b231b7",
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
