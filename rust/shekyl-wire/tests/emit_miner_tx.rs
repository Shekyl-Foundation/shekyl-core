// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emitter for `shekyl-rpc-types/tests/vectors/regtest_coinbase_h{0,1}.tx` — the
//! miner-tx blobs whose txids `shekyl-rpc-types/tests/txid_kat.rs` pins. Extracts
//! the miner transaction from this crate's committed
//! `tests/vectors/regtest_coinbase_h{0,1}.block` vectors and re-serializes it
//! (byte-identity of that round-trip is proven by `coinbase_roundtrip.rs`), so
//! regenerating the block corpus via `capture_coinbase.py` and then running this
//! emitter keeps the rpc-types blobs in sync — "all three move together"
//! (`shekyl-rpc-types/tests/vectors/README.md`). The pinned txid hex in
//! `txid_kat.rs` is then copied from `regtest_coinbase_hashes.json`, never
//! recomputed on the Rust side.
//!
//! ```text
//! cargo test -p shekyl-wire --test emit_miner_tx -- --ignored --nocapture
//! ```

#[test]
#[ignore = "rewrites the shekyl-rpc-types miner-tx vector blobs from the committed block vectors"]
fn emit_rpc_types_miner_tx_vectors() {
    use shekyl_wire::Block;

    let corpus: [(&str, &[u8]); 2] = [
        (
            "regtest_coinbase_h0.tx",
            include_bytes!("vectors/regtest_coinbase_h0.block"),
        ),
        (
            "regtest_coinbase_h1.tx",
            include_bytes!("vectors/regtest_coinbase_h1.block"),
        ),
    ];
    let out_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../shekyl-rpc-types/tests/vectors"
    );
    for (name, blob) in corpus {
        let block = Block::from_bytes(blob).expect("committed block vector must parse");
        let tx_bytes = block.miner_transaction.serialize();
        let path = format!("{out_dir}/{name}");
        std::fs::write(&path, &tx_bytes).expect("write miner-tx vector");
        println!("wrote {path} ({} bytes)", tx_bytes.len());
    }
}
