// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One-shot regenerator for shekyl-rpc-types §3.4 oracle txs.
//! Run: cargo test -p shekyl-wire --test extract_rpc_oracle -- --ignored --nocapture

use shekyl_wire::Block;
use std::path::PathBuf;

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "generator: re-extract miner txs into shekyl-rpc-types vectors"]
fn extract_rpc_types_oracle_txs() {
    let wire_vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let rpc_vectors =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../shekyl-rpc-types/tests/vectors");

    for h in [0u64, 1] {
        let blob = std::fs::read(wire_vectors.join(format!("regtest_coinbase_h{h}.block")))
            .unwrap_or_else(|e| panic!("read h{h}: {e}"));
        let block = Block::from_bytes(&blob).expect("parse");
        let tx_bytes = block.miner_transaction.serialize();
        let out = rpc_vectors.join(format!("regtest_coinbase_h{h}.tx"));
        std::fs::write(&out, &tx_bytes).expect("write");
        println!(
            "h{h}: wrote {} ({} bytes) miner_tx_hash={}",
            out.display(),
            tx_bytes.len(),
            hex32(&block.miner_transaction.hash())
        );
    }
}
