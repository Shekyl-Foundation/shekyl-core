// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block and transaction corpus for the zstd → ruzstd measurement (Rick,
//! 2026-10-19): "Before the swap, measure on the Rust path: ratio and
//! throughput vs libzstd level 1 on real block/tx payloads, Pi decode time
//! for a full block." This writes the blobs; `shekyl-levin`'s
//! `zstd_corpus_compare` example builds the Levin messages the relay
//! compresses from them and measures both codecs.
//!
//! # What it captures
//!
//! A regtest daemon, a wallet mining its own coinbases, and about fifty
//! one-input FCMP++ spends submitted past the C++'s weight limit
//! ([`super::overfill_pool`]). Then:
//!
//! - `pool/<n>.tx`: every spend in the pool before the next block, the
//!   bodies a node relays as `NOTIFY_NEW_TRANSACTIONS`;
//! - one block mined from that pool, the fullest block the C++ producer
//!   builds from it (filled to its median, `e2e_cxx_template_fills_to_its_median`);
//! - `blocks/<height>/block.bin` and `blocks/<height>/tx_<i>.bin` for every
//!   block carrying transactions, and for the last coinbase-only blocks
//!   ([`COINBASE_ONLY`] of them), the bodies sync carries as
//!   `RESPONSE_GET_OBJECTS` and a block announcement carries as
//!   `NOTIFY_NEW_COMPACT_BLOCK`;
//! - `full`: the full block's height.
//!
//! The proofs, keys, ciphertexts and block structure are real, produced by
//! the production wallet and daemon. The activity mix is not a network's:
//! every spend is the same one-input shape. A testnet capture would need a
//! host claim (rule 38) and is not this run.
//!
//! # Not production code
//!
//! A child of the regtest harness, compiled only under `cfg(test)`. Its one
//! entry point is `#[ignore]`d and listed as decided dark in
//! `scripts/ci/run_live_daemon_gates.sh`: a measurement's input, not a
//! pass/fail proposition.
#![cfg(test)]

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use shekyl_rpc_client::Rpc;
use tokio::sync::RwLock;

use super::{hex_decode, mainnet_wallet, overfill_pool, RegtestDaemon};

/// Coinbase-only blocks kept beside the transaction-bearing ones: the small
/// end of what sync carries.
const COINBASE_ONLY: u64 = 8;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "zstd corpus: requires SHEKYLD_BIN and ZSTD_CORPUS_OUT; spawns a live daemon"]
async fn zstd_corpus_capture() {
    let out = output_dir();
    let daemon = RegtestDaemon::start().await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x7a).await;
    let arc = Arc::new(RwLock::new(wallet));
    let overfilled = overfill_pool(&daemon, &arc, &address).await;

    // The pool, as the daemon holds it: what tx relay carries.
    let pool: serde_json::Value = daemon
        .rpc
        .rpc_call("get_transaction_pool", None::<serde_json::Value>)
        .await
        .expect("get_transaction_pool");
    let pool_dir = out.join("pool");
    std::fs::create_dir_all(&pool_dir).expect("create pool dir");
    let mut pooled = 0usize;
    for (n, t) in pool["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .enumerate()
    {
        let blob = hex_decode(t["tx_blob"].as_str().expect("tx_blob"));
        shekyl_wire::Transaction::from_bytes(&blob).expect("a pool body parses");
        std::fs::write(pool_dir.join(format!("{n}.tx")), &blob).expect("write a pool body");
        pooled += 1;
    }
    assert!(
        pooled >= 20,
        "the overfilled pool holds the spends: {pooled}"
    );

    // The fullest block the C++ producer builds from that pool.
    let mined = daemon.generate_blocks(1, &address).await;
    let full_hash = mined.blocks.first().expect("one block").clone();
    let (full_weight, full_txs) = daemon.block_weight_of(&full_hash).await;

    let info: serde_json::Value = daemon
        .rpc
        .json_rpc_call("get_block_count", None)
        .await
        .expect("get_block_count");
    let tip = info["count"].as_u64().expect("count") - 1;
    let blocks_dir = out.join("blocks");
    let mut kept = 0usize;
    let mut full_height = None;
    for height in 0..=tip {
        let resp: serde_json::Value = daemon
            .rpc
            .json_rpc_call("get_block", Some(json!({ "height": height })))
            .await
            .unwrap_or_else(|e| panic!("get_block {height}: {e:?}"));
        let blob = hex_decode(resp["blob"].as_str().expect("blob"));
        let block = shekyl_wire::Block::from_bytes(&blob)
            .unwrap_or_else(|e| panic!("parse block {height}: {e:?}"));
        if resp["block_header"]["hash"].as_str() == Some(full_hash.as_str()) {
            full_height = Some(height);
        }
        let coinbase_only = block.transaction_hashes.is_empty();
        if coinbase_only && height + COINBASE_ONLY <= tip {
            continue;
        }
        let dir = blocks_dir.join(height.to_string());
        std::fs::create_dir_all(&dir).expect("create a block dir");
        std::fs::write(dir.join("block.bin"), &blob).expect("write a block");
        if !coinbase_only {
            let hashes: Vec<String> = block.transaction_hashes.iter().map(hex::encode).collect();
            let txs: serde_json::Value = daemon
                .rpc
                .rpc_call(
                    "get_transactions",
                    Some(json!({ "txs_hashes": hashes, "prune": false })),
                )
                .await
                .unwrap_or_else(|e| panic!("get_transactions @ {height}: {e:?}"));
            for (i, t) in txs["txs"]
                .as_array()
                .expect("get_transactions txs")
                .iter()
                .enumerate()
            {
                let body = hex_decode(
                    t["as_hex"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .expect("a full tx as_hex"),
                );
                std::fs::write(dir.join(format!("tx_{i}.bin")), &body).expect("write a block tx");
            }
        }
        kept += 1;
    }
    let full_height = full_height.expect("the mined block is in the chain");
    std::fs::write(out.join("full"), full_height.to_string())
        .expect("write the full block's height");
    std::fs::write(
        out.join("provenance"),
        format!(
            "regtest, generated by shekyl-engine-core's zstd_corpus_capture\n\
             pool spends: {pooled}\nblocks kept: {kept} (tip {tip})\n\
             full block: height {full_height}, weight {full_weight}, {full_txs} spends, \
             against median {} and limit {}\n",
            overfilled.median, overfilled.limit
        ),
    )
    .expect("write provenance");
}

/// `ZSTD_CORPUS_OUT`, a directory that must not exist yet, so two runs never
/// share one.
fn output_dir() -> PathBuf {
    let dir = std::env::var_os("ZSTD_CORPUS_OUT")
        .map(PathBuf::from)
        .expect("ZSTD_CORPUS_OUT must name a directory for this run's corpus");
    assert!(
        !dir.exists(),
        "the corpus directory already exists; a run never writes over another"
    );
    std::fs::create_dir_all(&dir).expect("create the corpus directory");
    dir
}
