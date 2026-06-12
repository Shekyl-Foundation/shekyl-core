// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-2 Tier-B reconstruct-root obligations (`CT2_DRAIN_ORDER.md` §8.2).
//!
//! Each test is written now and gated with `#[ignore]` until Phase 2A can mint
//! regular/staked outputs and a `ct2_tier_b.json` oracle exists. Bodies end in
//! `todo!()` — no fake passes.
//!
//! The `_drift_canary` helpers reference the APIs each test will use so
//! signature drift fails compile before Tier-B resumes.

use serde_json::Value;
use shekyl_curve_tree::recon::{
    assemble_leaf_stream, collect_block_leaves, extract_leaf_hashes, per_output_h_pqc,
    root_from_scalars, TxOutputs,
};
use shekyl_curve_tree::{
    BlockHeight, BlockLeaves, CurveTreeClient, OutputIdentity, RawOutput, ReferenceBlock,
    TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::selene_hash_init;

const FIXTURE: &str = include_str!("fixtures/ct2_tier_a.json");

fn _fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn _drift_canary_recon_block_path(f: &Value) {
    let chain = f["chains"]
        .as_array()
        .and_then(|chains| chains.first())
        .expect("chain");
    let block = &chain["blocks"][0];
    let blob: &[u8] = &[];
    let leaf_hashes = extract_leaf_hashes(Some(blob));
    let outputs: Vec<OutputIdentity> = block["miner_tx"]["outputs"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(i, _o)| OutputIdentity {
                    output_key: [0u8; 32],
                    commitment: None,
                    h_pqc: per_output_h_pqc(&leaf_hashes, i),
                    target: TargetKind::TaggedKey,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut entries = Vec::new();
    let txs = [TxOutputs {
        is_miner: true,
        outputs: &outputs,
    }];
    let _gindex = collect_block_leaves(0, &txs, 0, &mut entries);
    let scalars = assemble_leaf_stream(&entries, 0);
    let _root = root_from_scalars(&scalars);
    let _init = selene_hash_init();
}

fn _drift_canary_client_path() {
    let raw = [RawOutput {
        output_key: [0u8; 32],
        commitment: None,
        target: TargetKind::TaggedKey,
    }];
    let tx = TxLeafInputs {
        is_miner: true,
        leaf_hash_blob: None,
        outputs: &raw,
    };
    let block = BlockLeaves {
        height: 0,
        txs: &[tx],
    };
    let mut client = CurveTreeClient::new();
    client.ingest_block(block).unwrap();
    let root = client.root_at(0).expect("store hot path");
    std::hint::black_box(root);
    let reference = ReferenceBlock {
        height: BlockHeight(0),
        curve_tree_root: [0u8; 32],
    };
    let verify_ok = client.verify_root(&reference).is_ok();
    std::hint::black_box(verify_ok);
}

/// Oracle TBD: read C++ `parse_tx_extra` + the wallet coinbase consumer, or add
/// a C++ adversarial duplicate/malformed `0x07` test. Cannot assert "matches
/// daemon" until that oracle exists (`CT2_ROUND1_CLOSEOUT.md`).

#[test]
#[ignore = "Tier B: needs 2A regtest spend path + ct2_tier_b.json"]
fn mixed_maturity_collision_orders_by_gindex() {
    _drift_canary_recon_block_path(&_fixture());
    todo!("Tier B fixture pending 2A spend path");
}

#[test]
#[ignore = "Tier B: needs 2A regtest spend path + ct2_tier_b.json"]
fn multi_tx_block_respects_coinbase_first_and_tx_hashes_order() {
    _drift_canary_recon_block_path(&_fixture());
    todo!("Tier B fixture pending 2A spend path");
}

#[test]
#[ignore = "Tier B: needs 2A regtest spend path + ct2_tier_b.json"]
fn staked_output_uses_max_lock_and_spendable() {
    _drift_canary_recon_block_path(&_fixture());
    todo!("Tier B fixture pending 2A spend path");
}

#[test]
#[ignore = "Tier B: needs 2A regtest spend path + ct2_tier_b.json"]
fn reorg_with_spend_mixed_leaves() {
    _drift_canary_client_path();
    _drift_canary_recon_block_path(&_fixture());
    todo!("Tier B fixture pending 2A spend path");
}

#[test]
#[ignore = "Tier B: needs daemon 0x07 adversarial oracle + ct2_tier_b.json"]
fn scanner_extra_0x07_matches_daemon_on_adversarial_extra() {
    // Scanner parse is `shekyl_scanner::extra::Extra`; validate stage is
    // `recon::extract_leaf_hashes`. Cross-crate seam — no scanner dep here.
    let hashes = extract_leaf_hashes(Some(&[0u8; 33]));
    std::hint::black_box(hashes);
    todo!("Tier B: daemon duplicate/malformed 0x07 oracle pending");
}
