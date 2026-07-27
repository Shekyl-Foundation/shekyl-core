// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus-state KAT: `R_market`, `Σwork`, determinism (ARCHIVAL_CONSENSUS_STATE.md).

use shekyl_archival_retention::{
    epoch_close_compute, r_market_count, sigma_work_milli, BadInterval, EpochCloseInputs,
    ServeCreditRow, WORK_MILLI_SCALE,
};

mod common;

const KAT: &str = include_str!("fixtures/consensus_state_kat_v1.json");

#[test]
fn consensus_state_kat_v1() {
    let doc: serde_json::Value = serde_json::from_str(KAT).expect("kat json");
    let e = doc["settlement_epoch"].as_u64().expect("epoch");
    let shard = doc["shard_id"].as_u64().expect("shard");

    let rows: Vec<ServeCreditRow> = doc["serve_credit_rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            let bad: Vec<BadInterval> = r["bad_intervals"]
                .as_array()
                .map(|ivs| {
                    ivs.iter()
                        .map(|iv| BadInterval {
                            start_epoch: iv["start"].as_u64().unwrap_or(0),
                            end_exclusive: iv["end_exclusive"].as_u64().unwrap_or(u64::MAX),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut p_id = [0u8; 32];
            let hex = r["p_id_hex"].as_str().unwrap_or("00");
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            p_id[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
            ServeCreditRow {
                p_id,
                shard_id: r["shard_id"].as_u64().unwrap_or(shard),
                serve_credit: r["serve_credit"].as_bool().unwrap_or(false),
                join_settlement_epoch: r["join_epoch"].as_u64().unwrap_or(0),
                bad_intervals: bad,
                is_foundation: r["foundation"].as_bool().unwrap_or(false),
            }
        })
        .collect();

    let expected_r = doc["expected"]["r_market"].as_u64().expect("r_market");
    assert_eq!(r_market_count(&rows, shard, e), expected_r);

    if let Some(work_arr) = doc["per_p_work_milli"].as_array() {
        let works: Vec<u64> = work_arr.iter().map(|v| v.as_u64().unwrap()).collect();
        let mask: Vec<bool> = doc["market_mask"]
            .as_array()
            .expect("mask")
            .iter()
            .map(|v| v.as_bool().unwrap())
            .collect();
        let expected_sigma = doc["expected"]["sigma_work_milli"].as_u64().expect("sigma");
        assert_eq!(sigma_work_milli(&works, &mask), expected_sigma);
    }

    // Composed epoch-close replay — the exact computation the daemon delegates
    // through `shekyl_archival_epoch_close_compute`.
    let ec = &doc["epoch_close"];
    assert!(
        !ec.is_null(),
        "fixture must carry the composed epoch_close section"
    );

    let bonds_owned = common::parse_bonds(&ec["bonds"]);
    let bonds = common::bonds_as_slice(&bonds_owned);
    let shards = common::parse_shards(&ec["shards"]);
    let pairs = common::parse_pairs(&ec["credit_pairs"]);

    let out = epoch_close_compute(&EpochCloseInputs {
        settlement_epoch: ec["settlement_epoch"].as_u64().expect("epoch"),
        close_block_height: ec["close_block_height"].as_u64().expect("close height"),
        settlement_epoch_blocks: ec["settlement_epoch_blocks"].as_u64().expect("seb"),
        age_weight_milli: ec["age_weight_milli"].as_u64().expect("age weight"),
        bonds: &bonds,
        shards: &shards,
        credit_pairs: &pairs,
    })
    .expect("well-formed fixture indices");

    let want_r: Vec<u64> = ec["expected"]["r_market_by_shard"]
        .as_array()
        .expect("r_market_by_shard")
        .iter()
        .map(|v| v.as_u64().expect("count"))
        .collect();
    let want_sigma = ec["expected"]["sigma_work_milli"]
        .as_u64()
        .expect("sigma_work_milli");
    assert_eq!(out.r_market_by_shard, want_r);
    assert_eq!(out.sigma_work_milli, want_sigma);
}

#[test]
fn work_milli_scale_is_frozen() {
    // Banded-PL curve golden pins live in reward_arithmetic_determinism_kat
    // (sim/counterfactual only after D3/R2). The consensus fixed-point scale
    // remains a consensus-state pin.
    assert_eq!(WORK_MILLI_SCALE, 1_000);
}
