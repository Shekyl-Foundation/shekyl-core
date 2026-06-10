// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus-state KAT: `R_market`, `Σwork`, determinism (ARCHIVAL_CONSENSUS_STATE.md).

use shekyl_archival_retention::{
    curve_milli, r_market_count, sigma_work_milli, BadInterval, BandedCurveParams, ServeCreditRow,
    WORK_MILLI_SCALE,
};

const KAT: &str = include_str!("fixtures/consensus_state_kat_v1.json");

#[test]
fn consensus_state_kat_v1() {
    let doc: serde_json::Value = serde_json::from_str(KAT).expect("kat json");
    let curve = BandedCurveParams {
        plateau_work_milli: doc["curve"]["plateau_work_milli"]
            .as_u64()
            .expect("plateau_work"),
        plateau_value_milli: doc["curve"]["plateau_value_milli"]
            .as_u64()
            .expect("plateau_value"),
    };
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
        assert_eq!(sigma_work_milli(&works, &curve, &mask), expected_sigma);
    }

    if let Some(cases) = doc["curve_cases"].as_array() {
        for case in cases {
            let work = case["work_milli"].as_u64().unwrap();
            let want = case["capped_milli"].as_u64().unwrap();
            assert_eq!(curve_milli(work, &curve), want, "work_milli={work}");
        }
    }
}

#[test]
fn determinism_curve_milli_cross_check() {
    let curve = BandedCurveParams::default_provisional();
    let samples = [0u64, 1, 500, 4_000, 8_000, 16_000, 100_000];
    for work in samples {
        let a = curve_milli(work, &curve);
        let b = curve_milli(work, &curve);
        assert_eq!(a, b, "determinism failed at work={work}");
    }
    assert_eq!(curve_milli(16_000, &curve), 8_000);
    assert_eq!(WORK_MILLI_SCALE, 1_000);
}
