// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixture decoders for the epoch-close KATs (`reward_gate_kat`,
//! `consensus_state_kat`). The JSON → `EpochClose*` shape lives in one place so
//! a fixture-schema change (e.g. the M1 `k_cover` / `frozen_shard_count` fields)
//! edits one decoder, not two that could silently drift apart.
//!
//! These are computational-replay fixtures, not byte-pinned crypto vectors, so
//! centralizing the decode carries none of the `30-cryptography.mdc`
//! reproducible-from-source obligation that keeps the emission-vin KAT fixtures
//! inlined.

// Each test binary that pulls this module in uses a subset of the decoders;
// the unused ones would otherwise trip `-D dead_code` per binary.
#![allow(dead_code)]

use serde_json::Value;
use shekyl_archival_retention::{
    BadInterval, BandedCurveParams, CreditPair, EpochCloseBond, EpochCloseResult, EpochCloseShard,
};

/// Owned bond storage. `EpochCloseBond` borrows its interval/held-id slices, so
/// the fixture-owned vectors must outlive the `epoch_close_compute` call that
/// borrows them — decode into this, then [`bonds_as_slice`] to borrow.
pub struct BondOwned {
    pub join: u64,
    pub complete: bool,
    pub bad: Vec<BadInterval>,
    pub held: Vec<u64>,
}

impl BondOwned {
    pub fn as_bond(&self) -> EpochCloseBond<'_> {
        EpochCloseBond {
            join_settlement_epoch: self.join,
            is_foundation_complete_tree: self.complete,
            bad_intervals: &self.bad,
            held_shard_ids: &self.held,
        }
    }
}

/// Borrow a slice of owned bonds as `EpochCloseBond`s for one compute call.
pub fn bonds_as_slice(owned: &[BondOwned]) -> Vec<EpochCloseBond<'_>> {
    owned.iter().map(BondOwned::as_bond).collect()
}

pub fn parse_bad_intervals(v: &Value) -> Vec<BadInterval> {
    v.as_array()
        .expect("bad_intervals")
        .iter()
        .map(|iv| BadInterval {
            start_epoch: iv["start"].as_u64().expect("start"),
            end_exclusive: iv["end_exclusive"].as_u64().expect("end_exclusive"),
        })
        .collect()
}

pub fn parse_bonds(v: &Value) -> Vec<BondOwned> {
    v.as_array()
        .expect("bonds")
        .iter()
        .map(|b| BondOwned {
            join: b["join_epoch"].as_u64().expect("join_epoch"),
            complete: b["complete_tree"].as_bool().expect("complete_tree"),
            bad: parse_bad_intervals(&b["bad_intervals"]),
            held: b["held_shard_ids"]
                .as_array()
                .expect("held_shard_ids")
                .iter()
                .map(|v| v.as_u64().expect("shard id"))
                .collect(),
        })
        .collect()
}

pub fn parse_shards(v: &Value) -> Vec<EpochCloseShard> {
    v.as_array()
        .expect("shards")
        .iter()
        .map(|s| EpochCloseShard {
            shard_id: s["shard_id"].as_u64().expect("shard_id"),
            has_segment: s["has_segment"].as_bool().expect("has_segment"),
            freeze_height: s["freeze_height"].as_u64().expect("freeze_height"),
        })
        .collect()
}

pub fn parse_pairs(v: &Value) -> Vec<CreditPair> {
    v.as_array()
        .expect("credit_pairs")
        .iter()
        .map(|p| CreditPair {
            bond_idx: usize::try_from(p["bond"].as_u64().expect("bond idx")).unwrap(),
            shard_idx: usize::try_from(p["shard"].as_u64().expect("shard idx")).unwrap(),
        })
        .collect()
}

pub fn parse_curve(v: &Value) -> BandedCurveParams {
    BandedCurveParams {
        plateau_work_milli: v["plateau_work_milli"].as_u64().expect("plateau_work"),
        plateau_value_milli: v["plateau_value_milli"].as_u64().expect("plateau_value"),
    }
}

pub fn expected_result(v: &Value) -> EpochCloseResult {
    EpochCloseResult {
        r_market_by_shard: v["r_market_by_shard"]
            .as_array()
            .expect("r_market_by_shard")
            .iter()
            .map(|x| x.as_u64().expect("count"))
            .collect(),
        sigma_work_milli: v["sigma_work_milli"].as_u64().expect("sigma_work_milli"),
    }
}
