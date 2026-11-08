// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire of the two archival reads the store flip serves natively
//! (`DRS_X_STORE_FLIP.md` DX-Q3, PR 3): `get_archival_emission_claim_source`
//! and `get_archival_shard_coverage`.
//!
//! Field for field the C++ definitions (`COMMAND_RPC_GET_ARCHIVAL_*` in
//! `core_rpc_server_commands_defs.h`). Their readers are the wallet's claim
//! builder (`shekyl-engine-core`'s `emission_source.rs`, which decodes the
//! claim source by these names) and `shekyl-cli`'s shard list, which
//! decodes [`GetArchivalShardCoverageResponse`] itself.
//!
//! Every list defaults to empty and is omitted when empty: epee omits an
//! empty container, so a reply without the field is the empty list.

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;

/// Params of `get_archival_emission_claim_source`: the persona, and
/// nothing else (`EMISSION_CLAIM_BUILDER.md` §7.2: the request cannot name
/// an epoch).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GetArchivalEmissionClaimSourceRequest {
    /// The persona's `P_canonical_id`, 64 hex characters.
    #[serde(default)]
    pub p_id: String,
}

/// One bond in an epoch's gather.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimBondRow {
    pub join_settlement_epoch: u64,
    pub is_support_complete_tree: bool,
    /// The bad intervals, flattened `[start, end_exclusive, …]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bad_intervals_flat: Vec<u64>,
}

/// One shard in an epoch's gather: its id and its close, as the
/// segment-keyed pair the wallet folds (`ShardClose::from_wire`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimShardRow {
    pub shard_id: u64,
    pub freeze_height: u64,
    pub has_segment: bool,
}

/// One `(bond, credited shard)` pair, as indices into the epoch's bonds
/// and shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimCreditPair {
    pub bond_idx: u64,
    pub shard_idx: u64,
}

/// One settlement epoch of the claim window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEpochSnapshot {
    pub settlement_epoch: u64,
    pub close_block_height: u64,
    /// `Σwork(E)`, `0` where the epoch has none.
    pub sigma_work_milli: u64,
    /// `budget(E)`, `0` where the epoch has none.
    pub budget_atomic: u64,
    /// Whether the epoch can be claimed against: its budget and its `Σwork`
    /// are both rows. Where it is `false` the gather is empty and the
    /// wallet treats the epoch as unclaimable.
    pub has_budget_row: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bonds: Vec<ClaimBondRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shards: Vec<ClaimShardRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credit_pairs: Vec<ClaimCreditPair>,
    /// The claimant's index into `bonds`, `u64::MAX` where it has none.
    pub claimant_bond_idx: u64,
}

/// Result of `get_archival_emission_claim_source`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetArchivalEmissionClaimSourceResponse {
    pub status: RpcStatus,
    /// The chain count: the height a claim built from this connects at.
    pub chain_height: u64,
    /// The settlement epoch at that height.
    pub current_settled_epoch: u64,
    pub has_bond_record: bool,
    // The record's fields, zero where it has none.
    pub join_settlement_epoch: u64,
    pub holdings_kind: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held_shard_ids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimed_settlement_epochs: Vec<u64>,
    pub bonded_total_atomic: u64,
    pub bad_interval_count: u64,
    /// Whether the record has ever served, and the last epoch it did.
    pub has_last_served_epoch: bool,
    pub last_served_epoch: u64,
    /// Whether any slash epoch has settled, and the last that did.
    pub has_last_settled_slash_epoch: bool,
    pub last_settled_slash_epoch: u64,
    /// Every epoch of the claim window, ascending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub epochs: Vec<ClaimEpochSnapshot>,
}

/// One closed shard on the operator coverage list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardCoverageRow {
    pub shard_id: u64,
    pub bonded_count: u64,
    pub served_count: u64,
    pub freeze_height: u64,
    pub join_scarcity_micro: u64,
    pub expected_profit_atomic: u64,
}

/// Result of `get_archival_shard_coverage`: the shards a join can hold,
/// ranked by join scarcity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetArchivalShardCoverageResponse {
    pub status: RpcStatus,
    /// The tip the list is as of.
    pub as_of_height: u64,
    /// Leaves in the curve tree after the tip.
    pub leaf_count: u64,
    /// Shards on the list.
    pub frozen_count: u64,
    /// The last settled epoch as of the tip.
    pub settled_epoch: u64,
    /// Its budget, `0` where it has none.
    pub budget_atomic: u64,
    /// Its `Σwork`, `0` where it has none.
    pub sigma_work_milli: u64,
    /// Whether an expected profit is computed: the epoch's `Σwork` is
    /// non-zero.
    pub profit_estimate_available: bool,
    /// The list, most join-scarce first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shards: Vec<ShardCoverageRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with nothing to list answers without the lists, and the
    /// replies read back empty and are written the same way.
    #[test]
    fn empty_lists_are_omitted_and_read_back_empty() {
        let coverage: GetArchivalShardCoverageResponse = serde_json::from_str(
            r#"{"status":"OK","as_of_height":5,"leaf_count":0,"frozen_count":0,"settled_epoch":0,"budget_atomic":0,"sigma_work_milli":0,"profit_estimate_available":false}"#,
        )
        .expect("decodes");
        assert!(coverage.shards.is_empty());
        let written = serde_json::to_value(&coverage).expect("encodes");
        assert!(written.get("shards").is_none());
        let source: GetArchivalEmissionClaimSourceResponse = serde_json::from_str(
            r#"{"status":"OK","chain_height":6,"current_settled_epoch":0,"has_bond_record":false,"join_settlement_epoch":0,"holdings_kind":0,"bonded_total_atomic":0,"bad_interval_count":0,"has_last_served_epoch":false,"last_served_epoch":0,"has_last_settled_slash_epoch":false,"last_settled_slash_epoch":0}"#,
        )
        .expect("decodes");
        assert!(source.epochs.is_empty() && source.held_shard_ids.is_empty());
        let back: GetArchivalEmissionClaimSourceResponse =
            serde_json::from_value(serde_json::to_value(&source).expect("encodes"))
                .expect("round trip");
        assert_eq!(back, source);
    }
}
