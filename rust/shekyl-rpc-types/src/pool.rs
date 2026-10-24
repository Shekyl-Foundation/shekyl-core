// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool methods' wire, at today's names, as the Rust pool serves them
//! (`DRS_X_STORE_FLIP.md` DX-Q3, Q10; the rename is RW-Q8's).
//!
//! The Rust pool keeps no receive time (S7: across many nodes' listings
//! it points at a transaction's origin), no relay timestamps, no failure
//! history and no double-spend flag, so the C++ fields that report them
//! are not on this wire: `receive_time`, `kept_by_block`,
//! `last_relayed_time`, `double_spend_seen`, `last_failed_height`,
//! `last_failed_id_hash`, `max_used_block_id_hash`,
//! `max_used_block_height`, `do_not_relay`, `tx_json`, and the stats'
//! `oldest`, `num_10m`, `num_failing`, `num_double_spends`, `histo` and
//! `histo_98pc`. Each is a row in the divergence register. `tx_json` was
//! epee's rendering, which retires with the C++ (RK-W).

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;
use crate::hash::HashHex;

/// One transaction in a pool listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolTxInfo {
    pub id_hash: HashHex,
    /// Its serialized length.
    pub blob_size: u64,
    pub weight: u64,
    /// In atomic units.
    pub fee: u64,
    /// Whether the node shows it; `false` is its stem phase, which only the
    /// host's administrator is shown.
    pub relayed: bool,
    /// The transaction, hexadecimal.
    pub tx_blob: String,
}

/// A key image the pool's entries spend, and which entries spend it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpentKeyImageInfo {
    /// The key image.
    pub id_hash: HashHex,
    pub txs_hashes: Vec<HashHex>,
}

/// `/get_transaction_pool`'s reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTransactionPoolResponse {
    pub status: RpcStatus,
    pub transactions: Vec<PoolTxInfo>,
    pub spent_key_images: Vec<SpentKeyImageInfo>,
}

/// `/get_transaction_pool_hashes`' reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTransactionPoolHashesResponse {
    pub status: RpcStatus,
    pub tx_hashes: Vec<HashHex>,
}

/// The pool's figures.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxpoolStats {
    /// Serialized bytes, summed.
    pub bytes_total: u64,
    pub bytes_min: u32,
    pub bytes_max: u32,
    /// The median serialized length.
    pub bytes_med: u32,
    /// Fees, summed, in atomic units.
    pub fee_total: u64,
    pub txs_total: u32,
    /// Entries in their stem phase; `0` unless the host asks.
    pub num_not_relayed: u32,
}

/// `/get_transaction_pool_stats`' reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTransactionPoolStatsResponse {
    pub status: RpcStatus,
    pub pool_stats: TxpoolStats,
}

/// One entry of `get_txpool_backlog`: no time in the pool (S7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxpoolBacklogEntry {
    pub weight: u64,
    pub fee: u64,
}

/// `get_txpool_backlog`'s reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTxpoolBacklogResponse {
    pub status: RpcStatus,
    pub backlog: Vec<TxpoolBacklogEntry>,
}

/// `flush_txpool`'s request: the ids to remove; none is every entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlushTxpoolRequest {
    #[serde(default)]
    pub txids: Vec<HashHex>,
}

/// `relay_tx`'s request: the node's own entries to offer to the relay
/// again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTxRequest {
    pub txids: Vec<HashHex>,
}
