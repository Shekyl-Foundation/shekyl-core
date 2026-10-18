// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire of six chain reads the store flip serves natively
//! (`DRS_X_STORE_FLIP.md` DX-Q3, PR 3): `get_alt_blocks_hashes`,
//! `get_alternate_chains`, `get_coinbase_tx_sum`, `calc_pow`,
//! `get_curve_tree_info` and `get_curve_tree_checkpoint`.
//!
//! Field for field the C++ definitions in `core_rpc_server_commands_defs.h`
//! — the names, the order, the 128-bit triples — so a client of the C++
//! table reads these replies unchanged. Where the Rust handler answers a
//! request the C++ refused, or refuses one the C++ answered, the
//! difference is in `DRS_X_STORE_FLIP.md`'s divergence register, not here:
//! these are shapes, and the shapes did not change.
//!
//! Requests default every field, as the epee map did: a missing field read
//! as its zero value there, and a client that relied on that still parses.

use serde::{Deserialize, Serialize};

use crate::{HashHex, RpcStatus};

/// Result of `get_alt_blocks_hashes` (`/get_alt_blocks_hashes`): every
/// block this node holds off its main chain, by identity, in the alt
/// table's key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetAltBlocksHashesResponse {
    pub status: RpcStatus,
    /// The alt blocks' identities. Absent on the wire when empty: epee
    /// omits an empty container, so a reply with no alt blocks has no field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blks_hashes: Vec<HashHex>,
}

/// One alternative chain: a tip no alt block extends, and the alt blocks
/// below it down to where it leaves the main chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AltChainInfo {
    /// The chain's tip.
    pub block_hash: HashHex,
    /// The tip's height.
    pub height: u64,
    /// How many alt blocks the chain holds — `block_hashes.len()`.
    pub length: u64,
    /// The tip's cumulative difficulty, low 64 bits.
    pub difficulty: u64,
    /// The tip's cumulative difficulty, whole, as `0x` hex.
    pub wide_difficulty: String,
    /// The tip's cumulative difficulty, high 64 bits.
    pub difficulty_top64: u64,
    /// The chain's blocks, tip first. Required: a chain holds at least its
    /// tip, so epee never omits it, and a reply without it is malformed.
    pub block_hashes: Vec<HashHex>,
    /// The block the chain's lowest block names as its parent.
    pub main_chain_parent_block: HashHex,
}

/// Result of `get_alternate_chains`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetAlternateChainsResponse {
    pub status: RpcStatus,
    /// Absent on the wire when empty, as epee omits an empty container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chains: Vec<AltChainInfo>,
}

/// Params of `get_coinbase_tx_sum`: `count` blocks from `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GetCoinbaseTxSumRequest {
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub count: u64,
}

/// Result of `get_coinbase_tx_sum`: the coins the range emitted and the
/// fees its transactions paid, each as the 128-bit triple `store_128`
/// wrote. A refused range answers its status with every amount zero, as
/// the C++ handler did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCoinbaseTxSumResponse {
    pub status: RpcStatus,
    pub emission_amount: u64,
    pub wide_emission_amount: String,
    pub emission_amount_top64: u64,
    pub fee_amount: u64,
    pub wide_fee_amount: String,
    pub fee_amount_top64: u64,
}

/// Params of `calc_pow`: the bytes to hash, the height whose seed they are
/// hashed under, and a seed that overrides it. The reply is the hash
/// alone, as a bare hex string.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CalcPowRequest {
    #[serde(default)]
    pub height: u64,
    /// Hex of the bytes RandomX is run over — a block's hashing blob.
    #[serde(default)]
    pub block_blob: String,
    /// Hex of a 32-byte seed; empty for the chain's seed at `height`.
    #[serde(default)]
    pub seed_hash: String,
}

/// Result of `get_curve_tree_info`: the tree after the top block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCurveTreeInfoResponse {
    pub status: RpcStatus,
    /// The tree's root, as hex.
    pub root: String,
    /// The tree's depth: its layer count less one, `0` for an empty tree.
    pub depth: u8,
    /// Leaves in the tree.
    pub leaf_count: u64,
    /// The top block's height — the block the tree is after.
    pub height: u64,
}

/// Params of `get_curve_tree_checkpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GetCurveTreeCheckpointRequest {
    #[serde(default)]
    pub block_height: u64,
}

/// Result of `get_curve_tree_checkpoint`: the tree after the block at
/// `block_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCurveTreeCheckpointResponse {
    pub status: RpcStatus,
    pub root: String,
    pub depth: u8,
    pub leaf_count: u64,
    pub block_height: u64,
}

/// `CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB` (-6): the request's blob is not hex.
pub const CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB: i64 = -6;

/// `CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE` (-10): the request's blob is
/// larger than any block.
pub const CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE: i64 = -10;

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with no alternative blocks answers without the list (epee
    /// omits an empty container); the reply decodes as empty, and an empty
    /// Rust reply is written the same way.
    #[test]
    fn an_empty_alt_block_list_is_omitted_and_reads_back_empty() {
        let cxx = r#"{"status":"OK","untrusted":false}"#;
        let decoded: GetAltBlocksHashesResponse = serde_json::from_str(cxx).expect("decodes");
        assert!(decoded.blks_hashes.is_empty());
        let written = serde_json::to_value(&decoded).expect("encodes");
        assert_eq!(written, serde_json::json!({"status": "OK"}));
        let back: GetAltBlocksHashesResponse = serde_json::from_value(written).expect("round trip");
        assert_eq!(back, decoded);
    }

    /// The same for the alternative chains.
    #[test]
    fn an_empty_alt_chain_list_is_omitted_and_reads_back_empty() {
        let cxx = r#"{"status":"OK","untrusted":false}"#;
        let decoded: GetAlternateChainsResponse = serde_json::from_str(cxx).expect("decodes");
        assert!(decoded.chains.is_empty());
        let written = serde_json::to_value(&decoded).expect("encodes");
        assert_eq!(written, serde_json::json!({"status": "OK"}));
        let back: GetAlternateChainsResponse = serde_json::from_value(written).expect("round trip");
        assert_eq!(back, decoded);
    }

    /// A chain without its block list is malformed, not empty.
    #[test]
    fn a_chain_without_its_blocks_is_refused() {
        let chain = r#"{"status":"OK","chains":[{"block_hash":"0000000000000000000000000000000000000000000000000000000000000000","height":5,"length":1,"difficulty":1,"wide_difficulty":"0x1","difficulty_top64":0,"main_chain_parent_block":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#;
        assert!(serde_json::from_str::<GetAlternateChainsResponse>(chain).is_err());
    }
}
