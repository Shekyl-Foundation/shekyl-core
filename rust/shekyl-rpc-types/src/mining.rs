// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mining methods' wire, at today's names (`DRS_X_STORE_FLIP.md`
//! DX-Q3, N2; the rename is RW-Q8's, at `CORE_RPC_VERSION` 4.0).
//!
//! Under N2 a node mines to one address, its `mine-address` row, and builds
//! one template per tip. So `get_block_template` and `start_mining` take
//! no address and `get_block_template` no reserve size: the extra nonce is
//! always reserved. A request that still carries either is refused as bad
//! parameters, never quietly accepted. Where a reply differs from the C++
//! one, the difference is a row in `DRS_X_STORE_FLIP.md`'s divergence
//! register.
//!
//! Blobs are hexadecimal, as today; RW-Q4's base64 arrives with the rename.

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;
use crate::errors::Diagnostic;
use crate::hash::HashHex;

/// `get_block_template`'s request: nothing (N2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockTemplateRequest {}

/// `get_block_template`'s reply: the posted job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockTemplateResponse {
    pub status: RpcStatus,
    /// The difficulty's low 64 bits.
    pub difficulty: u64,
    /// The whole difficulty, `0x`-prefixed hexadecimal.
    pub wide_difficulty: String,
    /// The difficulty's high 64 bits.
    pub difficulty_top64: u64,
    /// The height the block connects at.
    pub height: u64,
    /// Where the coinbase's eight reserved extra-nonce bytes sit in
    /// `blocktemplate_blob`.
    pub reserved_offset: u64,
    /// Where the header's four nonce bytes sit, in both blobs.
    pub nonce_offset: u64,
    /// What the coinbase pays the miner, in atomic units.
    pub expected_reward: u64,
    /// The tip the block extends.
    pub prev_hash: HashHex,
    /// The height of the block whose id seeds RandomX for this block.
    pub seed_height: u64,
    /// That block's id.
    pub seed_hash: HashHex,
    /// The next epoch's seed, once the chain has it and it differs from
    /// `seed_hash`; empty otherwise.
    pub next_seed_hash: String,
    /// The block, hexadecimal.
    pub blocktemplate_blob: String,
    /// What the longhash is computed over, hexadecimal.
    pub blockhashing_blob: String,
}

/// One body `get_miner_data` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxBacklogEntry {
    pub id: HashHex,
    pub weight: u64,
    pub fee: u64,
}

/// `get_miner_data`'s reply: the posted job's chain facts and bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetMinerDataResponse {
    pub status: RpcStatus,
    pub major_version: u8,
    pub height: u64,
    pub prev_id: HashHex,
    pub seed_hash: HashHex,
    /// `0x`-prefixed hexadecimal.
    pub difficulty: String,
    pub median_weight: u64,
    pub already_generated_coins: u64,
    /// The job's listed bodies, in block order (N2: the template's, not
    /// the whole pool).
    pub tx_backlog: Vec<TxBacklogEntry>,
}

/// How many threads the built-in miner runs (`mine start [threads|auto]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MinerThreads {
    /// The host's parallelism, which is also the most a count may ask for.
    #[default]
    #[serde(with = "auto")]
    Auto,
    /// This many.
    Count(core::num::NonZeroU32),
}

mod auto {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("auto")
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
        let word = String::deserialize(deserializer)?;
        if word == "auto" {
            Ok(())
        } else {
            Err(serde::de::Error::custom(
                "expected `auto` or a thread count",
            ))
        }
    }
}

/// `start_mining`'s request: the thread count only (N2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartMiningRequest {
    #[serde(default)]
    pub threads: MinerThreads,
}

/// A reply with nothing but its status: `start_mining`, `stop_mining`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusOnlyResponse {
    pub status: RpcStatus,
}

/// `mining_status`'s reply: the miner, the posted job, and why none is
/// posted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiningStatusResponse {
    pub status: RpcStatus,
    /// Whether the built-in miner is running.
    pub active: bool,
    /// Hashes per second over the miner's window.
    pub speed: u64,
    pub threads_count: u32,
    /// The `mine-address` row, as written; empty when unset.
    pub address: String,
    pub pow_algorithm: String,
    /// The target block time, in seconds.
    pub block_target: u32,
    /// The posted job's coinbase payment to the miner; `0` with no job.
    pub block_reward: u64,
    /// The posted job's difficulty; `0` with no job.
    pub difficulty: u64,
    pub wide_difficulty: String,
    pub difficulty_top64: u64,
    /// The posted job's height; `0` with no job.
    pub height: u64,
    /// The pool file faulted; the node builds no template until it
    /// restarts.
    pub pool_retired: bool,
    /// Why no job is posted, when none is.
    pub no_template: Option<Diagnostic>,
}

/// `submit_block`'s request: one block (b3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBlockRequest {
    /// The block, hexadecimal. Its listed bodies come from the pool.
    pub body: String,
}

/// `submit_block`'s reply: the block that connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBlockResponse {
    pub status: RpcStatus,
    pub block_id: HashHex,
}

/// `generateblocks`' request: how many blocks (N2: no address, no
/// starting nonce, no previous block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateBlocksRequest {
    pub count: u64,
}

/// `generateblocks`' reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateBlocksResponse {
    pub status: RpcStatus,
    /// The chain height when it returned: the tip's height plus one.
    pub height: u64,
    /// The blocks that connected while it ran, in height order.
    pub blocks: Vec<HashHex>,
}

/// `/pop_blocks`' request, an armed lever (`DRS_X_STORE_FLIP.md` DX-Q3,
/// Q7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopBlocksRequest {
    /// How many blocks to pop from the tip.
    pub nblocks: u64,
}

/// `/pop_blocks`' reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopBlocksResponse {
    pub status: RpcStatus,
    /// The chain height afterwards: the tip's height plus one.
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N2: a request carrying an address or a reserve size is refused,
    /// never read as one without them.
    #[test]
    fn an_address_or_a_reserve_size_is_refused_not_ignored() {
        for body in [r#"{"wallet_address":"x"}"#, r#"{"reserve_size":8}"#] {
            assert!(
                serde_json::from_str::<GetBlockTemplateRequest>(body).is_err(),
                "{body}"
            );
        }
        assert!(serde_json::from_str::<StartMiningRequest>(r#"{"miner_address":"x"}"#).is_err());
        assert!(serde_json::from_str::<GenerateBlocksRequest>(
            r#"{"count":1,"wallet_address":"x"}"#
        )
        .is_err());
        assert_eq!(
            serde_json::from_str::<GetBlockTemplateRequest>("{}").expect("empty"),
            GetBlockTemplateRequest {}
        );
    }

    #[test]
    fn threads_are_a_count_or_auto_and_auto_by_default() {
        let read = |body: &str| serde_json::from_str::<StartMiningRequest>(body).map(|r| r.threads);
        assert_eq!(read("{}").expect("absent"), MinerThreads::Auto);
        assert_eq!(
            read(r#"{"threads":"auto"}"#).expect("auto"),
            MinerThreads::Auto
        );
        assert_eq!(
            read(r#"{"threads":3}"#).expect("three"),
            MinerThreads::Count(core::num::NonZeroU32::new(3).expect("three"))
        );
        assert!(
            read(r#"{"threads":0}"#).is_err(),
            "zero threads is not a count"
        );
        assert!(read(r#"{"threads":"all"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&StartMiningRequest::default()).expect("json"),
            r#"{"threads":"auto"}"#
        );
    }
}
