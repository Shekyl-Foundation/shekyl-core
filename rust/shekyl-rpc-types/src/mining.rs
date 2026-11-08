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

/// Hundredths of a hash. [`MineSpeed::hashes_per_second_text`] prints
/// that many digits, which is finer than a ten-second window's tenth
/// and matches the console's two-decimal prefixes.
const HUNDREDTHS_PER_HASH: u128 = 100;

/// The miner's hash rate: hashes counted over a window of complete seconds.
///
/// `window` is zero before the first second completes, and `count` is
/// zero then too. A stopped miner is the same pair; `active` on the
/// status is what distinguishes the two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MineSpeed {
    /// Hashes computed in the window.
    pub count: u64,
    /// Complete seconds the count covers.
    pub window: u64,
}

impl MineSpeed {
    /// No hashes, and no completed second.
    pub const NONE: Self = Self {
        count: 0,
        window: 0,
    };

    /// Whole hashes per second. Zero when [`window`](Self::window) is
    /// zero, and zero when the count is below one hash a second.
    #[must_use]
    pub const fn whole_hashes_per_second(self) -> u64 {
        match self.window {
            0 => 0,
            window => self.count / window,
        }
    }

    /// The rate in hashes per second, to the hundredth. A whole number
    /// prints without a fraction. [`NONE`](Self::NONE) prints `0 H/s`.
    #[must_use]
    pub fn hashes_per_second_text(self) -> String {
        if self.window == 0 {
            return "0 H/s".to_owned();
        }
        let hundredths = u128::from(self.count) * HUNDREDTHS_PER_HASH / u128::from(self.window);
        let whole = hundredths / HUNDREDTHS_PER_HASH;
        let frac = hundredths % HUNDREDTHS_PER_HASH;
        if frac == 0 {
            format!("{whole} H/s")
        } else {
            format!("{whole}.{frac:02} H/s")
        }
    }
}

/// `mining_status`'s reply: the miner, the posted job, and why none is
/// posted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiningStatusResponse {
    pub status: RpcStatus,
    /// Whether the built-in miner is running.
    pub active: bool,
    /// Hashes counted over the miner's window of complete seconds.
    /// [`MineSpeed::NONE`] when the miner is stopped, and during its
    /// first second.
    pub speed: MineSpeed,
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

    /// Eight hashes in ten seconds is 0.8 H/s. The wire carries the count
    /// and the window, so the reading is not the whole-hash quotient 0.
    #[test]
    fn a_rate_below_one_hash_a_second_is_the_count_over_its_window() {
        let speed = MineSpeed {
            count: 8,
            window: 10,
        };
        assert_eq!(speed.whole_hashes_per_second(), 0);
        assert_eq!(speed.hashes_per_second_text(), "0.80 H/s");
        assert_eq!(
            serde_json::to_string(&speed).expect("json"),
            r#"{"count":8,"window":10}"#
        );
        let back: MineSpeed = serde_json::from_str(r#"{"count":8,"window":10}"#).expect("object");
        assert_eq!(back, speed);
        assert!(
            serde_json::from_str::<MineSpeed>("8").is_err(),
            "a whole-hash number is not a rate"
        );
        assert_eq!(MineSpeed::NONE.hashes_per_second_text(), "0 H/s");
        assert_eq!(
            MineSpeed {
                count: 15,
                window: 10
            }
            .hashes_per_second_text(),
            "1.50 H/s"
        );
        assert_eq!(
            MineSpeed {
                count: 999,
                window: 1
            }
            .hashes_per_second_text(),
            "999 H/s"
        );
    }
}
