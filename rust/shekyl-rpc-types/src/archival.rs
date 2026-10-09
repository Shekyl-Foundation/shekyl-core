// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! `request_archival_shard` — the shard view (`SHARD_VIEW_FETCH.md`).
//!
//! A wallet names a closed archival shard by id; its daemon reads the body
//! from a holder, folds the view hash over what streamed, and answers with
//! the aggregate a viewer renders. **No shard bytes cross this wire** — the
//! daemon's fetch is the point of the surface, the aggregate is what a
//! viewer needs, and a body on a wallet RPC would be a second serving path
//! (`SV-D3`).
//!
//! Three refusals are the method's own answers, each a state a viewer
//! shows, never a blank (`SV-D5`, rule 82):
//!
//! - [`CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE`] — the shard is closed and
//!   no holder served it this time;
//! - [`CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN`] — the shard is still
//!   filling, or does not exist yet;
//! - [`CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT`] — this daemon does
//!   not hold the skeleton the view is read against, so it serves no shard
//!   view at all.
//!
//! The method is admin-only (`RESTRICTED_METHODS`): a shard view is a
//! fetch the daemon makes on the caller's behalf, and the public listener
//! does not fetch for strangers (`SV-D6`).

use serde::{Deserialize, Serialize};

use crate::chain::{RpcStatus, CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE};
use crate::hash::HashHex;

/// Request of `request_archival_shard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestArchivalShardRequest {
    /// The shard, by `SHT-Q2` id: `⌊cum_before / W⌋` over the cumulative
    /// archival length. Required — there is no default shard.
    pub shard_id: u64,
}

/// Response of `request_archival_shard`: one closed shard's view
/// (`SV-D4`). Every field is a deterministic function of the shard's body
/// and the public skeleton; a viewer renders from them and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestArchivalShardResponse {
    pub status: RpcStatus,
    pub shard_id: u64,
    /// The view hash (`SV-D1`): the `ShardViewHasher` fold over the
    /// shard's verified archival bytes. Not the pass verifier's digest.
    pub shard_hash: HashHex,
    /// Archival bytes the body carried.
    pub archival_len: u64,
    /// Blocks spanned by the shard's transactions, inclusive.
    pub block_count: u64,
    /// In-domain transactions in the shard.
    pub tx_count: u64,
    /// Outputs of those transactions plus the span's coinbase outputs.
    pub output_count: u64,
    /// Coinbase outputs across the span's blocks.
    pub coinbase_output_count: u64,
    /// Last block's timestamp minus the first's, saturating.
    pub time_range_seconds: u64,
    /// The block whose connection closed the shard. Two views of one id
    /// with different `close_height` are views across a reorg (`SV-D5`).
    pub close_height: u64,
}

/// The requested shard is not closed: it is the shard still filling at the
/// tip, or an id past it. Nothing was fetched. Not
/// [`CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE`]: there is no body to be
/// unavailable yet, and a viewer says "still filling", not "could not be
/// retrieved" (`SV-D5`).
pub const CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN: i64 = -24;

/// This daemon holds no archival skeleton — the per-transaction
/// `txid_parts` rows and the bond records a shard view is read against —
/// and so serves no shard view. A property of the daemon, stated once per
/// request, never a fact about the shard asked for
/// (`SHARD_VIEW_FETCH.md` `SV-D9`).
pub const CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT: i64 = -25;

/// The three refusal codes, so a client can check it handles each.
pub const ARCHIVAL_SHARD_REFUSAL_CODES: [i64; 3] = [
    CORE_RPC_ERROR_CODE_ARCHIVAL_UNAVAILABLE,
    CORE_RPC_ERROR_CODE_ARCHIVAL_SHARD_OPEN,
    CORE_RPC_ERROR_CODE_ARCHIVAL_SKELETON_ABSENT,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trips_with_hex_hash() {
        let response = RequestArchivalShardResponse {
            status: RpcStatus::ok(),
            shard_id: 7,
            shard_hash: HashHex::from_bytes([0xab; 32]),
            archival_len: 3_000_123,
            block_count: 11,
            tx_count: 42,
            output_count: 95,
            coinbase_output_count: 11,
            time_range_seconds: 1_200,
            close_height: 9_000,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["shard_hash"], "ab".repeat(32));
        assert_eq!(json["close_height"], 9_000);
        let back: RequestArchivalShardResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, response);
    }

    #[test]
    fn request_requires_shard_id_and_refuses_strangers() {
        assert!(serde_json::from_str::<RequestArchivalShardRequest>("{}").is_err());
        assert!(
            serde_json::from_str::<RequestArchivalShardRequest>(r#"{"shard_id":3,"x":1}"#).is_err()
        );
        assert_eq!(
            serde_json::from_str::<RequestArchivalShardRequest>(r#"{"shard_id":3}"#).unwrap(),
            RequestArchivalShardRequest { shard_id: 3 }
        );
    }

    #[test]
    fn refusal_codes_are_distinct_and_in_the_daemon_range() {
        let mut codes = ARCHIVAL_SHARD_REFUSAL_CODES.to_vec();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 3);
        assert!(codes.iter().all(|c| *c < 0));
    }
}
