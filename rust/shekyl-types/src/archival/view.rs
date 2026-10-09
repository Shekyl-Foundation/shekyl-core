// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The shard view: one closed shard's aggregate, as a viewer renders it
//! (`SHARD_VIEW_FETCH.md` `SV-D4`).
//!
//! Here rather than in the scheduler that assembles it because two crates
//! on opposite sides of the fetch-client dep cut need the one shape: the
//! scheduler fills it from a verified body and the skeleton, the daemon RPC
//! projects it onto the wire. A quantity two crates need is a type, not
//! two field-for-field copies (`05-system-thinking.mdc`).

use crate::{ArchivalLength, BlockCount, BlockHeight, ShardId, ShardViewHash};

/// One closed shard's view (`SV-D4`).
///
/// Every field is a deterministic function of the shard's body and the
/// public skeleton — no key, no wallet state, no holder privilege — which
/// is the admissibility rule the renderer's input is held to. Two daemons
/// fetching the same closed shard agree on every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardView {
    pub shard_id: ShardId,
    /// The view hash folded over the verified body (`SV-D8`): the hash the
    /// viewer draws from. Not the pass verifier's digest.
    pub shard_hash: ShardViewHash,
    /// Archival bytes the body carried.
    pub archival_len: ArchivalLength,
    /// Blocks in the span `[first, last]`, inclusive.
    pub block_count: BlockCount,
    /// In-domain transactions, as the stream delivered them.
    pub tx_count: u64,
    /// Outputs of those transactions plus the span's coinbase outputs.
    pub output_count: u64,
    /// Coinbase outputs across the span's blocks.
    pub coinbase_output_count: u64,
    /// `last`'s timestamp minus `first`'s, saturating.
    pub time_range_seconds: u64,
    /// The block whose connection closed the shard: the cache key the
    /// response carries so a viewer can tell two views of one id apart
    /// across a reorg (`SV-D5`).
    pub close_height: BlockHeight,
}
