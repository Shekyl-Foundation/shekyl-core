// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! What the scheduler reads from the daemon's own chain state, and from
//! whom.
//!
//! Two seams, both read-only, both the daemon's **local** facts
//! (`SF-D7` amendment: whom to dial and what the shard must hold are never
//! learned from a response):
//!
//! - [`ShardFacts`] — the skeleton. Which shard a byte offset is in, which
//!   transactions a closed shard comprises and what their retained rows
//!   say, the block span those transactions sit in, the tip, and a block
//!   hash at a height. Every requester holds this (`SF-D8`: the
//!   `txid_parts` rows are what the pruned daemon keeps).
//! - [`HolderSource`] — who can be asked. The drawable holders of a shard,
//!   each with the bond record's endpoint and identity key (`SF-D10`'s
//!   snapshot; `SF-D13`'s key).
//!
//! Each is a trait with, in production, one implementation: the daemon's
//! store adapter. The trait exists so the scheduler's own behaviour — the
//! draw, the `SF-D6` moves, the view cache — is tested against in-memory
//! facts, and so the production adapter is one file whose job is reading
//! rows, not deciding anything.

use shekyl_p_fetch::{ExpectedShard, FetchTarget};
use shekyl_types::{ArchivalLength, BlockCount, BlockHash, BlockHeight, PCanonicalId, ShardId};

/// Why a facts read could not be served. The scheduler never guesses a
/// fact past one of these; a need that hits one ends as
/// [`ReadFailure::Facts`](crate::ReadFailure::Facts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FactsFault {
    /// The store is not open yet (startup), or is being torn down.
    #[error("chain facts are not ready")]
    NotReady,
    /// The store contradicted itself — a transaction the skeleton lists with
    /// no row beside it, a height past the tip with a block under it. This
    /// daemon's data, never a fact about the shard asked for.
    #[error("chain facts are inconsistent")]
    Inconsistent,
    /// A read failed for a reason the adapter has logged.
    #[error("chain facts read failed")]
    Internal,
}

/// A holder the draw may pick: a persona bonded to the shard, read from its
/// bond record.
#[derive(Clone, Debug)]
pub struct Holder {
    /// The persona's canonical id — what a pass record and a log line name.
    pub id: PCanonicalId,
    /// Where to dial it and whose signature to accept.
    pub target: FetchTarget,
}

/// Where a closed shard's transactions sit on the chain, read from the
/// skeleton. Everything the view's aggregate carries besides what the body
/// itself says (`SV-D4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSpan {
    /// The block holding the shard's first in-domain transaction.
    pub first: BlockHeight,
    /// The block holding its last. A block straddling a shard boundary is in
    /// both shards' spans (`SV-D4`).
    pub last: BlockHeight,
    /// `first`'s header timestamp, consensus seconds.
    pub first_timestamp: u64,
    /// `last`'s header timestamp.
    pub last_timestamp: u64,
    /// Coinbase outputs across the blocks `first..=last`.
    pub coinbase_outputs: u64,
    /// Outputs of the shard's in-domain transactions, summed. Not the
    /// coinbases: those are the line above.
    pub tx_outputs: u64,
}

impl BlockSpan {
    /// Blocks in the span, inclusive. Never zero.
    #[must_use]
    pub fn block_count(&self) -> BlockCount {
        BlockCount::from_raw(
            self.last
                .saturating_sub(self.first)
                .to_raw()
                .saturating_add(1),
        )
    }

    /// `last_timestamp − first_timestamp`, saturating: a later block with
    /// an earlier timestamp is legal under the median rule and reads as
    /// zero span, not as an underflow.
    #[must_use]
    pub fn time_range_seconds(&self) -> u64 {
        self.last_timestamp.saturating_sub(self.first_timestamp)
    }
}

/// The block whose connection closed the shard — the last block of the
/// span — and its hash at the time the facts were read. The view cache's
/// key (`SV-D5`): a reorg past this height changes the hash, and the
/// cached view with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardClose {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

/// A shard the skeleton says is closed: what its body must hold, where it
/// sits, and what closed it.
#[derive(Clone, Debug)]
pub struct ClosedShard {
    /// The rows the body is checked against, as the fetch client takes
    /// them.
    pub expected: ExpectedShard,
    pub span: BlockSpan,
    pub close: ShardClose,
}

/// What the skeleton says about a shard id.
#[derive(Clone, Debug)]
pub enum ShardStanding {
    /// Closed: its last in-domain transaction's cumulative-after has left
    /// the shard. The body is fetchable and the view is cacheable.
    Closed(Box<ClosedShard>),
    /// Not closed. Either this is the tip shard — the one still filling — or
    /// an id past it. `open_shard` is the one filling; `archival_through_tip`
    /// is the cumulative archival length at the tip, so the caller can say
    /// how far the tip shard is from closing (`SV-D5`).
    Open {
        open_shard: ShardId,
        archival_through_tip: ArchivalLength,
    },
}

/// The daemon's skeleton, read-only.
pub trait ShardFacts: Send + Sync {
    /// The requester's own tip height.
    ///
    /// # Errors
    ///
    /// [`FactsFault`]: the store could not answer.
    fn tip_height(&self) -> Result<BlockHeight, FactsFault>;

    /// The hash of the block at `height` on the requester's main chain, or
    /// `None` past the tip.
    ///
    /// # Errors
    ///
    /// [`FactsFault`]: the store could not answer.
    fn block_hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, FactsFault>;

    /// What the skeleton says about shard `shard_id`.
    ///
    /// # Errors
    ///
    /// [`FactsFault`]: the store could not answer.
    fn shard(&self, shard_id: ShardId) -> Result<ShardStanding, FactsFault>;
}

/// Who can be asked for a shard, read-only.
pub trait HolderSource: Send + Sync {
    /// The drawable holders of `shard_id` — the personas whose bond records
    /// list it, in any order. The scheduler draws from this set uniformly
    /// and without replacement within one need (`SF-D10`); order here
    /// carries nothing.
    ///
    /// The ruled producer is the epoch's drawable snapshot
    /// (`DrawableSet::at_epoch_open`, `SO-D8` Q3). Until that is built, an
    /// adapter reads the bond records' held sets at the tip; the
    /// scheduler's draw is the same over either.
    ///
    /// # Errors
    ///
    /// [`FactsFault`]: the store could not answer.
    fn holders_of(&self, shard_id: ShardId) -> Result<Vec<Holder>, FactsFault>;
}
