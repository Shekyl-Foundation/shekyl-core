// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One shard's standing, read off the indexed archival fold.
//!
//! `block_info.cumulative_archival_len` is the running total (`SHT-Q2`).
//! A closed shard is the transactions whose cumulative-before lies in
//! `[k·W, (k+1)·W)`, and the height span is the binary search that total
//! already supports. The genesis-to-tip scan this replaces could disagree
//! with the cell (SI-24) and parsed pruned bytes to count outputs.

use shekyl_chain_rules::AtHeight;
use shekyl_types::{
    shard_of, shard_start, ArchivalLength, BlockHash, BlockHeight, ShardId, TxHash,
};
use shekyl_wire::{carries_archival_good, TxidParts};

use super::read::ReadSnapshot;
use super::{AtIndex, CellFault, StoreError, StoreInvariant};

/// Where shard `shard_id` stands against the tip fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardFold {
    /// `shard_id` is the open shard, or later. `open_shard` is
    /// `shard_of` of the tip fold, and `archival_through_tip` is that fold.
    /// An empty chain is shard 0 open at zero, for any requested id.
    Open {
        /// The shard the tip fold is still inside.
        open_shard: ShardId,
        /// Cumulative archival length through the tip. Zero when no block
        /// is recorded.
        archival_through_tip: ArchivalLength,
    },
    /// `shard_id` has closed: the tip fold has reached `(k+1)·W`.
    Closed(ClosedShardRows),
}

/// The rows a closed shard is: the in-domain transactions, in chain
/// order, and the block span those transactions occupy.
///
/// `cum_before_first` is the cumulative archival length **before** the
/// first in-domain transaction, which is the fetch expectation's
/// `cum_before`. `first` and `last` are heights that contain an in-domain
/// transaction, not the raw heights where the fold crossed `k·W`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedShardRows {
    /// The shard these rows close.
    pub shard_id: ShardId,
    /// Cumulative archival length before the first in-domain transaction.
    pub cum_before_first: ArchivalLength,
    /// In-domain transactions, miner-then-listed within each block.
    pub txs: Vec<TxidParts>,
    /// Height of the first block that contains an in-domain transaction.
    pub first: BlockHeight,
    /// Height of the last block that contains an in-domain transaction.
    pub last: BlockHeight,
    /// `block_info.timestamp` at `first`.
    pub first_timestamp: u64,
    /// `block_info.timestamp` at `last`.
    pub last_timestamp: u64,
    /// Miner-transaction outputs over `first..=last`, middle blocks included.
    pub coinbase_outputs: u64,
    /// Outputs of the in-domain transactions only, from `tx_outputs`.
    pub tx_outputs: u64,
    /// `block_info.hash` of `last`.
    pub close_hash: BlockHash,
}

/// One block the fold walked.
struct WalkedBlock {
    height: BlockHeight,
    timestamp: u64,
    hash: BlockHash,
    coinbase_outputs: u64,
    /// Cumulative-before of this block's first in-domain transaction.
    cum_before_first: Option<ArchivalLength>,
    txs: Vec<TxidParts>,
    tx_outputs: u64,
}

impl ReadSnapshot<'_> {
    /// The standing of `shard_id` against this snapshot's tip fold.
    ///
    /// Closed shards are `0..shard_of(tip)`. The height span is the first
    /// block whose fold passes `k·W` through the first whose fold reaches
    /// `(k+1)·W`. Inside a block the transactions are the miner's, then
    /// `transaction_hashes`, which is the order `connect` records them.
    /// Each block's rows must sum to its own cell (SI-24). Output counts
    /// come from `tx_outputs`, not from parsing a pruned body.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::ArchivalLengthsDisagree`] when a block's rows do
    /// not meet its cell, or the cell says the shard is closed and the
    /// span holds no in-domain transaction. [`StoreInvariant::FoldNotMonotone`]
    /// when the tip fold has passed a boundary and no height's fold still
    /// meets it. [`StoreInvariant::FoldOverflow`] when a length or
    /// `(k+1)·W` does not fit. [`StoreInvariant::CellCorrupt`] when a hash
    /// the block names has no `tx_indices` row, a height at or below the
    /// tip has no `block_info`, or an in-domain id is past `tx_outputs`.
    pub fn shard_fold(&self, shard_id: ShardId) -> Result<ShardFold, StoreError> {
        let Some(tip) = self.tip()?.recorded else {
            return Ok(ShardFold::Open {
                open_shard: ShardId::from_raw(0),
                archival_through_tip: ArchivalLength::ZERO,
            });
        };
        let through = info_at(self, tip.height)?.cumulative_archival_len;
        let open_shard = shard_of(through);
        if shard_id >= open_shard {
            return Ok(ShardFold::Open {
                open_shard,
                archival_through_tip: through,
            });
        }
        Ok(ShardFold::Closed(closed_rows(self, shard_id, tip.height)?))
    }
}

fn closed_rows(
    snap: &ReadSnapshot<'_>,
    shard_id: ShardId,
    tip: BlockHeight,
) -> Result<ClosedShardRows, StoreError> {
    let end = next_shard_start(shard_id)?;
    let start = shard_start(shard_id).ok_or_else(fold_overflow)?;
    let close_h = smallest_reaching(snap, tip, end, Reach::AtLeast)?;
    let enter_h = smallest_reaching(snap, tip, start, Reach::Past)?;
    let mut walked = Vec::new();
    if enter_h <= close_h {
        for raw in enter_h.to_raw()..=close_h.to_raw() {
            walked.push(walk_block(snap, BlockHeight::from_raw(raw), shard_id)?);
        }
    }
    assemble(shard_id, close_h, end, &walked)
}

/// `(k+1)·W`. A shard the tip fold says is closed has an end that fits:
/// the tip fold is at least that end.
fn next_shard_start(shard_id: ShardId) -> Result<ArchivalLength, StoreError> {
    let next = shard_id.to_raw().checked_add(1).ok_or_else(fold_overflow)?;
    shard_start(ShardId::from_raw(next)).ok_or_else(fold_overflow)
}

/// How a height's fold meets the boundary being searched.
#[derive(Clone, Copy)]
enum Reach {
    /// The shard's end: the first height whose fold is at least `(k+1)·W`.
    AtLeast,
    /// The shard's start: a fold sitting on `k·W` has not entered shard `k`.
    Past,
}

/// Smallest `h ≤ tip` whose fold has [`Reach`]ed `target`.
///
/// The caller asks only for a shard the tip fold has already closed, so
/// the tip meets `target`. A landing that does not is a fold that went
/// backwards ([`StoreInvariant::FoldNotMonotone`]), the same post-condition
/// `shard_close_height` holds on its own search.
fn smallest_reaching(
    snap: &ReadSnapshot<'_>,
    tip: BlockHeight,
    target: ArchivalLength,
    reach: Reach,
) -> Result<BlockHeight, StoreError> {
    let reached = |fold: ArchivalLength| match reach {
        Reach::AtLeast => fold >= target,
        Reach::Past => fold > target,
    };
    let (mut lo, mut hi) = (0u64, tip.to_raw());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let fold = info_at(snap, BlockHeight::from_raw(mid))?.cumulative_archival_len;
        if reached(fold) {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    let height = BlockHeight::from_raw(lo);
    let fold = info_at(snap, height)?.cumulative_archival_len;
    if !reached(fold) {
        return Err(StoreInvariant::FoldNotMonotone {
            cell: "block_info.cumulative_archival_len",
            height: height.to_raw(),
        }
        .into());
    }
    Ok(height)
}

fn walk_block(
    snap: &ReadSnapshot<'_>,
    height: BlockHeight,
    shard_id: ShardId,
) -> Result<WalkedBlock, StoreError> {
    let info = info_at(snap, height)?;
    let body = match snap.block(height)? {
        AtHeight::Recorded(body) => body,
        AtHeight::AboveTip => return Err(absent("block_info")),
    };
    let parent = match height.to_raw().checked_sub(1) {
        Some(parent) => info_at(snap, BlockHeight::from_raw(parent))?.cumulative_archival_len,
        None => ArchivalLength::ZERO,
    };
    let mut cum = parent;
    let mut cum_before_first = None;
    let mut txs = Vec::new();
    let mut tx_outputs = 0u64;
    let miner = body.block.miner_transaction.hash();
    for hash in std::iter::once(miner).chain(body.block.transaction_hashes.into_iter()) {
        let placed = place_tx(snap, hash, shard_id, cum)?;
        if let Some(domain) = placed.in_domain {
            if cum_before_first.is_none() {
                cum_before_first = Some(placed.before);
            }
            tx_outputs = tx_outputs
                .checked_add(domain.outputs)
                .ok_or_else(fold_overflow)?;
            txs.push(domain.parts);
        }
        cum = placed.after;
    }
    if cum != info.cumulative_archival_len {
        return Err(StoreInvariant::ArchivalLengthsDisagree {
            height: height.to_raw(),
            rows: cum.to_raw(),
            cell: info.cumulative_archival_len.to_raw(),
        }
        .into());
    }
    let coinbase_outputs = u64::try_from(body.block.miner_transaction.prefix.outputs.len())
        .expect("a miner output count fits u64");
    Ok(WalkedBlock {
        height,
        timestamp: info.timestamp.to_raw(),
        hash: info.hash,
        coinbase_outputs,
        cum_before_first,
        txs,
        tx_outputs,
    })
}

/// One in-domain transaction: the skeleton row and its output count.
struct InDomain {
    parts: TxidParts,
    outputs: u64,
}

/// Where one transaction sits in the fold.
struct Placed {
    before: ArchivalLength,
    after: ArchivalLength,
    in_domain: Option<InDomain>,
}

fn place_tx(
    snap: &ReadSnapshot<'_>,
    hash: TxHash,
    shard_id: ShardId,
    cum: ArchivalLength,
) -> Result<Placed, StoreError> {
    let Some(record) = snap.tx_record(&hash)? else {
        return Err(absent("tx_indices"));
    };
    let after = cum
        .checked_add(record.archival_len)
        .ok_or_else(fold_overflow)?;
    let in_domain = if shard_of(cum) == shard_id
        && carries_archival_good(record.pqc_auth_hash, record.prunable_hash)
    {
        let outputs = match snap.tx_output_count(record.location.id)? {
            AtIndex::Recorded(count) => count,
            AtIndex::BeyondCount => return Err(absent("tx_outputs")),
        };
        Some(InDomain {
            parts: TxidParts {
                hash,
                pqc_auth_hash: record.pqc_auth_hash,
                prunable_hash: record.prunable_hash,
                archival_len: record.archival_len,
            },
            outputs,
        })
    } else {
        None
    };
    Ok(Placed {
        before: cum,
        after,
        in_domain,
    })
}

fn assemble(
    shard_id: ShardId,
    close_h: BlockHeight,
    shard_end: ArchivalLength,
    walked: &[WalkedBlock],
) -> Result<ClosedShardRows, StoreError> {
    let mut txs = Vec::new();
    let mut tx_outputs = 0u64;
    let mut cum_before_first = None;
    let mut first = None;
    let mut last = None;
    let mut first_timestamp = 0u64;
    let mut last_timestamp = 0u64;
    let mut close_hash = None;
    for block in walked {
        if block.txs.is_empty() {
            continue;
        }
        if first.is_none() {
            first = Some(block.height);
            first_timestamp = block.timestamp;
            cum_before_first = block.cum_before_first;
        }
        last = Some(block.height);
        last_timestamp = block.timestamp;
        close_hash = Some(block.hash);
        tx_outputs = tx_outputs
            .checked_add(block.tx_outputs)
            .ok_or_else(fold_overflow)?;
        txs.extend(block.txs.iter().copied());
    }
    let (Some(first), Some(last), Some(cum_before_first), Some(close_hash)) =
        (first, last, cum_before_first, close_hash)
    else {
        // The cell says the shard closed, and no transaction in the span
        // starts inside it. There is no SI row for that shape; the lengths
        // the cell is built from do not place the shard.
        return Err(StoreInvariant::ArchivalLengthsDisagree {
            height: close_h.to_raw(),
            rows: 0,
            cell: shard_end.to_raw(),
        }
        .into());
    };
    let mut coinbase_outputs = 0u64;
    for block in walked {
        if block.height < first || block.height > last {
            continue;
        }
        coinbase_outputs = coinbase_outputs
            .checked_add(block.coinbase_outputs)
            .ok_or_else(fold_overflow)?;
    }
    Ok(ClosedShardRows {
        shard_id,
        cum_before_first,
        txs,
        first,
        last,
        first_timestamp,
        last_timestamp,
        coinbase_outputs,
        tx_outputs,
        close_hash,
    })
}

fn info_at(
    snap: &ReadSnapshot<'_>,
    height: BlockHeight,
) -> Result<crate::codec::BlockInfo, StoreError> {
    match snap.block_info(height)? {
        AtHeight::Recorded(info) => Ok(info),
        AtHeight::AboveTip => Err(absent("block_info")),
    }
}

fn absent(cell: &'static str) -> StoreError {
    StoreInvariant::CellCorrupt {
        key: cell,
        fault: CellFault::Absent,
    }
    .into()
}

fn fold_overflow() -> StoreError {
    StoreInvariant::FoldOverflow {
        cell: "block_info.cumulative_archival_len",
    }
    .into()
}
