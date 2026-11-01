// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One archival-length fold (`SB-Q2`, `SHT-Q2`).
//!
//! [`span_of_ids`] sums a dense id range: an absent `txs_archival_len` row
//! is zero, and the sum is [`ArchivalLength::checked_add`] (SI-8).
//! [`block_span`] is that sum for one block, after SI-13 on both folds
//! against the parent and before SI-24 against the block's own cell. The
//! prune descent and the shard read both go through it, so a length row
//! and the cell cannot disagree on one path and be trusted on the other.
//!
//! `shard_reads` is not this fold. It walks miner-then-listed hashes and
//! interleaves the record reads; it already checks SI-24, and summing
//! first would change which corruption surfaces first. It stays the
//! domain walk.

use core::ops::Range;

use redb::ReadableTable;
use shekyl_types::{shard_of, storage_ids_through, ArchivalLength, BlockHeight, ShardId};

use crate::codec::BlockInfo;
use crate::ids::TxStorageId;
use crate::schema::{BLOCK_INFO, TXS_ARCHIVAL_LEN};

use super::chain_reads::{self, ReadFault, ReadTables};
use super::error::{StoreError, StoreInvariant};

/// The `block_info` cell as faults name it.
pub(super) const BLOCK_INFO_CELL: &str = "block_info";

/// The listed-transaction fold inside that cell. SI-8 and SI-13 name it.
const TX_COUNT_CELL: &str = "block_info.cumulative_tx_count";

/// The archival-length fold inside that cell (`SHT-Q2`). SI-8, SI-13 and
/// SI-24 name it.
pub(super) const ARCHIVAL_LEN_CELL: &str = "block_info.cumulative_archival_len";

/// The per-transaction length rows, as a decode fault names them.
const ARCHIVAL_LEN_ROW: &str = "txs_archival_len";

/// The lengths of one dense id range, summed from a starting offset.
#[derive(Debug)]
pub(super) struct ArchivalSpan {
    first_id: u64,
    end_id: u64,
    /// Cumulative archival length **before** each id, in issue order.
    /// `before[i]` is the length recorded before `first_id + i`.
    before: Vec<ArchivalLength>,
    through: ArchivalLength,
}

impl ArchivalSpan {
    /// The first id whose length **before** it is at or past `offset`, or
    /// the end id when every id in the span starts below it.
    pub(super) fn id_reaching(&self, offset: ArchivalLength) -> u64 {
        self.before
            .iter()
            .position(|at| *at >= offset)
            .map_or(self.end_id, |index| {
                self.first_id
                    .checked_add(u64::try_from(index).expect("a span index fits the id space"))
                    .expect("the id is inside the span")
            })
    }
}

/// One block's checked span, indexed by storage id. The only question it
/// answers is the shard of an id the block issued.
#[derive(Debug)]
pub struct BlockArchivalFold {
    span: ArchivalSpan,
}

impl BlockArchivalFold {
    /// [`shard_of`] over the length recorded before `id`.
    ///
    /// # Errors
    ///
    /// **SI-9** when `id` is outside the ids this block issued. The fold
    /// was already held to the cell, so a miss here is the index
    /// disagreeing with that issue order, not a length to guess past.
    pub fn shard(&self, id: TxStorageId) -> Result<ShardId, StoreError> {
        id.to_raw()
            .checked_sub(self.span.first_id)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|index| self.span.before.get(index).copied())
            .map(shard_of)
            .ok_or_else(|| StoreInvariant::IdNotFresh.into())
    }
}

/// A `block_info` row the calendar says exists. Absent is SI-7, as is a
/// row that does not decode.
pub(super) fn block_info<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
) -> Result<BlockInfo, ReadFault> {
    chain_reads::cell(txn, BLOCK_INFO, height.to_raw(), BLOCK_INFO_CELL)?
        .ok_or_else(|| chain_reads::absent(BLOCK_INFO_CELL))
}

/// The checked span of block `height`, from the row the caller already
/// loaded and its parent's (`None` at genesis).
///
/// SI-13 on both folds first — on the raw listed samples, before the
/// coinbase term, because a decrease of one derives to an empty id range
/// rather than an inverted one. Then [`span_of_ids`] from the parent's
/// archival cell over the ids the block issued, and that sum must land on
/// the block's own cell (SI-24).
pub(super) fn block_span<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
    info: &BlockInfo,
    parent: Option<&BlockInfo>,
) -> Result<ArchivalSpan, ReadFault> {
    let (before, listed_before) = parent.map_or((ArchivalLength::ZERO, 0), |parent| {
        (parent.cumulative_archival_len, parent.cumulative_tx_count)
    });
    if info.cumulative_archival_len < before {
        return Err(decreased(ARCHIVAL_LEN_CELL, height));
    }
    if info.cumulative_tx_count < listed_before {
        return Err(decreased(TX_COUNT_CELL, height));
    }
    let raw = height.to_raw();
    let first = first_id(height, listed_before)?;
    let end = ids_through(info.cumulative_tx_count, height)?;
    let span = span_of_ids(txn, first..end, before)?;
    if span.through != info.cumulative_archival_len {
        return Err(ReadFault::Invariant(
            StoreInvariant::ArchivalLengthsDisagree {
                height: raw,
                rows: span.through.to_raw(),
                cell: info.cumulative_archival_len.to_raw(),
            },
        ));
    }
    Ok(span)
}

/// [`block_span`] for a height whose rows this read loads itself. The
/// shard of one id, and a block reply's one running total, are this fold.
pub(super) fn fold_of<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
) -> Result<BlockArchivalFold, ReadFault> {
    let info = block_info(txn, height)?;
    let parent = match height.to_raw().checked_sub(1) {
        None => None,
        Some(parent) => Some(block_info(txn, BlockHeight::from_raw(parent))?),
    };
    Ok(BlockArchivalFold {
        span: block_span(txn, height, &info, parent.as_ref())?,
    })
}

/// Sum `ids` from `start`. An absent row is zero. Overflow is SI-8.
fn span_of_ids<T: ReadTables>(
    txn: &T,
    ids: Range<u64>,
    start: ArchivalLength,
) -> Result<ArchivalSpan, ReadFault> {
    let lens = txn.table(TXS_ARCHIVAL_LEN)?;
    let first_id = ids.start;
    let end_id = ids.end;
    let mut before = Vec::new();
    if let Ok(count) = usize::try_from(end_id.saturating_sub(first_id)) {
        before.reserve(count);
    }
    let mut at = start;
    for id in ids {
        before.push(at);
        let len = match lens.get(id)? {
            Some(guard) => guard
                .value()
                .decode()
                .map_err(|cause| chain_reads::undecodable(ARCHIVAL_LEN_ROW, cause))?,
            None => ArchivalLength::ZERO,
        };
        at = at
            .checked_add(len)
            .ok_or(ReadFault::Invariant(StoreInvariant::FoldOverflow {
                cell: ARCHIVAL_LEN_CELL,
            }))?;
    }
    Ok(ArchivalSpan {
        first_id,
        end_id,
        before,
        through: at,
    })
}

/// Storage id of the first transaction at `height`: `0` at genesis,
/// otherwise every id issued through the parent.
fn first_id(height: BlockHeight, listed_before: u64) -> Result<u64, ReadFault> {
    match height.to_raw().checked_sub(1) {
        None => Ok(0),
        Some(parent) => ids_through(listed_before, BlockHeight::from_raw(parent)),
    }
}

/// Storage ids issued through `height` inclusive. The coinbase term is
/// [`storage_ids_through`]. Overflow is SI-8.
fn ids_through(listed: u64, height: BlockHeight) -> Result<u64, ReadFault> {
    storage_ids_through(listed, height.to_raw()).ok_or(ReadFault::Invariant(
        StoreInvariant::FoldOverflow {
            cell: TX_COUNT_CELL,
        },
    ))
}

/// SI-13: the named fold decreased. `height` is the later sample.
fn decreased(cell: &'static str, height: BlockHeight) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::FoldNotMonotone {
        cell,
        height: height.to_raw(),
    })
}
