// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Alt-chain reads (DRS-E1 S-ALT, `DRS_E1_SALT.md` §3.2): **AL4**
//! `alt_block`, **AL5** `has_alt_block`, **AL6** `alt_block_count`, **AL7**
//! `alt_blocks`. One body each. [`ReadSnapshot`]'s methods are here, with
//! those bodies, so `read.rs` does not grow a façade for a surface that is
//! not the recorded chain. The batch methods live on
//! [`super::write::WriteBatch`] (`store/alt.rs`): the same bodies, and an
//! invariant poisons that batch.
//!
//! Alt data is **never** projected onto the validator's `ChainView`
//! (SAL-7): alt-store membership is not a recorded-chain fact (CEN-A4), and
//! a rule that asked would be a rule about the store's contents (C2-R8).
//! These reads belong to the reorg's orchestration (E5) and to the RPCs.
//!
//! The block is already parsed. [`AltBlock::block`] is that
//! [`shekyl_wire::Block`]; a row that does not decode, or whose block does
//! not hash to the key, is SI-7 and is not handed out. [`has_alt_block`]
//! does not decode: membership is the key's presence, which is what
//! `have_block` asks.

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::BlockHash;

use crate::codec::AltBlock;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::ALT_BLOCKS;

use super::chain_reads::{self, undecodable, ReadFault, ReadTables};
use super::error::StoreError;
use super::read::ReadSnapshot;

/// The `alt_blocks` cell as faults name it.
pub(super) const ALT_BLOCKS_CELL: &str = "alt_blocks";

/// One enumerated alt block (AL7): the hash and the whole record. Both
/// C++ enumerators want the block, so there is no block-less shape to
/// offer (SAL-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltEntry {
    /// The block's hash — the table key, checked against [`AltBlock::block`].
    pub id: BlockHash,
    /// Bookkeeping, the parsed block, and the witness.
    pub block: AltBlock,
}

/// SI-7 reason when a decoded alt row's block does not hash to its key.
pub(super) const ALT_KEY_MISMATCH: &str = "alt block does not hash to its key";

/// The table key for a block hash. `alt_blocks` keeps LMDB's
/// `compare_hash32` order (the key-types gate holds it), so the key is
/// [`LmdbHashKey`], never the bare array.
pub(super) fn key(id: &BlockHash) -> LmdbHashKey {
    LmdbHashKey::from_bytes(*id.as_bytes())
}

/// **AL4.** `alt_blocks[id]`, decoded, and only when the block hashes to
/// `id`. `None` is "not an alt block". A row that does not decode, or
/// whose block hashes to something else, is SI-7 — the key is the
/// identity, and a decoded row is never returned under another one.
pub(super) fn alt_block<T: ReadTables>(
    txn: &T,
    id: &BlockHash,
) -> Result<Option<AltBlock>, ReadFault> {
    match chain_reads::cell(txn, ALT_BLOCKS, key(id), ALT_BLOCKS_CELL)? {
        None => Ok(None),
        Some(block) => bound_to_key(*id, block).map(Some),
    }
}

/// The `block_body` belt for this table: `block.hash()` is `id`, or the
/// row is SI-7. Insert refuses the same disagreement as
/// [`super::error::AltCannot::IdentityMismatch`] before the row exists;
/// this is the row that reached the file around that boundary.
fn bound_to_key(id: BlockHash, block: AltBlock) -> Result<AltBlock, ReadFault> {
    if block.block().hash() == id {
        return Ok(block);
    }
    Err(undecodable(
        ALT_BLOCKS_CELL,
        CodecError::Invalid {
            codec: AltBlock::NAME,
            reason: ALT_KEY_MISMATCH,
        },
    ))
}

/// **AL5.** Whether `alt_blocks` holds `id` — without decoding or copying
/// the block. `have_block` asks this for every hash a peer announces
/// (`SAL-Q5`: a separate read on performance, stated so).
pub(super) fn has_alt_block<T: ReadTables>(txn: &T, id: &BlockHash) -> Result<bool, ReadFault> {
    let table = txn.table(ALT_BLOCKS)?;
    let held = table.get(key(id))?.is_some();
    Ok(held)
}

/// **AL6.** How many alt blocks the store holds.
pub(super) fn alt_block_count<T: ReadTables>(txn: &T) -> Result<u64, ReadFault> {
    let table = txn.table(ALT_BLOCKS)?;
    Ok(table.len()?)
}

/// **AL7.** Every alt block, in key order. A row that does not decode, or
/// whose block does not hash to its key, is SI-7 and ends the enumeration.
///
/// Returns a `Vec` rather than an iterator: the alt table is small by
/// construction (dropped at every init unless `--keep-alt-blocks`, SAL-8),
/// both callers collect, and one body must serve a `ReadOnlyTable` and a
/// write transaction's `Table` alike.
pub(super) fn alt_blocks<T: ReadTables>(txn: &T) -> Result<Vec<AltEntry>, ReadFault> {
    let table = txn.table(ALT_BLOCKS)?;
    let mut out = Vec::new();
    for item in table.range::<LmdbHashKey>(..)? {
        let (k, v) = item?;
        let id = BlockHash::from_bytes(k.value().to_bytes());
        let block = v
            .value()
            .decode()
            .map_err(|cause| undecodable(ALT_BLOCKS_CELL, cause))?;
        out.push(AltEntry {
            id,
            block: bound_to_key(id, block)?,
        });
    }
    Ok(out)
}

/// Alt-chain reads on a committed snapshot. The bodies above are the ones
/// the batch calls too (`store/alt.rs`).
impl ReadSnapshot<'_> {
    /// **AL4.** `alt_blocks[id]`: bookkeeping, the parsed block, and the
    /// witness. `None` is "not an alt block".
    ///
    /// A row that does not decode is SI-7. A row whose block does not hash
    /// to `id` is the same fault: the key is the block's identity, and the
    /// read does not return a block under another one.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`]; engine faults.
    pub fn alt_block(&self, id: &BlockHash) -> Result<Option<AltBlock>, StoreError> {
        alt_block(self.txn(), id).map_err(ReadFault::into_plain)
    }

    /// **AL5.** Whether `alt_blocks` holds `id`, without decoding the row.
    /// `have_block` asks this per announced hash (`SAL-Q5`). A corrupt or
    /// mis-keyed row still answers `true`: membership is the key, and the
    /// identity check is AL4's.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn has_alt_block(&self, id: &BlockHash) -> Result<bool, StoreError> {
        has_alt_block(self.txn(), id).map_err(ReadFault::into_plain)
    }

    /// **AL6.** How many alt blocks the store holds.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn alt_block_count(&self) -> Result<u64, StoreError> {
        alt_block_count(self.txn()).map_err(ReadFault::into_plain)
    }

    /// **AL7.** Every alt block in key order. Each row is held to AL4's
    /// rule, so one undecodable or mis-keyed row fails the enumeration.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`]; engine faults.
    pub fn alt_blocks(&self) -> Result<Vec<AltEntry>, StoreError> {
        alt_blocks(self.txn()).map_err(ReadFault::into_plain)
    }
}
