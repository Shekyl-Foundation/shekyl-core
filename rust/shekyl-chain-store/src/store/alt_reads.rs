// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Alt-chain reads (DRS-E1 S-ALT, `DRS_E1_SALT.md` §3.2): **AL4**
//! `alt_block`, **AL5** `has_alt_block`, **AL6** `alt_block_count`, **AL7**
//! `alt_blocks` — one body each, read by both the committed snapshot
//! (`ReadSnapshot`) and the batch that is about to change the table
//! (`WriteBatch`, for the switch), through [`ReadTables`].
//!
//! Alt data is **never** projected onto the validator's `ChainView`
//! (SAL-7): alt-store membership is not a recorded-chain fact (CEN-A4), and
//! a rule that asked would be a rule about the store's contents (C2-R8).
//! These reads belong to the reorg's orchestration (E5) and to the RPCs.
//!
//! What the reads do not do: walk a chain, choose a fork, or parse the
//! block — the bytes are the consumer's (S-CHAIN-R's `RawBlockBytes`
//! discipline).

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_types::BlockHash;

use crate::codec::AltBlock;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::ALT_BLOCKS;

use super::chain_reads::{self, undecodable, ReadFault, ReadTables};

/// The `alt_blocks` cell as faults name it.
pub(super) const ALT_BLOCKS_CELL: &str = "alt_blocks";

/// One enumerated alt block (AL7): the hash and the whole record — both
/// C++ enumerators want the bytes, so there is no bytes-less shape to offer
/// (SAL-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltEntry {
    /// The block's hash — the table key.
    pub id: BlockHash,
    /// The record: bookkeeping, bytes, witness.
    pub block: AltBlock,
}

/// The table key for a block hash. `alt_blocks` keeps LMDB's
/// `compare_hash32` order (the key-types gate holds it), so the key is
/// [`LmdbHashKey`], never the bare array.
pub(super) fn key(id: &BlockHash) -> LmdbHashKey {
    LmdbHashKey::from_bytes(*id.as_bytes())
}

/// **AL4.** `alt_blocks[id]`, decoded. `None` is "not an alt block"; a row
/// that does not decode is SI-7.
pub(super) fn alt_block<T: ReadTables>(
    txn: &T,
    id: &BlockHash,
) -> Result<Option<AltBlock>, ReadFault> {
    chain_reads::cell(txn, ALT_BLOCKS, key(id), ALT_BLOCKS_CELL)
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

/// **AL7.** Every alt block, in key order, each decoded. A row that does
/// not decode is SI-7 and ends the enumeration with the fault.
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
        let block = v
            .value()
            .decode()
            .map_err(|cause| undecodable(ALT_BLOCKS_CELL, cause))?;
        out.push(AltEntry {
            id: BlockHash::from_bytes(k.value().to_bytes()),
            block,
        });
    }
    Ok(out)
}
