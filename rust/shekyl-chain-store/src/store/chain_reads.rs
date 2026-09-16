// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One decode / verify / classify body for the committed-chain tables,
//! shared by every reader of them (S-CHAIN-R commit 1; `DRS_E1_SCHAIN_R.md`
//! §3.3, SCR-13, SCR-7).
//!
//! # Why one body
//!
//! The store reads `block_info`, `blocks` and their siblings from two
//! transactions: the live write batch (`BatchView`, the validator's
//! `ChainView`) and — from S-CHAIN-R commit 3 on — the read snapshot. Two
//! copies of "decode this row, check the blob hashes to the recorded
//! identity, decide whether an absent row is *above the tip* or *a hole*"
//! is exactly the drift the S-CHAIN-R row exists to prevent: the two
//! halves of one table's contract moving separately, so that a mismatch
//! cannot be blamed on either. So the body lives here once, generic over
//! the transaction, and each implementor only decides **what a fault
//! does** — the batch arms its poison, a snapshot returns the error.
//!
//! # Absence is classified against the tip, never mapped to a value
//!
//! `AtHeight::AboveTip` is permitted only above the dense tip: `block_info`
//! and `blocks` have one row per height `0..=tip` (SI-2). A row missing
//! *inside* that range is store corruption and comes back as SI-7
//! [`ReadFault::Invariant`]`(CellCorrupt { fault: Absent })`, never as
//! `AboveTip` — which a rule would read as an ordinary "not yet" and turn
//! into a verdict. The LMDB reader got this wrong for `curve_tree_roots[0]`
//! (32 zero bytes, a *valid* encoding of the identity point); this module
//! is where the store makes that shape unrepresentable.
//!
//! # The blob is verified where it is decoded
//!
//! `block_info.hash` is the block's recorded identity (CEN-B6). A blob that
//! does not parse, or parses to a block whose hash is not that identity, is
//! never exposed as a `(hash, block)` pair that does not belong together —
//! it is SI-7 on `blocks`. The C++ `for_blocks_range` re-hashed each blob
//! and never consulted the recorded identity (`db_lmdb.cpp:3931`–`:3933`);
//! two notions of a block's identity in one store is SCR-7, and this body
//! has one.

use redb::{Key, ReadTransaction, ReadableTable, TableDefinition, Value, WriteTransaction};
use shekyl_chain_rules::AtHeight;
use shekyl_wire::Block;

use crate::codec::{BlockInfo, Canonical, CodecError};
use crate::lmdb_order::Hash32;
use crate::schema::{BLOCKS, BLOCK_INFO};

use super::error::{CellFault, EngineError, StoreInvariant};

/// A transaction the chain tables can be opened from for reading.
///
/// Implemented for redb's two transaction types. The associated table type
/// is generic over the key and value so one body can open any typed table
/// through it; the lifetime is the borrow of the transaction, which is what
/// a write-side [`redb::Table`] needs and a [`redb::ReadOnlyTable`] ignores.
pub(super) trait ReadTables {
    /// The opened table.
    type Table<'t, K, V>: ReadableTable<K, V>
    where
        Self: 't,
        K: Key + 'static,
        V: Value + 'static;

    /// Open `definition` for reading.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the table does not exist or the engine
    /// refuses. An absent chain table is not a value: from S-CHAIN-R's
    /// layout commit the seal creates every chain table, so a reader that
    /// meets `TableDoesNotExist` is looking at a file the store did not
    /// write (`DRS_E1_SCHAIN_R.md` §3.3, amendment A2).
    fn table<'t, K, V>(
        &'t self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'t, K, V>, EngineError>
    where
        K: Key + 'static,
        V: Value + 'static;
}

impl ReadTables for WriteTransaction {
    type Table<'t, K, V>
        = redb::Table<'t, K, V>
    where
        Self: 't,
        K: Key + 'static,
        V: Value + 'static;

    fn table<'t, K, V>(
        &'t self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'t, K, V>, EngineError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.open_table(definition).map_err(EngineError::Table)
    }
}

impl ReadTables for ReadTransaction {
    type Table<'t, K, V>
        = redb::ReadOnlyTable<K, V>
    where
        Self: 't,
        K: Key + 'static,
        V: Value + 'static;

    fn table<'t, K, V>(
        &'t self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'t, K, V>, EngineError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.open_table(definition).map_err(EngineError::Table)
    }
}

/// Why a classified read did not produce a value.
///
/// The classification is made here, once; **what it does** is the
/// implementor's: a `BatchView` arms its poison on
/// [`ReadFault::Invariant`] so a verdict minted over a corrupt read cannot
/// commit, while a read snapshot returns it and arms nothing — the halt is
/// the writer's state (`DAEMON_REDB_STORE.md` §3.6.2). Neither implementor
/// re-derives the row.
#[derive(Debug)]
pub(super) enum ReadFault {
    /// The engine failed; nothing about the file's contents is implied.
    Engine(EngineError),
    /// An `SI-` row broke at the read — SI-7 for every arm this module
    /// produces.
    Invariant(StoreInvariant),
}

impl From<EngineError> for ReadFault {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

impl From<redb::StorageError> for ReadFault {
    fn from(e: redb::StorageError) -> Self {
        Self::Engine(EngineError::Storage(e))
    }
}

/// SI-7 for a row the dense ranges say must exist and does not.
fn absent(cell: &'static str) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::CellCorrupt {
        key: cell,
        fault: CellFault::Absent,
    })
}

/// SI-7 for a row that is present and does not decode under its codec.
fn undecodable(cell: &'static str, cause: CodecError) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::CellCorrupt {
        key: cell,
        fault: CellFault::Undecodable(cause),
    })
}

/// SI-7 for a `blocks` row that is present but is not a canonical block
/// for its height.
fn blocks_invalid(reason: &'static str) -> ReadFault {
    undecodable(
        "blocks",
        CodecError::Invalid {
            codec: "block",
            reason,
        },
    )
}

/// The recorded tip: the last `block_info` row, decoded. `None` is an
/// empty chain. `block_info` is dense (SI-2), so its last key is the tip.
pub(super) fn tip_of<T: ReadTables>(txn: &T) -> Result<Option<(u64, BlockInfo)>, ReadFault> {
    let table = txn.table(BLOCK_INFO)?;
    let Some((height, info)) = table.last()? else {
        return Ok(None);
    };
    let info = BlockInfo::decode(info.value()).map_err(|cause| undecodable("block_info", cause))?;
    Ok(Some((height.value(), info)))
}

/// One typed cell of a `u64 → bytes` table, decoded under `V`. Absent is
/// `Ok(None)` — **the caller classifies it** against the tip, because
/// whether an absent row is a hole is not this function's to know.
pub(super) fn cell<T: ReadTables, V: Canonical>(
    txn: &T,
    table: TableDefinition<'static, u64, &'static [u8]>,
    key: u64,
    cell_name: &'static str,
) -> Result<Option<V>, ReadFault> {
    let table = txn.table(table)?;
    let Some(guard) = table.get(key)? else {
        return Ok(None);
    };
    V::decode(guard.value())
        .map(Some)
        .map_err(|cause| undecodable(cell_name, cause))
}

/// The block recorded at `height`: its identity from `block_info`, its body
/// parsed from `blocks` and **verified to hash to that identity**.
///
/// Classified against `tip` (the caller's `tip_of`, so one read of the tip
/// serves a whole range): above it is [`AtHeight::AboveTip`]; a missing
/// `block_info` or `blocks` row at or below it is SI-7 `Absent`; a blob that
/// does not parse, or hashes to something other than `block_info.hash`, is
/// SI-7 on `blocks`.
pub(super) fn block_body<T: ReadTables>(
    txn: &T,
    tip: Option<u64>,
    height: u64,
) -> Result<AtHeight<(Hash32, Block)>, ReadFault> {
    match tip {
        Some(tip) if height <= tip => {}
        _ => return Ok(AtHeight::AboveTip),
    }
    let info: BlockInfo =
        cell(txn, BLOCK_INFO, height, "block_info")?.ok_or_else(|| absent("block_info"))?;
    let blocks = txn.table(BLOCKS)?;
    let blob = blocks.get(height)?.ok_or_else(|| absent("blocks"))?;
    let block =
        Block::from_bytes(blob.value()).map_err(|_| blocks_invalid("block blob does not parse"))?;
    if block.hash() != info.hash.to_bytes() {
        return Err(blocks_invalid(
            "block blob does not hash to block_info.hash",
        ));
    }
    Ok(AtHeight::Recorded((info.hash, block)))
}
