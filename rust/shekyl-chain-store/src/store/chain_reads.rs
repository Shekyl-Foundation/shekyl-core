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
//! does**. Two kinds of fault, two policies: an [`ReadFault::Invariant`]
//! (an `SI-` row broke) is what the implementors differ on — the batch
//! **arms its poison** so no verdict minted over the read can commit, a
//! snapshot **returns it** and arms nothing (the halt is the writer's
//! state, `DAEMON_REDB_STORE.md` §3.6.2); an [`ReadFault::Engine`] failure
//! passes through on both — nothing about the file is implied, so there is
//! nothing to latch.
//!
//! # The tip is one decoded read
//!
//! [`tip_of`] returns the last `block_info` row **decoded**, not its key
//! alone. The batch view's first implementation read only the key, so a
//! corrupt tip row went unnoticed by a read of a lower height. That is
//! **deliberately tightened here**: an undecodable `block_info[tip]` is
//! SI-7 on any classified read of that chain — the store's tip row does not
//! decode, so no read of it can be trusted, and `connect` decodes exactly
//! this row before its first belt and poisons on the same failure
//! (`store/connect.rs`, phase 1). One tip read, decoded, serves every
//! reader — `ChainView::tip()` needs the hash, the snapshot's tip needs the
//! hash, and a second key-only path would be two readings of one row, the
//! which-key ambiguity SCW-19 closed for `curve_tree_roots`. The cost is
//! one 104-byte decode per read. The test that first pinned the tightening
//! planted an undecodable tip row; under §11.1(f) that row cannot reach
//! the file (the engine holds `block_info`'s width and the crate refuses
//! first), so what is pinned now is the refusal —
//! `view_tests::a_wrong_width_row_is_refused_before_it_can_reach_a_coded_table`
//! — and the decoded-tip path is exercised by every classified read.
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

use std::borrow::Borrow;

use redb::{Key, ReadTransaction, ReadableTable, TableDefinition, Value, WriteTransaction};
use shekyl_chain_rules::AtHeight;
use shekyl_types::KeyImage;
use shekyl_wire::Block;

use crate::codec::{BlockInfo, Canonical, CodecError, Coded};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{BLOCKS, BLOCK_INFO, SPENT_KEYS};

use super::error::{CellFault, EngineError, StoreError, StoreInvariant};

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

impl ReadFault {
    /// The snapshot reader's policy: **return** the fault, arm nothing
    /// (`DAEMON_REDB_STORE.md` §3.6.2 — the halt is the writer's state).
    /// A named conversion rather than `From<ReadFault> for StoreError` on
    /// purpose: `BatchView` must go through its `arm`, and a `From` would
    /// let a `?` there choose this policy silently.
    pub(super) fn into_plain(self) -> StoreError {
        match self {
            Self::Engine(e) => e.into(),
            Self::Invariant(row) => row.into(),
        }
    }
}

/// SI-7 for a row the dense ranges say must exist and does not. Shared
/// with `tx_reads`: a permanent hash row missing below its record is the
/// same fault class.
pub(super) fn absent(cell: &'static str) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::CellCorrupt {
        key: cell,
        fault: CellFault::Absent,
    })
}

/// SI-7 for a row that is present and does not decode under its codec.
/// Shared with `output_reads`: one classification of "the bytes are not
/// this codec" for every typed cell.
pub(super) fn undecodable(cell: &'static str, cause: CodecError) -> ReadFault {
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

/// The recorded tip: the last `block_info` row, **decoded** (module docs,
/// *The tip is one decoded read*). `None` is an empty chain. `block_info`
/// is dense (SI-2), so its last key is the tip. An undecodable tip row is
/// SI-7 here, whatever height the caller went on to ask about.
pub(super) fn tip_of<T: ReadTables>(txn: &T) -> Result<Option<(u64, BlockInfo)>, ReadFault> {
    let table = txn.table(BLOCK_INFO)?;
    let Some((height, info)) = table.last()? else {
        return Ok(None);
    };
    let info = info
        .value()
        .decode()
        .map_err(|cause| undecodable("block_info", cause))?;
    Ok(Some((height.value(), info)))
}

/// One cell of a `K → Coded<V>` table, decoded under **the table's**
/// codec: `V` is inferred from the definition, never named independently,
/// so table identity and codec identity are one inference (`codec::shape`
/// module docs, *Two guards*). Absent is `Ok(None)` — **the caller
/// classifies it** against the tip, because whether an absent row is a
/// hole is not this function's to know.
pub(super) fn cell<T, K, V>(
    txn: &T,
    table: TableDefinition<'static, K, Coded<V>>,
    key: K,
    cell_name: &'static str,
) -> Result<Option<V>, ReadFault>
where
    T: ReadTables,
    K: Key + 'static,
    // `ReadableTable::get` takes `Borrow<K::SelfType<'a>>`. For the keys
    // this store uses, that associated type is `K`.
    for<'a> K: Borrow<K::SelfType<'a>>,
    V: Canonical + 'static,
{
    let table = txn.table(table)?;
    let Some(guard) = table.get(key)? else {
        return Ok(None);
    };
    guard
        .value()
        .decode()
        .map(Some)
        .map_err(|cause| undecodable(cell_name, cause))
}

/// `spent_keys` membership — the chain half of CEN-L1 / CEN-I7, read from
/// the table SI-1 guards (S-OUT-KI **K1**, `DRS_E1_SOUT_KI.md` §3.2). One
/// body for both readers: the validator's `BatchView::has_key_image` inside
/// a batch and `ReadSnapshot::has_key_image` on the committed chain. The
/// answer is exact — a table read, never a filter or a cache — and `bool`
/// is the right shape: "not spent" is a value inside the type's range with
/// no arm that differs (`CURVE_TREE_STORE_SHAPES.md` §3.1's counter-rule).
///
/// The C++ warned in prose that this read takes no lock and must not be
/// paired with another (`blockchain.cpp:250`–`:253`); here the transaction
/// is the lock, and N calls on one snapshot are the batch form
/// `has_key_images` existed to be (SOK-3).
pub(super) fn has_key_image<T: ReadTables>(
    txn: &T,
    key_image: &KeyImage,
) -> Result<bool, ReadFault> {
    let table = txn.table(SPENT_KEYS)?;
    let found = table
        .get(LmdbHashKey::from_bytes(*key_image.as_bytes()))?
        .is_some();
    Ok(found)
}

/// Where `height` sits relative to the recorded tip. One match; every
/// classified read dispatches on this so `==` / `<` / `<=` cannot drift.
pub(super) enum HeightClass<'a> {
    /// `height` is above the dense tip, or the chain is empty.
    AboveTip,
    /// `height` is the tip: the decoded row is already in hand.
    AtTip(&'a BlockInfo),
    /// `height` is strictly below the tip: the row must exist (SI-2).
    Below,
}

pub(super) fn class_of(tip: Option<&(u64, BlockInfo)>, height: u64) -> HeightClass<'_> {
    match tip {
        Some((t, info)) if height == *t => HeightClass::AtTip(info),
        Some((t, _)) if height < *t => HeightClass::Below,
        _ => HeightClass::AboveTip,
    }
}

/// The `block_info` row at `height`, classified against `tip` (the caller's
/// [`tip_of`]): above it is [`AtHeight::AboveTip`]; **at** it the row
/// already decoded is reused; below it the row is read and its absence is
/// SI-7 (SI-2: `block_info` is dense to the tip). R3's body, and the first
/// half of [`block_body`]'s.
pub(super) fn info_at<T: ReadTables>(
    txn: &T,
    tip: Option<&(u64, BlockInfo)>,
    height: u64,
) -> Result<AtHeight<BlockInfo>, ReadFault> {
    Ok(match class_of(tip, height) {
        HeightClass::AtTip(info) => AtHeight::Recorded(*info),
        HeightClass::Below => AtHeight::Recorded(
            cell(txn, BLOCK_INFO, height, "block_info")?.ok_or_else(|| absent("block_info"))?,
        ),
        HeightClass::AboveTip => AtHeight::AboveTip,
    })
}

/// The recorded `blocks` blob at `height`, **unverified** — R5's body. The
/// same classification as [`block_body`] (above the tip is `AboveTip`, a
/// hole is SI-7), and none of its verification: the bytes are for the relay
/// and sync path, which forwards them and would only re-verify to discard
/// the result (Q2). The identity lives on `block_info`; the two are checked
/// against each other only where a parsed body is handed out.
pub(super) fn blob_at<T: ReadTables>(
    txn: &T,
    tip: Option<&(u64, BlockInfo)>,
    height: u64,
) -> Result<AtHeight<Vec<u8>>, ReadFault> {
    match class_of(tip, height) {
        HeightClass::AboveTip => return Ok(AtHeight::AboveTip),
        HeightClass::AtTip(_) | HeightClass::Below => {}
    }
    let blocks = txn.table(BLOCKS)?;
    let blob = blocks.get(height)?.ok_or_else(|| absent("blocks"))?;
    Ok(AtHeight::Recorded(blob.value().bytes().to_vec()))
}

/// The block recorded at `height`: its `block_info` row (identity and the
/// per-height record — the view projects `cumulative_difficulty` from it
/// for CEN-D4, E6 slice 2), its body parsed from `blocks` and **verified to
/// hash to that identity**.
///
/// Classified against `tip` — the caller's [`tip_of`], passed in whole so
/// one read of the tip serves a whole range and a read **of** the tip
/// reuses the row already decoded instead of decoding it twice: above it is
/// [`AtHeight::AboveTip`]; a missing `block_info` or `blocks` row at or
/// below it is SI-7 `Absent`; a blob that does not parse, or hashes to
/// something other than `block_info.hash`, is SI-7 on `blocks`.
pub(super) fn block_body<T: ReadTables>(
    txn: &T,
    tip: Option<&(u64, BlockInfo)>,
    height: u64,
) -> Result<AtHeight<(BlockInfo, Block)>, ReadFault> {
    let info = match info_at(txn, tip, height)? {
        AtHeight::Recorded(info) => info,
        AtHeight::AboveTip => return Ok(AtHeight::AboveTip),
    };
    let blocks = txn.table(BLOCKS)?;
    let blob = blocks.get(height)?.ok_or_else(|| absent("blocks"))?;
    let block = Block::from_bytes(blob.value().bytes())
        .map_err(|_| blocks_invalid("block blob does not parse"))?;
    if block.hash() != info.hash {
        return Err(blocks_invalid(
            "block blob does not hash to block_info.hash",
        ));
    }
    Ok(AtHeight::Recorded((info, block)))
}
