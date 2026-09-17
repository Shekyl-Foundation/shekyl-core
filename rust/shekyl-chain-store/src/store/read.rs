// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A read snapshot, and the committed-chain read surface on it (S-CHAIN-R,
//! `DRS_E1_SCHAIN_R.md` §3).
//!
//! Concurrent with a live [`WriteBatch`](super::WriteBatch): redb's MVCC
//! readers do not take the write-held flag. One snapshot is one read
//! transaction, so a sequence of reads sees one committed state — `tip()`
//! then `block_info(tip.height)` cannot straddle a connect. The C++ carries
//! exactly that hazard as a warning in prose (`blockchain.cpp:2735`–`:2738`,
//! "no getheight + gethash(height-1)"); here it is the handle's shape.
//!
//! # What a read may not do (§3.3)
//!
//! - **By-height reads return [`AtHeight`].** `AboveTip` only above the
//!   dense tip; a `block_info` or `blocks` row missing at or below it is
//!   SI-7 `CellCorrupt { fault: Absent }` — the same classification as
//!   `BatchView::block_at`, from the same body (`chain_reads`, SCR-13).
//! - **By-hash reads return `Option`.** A hash the chain does not contain
//!   has one meaning.
//! - **Every decode is SI-7**, uniformly strict (SCR-5).
//! - **A read never arms the halt.** The halt is the writer's state
//!   (`DAEMON_REDB_STORE.md` §3.6.2). A snapshot that meets SI-7 returns it
//!   as a plain `StoreError::InvariantViolated`; the writer arms the next
//!   time it touches the cell. This is the one behavioural difference from
//!   `BatchView`, and it is the batch's poison arm that differs, not the
//!   classification ([`ReadFault::into_plain`](super::chain_reads::ReadFault)).
//! - **The body is verified where it is decoded.** `block` / `blocks`
//!   refuse a blob that does not hash to `block_info[h].hash`; `block_blob`
//!   hands out bytes for the sync path and does not hash them, in a type no
//!   consensus path can consume without an explicit decode (Q2,
//!   [`RawBlockBytes`]).
//! - **A missing table is corruption, never a value.** Every table with a
//!   writer exists from the seal (amendment A2), so `TableDoesNotExist` on
//!   a chain table is a file this store did not write, not an empty chain.

use redb::{
    Key, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    TableDefinition, Value,
};
use shekyl_chain_rules::{AtHeight, Tip};
use shekyl_types::{BlockHash, BlockHeight};

use crate::codec::{BlockInfo, PropertyCell};
use crate::lmdb_order::{Hash32, LmdbHashKey};
use crate::schema::{BLOCK_HEIGHTS, PROPERTIES};

use super::chain_reads;
use super::error::{CellFault, EngineError, StoreError, StoreInvariant};
use super::halt::ConnectState;
use super::header;
use super::ChainStore;

/// The recorded tip **and** the writer's state, together (R1; §3.4).
///
/// `connect` sits outside the `Option` on purpose (SCR-18): `connect` notes
/// the connecting height before any belt runs, including height 0, so a
/// genesis connect that hits SI-4 or SI-8 halts the writer with nothing
/// recorded. An `Option<{ tip, connect }>` could not say so — `None` would
/// read as "empty, live", the silently-wrong tip §3.6.2 exists to prevent.
/// The envelope always carries the writer's state; only the block is
/// optional. And `recorded` stays an `Option` (ruled): there is no zero tip
/// that reads as data, so a bespoke absence type would buy nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipState {
    /// The last recorded block — the rules crate's one definition of "the
    /// tip". `None`: nothing recorded.
    pub recorded: Option<Tip>,
    /// [`ChainStore::connect_state`] read **after** the snapshot was taken.
    /// Sound because the halt is monotonic: a snapshot taken before a halt
    /// latched shows a tip the refused write did not move, and a `Halted`
    /// read afterwards is at a height ≥ that tip.
    pub connect: ConnectState,
}

/// One row of a range read (R4, R7): the height and what the store
/// recorded there, or that row's own fault. The range's `Err`s are
/// per-item so a hole is reported where it is, not as an early end.
pub type RangeItem<T> = Result<(BlockHeight, T), StoreError>;

/// A read snapshot of the store.
///
/// Table access goes through this type, not a raw `ReadTransaction`, so
/// later read paths cannot grow a second way to open tables. Holds the
/// store it was taken from so [`tip`](Self::tip) can report the writer's
/// state beside the recorded tip.
pub struct ReadSnapshot<'store> {
    txn: ReadTransaction,
    store: &'store ChainStore,
}

impl<'store> ReadSnapshot<'store> {
    pub(super) fn new(txn: ReadTransaction, store: &'store ChainStore) -> Self {
        Self { txn, store }
    }

    /// Open a table for reading.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the table does not exist or the engine refuses.
    pub fn open_table<K, V>(
        &self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyTable<K, V>, StoreError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.txn
            .open_table(definition)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Open a multimap table for reading.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the table does not exist or the engine refuses.
    pub fn open_multimap_table<K, V>(
        &self,
        definition: MultimapTableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyMultimapTable<K, V>, StoreError>
    where
        K: Key + 'static,
        V: Key + 'static,
    {
        self.txn
            .open_multimap_table(definition)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Read a typed `properties` cell as of this snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::CellCorrupt`] if the cell is present but is not an
    /// encoding of `C::Value`; [`EngineError::Table`] / [`EngineError::Storage`]
    /// if the engine refuses. Absent is `Ok(None)`.
    pub fn get_property<C: PropertyCell>(&self) -> Result<Option<C::Value>, StoreError> {
        let table = self
            .txn
            .open_table(PROPERTIES)
            .map_err(EngineError::Table)?;
        header::get::<C>(&table)
    }

    // ------------------------------------------------------------------
    // R1–R4: the tip and `block_info`
    // ------------------------------------------------------------------

    /// The tip row, decoded, through the shared body — the one read every
    /// by-height classification in this snapshot is made against.
    fn tip_row(&self) -> Result<Option<(u64, BlockInfo)>, StoreError> {
        chain_reads::tip_of(&self.txn).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **R1.** The recorded tip and the writer's state (§3.4).
    ///
    /// Replaces `height()`, `top_block_hash`, `get_top_block_timestamp` and
    /// `get_top_block`, and the three sentinels plus one underflow they
    /// returned on an empty chain (SCR-4): `recorded` is `None` there.
    ///
    /// # Errors
    ///
    /// SI-7 if the tip row does not decode; engine errors pass through.
    pub fn tip(&self) -> Result<TipState, StoreError> {
        let recorded = self.tip_row()?.map(|(height, info)| Tip {
            height: BlockHeight::from_raw(height),
            hash: BlockHash::from_bytes(info.hash.to_bytes()),
        });
        // After `begin_read`, deliberately (type docs).
        let connect = self.store.connect_state();
        Ok(TipState { recorded, connect })
    }

    /// **R2.** The height a block hash sits at, or `None` if the chain does
    /// not contain it. By-hash, so `Option`: absence has one meaning here
    /// (§3.3). Replaces `block_exists` and `get_block_height`.
    ///
    /// # Errors
    ///
    /// SI-7 if the row does not decode; engine errors pass through.
    pub fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, StoreError> {
        let table = self.open_table(BLOCK_HEIGHTS)?;
        let Some(guard) = table
            .get(LmdbHashKey::from(Hash32::from_bytes(*hash.as_bytes())))
            .map_err(EngineError::Storage)?
        else {
            return Ok(None);
        };
        guard.value().decode().map(Some).map_err(|cause| {
            StoreInvariant::CellCorrupt {
                key: "block_heights",
                fault: CellFault::Undecodable(cause),
            }
            .into()
        })
    }

    /// **R3.** The per-height record at `height` — timestamp, weight,
    /// cumulative difficulty, coins generated, long-term weight, identity,
    /// this block's RCT output count, and the two FL-R3 fold fields (§3.6).
    /// Replaces the six `get_block_*` field getters; `get_block_difficulty`
    /// is **not** here — `shekyl-chain-rules` owns `difficulty_at` (Q1).
    ///
    /// # Errors
    ///
    /// SI-7 for a hole at or below the tip or a row that does not decode;
    /// engine errors pass through. Above the tip is [`AtHeight::AboveTip`].
    pub fn block_info(&self, height: BlockHeight) -> Result<AtHeight<BlockInfo>, StoreError> {
        let tip = self.tip_row()?;
        chain_reads::info_at(&self.txn, tip.as_ref(), height.to_raw())
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// **R4.** The records for a **half-open** range of heights, ascending
    /// (§3.5). [`AtHeight::AboveTip`] when `range.start > tip` — the whole
    /// range is absent, and the caller matches it rather than receiving an
    /// empty iterator; otherwise the rows `start..min(end, tip + 1)`, the
    /// end clamped, and the caller counts what it got. Replaces
    /// `get_block_weights` / `get_long_term_block_weights`
    /// (`get_block_info_64bit_fields`); the caller projects the field.
    ///
    /// # Errors
    ///
    /// The outer `Err` is the tip read; each item is its own row's read
    /// (SI-7 for a hole — SI-2 says there are none — or an undecodable row).
    pub fn block_infos(
        &self,
        range: core::ops::Range<BlockHeight>,
    ) -> Result<AtHeight<impl Iterator<Item = RangeItem<BlockInfo>> + '_>, StoreError> {
        let tip = self.tip_row()?;
        let Some(clamped) = clamp_to_tip(&range, tip.as_ref().map(|(h, _)| *h)) else {
            return Ok(AtHeight::AboveTip);
        };
        Ok(AtHeight::Recorded(clamped.map(move |h| {
            match chain_reads::info_at(&self.txn, tip.as_ref(), h)
                .map_err(chain_reads::ReadFault::into_plain)?
            {
                AtHeight::Recorded(info) => Ok((BlockHeight::from_raw(h), info)),
                // Unreachable by construction — `clamp_to_tip` stopped at the
                // tip — and said so rather than silently ending the iterator.
                AtHeight::AboveTip => Err(StoreInvariant::CellCorrupt {
                    key: "block_info",
                    fault: CellFault::Absent,
                }
                .into()),
            }
        })))
    }
}

/// The heights of `range` that are at or below `tip`, or `None` when
/// `range.start` is above it (the whole range is absent — §3.5's typed
/// `AboveTip` arm, on both range reads). An empty chain has no tip, so
/// every start is above it. `start >= end` at or below the tip is an empty
/// iterator, as for any half-open range.
fn clamp_to_tip(
    range: &core::ops::Range<BlockHeight>,
    tip: Option<u64>,
) -> Option<core::ops::Range<u64>> {
    let tip = tip?;
    let start = range.start.to_raw();
    if start > tip {
        return None;
    }
    let end = range.end.to_raw().min(tip.saturating_add(1));
    Some(start..end)
}
