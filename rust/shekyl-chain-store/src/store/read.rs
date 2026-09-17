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

use redb::{Key, ReadOnlyTable, ReadTransaction, TableDefinition, Value};
#[cfg(test)]
use redb::{MultimapTableDefinition, ReadOnlyMultimapTable};
use shekyl_chain_rules::{AtHeight, Tip};
use shekyl_types::{BlockHash, BlockHeight, LongTermWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::Block;

use crate::codec::{BlockInfo, PropertyCell, TotalBurnedCell};
use crate::lmdb_order::{Hash32, LmdbHashKey};
use crate::schema::{BLOCK_BURN, BLOCK_HEIGHTS, PROPERTIES};

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

/// A recorded block's body **with** its recorded identity (R6, R7).
///
/// The identity is `block_info[h].hash` (CEN-B6) and the body was verified
/// to hash to it where it was decoded (`chain_reads::block_body`), so the
/// pair cannot disagree. A bare `Block` would let a caller re-hash and reach
/// a second notion of the block's identity — the two-identities defect
/// SCR-7 closed in the C++ `for_blocks_range`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedBlockBody {
    /// The block's recorded identity.
    pub hash: BlockHash,
    /// The body, parsed from the recorded blob and verified against `hash`.
    pub block: Block,
}

/// The recorded bytes of a block, **not** verified against the recorded
/// identity (R5; Q2, ruled).
///
/// For the relay and sync path, which forwards bytes and would only
/// re-verify to discard the result. The hazard Q2 names is a consensus
/// caller reaching for the cheap reader because it differs from
/// [`block`](ReadSnapshot::block) only by name — so it differs by **type**:
/// no `Deref<Target = [u8]>`, no `AsRef<[u8]>`, no `From<RawBlockBytes>`
/// for `Block` or [`RecordedBlockBody`], no parse method. The one way out
/// is [`into_wire_bytes`](Self::into_wire_bytes), named for its consumer;
/// the one way to a parsed block is `ReadSnapshot::block`, which re-reads
/// and verifies. `rg RawBlockBytes` is the audit.
///
/// ```compile_fail
/// # use shekyl_chain_store::store::RawBlockBytes;
/// fn consensus_path(bytes: RawBlockBytes) -> usize {
///     bytes.len() // no Deref, no AsRef: the bytes are not a slice here
/// }
/// ```
///
/// ```compile_fail
/// # use shekyl_chain_store::store::RawBlockBytes;
/// # use shekyl_wire::Block;
/// fn parse(bytes: RawBlockBytes) -> Block {
///     bytes.into() // no From<RawBlockBytes> for Block
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlockBytes(Vec<u8>);

impl RawBlockBytes {
    /// The bytes, for the writer that puts them on the wire. Consumes the
    /// value: there is no borrowed view.
    #[must_use]
    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// One row of a range read (R4, R7): the height and what the store
/// recorded there, or that row's own fault. The range's `Err`s are
/// per-item so a hole is reported where it is, not as an early end.
pub type RangeItem<T> = Result<(BlockHeight, T), StoreError>;

/// A read snapshot of the store.
///
/// Table access goes through this type, not a raw `ReadTransaction`, and
/// from S-CHAIN-R commit 6 the raw handles are crate-private too (Q3): what
/// a caller outside the crate reads is the typed surface above. Holds the
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

    /// Open a table for reading — the raw handle, **crate-private** (Q3,
    /// SCR-9). Every table this surface serves has a typed read above;
    /// a raw handle on the read side is the mirror of the raw `properties`
    /// handle the write side already refuses (`PropertiesAreTyped`), and
    /// a later surface lands its own typed reads rather than reaching for
    /// this. In-crate tests keep it.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the table does not exist or the engine refuses.
    pub(crate) fn open_table<K, V>(
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

    /// Open a multimap table for reading — crate-private as
    /// [`open_table`](Self::open_table), and **test-only**: no production
    /// read in the crate opens a multimap raw (`output_amounts` has no
    /// S-CHAIN-R read; S-ARCH lands its own typed ones), so outside tests
    /// this would be dead code.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the table does not exist or the engine refuses.
    #[cfg(test)]
    pub(crate) fn open_multimap_table<K, V>(
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

impl ReadSnapshot<'_> {
    // ------------------------------------------------------------------
    // R5–R7: the block body
    // ------------------------------------------------------------------

    /// **R5.** The recorded blob at `height`, unverified, as
    /// [`RawBlockBytes`] (Q2). Replaces `get_block_blob_from_height`; the
    /// by-hash `get_block_blob` is R2 then R5.
    ///
    /// # Errors
    ///
    /// SI-7 for a hole at or below the tip; engine errors pass through.
    /// Above the tip is [`AtHeight::AboveTip`].
    pub fn block_blob(&self, height: BlockHeight) -> Result<AtHeight<RawBlockBytes>, StoreError> {
        let tip = self.tip_row()?;
        Ok(
            match chain_reads::blob_at(&self.txn, tip.as_ref(), height.to_raw())
                .map_err(chain_reads::ReadFault::into_plain)?
            {
                AtHeight::Recorded(bytes) => AtHeight::Recorded(RawBlockBytes(bytes)),
                AtHeight::AboveTip => AtHeight::AboveTip,
            },
        )
    }

    /// **R6.** The block at `height`: its recorded identity and its body,
    /// parsed and **verified to hash to that identity** (SCR-7). Replaces
    /// `get_block_from_height`; the by-hash `get_block` is R2 then R6.
    ///
    /// # Errors
    ///
    /// SI-7 for a hole, a blob that does not parse, or one that hashes to
    /// something other than `block_info[h].hash`; engine errors pass
    /// through. Above the tip is [`AtHeight::AboveTip`].
    pub fn block(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlockBody>, StoreError> {
        let tip = self.tip_row()?;
        body_at(&self.txn, tip.as_ref(), height.to_raw())
    }

    /// **R7.** The blocks for a **half-open** range of heights, ascending,
    /// each verified as in [`block`](Self::block); the same range rules as
    /// [`block_infos`](Self::block_infos) (§3.5). Replaces
    /// `for_blocks_range(h1, h2, f)`, whose `h2` is **inclusive** — its
    /// caller's `start..=start + count − 1` is `start..start + count` here
    /// (SCR-20) — and whose early-stop closure is the caller's `take_while`
    /// or `?` over this iterator.
    ///
    /// # Errors
    ///
    /// The outer `Err` is the tip read; each item is its own row's.
    pub fn blocks(
        &self,
        range: core::ops::Range<BlockHeight>,
    ) -> Result<AtHeight<impl Iterator<Item = RangeItem<RecordedBlockBody>> + '_>, StoreError> {
        let tip = self.tip_row()?;
        let Some(clamped) = clamp_to_tip(&range, tip.as_ref().map(|(h, _)| *h)) else {
            return Ok(AtHeight::AboveTip);
        };
        Ok(AtHeight::Recorded(clamped.map(move |h| {
            match body_at(&self.txn, tip.as_ref(), h)? {
                AtHeight::Recorded(body) => Ok((BlockHeight::from_raw(h), body)),
                AtHeight::AboveTip => Err(StoreInvariant::CellCorrupt {
                    key: "blocks",
                    fault: CellFault::Absent,
                }
                .into()),
            }
        })))
    }
}

impl ReadSnapshot<'_> {
    // ------------------------------------------------------------------
    // R8–R9 and the fold reads
    // ------------------------------------------------------------------

    /// **R8.** Atomic units burned by the block at `height`, as the
    /// `shekyl-units` newtype (§11.1(f): the scalar takes the domain type that
    /// exists). An absent
    /// **row** at or below the tip is `Recorded(0)` — the writer's own
    /// convention (`connect` phase 8 writes no row for a zero burn, and
    /// none at genesis, `blockchain.cpp:6148`); an absent **table** is not
    /// a value (the table exists from the seal, amendment A2). Replaces
    /// `get_block_burn`.
    ///
    /// # Errors
    ///
    /// SI-7 if the row does not decode; engine errors pass through. Above
    /// the tip is [`AtHeight::AboveTip`].
    pub fn block_burn(&self, height: BlockHeight) -> Result<AtHeight<AtomicUnits>, StoreError> {
        let tip = self.tip_row()?;
        match tip {
            Some((tip, _)) if height.to_raw() <= tip => {}
            _ => return Ok(AtHeight::AboveTip),
        }
        let burned = chain_reads::cell(&self.txn, BLOCK_BURN, height.to_raw(), "block_burn")
            .map_err(chain_reads::ReadFault::into_plain)?
            .unwrap_or(AtomicUnits::ZERO);
        Ok(AtHeight::Recorded(burned))
    }

    /// **R9.** Atomic units burned by the whole chain — the `total_burned`
    /// fold `connect` maintains under SI-8. An absent cell is `0`: nothing
    /// has burned, and `connect` reads it the same way before its first
    /// `checked_add`. Replaces `get_total_burned` (whose unchecked 8-byte
    /// `memcpy`, `:5097`, is SCR-5's example; this decode is strict).
    ///
    /// # Errors
    ///
    /// SI-7 if the cell does not decode; engine errors pass through.
    pub fn total_burned(&self) -> Result<AtomicUnits, StoreError> {
        Ok(self
            .get_property::<TotalBurnedCell>()?
            .unwrap_or(AtomicUnits::ZERO))
    }

    /// Non-coinbase transactions recorded through `height` —
    /// `Σ_{i ≤ h} |transactions(i)|`, the O(1) read FL-R3-STORE owes
    /// (`FEE_LADDER_DERIVATION.md` §10.12.2) in place of
    /// `get_tx_volume_window`'s 720-block blob walk. A projection of R3.
    ///
    /// # Errors
    ///
    /// As [`block_info`](Self::block_info).
    pub fn cumulative_tx_count(&self, height: BlockHeight) -> Result<AtHeight<u64>, StoreError> {
        Ok(match self.block_info(height)? {
            AtHeight::Recorded(info) => AtHeight::Recorded(info.cumulative_tx_count),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    /// The long-term weight median **in force for** the block at `height`
    /// — the value it was validated and fee-floored against (SCR-19), the
    /// O(1) read that retires `rebuild_relay_floor_ring`'s stepped median
    /// (FL-R3-STORE). A projection of R3.
    ///
    /// # Errors
    ///
    /// As [`block_info`](Self::block_info).
    pub fn long_term_effective_median(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<LongTermWeight>, StoreError> {
        Ok(match self.block_info(height)? {
            AtHeight::Recorded(info) => AtHeight::Recorded(info.long_term_effective_median),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }
}

/// R6's and R7's shared step: the verified `(identity, body)` pair from the
/// shared read body, wrapped as [`RecordedBlockBody`], the fault returned
/// plain (the snapshot's policy).
fn body_at(
    txn: &ReadTransaction,
    tip: Option<&(u64, BlockInfo)>,
    height: u64,
) -> Result<AtHeight<RecordedBlockBody>, StoreError> {
    Ok(
        match chain_reads::block_body(txn, tip, height)
            .map_err(chain_reads::ReadFault::into_plain)?
        {
            AtHeight::Recorded((hash, block)) => AtHeight::Recorded(RecordedBlockBody {
                hash: BlockHash::from_bytes(hash.to_bytes()),
                block,
            }),
            AtHeight::AboveTip => AtHeight::AboveTip,
        },
    )
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
