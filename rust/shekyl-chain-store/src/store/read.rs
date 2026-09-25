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

use core::ops::{Range, RangeInclusive};
use redb::{Key, ReadOnlyTable, ReadTransaction, TableDefinition, Value};
use shekyl_chain_rules::{AtHeight, Tip};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, GlobalOutputIndex, KeyImage, LongTermWeight,
    PCanonicalId, SettlementEpoch, ShardId, TreeLeaf, TreePosition, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::Block;

use crate::codec::{
    AltBlock, ArchivalLastSlashEpochCell, BlockInfo, BondRecord, CurveTreeState, OutTx,
    PropertyCell, RMarket, SigmaWorkMilli, TotalBurnedCell, TxOutputIndices,
};
use crate::ids::TxStorageId;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{BLOCK_BURN, BLOCK_HEIGHTS, PROPERTIES, SPENT_KEYS, TX_INDICES};

use super::alt_reads::{self, AltEntry};
use super::archival_reads::{self, PassCount, ServedShard};
use super::at_index::AtIndex;
use super::output_reads::{self, RecordedOutput};
use super::tx_reads::{self, Prunable, TxLocation, TxRecord};

use super::chain_reads;
use super::curve_reads;
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
    /// [`ChainStore::connect_state`] read **after** the snapshot was taken:
    /// the writer's **current** state, not a property of the snapshot.
    /// What a caller may rely on: `Halted` means the writer is halted now
    /// and `recorded` is the last committed tip this snapshot sees; the
    /// halt is monotonic (it latches, and a refused write moved nothing),
    /// so a snapshot never shows a tip a halting write produced. What a
    /// caller may **not** rely on: an ordering between `at_height` and
    /// `recorded.height`. Another batch can pop below this snapshot's tip
    /// and then halt at the lower current height, so `at_height` may be
    /// below `recorded`.
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
            hash: info.hash,
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
            .get(LmdbHashKey::from(*hash))
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
        Ok(range_at(&range, tip, "block_info", |tip, h| {
            chain_reads::info_at(&self.txn, tip, h).map_err(chain_reads::ReadFault::into_plain)
        }))
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
        Ok(range_at(&range, tip, "blocks", |tip, h| {
            body_at(&self.txn, tip, h)
        }))
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
        match chain_reads::class_of(tip.as_ref(), height.to_raw()) {
            chain_reads::HeightClass::AboveTip => return Ok(AtHeight::AboveTip),
            chain_reads::HeightClass::AtTip(_) | chain_reads::HeightClass::Below => {}
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

    // ------------------------------------------------------------------
    // S-OUT-KI (`DRS_E1_SOUT_KI.md` §3.2): key images.
    // ------------------------------------------------------------------

    /// **K1.** Whether `key_image` is spent on the committed chain — the
    /// chain half of CEN-I7, served to the pool's admission check, the
    /// submit verdict and `is_key_image_spent` from one snapshot. Replaces
    /// `has_key_image` **and** `has_key_images`: the batch form existed to
    /// hold one LMDB `rtxn` across N keys (`db_lmdb.cpp:3851`–`:3869`), and
    /// this snapshot *is* that transaction — N calls on it are the batch
    /// (SOK-3). Exact, never approximate (§3.3). One body with the
    /// validator's `BatchView::has_key_image`
    /// ([`chain_reads::has_key_image`]).
    ///
    /// # Errors
    ///
    /// Engine errors pass through; a membership read has no decode and no
    /// invariant arm.
    pub fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, StoreError> {
        chain_reads::has_key_image(&self.txn, key_image).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **K2.** Every key image on the committed chain, in the table's
    /// (`LmdbHashKey`) order — the `spent_keys` scan E2's
    /// `logical_state_digest_v0` needs (SCR-11), and the only consumer
    /// named. Replaces `for_all_key_images`. The digest is order-insensitive
    /// (`chain_digest_ffi.rs:29`–`:30`, "in any order"); no consumer may
    /// depend on the order this yields.
    ///
    /// # Errors
    ///
    /// Opening the table: engine errors pass through. Each yielded item is
    /// `Err` on a storage fault at that position; a caller folding the set
    /// stops at the first.
    pub fn key_images(
        &self,
    ) -> Result<impl Iterator<Item = Result<KeyImage, StoreError>> + '_, StoreError> {
        let table = self.open_table(SPENT_KEYS)?;
        let range = table
            .range::<LmdbHashKey>(..)
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(range.map(|entry| {
            entry
                .map(|(key, _present)| KeyImage::from_bytes(key.value().to_bytes()))
                .map_err(|e| StoreError::from(EngineError::Storage(e)))
        }))
    }

    // ------------------------------------------------------------------
    // DRS-E2 (`DRS_E2_REPLAY_DRIVER.md` RD-F5): the redb half of the digest.
    // ------------------------------------------------------------------

    /// The layout-independent logical state digest v0 of **this** file —
    /// the redb half of DRS-E2's comparison. The C++ half is
    /// `BlockchainLMDB::logical_state_digest_v0` walking LMDB into the same
    /// hasher through `shekyl_logical_state_digest_v0`; until this method
    /// existed the hasher had one caller and E2 had one side (RD-F5).
    ///
    /// The three families, assembled from the reads the rules already
    /// depend on, so the digest cannot see a table the validator does not:
    ///
    /// - **block hashes**, height-ordered — `block_info[h].hash` for
    ///   `h ∈ 0..=tip` (the same rows R3 reads);
    /// - **spent keys** — the `spent_keys` scan K2 exists for
    ///   ([`key_images`](Self::key_images); the fold is order-insensitive);
    /// - **the live curve-tree root** — `curve_tree_roots[tip + 1]`, the
    ///   state *after* the tip's drain, which is what the C++'s single
    ///   `"root"` cell holds (`db_lmdb.cpp:9495`) and what `connect` wrote
    ///   from `root_after` (SCW-19); [`CurveTreeRoot::EMPTY`] for an empty
    ///   chain, where nothing has been written and the C++ cell is the
    ///   identity.
    ///
    /// What the digest *proves* is the grader's business, not this read's:
    /// under RD-Q9 the root component is **borrowed** while `root_after` is
    /// passed through (it is LMDB's root copied in), so identity there is
    /// never evidence; the block hashes and spent keys are real replay
    /// products. This method reports the file; the grader carries the
    /// per-component origin.
    ///
    /// # Errors
    ///
    /// A hole or undecodable row inside the dense ranges is SI-7 (a
    /// [`StoreInvariant::CellCorrupt`]); engine errors pass through. On a
    /// read-only snapshot nothing is poisoned — the caller decides what a
    /// corrupt file means for its run.
    pub fn logical_state_digest_v0(&self) -> Result<[u8; 32], StoreError> {
        let tip = self.tip_row()?;
        let hashes = self.block_hashes_through_tip(tip.as_ref())?;
        let mut spent: Vec<[u8; 32]> = Vec::new();
        for key_image in self.key_images()? {
            spent.push(*key_image?.as_bytes());
        }
        let root = self.live_root(tip.as_ref())?;
        Ok(crate::digest_v0::digest_v0(
            &hashes,
            &spent,
            root.as_bytes(),
        ))
    }

    /// Height-ordered `block_info.hash` for `h ∈ 0..=tip`. An empty chain
    /// is no hashes. A tip whose range classifies as [`AtHeight::AboveTip`]
    /// is SI-7, not a successful digest of an empty chain.
    fn block_hashes_through_tip(
        &self,
        tip: Option<&(u64, BlockInfo)>,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let Some((tip_height, _)) = tip else {
            return Ok(Vec::new());
        };
        let end = BlockHeight::from_raw(*tip_height)
            .checked_add(BlockCount::ONE)
            .expect("a recorded tip is not u64::MAX");
        let rows = match self.block_infos(BlockHeight::ZERO..end)? {
            AtHeight::Recorded(rows) => rows,
            AtHeight::AboveTip => {
                return Err(StoreInvariant::CellCorrupt {
                    key: "block_info",
                    fault: CellFault::Absent,
                }
                .into());
            }
        };
        let mut hashes = Vec::new();
        for row in rows {
            let (_, info) = row?;
            hashes.push(*info.hash.as_bytes());
        }
        let expected = tip_height
            .checked_add(1)
            .expect("a recorded tip is not u64::MAX");
        let got = u64::try_from(hashes.len()).expect("hash count fits u64");
        if got != expected {
            return Err(StoreInvariant::CellCorrupt {
                key: "block_info",
                fault: CellFault::Absent,
            }
            .into());
        }
        Ok(hashes)
    }

    /// `curve_tree_roots[tip + 1]`, or [`CurveTreeRoot::EMPTY`] on an empty
    /// chain. A tip with no live-root row is SI-7. The body is
    /// [`curve_reads::live_root`] — the digest, [`Self::root_at`], and the
    /// summary's SI-12 belt share it, so a missing row means one thing.
    fn live_root(&self, tip: Option<&(u64, BlockInfo)>) -> Result<CurveTreeRoot, StoreError> {
        curve_reads::live_root(&self.txn, tip.map(|(height, _)| *height))
            .map_err(chain_reads::ReadFault::into_plain)
    }

    // ------------------------------------------------------------------
    // S-OUT-KI (`DRS_E1_SOUT_KI.md` §3.2): outputs, by global index.
    // ------------------------------------------------------------------

    /// **O1.** The stored record of the output at `index`. Replaces
    /// `get_output_key(amount, index)` in both its single and batch forms
    /// (the batch form dissolves into N calls on one snapshot, SOK-3), and
    /// the C++'s `amount` parameter: the read is the confidential bucket's
    /// slot ([`OutputSlot::confidential`](crate::OutputSlot::confidential)),
    /// because Shekyl has one bucket — every miner and emission vout is
    /// stored under `0` and CEN-H14 makes every other vout's amount `0` —
    /// and the C++ itself refused any other amount (`db_lmdb.cpp:3746`). The
    /// amount dimension in the key is carried, not chosen, while R8b-2 is
    /// open (§3.4); if R8b-2 rules it consensus-visible, this read grows a
    /// parameter and the table needs no change.
    ///
    /// `index` is the chain-wide [`GlobalOutputIndex`] — under one bucket
    /// equal to the store's `amount_index` and `output_id` (SOK-2's belt,
    /// enforced at every connect and **re-validated by this read** against
    /// the record's own `output_id`, `output_reads` module docs). It is
    /// **not** a curve-tree position: leaf order is `(maturity, gindex)`, not
    /// gindex (`CT2_DRAIN_ORDER.md` §"Index ≠ tree position"), and a caller
    /// holding a position resolves it through `leaf_to_output` first
    /// (SOK-10). The parameter type is what makes the confusion
    /// unrepresentable here.
    ///
    /// # Errors
    ///
    /// Bound first: at or beyond the dense count this is
    /// [`AtIndex::BeyondCount`] and no row is read. Below it, a missing row
    /// or a record whose `output_id` is not `index` is **SI-9**
    /// (`InvariantViolated(IdNotFresh)`); an undecodable row is SI-7; engine
    /// errors pass through.
    pub fn output(&self, index: GlobalOutputIndex) -> Result<AtIndex<RecordedOutput>, StoreError> {
        output_reads::output_at(&self.txn, index).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **O2.** Which transaction created the output at `index`, and at which
    /// `vout` position. Replaces `get_output_tx_and_index` (single and batch)
    /// and is the `_from_global` read — `output_txs[output_id]`, one lookup
    /// — **not** the amount-specific composition through `OutKey.output_id`,
    /// which equals it only by SOK-2's belt; a read that is right only while
    /// a belt holds is the wrong read. Returns [`OutTx`] as it exists
    /// (SOK-Q4: no renamed twin). Kept although its `blockchain.cpp` callers
    /// are dead: E2's comparator projects `output_txs` through it.
    ///
    /// # Errors
    ///
    /// As [`output`](Self::output).
    pub fn output_origin(&self, index: GlobalOutputIndex) -> Result<AtIndex<OutTx>, StoreError> {
        output_reads::origin_at(&self.txn, index).map_err(chain_reads::ReadFault::into_plain)
    }

    // ------------------------------------------------------------------
    // S-TX (`DRS_E1_STX.md` §3.2): transactions, by hash and by dense id.
    // ------------------------------------------------------------------

    /// **T1.** Where the transaction with `hash` is, or `None`. Replaces
    /// `tx_exists` in both overloads: the index row *is* existence, and a
    /// caller that then wants the id (`get_tx_outputs_gindexs`) has it.
    ///
    /// `Option`, not an absence enum: a hash miss is ordinary and instructs
    /// nothing beyond *not here* — the counter-rule's worked case
    /// (`tx_reads` module docs, STX-Q1 B). The answer is [`TxLocation`], the
    /// stored row **without `unlock_time`** (STX-9).
    ///
    /// # Errors
    ///
    /// An undecodable row is SI-7; a present index whose `tx_id` is at or
    /// past the dense count is **SI-9**; engine errors pass through.
    pub fn tx_location(&self, hash: &TxHash) -> Result<Option<TxLocation>, StoreError> {
        tx_reads::location_at(&self.txn, hash).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **T2.** How many transactions the chain has recorded — `txs_pruned`'
    /// length, the dense count `tx_id` is fresh in (SI-9). Replaces
    /// `get_tx_count`. The bond-admission shard predicate stands on this
    /// being the dense authority (`ARCHIVAL_BOND_ADD_ADMISSION.md` §4.1).
    ///
    /// # Errors
    ///
    /// Engine errors pass through.
    pub fn tx_count(&self) -> Result<u64, StoreError> {
        tx_reads::tx_count(&self.txn).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **T3.** The permanent half of the transaction with `hash` — where it
    /// is, its pruned and `pqc_auths` segments, its two permanent hash rows
    /// — or `None`. Replaces `get_pruned_tx_blob`, `get_prunable_tx_hash`,
    /// `get_tx_block_height`, and with [`tx_prunable`](Self::tx_prunable)
    /// the whole of `get_tx_blob` ([`TxRecord::wire_bytes`], STX-8).
    ///
    /// # Errors
    ///
    /// A recorded transaction missing its pruned segment or its prunable
    /// hash row, or a `pqc_auths` segment and hash row that disagree on
    /// presence, is **SI-7** with the table named (§7.7 legs (i)–(ii));
    /// a present index whose `tx_id` is at or past the dense count is
    /// **SI-9**; an undecodable row is SI-7; engine errors pass through.
    pub fn tx_record(&self, hash: &TxHash) -> Result<Option<TxRecord>, StoreError> {
        tx_reads::record_at(&self.txn, hash).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **T4.** Whether this node holds the prunable region of the
    /// transaction at `id` — the archival good (`PDM-Q6` item 1;
    /// `DRS_E1_STX.md` §2.3). Replaces `get_prunable_tx_blob`.
    ///
    /// Bound first: at or beyond [`tx_count`](Self::tx_count) this is
    /// [`AtIndex::BeyondCount`] and no row is read — `TxStorageId::from_raw`
    /// is public, so a forged or stale id is invalid input, not corruption.
    /// Below it, [`Prunable::Retained`] or [`Prunable::Discarded`] — the
    /// latter §7.7 leg (iii)'s defined state, never an absence.
    ///
    /// # Errors
    ///
    /// An id below the count with no primary `txs_pruned` row is **SI-9**;
    /// below it with no `txs_prunable_hash` row is **SI-7** (leg (i));
    /// engine errors pass through.
    pub fn tx_prunable(&self, id: TxStorageId) -> Result<AtIndex<Prunable>, StoreError> {
        tx_reads::prunable_at(&self.txn, id).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **T5.** The `output_amounts` indices of the outputs of the
    /// transaction at `id`, in `vout` order. Replaces
    /// `get_tx_amount_output_indices`. Bound first, as
    /// [`tx_prunable`](Self::tx_prunable).
    ///
    /// # Errors
    ///
    /// A hole below the count is **SI-9**; an undecodable row is SI-7;
    /// engine errors pass through.
    pub fn tx_output_indices(
        &self,
        id: TxStorageId,
    ) -> Result<AtIndex<TxOutputIndices>, StoreError> {
        tx_reads::output_indices_at(&self.txn, id).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **T6.** Every recorded transaction whose key lies in `hashes`, in
    /// `tx_indices`' own key order — the table's projection, one sequential
    /// scan, nothing joined to it. The range is [`RangeInclusive`] over
    /// [`LmdbHashKey`]: that is the table's `Ord`, both endpoints are
    /// present so `..` does not compile, and the bound is inclusive so
    /// [`LmdbHashKey::MAX`] is nameable (a half-open range has no successor
    /// of that key). Convert a [`TxHash`] at the edge with
    /// [`LmdbHashKey::from`]; do not range over `TxHash` — its `Ord` is
    /// byte-lexicographic, the order this key type exists to reject.
    /// Successor to `for_all_transactions`, which cursored this same table;
    /// lands on completeness grounds (STX-10), with no consumer named —
    /// E2's redb-side digest projects no tx table (#788 §3.1). A join to
    /// the hash rows, an id-ordered alternative and a reverse index are one
    /// coupled reopen criterion (`DRS_E1_STX.md` §3.2): a consumer names
    /// the row and the order it needs *together*.
    ///
    /// ```compile_fail
    /// # use shekyl_chain_store::store::ReadSnapshot;
    /// # use shekyl_types::TxHash;
    /// fn walk(snap: &ReadSnapshot<'_>, hashes: core::ops::RangeInclusive<TxHash>) {
    ///     let _ = snap.tx_locations(hashes); // the walk is LmdbHashKey order, not TxHash order
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Opening the table or the range; then per item, so an undecodable
    /// row (SI-7) or an index whose `tx_id` is at or past the dense count
    /// (SI-9) is reported where it is, not as an early end.
    pub fn tx_locations(
        &self,
        hashes: RangeInclusive<LmdbHashKey>,
    ) -> Result<impl Iterator<Item = TxWalkItem> + '_, StoreError> {
        let count = tx_reads::tx_count(&self.txn).map_err(chain_reads::ReadFault::into_plain)?;
        let table = self.open_table(TX_INDICES)?;
        let range = table
            .range(hashes)
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(tx_reads::walk_indices(range, count)
            .map(|item| item.map_err(chain_reads::ReadFault::into_plain)))
    }

    // ------------------------------------------------------------------
    // S-CURVE (`DRS_E1_SCURVE.md` §3.2): the curve tree.
    // ------------------------------------------------------------------

    /// **C1.** The tree's summary as **one row**: its root, its depth
    /// (layers above the leaves) and its leaf count — `curve_tree_meta`'s
    /// whole content ([`CurveTreeState`]). Replaces `get_curve_tree_root`,
    /// `get_curve_tree_depth` and `get_curve_tree_leaf_count`, which the
    /// C++ always consumed together and wrote together; three cells that
    /// had to agree become one value that cannot disagree (`SCU-Q1`).
    ///
    /// The empty tree is [`CurveTreeState::EMPTY`], **a row the seal
    /// wrote** — so an absent row is SI-7 (`CellCorrupt { Absent }`), never
    /// a default, and no caller compares a root against the identity to
    /// learn whether the tree is empty (SCU-1). EMPTY stays the answer
    /// after `connect` until the grow path (DRS-E3) replaces it: connect
    /// records the live root in `curve_tree_roots` whether or not the tree
    /// has grown (SI-4). A summary that is not EMPTY must carry that live
    /// root (SI-12, [`StoreInvariant::SummaryRootDiverged`]). A count that
    /// is not the leaf table's length is SI-11
    /// ([`LeafDensity::Length`](crate::store::LeafDensity::Length)).
    pub fn curve_tree(&self) -> Result<CurveTreeState, StoreError> {
        curve_reads::summary(&self.txn).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **C2.** `curve_tree_roots[height]` — the tree state **going into**
    /// block `height`, written by the connect of `height − 1`; the table's
    /// own key, stated once. Height 0 is [`CurveTreeRoot::EMPTY`]; rows
    /// `1..=tip + 1` are present (SI-7 otherwise) and `tip + 1` is the live
    /// root; above that is [`AtHeight::AboveTip`]. The same body the
    /// validator's `ChainView::root_at` reads inside a batch (CEN-B5),
    /// made the store's public read. Replaces `get_curve_tree_root_at`,
    /// whose all-zero root on `MDB_NOTFOUND` (SCU-4) is the arm the type
    /// removes.
    pub fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError> {
        curve_reads::root_at(&self.txn, height).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **C3.** The leaves at `range`, in position order — a bounded walk
    /// over `curve_tree_leaves`. Bound first: a range whose end is past the
    /// summary's count is [`AtIndex::BeyondCount`] and no row is read.
    /// Inside the count the table is dense (SI-11): a position with no row
    /// is `LeavesNotDense { observed: Hole { position } }`, an undecodable
    /// row is SI-7. An
    /// empty range is `Recorded(vec![])`.
    ///
    /// Successor to `get_curve_tree_leaves`, whose C++ consumer is retired
    /// (SCU-2); lands on completeness grounds (S-TX Q3's re-ruling — a range
    /// read is part of what makes a dense keyed table a table) with its
    /// Rust consumer named: **DRS-E3**, the grow path, reads back what it
    /// writes (`SCU-Q4`, rule 23 STAGED). A range is one chunk's worth of
    /// leaves in practice; this is not a full-tree walk.
    pub fn leaves(&self, range: Range<TreePosition>) -> Result<AtIndex<Vec<TreeLeaf>>, StoreError> {
        curve_reads::leaves(&self.txn, range).map_err(chain_reads::ReadFault::into_plain)
    }
}

/// Alt-chain reads (DRS-E1 S-ALT). The bodies live in `alt_reads`; the same
/// bodies serve the batch (`store/alt.rs`) so a switch reads what it is
/// about to change. Never on `ChainView` (SAL-7).
impl ReadSnapshot<'_> {
    /// **AL4.** `alt_blocks[id]`: the record, the block bytes and the
    /// witness. `None` is "not an alt block". An undecodable row is SI-7.
    pub fn alt_block(&self, id: &BlockHash) -> Result<Option<AltBlock>, StoreError> {
        alt_reads::alt_block(&self.txn, id).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **AL5.** Whether `alt_blocks` holds `id`, without decoding the row —
    /// `have_block`'s question, asked per announced hash (`SAL-Q5`).
    pub fn has_alt_block(&self, id: &BlockHash) -> Result<bool, StoreError> {
        alt_reads::has_alt_block(&self.txn, id).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **AL6.** How many alt blocks the store holds.
    pub fn alt_block_count(&self) -> Result<u64, StoreError> {
        alt_reads::alt_block_count(&self.txn).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **AL7.** Every alt block in key order, each with its record. The
    /// consumer parses the bytes and walks the chains; a row that does not
    /// decode is SI-7.
    pub fn alt_blocks(&self) -> Result<Vec<AltEntry>, StoreError> {
        alt_reads::alt_blocks(&self.txn).map_err(chain_reads::ReadFault::into_plain)
    }
}

/// Archival reads (DRS-E1 S-ARCH). The bodies and the absence rules live in
/// `archival_reads`.
impl ReadSnapshot<'_> {
    /// **A1.** `archival_bond[persona]`. `None` is no record. An undecodable
    /// row is SI-7.
    pub fn bond_record(&self, persona: &PCanonicalId) -> Result<Option<BondRecord>, StoreError> {
        archival_reads::bond_record(&self.txn, persona).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A3.** Latest epoch `persona` served `shard`, one reverse seek.
    /// `None` is never-served. SI-15 when rows exist and the persona has no
    /// bond record.
    pub fn last_served_epoch(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
    ) -> Result<Option<SettlementEpoch>, StoreError> {
        archival_reads::last_served_epoch(&self.txn, persona, shard)
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A4.** Every shard `persona` served, each with its latest epoch.
    /// One reverse seek per served shard. Empty when the persona never served.
    pub fn served_shards(&self, persona: &PCanonicalId) -> Result<Vec<ServedShard>, StoreError> {
        archival_reads::served_shards(&self.txn, persona)
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A5.** Pass bits for `(persona, shard, epoch)`. [`PassCount::ZERO`]
    /// when none.
    pub fn pass_count(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<PassCount, StoreError> {
        archival_reads::pass_count(&self.txn, persona, shard, epoch)
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A6.** Co-holder count at `(shard, epoch)`. `None` is an epoch that
    /// never closed; a written zero is a closed epoch with no co-holders.
    pub fn r_market(
        &self,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<RMarket>, StoreError> {
        archival_reads::r_market(&self.txn, shard, epoch)
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A7.** Frozen `Σwork(E)`, in milli-units. `None` is an epoch that
    /// never closed.
    pub fn sigma_work(&self, epoch: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, StoreError> {
        archival_reads::sigma_work(&self.txn, epoch).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A8.** Frozen `budget(E)`. `None` is an epoch that never closed.
    pub fn budget(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, StoreError> {
        archival_reads::budget(&self.txn, epoch).map_err(chain_reads::ReadFault::into_plain)
    }

    /// **A9.** Slash watermark ([`ArchivalLastSlashEpochCell`]). `None` is
    /// no epoch settled yet.
    pub fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, StoreError> {
        self.get_property::<ArchivalLastSlashEpochCell>()
    }

    /// **A10.** Attestation witness bytes, unparsed. [`AtHeight::AboveTip`]
    /// past the tip; `Recorded(None)` when the recorded block stored no row;
    /// `Recorded(Some(bytes))` for a non-empty row within the witness cap.
    /// An empty or over-cap row is SI-7.
    pub fn attestation_witness_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<Option<Vec<u8>>>, StoreError> {
        archival_reads::attestation_witness_at(&self.txn, height)
            .map_err(chain_reads::ReadFault::into_plain)
    }
}

/// One row of the tx walk (T6): the hash and where the store recorded it,
/// or that row's own fault — per-item, as [`RangeItem`] is for heights.
pub type TxWalkItem = Result<(TxHash, TxLocation), StoreError>;

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
            AtHeight::Recorded((info, block)) => AtHeight::Recorded(RecordedBlockBody {
                hash: info.hash,
                block,
            }),
            AtHeight::AboveTip => AtHeight::AboveTip,
        },
    )
}

/// R4 / R7: clamp `range` to the dense tip and yield each height's read.
/// `AboveTip` from `at` inside the clamped range is a hole (SI-7) — the
/// clamp already excluded heights above the tip.
fn range_at<'a, T>(
    range: &core::ops::Range<BlockHeight>,
    tip: Option<(u64, BlockInfo)>,
    cell: &'static str,
    mut at: impl FnMut(Option<&(u64, BlockInfo)>, u64) -> Result<AtHeight<T>, StoreError> + 'a,
) -> AtHeight<impl Iterator<Item = RangeItem<T>> + 'a> {
    let Some(clamped) = clamp_to_tip(range, tip.as_ref().map(|(h, _)| *h)) else {
        return AtHeight::AboveTip;
    };
    AtHeight::Recorded(clamped.map(move |h| {
        match at(tip.as_ref(), h)? {
            AtHeight::Recorded(v) => Ok((BlockHeight::from_raw(h), v)),
            AtHeight::AboveTip => Err(StoreInvariant::CellCorrupt {
                key: cell,
                fault: CellFault::Absent,
            }
            .into()),
        }
    }))
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
