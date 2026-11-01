// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One read body for the transaction tables (S-TX, `DRS_E1_STX.md` §3),
//! the third sibling of `chain_reads` and `output_reads`.
//!
//! # Three absence shapes, one discriminator
//!
//! `CHAIN_RULES_CRATE.md` G11: absence earns a type when its case carries
//! caller-actionable semantics; S-CHAIN-R's counter-rule: `Option` stays
//! `Option` when it does not. This surface has three lookups and they land
//! on three sides of that line (`DRS_E1_STX.md` §3.3):
//!
//! - **By hash** ([`location_at`], [`record_at`]) — **`Option`**. Hashes are
//!   sparse; a miss is ordinary and instructs nothing beyond *not here*.
//!   This is the counter-rule's worked case, written down so the absence
//!   pattern is not cargo-culted onto a sparse key (STX-Q1 B). A present
//!   index row whose `tx_id` is at or past the dense count is **SI-9**,
//!   not a location: T4 would call that id [`AtIndex::BeyondCount`], and
//!   a location T4 refuses is not a location.
//! - **By dense id** ([`archival_good_at`], [`output_indices_at`]) —
//!   [`AtIndex`]. `tx_id` is dense (SI-9: `txs_pruned`' entry count at write
//!   time), so the count is the authority and every by-id read classifies
//!   **bound first, then the primary**: at or beyond the count is
//!   [`AtIndex::BeyondCount`] and no row is read; below it the primary
//!   `txs_pruned[id]` must exist before any side table is consulted — a
//!   side row present at an id whose primary is missing is not a recorded
//!   transaction, it is the count lying (**SI-9**); and a missing side row
//!   under a present primary is SI-9 or SI-7 by its leg. `TxStorageId` has a
//!   public `from_raw`, so a forged or stale id is ordinary invalid input,
//!   never corruption — which is why T4 is `AtIndex<ArchivalGood>` and not a
//!   bare two-state enum (STX-Q, round 4).
//! - **The archival good** ([`archival_good_at`], inside the bound) —
//!   [`ArchivalGood`]`{ Retained, Discarded }`. `PDM-Q6` item 1 defines the
//!   good as **one unit**: a transaction's prunable region and, where the
//!   txid is 4-part, its `pqc_auths` region, which S-PRUNE discards together
//!   by shard (`prune.rs`). Given an id below the count, the unit is held or
//!   it is not, and *not held* is a **defined store state**
//!   (`DAEMON_REDB_STORE.md` §7.7 leg (iii): hash row present ∧ segment
//!   absent ⇔ discarded — below the horizon, or never held; one state, one
//!   meaning). It is not corruption and it is not "not here": the caller's
//!   action — answer the skeleton and let the client fetch from an archiver,
//!   or refuse to serve — differs from both. Two shapes it may **not** be: a
//!   `Discarded` for an id with no `txs_prunable_hash` row, which is the
//!   record-without-hash-row shape §7.7 leg (i) forbids — **SI-7**; and a
//!   **half** — one region held and the other not — which is neither state
//!   and **SI-42** ([`StoreInvariant::ArchivalGoodHalfHeld`]), never a third
//!   arm (`SB-Q2`).
//!
//! # What no read hands out
//!
//! **No public read type under `store/` has an `unlock_time` field**
//! (STX-9, gated by `scripts/ci/check_store_unlock_time_projection.py`).
//! The stored `TxIndex` row carries it and the reads decode that row; the
//! types they return — [`TxLocation`], [`TxRecord`] — do not. The field's
//! fate is census U-2's, and a projection nobody consumes is how a dead
//! field acquires a second reason to exist.
//!
//! # The prunable region is the good
//!
//! `get_prunable_tx_blob` / `get_prunable_tx_hash` are not stripe-engine
//! residue (`PDM-Q7` deleted the *mechanism*): `PDM-Q6` item 1 rules a
//! transaction's prunable region the archival good — unit of possession its
//! `CtSigPrunable` bytes (with the `pqc_auths` region of a 4-part txid),
//! unit of verification its `txs_prunable_hash`. T3 and T4 are that good's
//! read path (`DRS_E1_STX.md` §2.3). What every node keeps at every horizon
//! is the **skeleton** — the pruned segment and the three txid operands —
//! and [`TxRecord::skeleton_of`] is its one constructor (`SB-Q2`).

use core::marker::PhantomData;

use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use shekyl_types::{
    shard_of, storage_ids_through, ArchivalLength, BlockHeight, PqcAuthHash, PrunableHash, ShardId,
    TxHash,
};
use shekyl_wire::SkeletonTx;

use crate::codec::{
    BlobKind, Canonical, Coded, TxIndex, TxOutputIndices, TxPqcAuthsSegment, TxPrunableSegment,
    TxPrunedSegment,
};
use crate::ids::TxStorageId;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{
    BLOCK_INFO, TXS_ARCHIVAL_LEN, TXS_PQC_AUTHS, TXS_PQC_AUTH_HASH, TXS_PRUNABLE,
    TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES, TX_OUTPUTS,
};

use super::at_index::AtIndex;
use super::chain_reads::{self, absent, undecodable, ReadFault, ReadTables};
use super::error::{HeldRegion, StoreInvariant};

// ---------------------------------------------------------------- types

/// The recorded bytes of one transaction **segment** — pruned, `pqc_auths`
/// or prunable — as `connect` stored them (`Transaction::write_segments`).
///
/// One newtype per segment through the [`BlobKind`] marker the table is
/// already typed by, so a `pqc_auths` segment cannot be handed where a
/// pruned one is expected. Same discipline as
/// [`RawBlockBytes`](super::RawBlockBytes) (S-CHAIN-R Q2): for the relay,
/// RPC and FFI paths that forward bytes — no `Deref`, no `AsRef<[u8]>`, no
/// parse. The one way out is [`into_wire_bytes`](Self::into_wire_bytes),
/// named for its consumer.
///
/// ```compile_fail
/// # use shekyl_chain_store::store::SegmentBytes;
/// # use shekyl_chain_store::codec::TxPrunedSegment;
/// fn consensus_path(bytes: &SegmentBytes<TxPrunedSegment>) -> u8 {
///     let view: &[u8] = bytes; // no Deref, no AsRef: the bytes are not a slice here
///     view[0]
/// }
/// ```
///
/// ```compile_fail
/// # use shekyl_chain_store::store::SegmentBytes;
/// # use shekyl_chain_store::codec::{TxPrunedSegment, TxPrunableSegment};
/// fn confuse(bytes: SegmentBytes<TxPrunedSegment>) -> SegmentBytes<TxPrunableSegment> {
///     bytes // a pruned segment is not a prunable one
/// }
/// ```
pub struct SegmentBytes<K: BlobKind> {
    bytes: Vec<u8>,
    kind: PhantomData<fn() -> K>,
}

// Handwritten: `#[derive(Clone, PartialEq, Eq)]` still demands `K: Clone + Eq`
// of the type parameter, even with `PhantomData<fn() -> K>`. The marker is a
// zero-sized name (`BlobKind`) and implements none of them.
impl<K: BlobKind> Clone for SegmentBytes<K> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            kind: PhantomData,
        }
    }
}

impl<K: BlobKind> PartialEq for SegmentBytes<K> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<K: BlobKind> Eq for SegmentBytes<K> {}

impl<K: BlobKind> SegmentBytes<K> {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            kind: PhantomData,
        }
    }

    /// The bytes, for the writer that puts them on the wire. Consumes the
    /// value: there is no borrowed view.
    #[must_use]
    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The segment's wire bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The segment's length in bytes — the one fact about the bytes a
    /// caller may learn without taking them (a fee or size estimate is not
    /// a parse).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the segment is empty. `connect` writes an empty `prunable`
    /// row for a transaction with no prunable region (LMDB parity), so an
    /// empty retained region ([`ArchivalGood::Retained`]) is a real state,
    /// distinct from [`ArchivalGood::Discarded`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<K: BlobKind> core::fmt::Debug for SegmentBytes<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SegmentBytes<{}>({} bytes)", K::NAME, self.bytes.len())
    }
}

/// Where a transaction is: its storage id and the height that recorded it.
/// **T1**'s answer and **T6**'s item.
///
/// The stored `TxIndex` row projected **without `unlock_time`** (STX-9).
/// This is **not** the identity-DTO hop SOK-Q4 / STX-Q4 refused — those
/// rejected a second struct that *renames* an identical shape; this one
/// deliberately *drops* a field, which is the opposite operation and the
/// whole reason it exists. A read projection, never stored, so not
/// `Canonical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxLocation {
    /// The storage id: the transaction's position in the `txs_*` tables.
    pub id: TxStorageId,
    /// The height of the block that recorded it.
    pub height: BlockHeight,
}

/// The permanent half of a recorded transaction — **T3**'s answer: where it
/// is, its pruned segment (eager, STX-Q4 A: every caller wants the bytes),
/// and the three permanent operand rows every node keeps at every horizon
/// (§7.7 leg (i)). Together these are the **skeleton** ([`Self::skeleton_of`]).
///
/// The archival good — the prunable region and, for a 4-part txid, the
/// `pqc_auths` region — is **not** here: it is held or discarded per node
/// as one unit, and [`archival_good_at`] (**T4**) answers for it by the id
/// this record carries. `get_tx_blob`'s callers compose the two
/// (`wire_bytes`).
///
/// No `unlock_time` (STX-9). A read projection, never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecord {
    /// Where the transaction is.
    pub location: TxLocation,
    /// The pruned segment: version, prefix, ct type, fee / reference block,
    /// committed base — `txs_pruned[id]`.
    pub pruned: SegmentBytes<TxPrunedSegment>,
    /// The prunable region's hash — the archival good's unit of
    /// verification (`PDM-Q6` item 1); permanent.
    pub prunable_hash: PrunableHash,
    /// The `pqc_auths` hash; present iff the txid carries the component;
    /// permanent.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// The archival length — `txs_archival_len[id]`, the third operand the
    /// txid binds (`SHT-Q2`); permanent. The row is sparse, present iff the
    /// transaction carries archival good, so a coinbase's reads zero here.
    ///
    /// **As recorded, not as verified** — like the two hash rows beside it.
    /// A row lost from a transaction that carries good also reads zero, and
    /// this read cannot tell the two apart. A consumer that names a txid
    /// from this record rebuilds it from these operands and compares it to
    /// the hash it asked by (`leaf_reads::outputs_at`, the one such consumer
    /// today); the prune reads the rows directly and holds them to the
    /// block's cell (SI-24).
    pub archival_len: ArchivalLength,
}

impl TxRecord {
    /// The whole transaction as the wire carries it, given its archival
    /// good: `pruned ‖ pqc_auths ‖ prunable`, the order `db_lmdb.cpp`'s
    /// `get_tx_blob` assembled and `connect` split (STX-8). One line, so it
    /// is written once; a third read for it would be the identity hop.
    ///
    /// Takes the good's **retained** regions, so the caller has already
    /// matched [`ArchivalGood`] and answered its `Discarded` arm — with the
    /// [skeleton](Self::skeleton_of), or a refusal — before composing.
    /// `pqc_auths` is `Some` iff the txid is 4-part.
    #[must_use]
    pub fn wire_bytes(
        self,
        prunable: SegmentBytes<TxPrunableSegment>,
        pqc_auths: Option<SegmentBytes<TxPqcAuthsSegment>>,
    ) -> Vec<u8> {
        let mut out = self.pruned.into_wire_bytes();
        if let Some(pqc) = pqc_auths {
            out.extend(pqc.into_wire_bytes());
        }
        out.extend(prunable.into_wire_bytes());
        out
    }

    /// The **skeleton** of this recorded transaction: its pruned segment
    /// and the three operands its txid binds — `prunable_hash`,
    /// `pqc_auth_hash` (where 4-part) and `archival_len`. This is what every
    /// node holds at every horizon (`PDM-Q5`, `SB-Q2`), what a pruned-sync
    /// peer serves below the checkpoint, and what a `prune` reply carries
    /// per transaction. The one constructor in the tree, in the crate that
    /// owns the rows; the recipient rebinds it with [`SkeletonTx::txid`].
    #[must_use]
    pub fn skeleton_of(&self) -> SkeletonTx {
        SkeletonTx {
            unprunable: self.pruned.as_bytes().to_vec(),
            prunable_hash: self.prunable_hash,
            pqc_auth_hash: self.pqc_auth_hash,
            archival_len: self.archival_len,
        }
    }
}

/// Whether this node holds a recorded transaction's **archival good** —
/// **T4**'s answer inside the dense-id bound (module docs). The good is one
/// unit (`PDM-Q6` item 1): the prunable region and, for a 4-part txid, the
/// `pqc_auths` region, held together or discarded together.
///
/// Matched exhaustively; deliberately not convertible to `Option` — the
/// two arms instruct differently, and a `None` would erase which.
///
/// ```compile_fail
/// # use shekyl_chain_store::store::ArchivalGood;
/// fn flatten(p: ArchivalGood) -> Option<()> {
///     p.into() // no such conversion
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "`Discarded` is a state the caller must act on, not an absence to skip"]
pub enum ArchivalGood {
    /// The good is held: `txs_prunable[id]` is present, and so is
    /// `txs_pqc_auths[id]` where the txid is 4-part.
    Retained {
        /// The prunable region. May be empty — a transaction with no
        /// prunable region has an empty row (LMDB parity).
        prunable: SegmentBytes<TxPrunableSegment>,
        /// The tx-level `pqc_auths` region — `Some` iff the txid is 4-part
        /// (`PDM-Q-F26`), i.e. iff the record's `pqc_auth_hash` is.
        pqc_auths: Option<SegmentBytes<TxPqcAuthsSegment>>,
    },
    /// The good is not held: the hash rows are present, the segments
    /// absent — §7.7 leg (iii)'s one state, whether the prune discarded it
    /// or the node never held it. Answer the skeleton; the bytes come from
    /// an archiver.
    Discarded,
}

// ------------------------------------------------------------ helpers

/// SI-9 for a read: the count and the keys disagree.
const fn not_dense() -> ReadFault {
    ReadFault::Invariant(StoreInvariant::IdNotFresh)
}

/// Whether a by-id read may proceed for `id`. Two facts, in order: the id
/// is below the count (else `BeyondCount`, and no row is read), and the
/// **primary** row `txs_pruned[id]` exists — the count is `txs_pruned`'
/// length, so a missing primary below it is the count lying about the id
/// space, **SI-9**, and a side row that happens to be present at that id
/// (`txs_prunable_hash`, `tx_outputs`) must not be served as if the
/// transaction were recorded. One helper, so T4 and T5 cannot disagree on
/// what "recorded at `id`" means.
enum Admitted {
    /// Below the count and the primary row is present: read the side table.
    Recorded,
    /// At or beyond the count: nothing was ever recorded here.
    Beyond,
}

fn admit<T: ReadTables>(txn: &T, id: TxStorageId) -> Result<Admitted, ReadFault> {
    let primary = txn.table(TXS_PRUNED)?;
    if id.to_raw() >= primary.len()? {
        return Ok(Admitted::Beyond);
    }
    if primary.get(id.to_raw())?.is_none() {
        return Err(not_dense());
    }
    Ok(Admitted::Recorded)
}

/// One `Coded<V>` row under a dense id — a digest row, or the archival
/// length row — read the only way such a row is read here: absent is `None`,
/// present **decodes** — a row that is not exactly one `V` is SI-7
/// `Undecodable` naming the table, the same fault whether T3 or T4 met it
/// (PR #800 review round 3). `Coded` does not decode on access, so a presence
/// check alone (`get(..).is_some()`) would take a row on faith; every such
/// read goes through here so none does. Today the arm is unreachable by construction — both codecs are
/// fixed-width 32, the engine refuses any other width at write time, and
/// every 32-byte row decodes — which the tests pin rather than plant
/// around; the reader still decodes so the seam holds if a codec gains
/// structure. `cell` is the table's name as the fault carries it (`'static`,
/// which redb's `TableHandle::name` borrow is not); the two are bound by
/// the debug assertion, so a test that reaches the row catches a drift.
fn coded_row<V: Canonical, T: ReadTables>(
    txn: &T,
    table: TableDefinition<'static, u64, Coded<V>>,
    cell: &'static str,
    id: u64,
) -> Result<Option<V>, ReadFault> {
    debug_assert_eq!(TableHandle::name(&table), cell, "fault names its table");
    let rows = txn.table(table)?;
    let Some(guard) = rows.get(id)? else {
        return Ok(None);
    };
    guard
        .value()
        .decode()
        .map(Some)
        .map_err(|cause| undecodable(cell, cause))
}

/// The stored row projected to what a read hands out — the **one** place
/// `TxIndex` becomes [`TxLocation`], so the field it drops is dropped once.
const fn project(row: TxIndex) -> TxLocation {
    TxLocation {
        id: row.tx_id,
        height: row.height,
    }
}

/// [`project`] after the id has been shown to sit inside the dense count.
/// An index pointing at or past `count` is SI-9: T4 would classify that id
/// as [`AtIndex::BeyondCount`], and a location T4 refuses is not a location.
fn location_of(row: TxIndex, count: u64) -> Result<TxLocation, ReadFault> {
    if row.tx_id.to_raw() >= count {
        return Err(not_dense());
    }
    Ok(project(row))
}

fn key_of(hash: &TxHash) -> LmdbHashKey {
    LmdbHashKey::from_bytes(hash.to_bytes())
}

fn decode_index(value: crate::codec::Encoded<'_, TxIndex>) -> Result<TxIndex, ReadFault> {
    value
        .decode()
        .map_err(|cause| undecodable("tx_indices", cause))
}

/// `tx_indices` membership — whether a transaction with identity `hash` is
/// recorded on the chain, the miner transactions included. The chain half
/// of CEN-G1, `ChainView::has_transaction`'s body (E6 slice 7), shared with
/// `ReadSnapshot::has_transaction` so the validator and the pool read one
/// answer. Membership only, as [`chain_reads::has_key_image`] is: the row is
/// not decoded, so an undecodable index is the locating reads' SI-7 to
/// report, not a false `false` here. The C++'s `tx_exists`.
pub(super) fn has_transaction<T: ReadTables>(txn: &T, hash: &TxHash) -> Result<bool, ReadFault> {
    let table = txn.table(TX_INDICES)?;
    let found = table.get(key_of(hash))?.is_some();
    Ok(found)
}

/// Read a `TxIndex` row by hash and locate it. A miss is `None`; a present
/// row whose `tx_id` is at or past the dense count is SI-9, not a location.
fn location_by_hash<T: ReadTables>(
    txn: &T,
    hash: &TxHash,
) -> Result<Option<TxLocation>, ReadFault> {
    let table = txn.table(TX_INDICES)?;
    let Some(guard) = table.get(key_of(hash))? else {
        return Ok(None);
    };
    let row = decode_index(guard.value())?;
    Ok(Some(location_of(row, tx_count(txn)?)?))
}

/// T6's body: each `tx_indices` entry in the caller's (already ordered)
/// range, located against `count`. Lives here so the field drop and the
/// domain check are the same functions T1 uses; the snapshot opens the
/// table because only its owned handle can feed a `'static` range.
pub(super) fn walk_indices<'a>(
    range: redb::Range<'a, LmdbHashKey, Coded<TxIndex>>,
    count: u64,
) -> impl Iterator<Item = Result<(TxHash, TxLocation), ReadFault>> + 'a {
    range.map(move |entry| {
        let (key, value) = entry?;
        Ok((
            TxHash::from_bytes(key.value().to_bytes()),
            location_of(decode_index(value.value())?, count)?,
        ))
    })
}

// -------------------------------------------------------------- reads

/// **T2.** The dense count: `txs_pruned`' length, the unique-key primary
/// `tx_id` is dense in (SI-9). One table is the authority; the other tx
/// tables are checked against it, never the reverse.
///
/// Named consumer beyond this surface: the bond-admission shard predicate
/// (`ARCHIVAL_BOND_ADD_ADMISSION.md` §4.1) stands on this count being the
/// dense authority — it is what makes "does shard `k` exist" a determinate
/// question rather than a lookup that can answer for a hole.
pub(super) fn tx_count<T: ReadTables>(txn: &T) -> Result<u64, ReadFault> {
    Ok(txn.table(TXS_PRUNED)?.len()?)
}

/// **T1.** Where the transaction with `hash` is, or `None` — the sparse
/// lookup, the counter-rule's worked case (module docs). Replaces
/// `tx_exists` in both overloads: the index row *is* existence, and a
/// caller that then wants the id has it.
pub(super) fn location_at<T: ReadTables>(
    txn: &T,
    hash: &TxHash,
) -> Result<Option<TxLocation>, ReadFault> {
    location_by_hash(txn, hash)
}

/// **T3.** The permanent half of the transaction with `hash`, or `None`.
///
/// Below the record's id the pruned segment and the prunable hash row are
/// rows that must exist (§7.7 leg (i); `connect` writes them in one batch
/// with the index row): missing is **SI-7** with the table named, which is
/// what `rpc_facts_ffi.cpp`'s `MERROR` on a missing prunable hash becomes
/// under a typed read (STX-6). The `pqc_auths` hash row is present iff the
/// txid is 4-part; no row is a 3-part transaction. The regions themselves
/// are the archival good, [`archival_good_at`]'s to answer for.
pub(super) fn record_at<T: ReadTables>(
    txn: &T,
    hash: &TxHash,
) -> Result<Option<TxRecord>, ReadFault> {
    let Some(location) = location_by_hash(txn, hash)? else {
        return Ok(None);
    };
    let id = location.id.to_raw();

    let pruned = txn.table(TXS_PRUNED)?;
    let Some(pruned) = pruned.get(id)? else {
        return Err(absent("txs_pruned"));
    };
    let pruned = SegmentBytes::new(pruned.value().bytes());

    let Some(prunable_hash) = coded_row(txn, TXS_PRUNABLE_HASH, "txs_prunable_hash", id)? else {
        return Err(absent("txs_prunable_hash"));
    };
    // Absent ⇔ the txid is 3-part. Not a fault: that is what no row means.
    let pqc_auth_hash = coded_row(txn, TXS_PQC_AUTH_HASH, "txs_pqc_auth_hash", id)?;

    // Sparse by definition (`connect` writes it iff the length is non-zero),
    // so absence is zero, not a hole. A row lost from a transaction that
    // carries good is caught where the length is used: the txid it then
    // rebuilds is not the one the block names.
    let archival_len =
        coded_row(txn, TXS_ARCHIVAL_LEN, "txs_archival_len", id)?.unwrap_or(ArchivalLength::ZERO);

    Ok(Some(TxRecord {
        location,
        pruned,
        prunable_hash,
        pqc_auth_hash,
        archival_len,
    }))
}

/// **T4.** Whether this node holds the **archival good** of the transaction
/// at `id`, bound first (module docs).
///
/// At or beyond the count: [`AtIndex::BeyondCount`], no row read — a forged
/// or stale id is invalid input, not corruption. Below it the primary row
/// must exist (a hole is **SI-9**, [`admit`]); then the prunable hash row
/// must exist and decode (leg (i); missing or malformed is **SI-7**,
/// [`coded_row`] — the answer is about the region whose digest that row is,
/// so a row that is not a digest is not a basis for it); the `pqc_auth_hash`
/// row says whether the txid is 4-part, and a `pqc_auths` segment without it
/// is leg (ii)'s breach, **SI-7**. Then the segments' presence is the
/// answer, as **one** unit: both present (or the prunable one, for a 3-part
/// txid) is [`ArchivalGood::Retained`]; both absent is
/// [`ArchivalGood::Discarded`], leg (iii)'s one state; one present and the
/// other not is **SI-42** ([`StoreInvariant::ArchivalGoodHalfHeld`]) — no
/// write path produces it, and it is not a third answer.
pub(super) fn archival_good_at<T: ReadTables>(
    txn: &T,
    id: TxStorageId,
) -> Result<AtIndex<ArchivalGood>, ReadFault> {
    if let Admitted::Beyond = admit(txn, id)? {
        return Ok(AtIndex::BeyondCount);
    }
    let raw = id.to_raw();
    if coded_row(txn, TXS_PRUNABLE_HASH, "txs_prunable_hash", raw)?.is_none() {
        return Err(absent("txs_prunable_hash"));
    }
    let four_part = coded_row(txn, TXS_PQC_AUTH_HASH, "txs_pqc_auth_hash", raw)?.is_some();
    let prunable = txn
        .table(TXS_PRUNABLE)?
        .get(raw)?
        .map(|guard| SegmentBytes::new(guard.value().bytes()));
    let pqc_auths = txn
        .table(TXS_PQC_AUTHS)?
        .get(raw)?
        .map(|guard| SegmentBytes::new(guard.value().bytes()));
    let half = |held| ReadFault::Invariant(StoreInvariant::ArchivalGoodHalfHeld { id, held });
    let answer = match (prunable, pqc_auths, four_part) {
        // Leg (ii): a `pqc_auths` segment implies its hash row.
        (_, Some(_), false) => return Err(absent("txs_pqc_auth_hash")),
        (None, None, _) => ArchivalGood::Discarded,
        (Some(prunable), None, false) => ArchivalGood::Retained {
            prunable,
            pqc_auths: None,
        },
        (Some(prunable), Some(pqc), true) => ArchivalGood::Retained {
            prunable,
            pqc_auths: Some(pqc),
        },
        (Some(_), None, true) => return Err(half(HeldRegion::Prunable)),
        (None, Some(_), true) => return Err(half(HeldRegion::PqcAuths)),
    };
    Ok(AtIndex::Recorded(answer))
}

/// **T5.** The archival shard the transaction at `location` belongs to
/// (`SB-Q2`; `PDM-Q10`): [`shard_of`] over the cumulative archival length
/// **before** it — the parent block's `cumulative_archival_len` cell, plus
/// the `txs_archival_len` rows of the transactions its block recorded
/// before it (the coinbase first, CEN-F; a sparse row is zero). `shard_of`
/// is the partition's one boundary function; this read only assembles its
/// operand, the way the prune's descent and the shard walk do.
///
/// The caller holds a [`TxLocation`] T1 or T3 answered, so the block exists
/// and the id is below the count. An id below its block's first id is the
/// index disagreeing with the dense issue order, **SI-9**.
pub(super) fn shard_at<T: ReadTables>(txn: &T, location: TxLocation) -> Result<ShardId, ReadFault> {
    let (before, first) = match location.height.to_raw().checked_sub(1) {
        None => (ArchivalLength::ZERO, 0),
        Some(parent) => {
            let info = chain_reads::cell(txn, BLOCK_INFO, parent, "block_info")?
                .ok_or_else(|| absent("block_info"))?;
            let first = storage_ids_through(info.cumulative_tx_count, parent).ok_or(
                ReadFault::Invariant(StoreInvariant::FoldOverflow {
                    cell: "block_info.cumulative_tx_count",
                }),
            )?;
            (info.cumulative_archival_len, first)
        }
    };
    let id = location.id.to_raw();
    if id < first {
        return Err(not_dense());
    }
    let lens = txn.table(TXS_ARCHIVAL_LEN)?;
    let mut cum = before;
    for earlier in first..id {
        let len = match lens.get(earlier)? {
            Some(guard) => guard
                .value()
                .decode()
                .map_err(|cause| undecodable("txs_archival_len", cause))?,
            None => ArchivalLength::ZERO,
        };
        cum = cum
            .checked_add(len)
            .ok_or(ReadFault::Invariant(StoreInvariant::FoldOverflow {
                cell: "block_info.cumulative_archival_len",
            }))?;
    }
    Ok(shard_of(cum))
}

/// **T4b.** Whether the transaction at `id` is in the **archival shard
/// partition's domain** — `SHT-Q1` RULED (Rick, 2026-09-27, design-owner lane).
///
/// The production path for the ruling's predicate. It reads the two digests **as
/// recorded at ingest** — `txs_prunable_hash` (written at `connect.rs:575`, leg
/// (i), mandatory) and `txs_pqc_auth_hash` (`connect.rs:584-586`, present ⇔ the
/// txid is 4-part) — and hands them to [`shekyl_wire::carries_archival_good`].
///
/// **Why the rows and not the body.** A prune deletes the regions and never these
/// rows (`schema.rs` on `TXS_PQC_AUTH_HASH`: a row without its segment is
/// *discarded*, §7.7 leg (iii), not a fault). Recomputing the digests from a
/// pruned body instead would yield `keccak256("")` and `None`, so a node past
/// the boundary would read its own discarded spends as carrying **no** good and
/// place them outside the domain while one still holding the body keeps them
/// inside — the two would disagree on shard boundaries, which is a consensus
/// split. That is why
/// `shekyl-wire` exposes the predicate only over explicit row values, and why
/// this answer is stable across a prune (pinned by
/// `the_predicate_survives_a_prune_on_the_stored_rows`).
///
/// Bound first, as [`archival_good_at`]: at or beyond the count, no row is read.
pub(super) fn carries_archival_good_at<T: ReadTables>(
    txn: &T,
    id: TxStorageId,
) -> Result<AtIndex<bool>, ReadFault> {
    if let Admitted::Beyond = admit(txn, id)? {
        return Ok(AtIndex::BeyondCount);
    }
    let raw = id.to_raw();
    // Leg (i): the prunable hash row is permanent and mandatory — its absence
    // below the count is SI-7, the same fault `archival_good_at` reports, because the
    // answer is *about* the region whose digest that row is.
    let Some(prunable_hash) = coded_row(txn, TXS_PRUNABLE_HASH, "txs_prunable_hash", raw)? else {
        return Err(absent("txs_prunable_hash"));
    };
    // Absent ⇔ the txid is 3-part. Not a fault: that is what no row means here.
    let pqc_auth_hash = coded_row(txn, TXS_PQC_AUTH_HASH, "txs_pqc_auth_hash", raw)?;
    Ok(AtIndex::Recorded(shekyl_wire::carries_archival_good(
        pqc_auth_hash,
        prunable_hash,
    )))
}

/// **T5.** The `output_amounts` indices of the transaction at `id`'s
/// outputs, in `vout` order — `tx_outputs[id]`, bound first. Replaces
/// `get_tx_amount_output_indices`; a hole below the count — in the primary
/// ([`admit`]) or in `tx_outputs` itself — is **SI-9**.
pub(super) fn output_indices_at<T: ReadTables>(
    txn: &T,
    id: TxStorageId,
) -> Result<AtIndex<TxOutputIndices>, ReadFault> {
    if let Admitted::Beyond = admit(txn, id)? {
        return Ok(AtIndex::BeyondCount);
    }
    let table = txn.table(TX_OUTPUTS)?;
    let Some(guard) = table.get(id.to_raw())? else {
        return Err(not_dense());
    };
    let indices = guard
        .value()
        .decode()
        .map_err(|cause| undecodable("tx_outputs", cause))?;
    Ok(AtIndex::Recorded(indices))
}
