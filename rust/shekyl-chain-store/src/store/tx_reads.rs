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
//!   pattern is not cargo-culted onto a sparse key (STX-Q1 B).
//! - **By dense id** ([`prunable_at`], [`output_indices_at`]) —
//!   [`AtIndex`]. `tx_id` is dense (SI-9: `txs_pruned`' entry count at write
//!   time), so the count is the authority and every by-id read classifies
//!   **bound first**: at or beyond the count is [`AtIndex::BeyondCount`] and
//!   no row is read; below it a missing row is **SI-9**. `TxStorageId` has a
//!   public `from_raw`, so a forged or stale id is ordinary invalid input,
//!   never corruption — which is why T4 is `AtIndex<Prunable>` and not a bare
//!   two-state enum (STX-Q, round 4).
//! - **The prunable region** ([`prunable_at`], inside the bound) —
//!   [`Prunable`]`{ Retained, Discarded }`. Given an id below the count, the
//!   region is held or it is not, and *not held* is a **defined store
//!   state** (`DAEMON_REDB_STORE.md` §7.7 leg (iii): hash row present ∧
//!   segment absent ⇔ discarded — below `W`, or never held; one state, one
//!   meaning). It is not corruption and it is not "not here": the caller's
//!   action — answer from the hash and let the client fetch from an
//!   archiver, or refuse to serve — differs from both. What it may **not**
//!   be: `Discarded` for an id with no `txs_prunable_hash` row, which is the
//!   record-without-hash-row shape §7.7 leg (i) forbids — **SI-7**, never a
//!   third arm.
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
//! `CtSigPrunable` bytes, unit of verification its `txs_prunable_hash`. T3
//! and T4 are that good's read path (`DRS_E1_STX.md` §2.3).

use core::marker::PhantomData;

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_types::{BlockHeight, PqcAuthHash, PrunableHash, TxHash};

use crate::codec::{
    BlobKind, TxIndex, TxOutputIndices, TxPqcAuthsSegment, TxPrunableSegment, TxPrunedSegment,
};
use crate::ids::TxStorageId;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{
    TXS_PQC_AUTHS, TXS_PQC_AUTH_HASH, TXS_PRUNABLE, TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES,
    TX_OUTPUTS,
};

use super::at_index::AtIndex;
use super::chain_reads::{absent, undecodable, ReadFault, ReadTables};
use super::error::StoreInvariant;

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

// Manual impls: a derive would demand `K: Clone + PartialEq + Eq` of the
// marker, which is a zero-sized name and implements none of them.
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

    /// The segment's length in bytes — the one fact about the bytes a
    /// caller may learn without taking them (a fee or size estimate is not
    /// a parse).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the segment is empty. `connect` writes an empty `prunable`
    /// row for a transaction with no prunable region (LMDB parity), so an
    /// empty [`Prunable::Retained`] is a real state, distinct from
    /// [`Prunable::Discarded`].
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
/// its `pqc_auths` segment where the txid is 4-part, and the two permanent
/// hash rows every node keeps at every horizon (§7.7 leg (i)).
///
/// The prunable region is **not** here: it is the archival good, held or
/// discarded per node, and [`prunable_at`] (**T4**) answers for it by the
/// id this record carries. `get_tx_blob`'s callers compose the two
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
    /// The tx-level `pqc_auths` segment — `txs_pqc_auths[id]`; present iff
    /// the txid is 4-part (`PDM-Q-F26`), i.e. iff `pqc_auth_hash` is.
    pub pqc_auths: Option<SegmentBytes<TxPqcAuthsSegment>>,
    /// The prunable region's hash — the archival good's unit of
    /// verification (`PDM-Q6` item 1); permanent.
    pub prunable_hash: PrunableHash,
    /// The `pqc_auths` hash; present iff the txid is 4-part; permanent.
    pub pqc_auth_hash: Option<PqcAuthHash>,
}

impl TxRecord {
    /// The whole transaction as the wire carries it, given its prunable
    /// region: `pruned ‖ pqc_auths ‖ prunable`, the order `db_lmdb.cpp`'s
    /// `get_tx_blob` assembled and `connect` split (STX-8). One line, so it
    /// is written once; a third read for it would be the identity hop.
    #[must_use]
    pub fn wire_bytes(self, prunable: SegmentBytes<TxPrunableSegment>) -> Vec<u8> {
        let mut out = self.pruned.into_wire_bytes();
        if let Some(pqc) = self.pqc_auths {
            out.extend(pqc.into_wire_bytes());
        }
        out.extend(prunable.into_wire_bytes());
        out
    }
}

/// Whether this node holds a recorded transaction's prunable region —
/// **T4**'s answer inside the dense-id bound (module docs).
///
/// Matched exhaustively; deliberately not convertible to `Option` — the
/// two arms instruct differently, and a `None` would erase which.
///
/// ```compile_fail
/// # use shekyl_chain_store::store::Prunable;
/// fn flatten(p: Prunable) -> Option<()> {
///     p.into() // no such conversion
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "`Discarded` is a state the caller must act on, not an absence to skip"]
pub enum Prunable {
    /// The region is held: `txs_prunable[id]` is present. May be empty — a
    /// transaction with no prunable region has an empty row (LMDB parity).
    Retained(SegmentBytes<TxPrunableSegment>),
    /// The region is not held: hash row present, segment absent — §7.7 leg
    /// (iii)'s one state, whether the prune discarded it or the node never
    /// held it. Answer from the hash; fetch the bytes from an archiver.
    Discarded,
}

// ------------------------------------------------------------ helpers

/// Where `id` sits relative to the dense count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdClass {
    Within,
    Beyond,
}

const fn class_of(count: u64, id: TxStorageId) -> IdClass {
    if id.to_raw() < count {
        IdClass::Within
    } else {
        IdClass::Beyond
    }
}

/// SI-9 for a read: the count and the keys disagree.
const fn not_dense() -> ReadFault {
    ReadFault::Invariant(StoreInvariant::IdNotFresh)
}

/// The stored row projected to what a read hands out — the **one** place
/// `TxIndex` becomes [`TxLocation`], so the field it drops is dropped once.
pub(super) const fn project(row: TxIndex) -> TxLocation {
    TxLocation {
        id: row.tx_id,
        height: row.height,
    }
}

/// The `tx_indices` key for a hash. `pub(super)` so the walk in `read.rs`
/// (which needs the snapshot's owned table for a `'static` range) builds
/// its bounds the same way.
pub(super) fn key_of(hash: &TxHash) -> LmdbHashKey {
    LmdbHashKey::from_bytes(hash.to_bytes())
}

/// Decode a `tx_indices` value, naming the table on a codec fault.
pub(super) fn decode_index(
    value: crate::codec::Encoded<'_, TxIndex>,
) -> Result<TxIndex, ReadFault> {
    value
        .decode()
        .map_err(|cause| undecodable("tx_indices", cause))
}

/// Read a `TxIndex` row by hash and project it.
fn location_by_hash<T: ReadTables>(
    txn: &T,
    hash: &TxHash,
) -> Result<Option<TxLocation>, ReadFault> {
    let table = txn.table(TX_INDICES)?;
    let Some(guard) = table.get(key_of(hash))? else {
        return Ok(None);
    };
    Ok(Some(project(decode_index(guard.value())?)))
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
/// under a typed read (STX-6). The `pqc_auths` pair is present iff the txid
/// is 4-part, and the two must agree — a segment without its hash row, or
/// a hash row without its segment, is leg (ii)'s breach, SI-7 too.
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

    let hashes = txn.table(TXS_PRUNABLE_HASH)?;
    let Some(prunable_hash) = hashes.get(id)? else {
        return Err(absent("txs_prunable_hash"));
    };
    let prunable_hash = prunable_hash
        .value()
        .decode()
        .map_err(|cause| undecodable("txs_prunable_hash", cause))?;

    let pqc_auth_hash = match txn.table(TXS_PQC_AUTH_HASH)?.get(id)? {
        Some(guard) => Some(
            guard
                .value()
                .decode()
                .map_err(|cause| undecodable("txs_pqc_auth_hash", cause))?,
        ),
        None => None,
    };
    let pqc_auths = txn
        .table(TXS_PQC_AUTHS)?
        .get(id)?
        .map(|guard| SegmentBytes::new(guard.value().bytes()));
    // §7.7 leg (ii), pairwise: the segment and its hash row are present
    // together or absent together.
    match (&pqc_auths, &pqc_auth_hash) {
        (Some(_), None) => return Err(absent("txs_pqc_auth_hash")),
        (None, Some(_)) => return Err(absent("txs_pqc_auths")),
        _ => {}
    }

    Ok(Some(TxRecord {
        location,
        pruned,
        pqc_auths,
        prunable_hash,
        pqc_auth_hash,
    }))
}

/// **T4.** Whether this node holds the prunable region of the transaction
/// at `id`, bound first (module docs).
///
/// At or beyond the count: [`AtIndex::BeyondCount`], no row read — a forged
/// or stale id is invalid input, not corruption. Below it: the hash row
/// must exist (leg (i); missing is **SI-7**), and then the segment's
/// presence is the answer — [`Prunable::Retained`] or
/// [`Prunable::Discarded`], leg (iii)'s one state.
pub(super) fn prunable_at<T: ReadTables>(
    txn: &T,
    id: TxStorageId,
) -> Result<AtIndex<Prunable>, ReadFault> {
    if let IdClass::Beyond = class_of(tx_count(txn)?, id) {
        return Ok(AtIndex::BeyondCount);
    }
    let raw = id.to_raw();
    if txn.table(TXS_PRUNABLE_HASH)?.get(raw)?.is_none() {
        return Err(absent("txs_prunable_hash"));
    }
    let answer = match txn.table(TXS_PRUNABLE)?.get(raw)? {
        Some(guard) => Prunable::Retained(SegmentBytes::new(guard.value().bytes())),
        None => Prunable::Discarded,
    };
    Ok(AtIndex::Recorded(answer))
}

/// **T5.** The `output_amounts` indices of the transaction at `id`'s
/// outputs, in `vout` order — `tx_outputs[id]`, bound first. Replaces
/// `get_tx_amount_output_indices`; a hole below the count is **SI-9**.
pub(super) fn output_indices_at<T: ReadTables>(
    txn: &T,
    id: TxStorageId,
) -> Result<AtIndex<TxOutputIndices>, ReadFault> {
    if let IdClass::Beyond = class_of(tx_count(txn)?, id) {
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
