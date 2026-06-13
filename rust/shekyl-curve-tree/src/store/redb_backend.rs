// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! redb-backed `LeafStore` tables and transactional operations.

use std::path::Path;

use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::segment::{leaves_per_segment, segment_freeze_eligible, SegmentId};
use crate::store::ops::{
    full_build_root, mixed_composition_root, recompute_segment_r_k, MixedRootError,
};
use crate::types::{BlockHeight, Gindex, LeafEntry, TargetKind, TreePosition};
use shekyl_fcmp::tree::{hash_grow_selene, selene_hash_init, SCALARS_PER_LEAF};

const LEAVES_TABLE: TableDefinition<TreePosition, &[u8; 128]> = TableDefinition::new("leaves");
const LEAF_META_TABLE: TableDefinition<TreePosition, &[u8; 192]> =
    TableDefinition::new("leaf_meta");
const FROZEN_SEGMENTS_TABLE: TableDefinition<SegmentId, &[u8; 56]> =
    TableDefinition::new("frozen_segments");
const OWNED_IDENTITIES_TABLE: TableDefinition<TreePosition, &[u8; 128]> =
    TableDefinition::new("owned_identities");
const PINNED_SEGMENTS_TABLE: TableDefinition<SegmentId, u32> =
    TableDefinition::new("pinned_segments");
// Pending (created but not yet drained) leaves, keyed by global output
// index. Value = 128-byte leaf || 192-byte leaf-meta payload (the same
// encoders as `LEAVES_TABLE`/`LEAF_META_TABLE` — one layout, two tables),
// so a pending row migrates to/from the drained tables without
// re-encoding. Rows enter on block ingest, leave on drain
// (`append_block_deltas`) or on the rollback creation-height filter.
const PENDING_TABLE: TableDefinition<Gindex, &[u8; 320]> = TableDefinition::new("pending");
// `META_TABLE` is a heterogeneous `&str`-keyed counter store; its `u64`
// values convert to `BlockHeight`/counts at the API boundary. This is the
// one legitimate raw-`u64` value site in the store.
const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta");

const META_LEAF_COUNT: &str = "leaf_count";
const META_SYNC_TIP: &str = "sync_tip_height";
const META_NEXT_FREEZE_SEG: &str = "next_freeze_seg";
const META_SCHEMA_VERSION: &str = "schema_version";

/// In-band layout version this build reads and writes.
///
/// redb's `TypeName` check catches key/value *type* drift (the typed-key
/// retrofit trips it for CT-1/CT-2 stores automatically), but codec layout
/// changes inside a same-width value — e.g. a field landing in a
/// previously-zeroed free range of `&[u8; 192]` — are invisible to it.
/// This cell is the loud guard for that class. CT-1/CT-2 stores are
/// implicitly version 1 (cell absent); the CT-3a schema (pending table +
/// `creation_height` in `leaf_meta`) is version 2; version 3 (CT-3b) is
/// **byte-identical to version 2** but changes the *contract*: the client
/// maintains the pending table on every ingest and resume reads it as the
/// source of truth for undrained leaves. A store synced in the CT-3a
/// window (drained table populated through the `append_drained` wrapper,
/// pending table never maintained) is v2-valid and silently wrong under
/// the v3 contract — resume would drop every undrained leaf and fail as
/// a baffling root mismatch at the first post-resume drain. The bump
/// retires that shape with a typed error. Pre-genesis disposition for a
/// mismatch: delete the store and re-sync (`15-deletion-and-debt.mdc` —
/// no in-Shekyl migration code).
const SCHEMA_VERSION: u64 = 3;

/// The CT-3a layout version: same byte layout as [`SCHEMA_VERSION`] 3 but
/// without the maintained-pending-table contract. Test-only — production
/// code never writes it.
#[cfg(test)]
const CT3A_SCHEMA_VERSION: u64 = 2;

/// Version reported for a store whose `schema_version` cell is absent —
/// the implicit CT-1/CT-2 layout.
const IMPLICIT_SCHEMA_VERSION: u64 = 1;

/// Peak memory bound when truncating large leaf ranges during reorg.
const TRUNCATE_DELETE_BATCH: usize = 256;

/// On-disk record for a frozen segment (`CT1_ROUND1_PINS.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenSegmentRecord {
    pub r_k: [u8; 32],
    pub end_tree_pos: TreePosition,
    pub end_block_height: BlockHeight,
    pub frozen_at_height: BlockHeight,
}

/// Persistent curve-tree leaf store (redb).
pub struct LeafStore {
    db: Database,
}

impl std::fmt::Debug for LeafStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafStore").finish_non_exhaustive()
    }
}

/// Store operation error.
#[derive(Debug)]
pub enum StoreError {
    /// redb failure.
    Redb(Box<redb::Error>),
    /// Leaf meta decode failure.
    CorruptMeta(&'static str),
    /// Truncation position exceeds the stored leaf count.
    InvalidTruncate { pos: u64, leaf_count: u64 },
    /// `root_at_count` requested more leaves than are persisted.
    LeafCountOutOfBounds { requested: u64, stored: u64 },
    /// Mixed-composition root failed for a non-recoverable reason.
    MixedComposition(MixedRootError),
    /// Truncation would retain a prefix with pruned leaf bytes but without
    /// the frozen `R_k` needed to query it — caller must rebuild the store.
    TruncatedIntoPrunedRange { pos: u64 },
    /// `append_drained` was handed leaf bytes that are not four canonical
    /// Selene scalars. Rejected at write time so invalid bytes can never
    /// poison the persisted stream (they would otherwise surface only later
    /// as a root-composition failure).
    InvalidLeafBytes {
        /// Index of the offending entry within the append batch.
        batch_index: usize,
    },
    /// `rollback_to_fork` was asked to roll back above the synced tip —
    /// a caller bug (there is nothing above the tip to roll back), never
    /// a recoverable store state.
    InvalidRollback {
        /// Fork height the caller requested.
        fork_height: u64,
        /// Synced tip height currently persisted.
        sync_tip: u64,
    },
    /// A pending-table insert would overwrite an existing row at the same
    /// gindex. A gindex is in exactly one of {drained, pending}; an insert
    /// colliding with a live pending row is an invariant breach, rejected
    /// rather than silently clobbered.
    PendingGindexCollision {
        /// Global output index of the colliding row.
        gindex: u64,
    },
    /// A pending-table removal named a gindex that is not present. Every
    /// drained leaf was necessarily pending first (minimum lock rules out
    /// same-block create-and-drain) and prune never touches the pending
    /// table, so a missing removal target is a caller bug or corruption —
    /// loud, not tolerated.
    PendingRowMissing {
        /// Global output index the removal targeted.
        gindex: u64,
    },
    /// Resume found the same gindex in both the drained and pending
    /// tables. A gindex is in exactly one of {drained, pending}; a
    /// cross-table duplicate is store corruption (the colliding value is
    /// carried so logs identify it for forensics).
    DuplicateGindex {
        /// Global output index present in both tables.
        gindex: u64,
    },
    /// The freeze cursor claims `segment` is frozen, but the frozen-segment
    /// table has no row for it. This is metadata corruption: `None` is not a
    /// clean "nothing to verify" result when the cursor names the segment.
    FrozenSegmentRecordMissing {
        /// Segment whose frozen record is absent.
        segment: SegmentId,
    },
    /// A frozen segment's stored `R_k` does not match recomputation from the
    /// full leaf bytes. This is the F9 stale/corrupt frozen metadata guard.
    FrozenSegmentRkMismatch {
        /// Segment whose root disagreed.
        segment: SegmentId,
        /// `R_k` persisted in the frozen-segment row.
        expected: [u8; 32],
        /// `R_k` recomputed from the present leaf bytes.
        recomputed: [u8; 32],
    },
    /// The store's in-band layout version stamp disagrees with this build.
    /// redb's `TypeName` check only catches key/value *type* drift; codec
    /// layout changes inside a same-width value are invisible to it, so the
    /// version cell is the loud guard. Pre-genesis disposition: delete the
    /// store and re-sync (no in-Shekyl migration code).
    SchemaVersionMismatch {
        /// Version found in the store (`1` when the cell is absent — the
        /// implicit CT-1/CT-2 layout).
        found: u64,
        /// Version this build reads and writes.
        expected: u64,
    },
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(Box::new(e))
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl LeafStore {
    /// Open (or create) a persistent store at `path`.
    ///
    /// Stamp-on-create-only contract: a newly created database file is
    /// stamped with the current [`SCHEMA_VERSION`]; an **existing** file
    /// has its version cell read-and-checked **before any write
    /// whatsoever** — reaching the open-or-create [`Self::init_tables`]
    /// path first would stamp a stale store to the current version in
    /// passing and the mismatch could never fire. On
    /// [`StoreError::SchemaVersionMismatch`] the store is unmodified
    /// (error-without-mutation at the open boundary).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let existed = path.as_ref().exists();
        let db = Database::create(path).map_err(StoreError::from)?;
        let store = Self { db };
        if existed {
            store.check_schema_version()?;
        }
        store.init_tables()?;
        Ok(store)
    }

    /// Ephemeral in-memory store (tests and default client).
    pub fn open_ephemeral() -> Result<Self, StoreError> {
        let db = Database::builder()
            .create_with_backend(InMemoryBackend::new())
            .map_err(StoreError::from)?;
        let store = Self { db };
        store.init_tables()?;
        Ok(store)
    }

    /// Read-and-check the schema version of an existing store, in a read
    /// transaction (no write side effects). A store without the version
    /// cell — or without a meta table at all — is the implicit version-1
    /// (CT-1/CT-2) layout.
    fn check_schema_version(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_read()?;
        let found = match txn.open_table(META_TABLE) {
            Ok(meta) => meta
                .get(META_SCHEMA_VERSION)?
                .map(|v| v.value())
                .unwrap_or(IMPLICIT_SCHEMA_VERSION),
            Err(redb::TableError::TableDoesNotExist(_)) => IMPLICIT_SCHEMA_VERSION,
            Err(e) => return Err(e.into()),
        };
        if found != SCHEMA_VERSION {
            return Err(StoreError::SchemaVersionMismatch {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    fn init_tables(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.open_table(LEAVES_TABLE)?;
        txn.open_table(LEAF_META_TABLE)?;
        txn.open_table(FROZEN_SEGMENTS_TABLE)?;
        txn.open_table(OWNED_IDENTITIES_TABLE)?;
        txn.open_table(PINNED_SEGMENTS_TABLE)?;
        txn.open_table(PENDING_TABLE)?;
        {
            let mut meta = txn.open_table(META_TABLE)?;
            if meta.get(META_LEAF_COUNT)?.is_none() {
                meta.insert(META_LEAF_COUNT, &0u64)?;
            }
            if meta.get(META_SYNC_TIP)?.is_none() {
                meta.insert(META_SYNC_TIP, &0u64)?;
            }
            if meta.get(META_NEXT_FREEZE_SEG)?.is_none() {
                meta.insert(META_NEXT_FREEZE_SEG, &0u64)?;
            }
            // Safe to stamp unconditionally: `open` checks an existing
            // file's version before this runs, so the only values that
            // can reach this insert are "absent" (fresh create / `clear`)
            // or the current version (idempotent re-stamp).
            meta.insert(META_SCHEMA_VERSION, &SCHEMA_VERSION)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Wipe all leaves and metadata (full chain replay / reorg rebuild).
    pub fn clear(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.delete_table(LEAVES_TABLE)?;
        txn.delete_table(LEAF_META_TABLE)?;
        txn.delete_table(FROZEN_SEGMENTS_TABLE)?;
        txn.delete_table(OWNED_IDENTITIES_TABLE)?;
        txn.delete_table(PINNED_SEGMENTS_TABLE)?;
        // A missed table here leaves stale pending rows that would corrupt
        // a subsequent `from_blocks` rebuild — pinned by the clear test.
        txn.delete_table(PENDING_TABLE)?;
        txn.delete_table(META_TABLE)?;
        txn.commit()?;
        self.init_tables()
    }

    /// Drained leaf count in the store.
    pub fn leaf_count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META_TABLE)?;
        Ok(meta.get(META_LEAF_COUNT)?.map(|v| v.value()).unwrap_or(0))
    }

    /// Synced chain tip height last written by the client.
    pub fn sync_tip_height(&self) -> Result<BlockHeight, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META_TABLE)?;
        Ok(BlockHeight(
            meta.get(META_SYNC_TIP)?.map(|v| v.value()).unwrap_or(0),
        ))
    }

    /// Append newly drained leaves and advance sync tip in one ACID write txn.
    ///
    /// Thin wrapper over [`Self::append_block_deltas`] with empty pending
    /// deltas — keeps CT-1/CT-2 callers and KATs byte-identical.
    pub fn append_drained(
        &self,
        entries: &[LeafEntry],
        tip_height: BlockHeight,
    ) -> Result<(), StoreError> {
        self.append_block_deltas(entries, &[], &[], tip_height)
    }

    /// Apply one ingested block's store deltas in a single ACID write txn:
    ///
    /// 1. append `drained` to the leaf tables (positions follow the
    ///    persisted leaf count in batch order);
    /// 2. remove `pending_removed` from the pending table — **every**
    ///    target must be present ([`StoreError::PendingRowMissing`]):
    ///    each drained leaf was necessarily pending first (minimum lock
    ///    ≥ 10 blocks rules out same-block create-and-drain) and prune
    ///    never touches the pending table, so a missing target is a
    ///    caller bug or corruption, not a tolerable state;
    /// 3. insert `pending_added` keyed by gindex — an existing row at the
    ///    same gindex is an invariant breach
    ///    ([`StoreError::PendingGindexCollision`]), never clobbered;
    /// 4. advance `META_SYNC_TIP` (monotonic) and re-evaluate segment
    ///    freezes.
    ///
    /// Leaf bytes in both `drained` and `pending_added` are validated as
    /// four canonical Selene scalars ([`StoreError::InvalidLeafBytes`],
    /// `batch_index` counting `drained` first, then `pending_added`). Any
    /// error aborts the whole transaction — no delta partially lands.
    ///
    /// All-empty deltas still advance the tip and freeze clock, exactly
    /// like the empty [`Self::append_drained`] of CT-1/CT-2.
    pub fn append_block_deltas(
        &self,
        drained: &[LeafEntry],
        pending_added: &[LeafEntry],
        pending_removed: &[Gindex],
        tip_height: BlockHeight,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        let mut leaf_count = {
            let meta = txn.open_table(META_TABLE)?;
            let v = meta.get(META_LEAF_COUNT)?;
            v.map(|g| g.value()).unwrap_or(0)
        };
        if !drained.is_empty() {
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            for (batch_index, entry) in drained.iter().enumerate() {
                if !leaf_bytes_are_canonical(&entry.leaf) {
                    return Err(StoreError::InvalidLeafBytes { batch_index });
                }
                let pos = TreePosition(leaf_count);
                leaves.insert(pos, &entry.leaf)?;
                leaf_meta.insert(pos, &encode_leaf_meta(entry))?;
                leaf_count += 1;
            }
        }
        if !pending_removed.is_empty() || !pending_added.is_empty() {
            let mut pending = txn.open_table(PENDING_TABLE)?;
            for &gindex in pending_removed {
                if pending.remove(gindex)?.is_none() {
                    return Err(StoreError::PendingRowMissing { gindex: gindex.0 });
                }
            }
            for (offset, entry) in pending_added.iter().enumerate() {
                if !leaf_bytes_are_canonical(&entry.leaf) {
                    return Err(StoreError::InvalidLeafBytes {
                        batch_index: drained.len() + offset,
                    });
                }
                if pending.get(entry.gindex)?.is_some() {
                    return Err(StoreError::PendingGindexCollision {
                        gindex: entry.gindex.0,
                    });
                }
                pending.insert(entry.gindex, &encode_pending(entry))?;
            }
        }
        let effective_tip = {
            let meta = txn.open_table(META_TABLE)?;
            let sync_tip = meta.get(META_SYNC_TIP)?.map(|v| v.value()).unwrap_or(0);
            tip_height.0.max(sync_tip)
        };
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_LEAF_COUNT, &leaf_count)?;
            meta.insert(META_SYNC_TIP, &effective_tip)?;
        }
        let next_freeze_seg = Self::maybe_freeze_segments_in_txn(&txn, effective_tip, leaf_count)?;
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_NEXT_FREEZE_SEG, &next_freeze_seg)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// All pending (not yet drained) leaves, in gindex order — the resume
    /// read path's pending half (CT-3b rebuilds the client's undrained set
    /// from this).
    ///
    /// Corruption-loud: any row that fails to decode is
    /// [`StoreError::CorruptMeta`] — no skip-and-continue, a corrupt
    /// pending row is a hard error, not a silently dropped output.
    pub fn read_pending_candidates(&self) -> Result<Vec<LeafEntry>, StoreError> {
        let txn = self.db.begin_read()?;
        let pending = txn.open_table(PENDING_TABLE)?;
        let mut out = Vec::new();
        for row in pending.iter()? {
            let (key, value) = row?;
            let entry = decode_pending(value.value())?;
            if entry.gindex != key.value() {
                return Err(StoreError::CorruptMeta(
                    "pending row gindex disagrees with its key",
                ));
            }
            out.push(entry);
        }
        Ok(out)
    }

    /// All drained leaves still present in the store, in tree-position
    /// order — the resume read path's drained half. Pruned positions
    /// (non-owned leaf bytes dropped by [`Self::prune_frozen`]) are simply
    /// absent; CT-3b rebuilds `entries`/`entries_by_maturity`/`next_gindex`
    /// from this plus [`Self::read_pending_candidates`] and
    /// [`Self::sync_tip_height`].
    ///
    /// Two structural invariants are runtime-checked on every scan:
    ///
    /// - **Key-set symmetry**: `leaves` and `leaf_meta` are written and
    ///   deleted in lockstep everywhere (append, truncate, prune), so any
    ///   asymmetry is corruption — [`StoreError::CorruptMeta`],
    ///   unconditionally (no pruned-range carve-out exists).
    /// - **Drain-order monotonicity (P7)**: `maturity` must be
    ///   non-decreasing in position order. The rollback partition search
    ///   rests on this S8 invariant; checking it here converts a
    ///   design-doc assumption into a precondition verified on every
    ///   resume, at one comparison per row.
    pub fn read_drained_entries(&self) -> Result<Vec<LeafEntry>, StoreError> {
        let txn = self.db.begin_read()?;
        let leaves = txn.open_table(LEAVES_TABLE)?;
        let meta = txn.open_table(LEAF_META_TABLE)?;
        let mut out = Vec::new();
        let mut last_maturity: Option<BlockHeight> = None;
        let mut leaves_iter = leaves.iter()?;
        let mut meta_iter = meta.iter()?;
        loop {
            let entry = match (leaves_iter.next(), meta_iter.next()) {
                (None, None) => break,
                (Some(leaf_row), Some(meta_row)) => {
                    let (leaf_key, leaf_value) = leaf_row?;
                    let (meta_key, meta_value) = meta_row?;
                    if leaf_key.value() != meta_key.value() {
                        return Err(StoreError::CorruptMeta(
                            "leaves/leaf_meta key-set asymmetry",
                        ));
                    }
                    let stored = decode_stored_leaf_meta(meta_value.value())?;
                    LeafEntry {
                        gindex: stored.gindex,
                        maturity: stored.maturity,
                        creation_height: stored.creation_height,
                        leaf: *leaf_value.value(),
                        identity: stored.identity,
                    }
                }
                _ => {
                    return Err(StoreError::CorruptMeta(
                        "leaves/leaf_meta key-set asymmetry",
                    ));
                }
            };
            if last_maturity.is_some_and(|prev| entry.maturity < prev) {
                return Err(StoreError::CorruptMeta(
                    "drain-order maturity regression in persisted leaves",
                ));
            }
            last_maturity = Some(entry.maturity);
            out.push(entry);
        }
        Ok(out)
    }

    /// Scan only from the persisted freeze cursor forward (O(newly eligible)
    /// per block, not O(total segments)).
    fn maybe_freeze_segments_in_txn(
        txn: &redb::WriteTransaction,
        tip_height: u64,
        leaf_count: u64,
    ) -> Result<u64, StoreError> {
        let e = leaves_per_segment() as u64;
        let complete_segments = leaf_count / e;
        let mut next_freeze_seg = {
            let meta = txn.open_table(META_TABLE)?;
            let next = meta.get(META_NEXT_FREEZE_SEG)?;
            next.map(|v| v.value()).unwrap_or(0)
        };
        let mut seg_k = next_freeze_seg;
        while seg_k < complete_segments {
            let segment_id = SegmentId(u32::try_from(seg_k).expect("segment id fits u32"));
            {
                let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
                if frozen.get(segment_id)?.is_some() {
                    seg_k += 1;
                    next_freeze_seg = seg_k;
                    continue;
                }
            }
            let end_tree_pos = (seg_k + 1) * e - 1;
            let end_block_height = read_drain_height(txn, end_tree_pos)?;
            if !segment_freeze_eligible(tip_height, end_block_height) {
                break;
            }
            let start = seg_k * e;
            let seg_leaves = read_leaf_bytes_range(txn, start, end_tree_pos + 1)?;
            let r_k = recompute_segment_r_k(&seg_leaves).map_err(store_mixed_root_err)?;
            let record = FrozenSegmentRecord {
                r_k,
                end_tree_pos: TreePosition(end_tree_pos),
                end_block_height: BlockHeight(end_block_height),
                frozen_at_height: BlockHeight(tip_height),
            };
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            frozen.insert(segment_id, &encode_frozen_segment(&record))?;
            seg_k += 1;
            next_freeze_seg = seg_k;
        }
        Ok(next_freeze_seg)
    }

    /// Freeze any newly eligible complete segments at `tip_height`.
    pub fn maybe_freeze_segments(&self, tip_height: BlockHeight) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        // Leaf count is read inside the write txn so the freeze scan and its
        // commit see one consistent snapshot (no check/use gap).
        let leaf_count = {
            let meta = txn.open_table(META_TABLE)?;
            let v = meta.get(META_LEAF_COUNT)?;
            v.map(|g| g.value()).unwrap_or(0)
        };
        let next_freeze_seg = Self::maybe_freeze_segments_in_txn(&txn, tip_height.0, leaf_count)?;
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_NEXT_FREEZE_SEG, &next_freeze_seg)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Curve-tree root for the first `leaf_count` drained leaves (hot path).
    pub fn root_at_count(&self, leaf_count: u64) -> Result<[u8; 32], StoreError> {
        if leaf_count == 0 {
            return Ok(selene_hash_init());
        }
        let txn = self.db.begin_read()?;
        // Bounds check and leaf reads share the one read txn (one snapshot).
        let stored = {
            let meta = txn.open_table(META_TABLE)?;
            let v = meta.get(META_LEAF_COUNT)?;
            v.map(|g| g.value()).unwrap_or(0)
        };
        if leaf_count > stored {
            return Err(StoreError::LeafCountOutOfBounds {
                requested: leaf_count,
                stored,
            });
        }
        let e = leaves_per_segment() as u64;
        let complete = leaf_count / e;
        let mut frozen_r: Vec<[u8; 32]> = Vec::new();
        {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            for k in 0..complete {
                let id = SegmentId(u32::try_from(k).expect("segment key fits u32"));
                if let Some(v) = frozen.get(id)? {
                    frozen_r.push(decode_frozen_segment(v.value()).r_k);
                } else {
                    let start = k * e;
                    let end = start + e;
                    let seg_leaves = read_leaf_bytes_range_read(&txn, start, end)?;
                    frozen_r
                        .push(recompute_segment_r_k(&seg_leaves).map_err(store_mixed_root_err)?);
                }
            }
        }
        let tail_start = complete * e;
        let tail = read_leaf_bytes_range_read(&txn, tail_start, leaf_count)?;
        match mixed_composition_root(leaf_count, &frozen_r, &tail) {
            Ok(root) => Ok(root),
            Err(MixedRootError::TailTooShortForLayerJ) => {
                match read_leaf_bytes_range_read(&txn, 0, leaf_count) {
                    Ok(all_leaves) => full_build_root(&all_leaves).map_err(store_mixed_root_err),
                    Err(_) => Err(StoreError::CorruptMeta(
                        "mixed root failed with incomplete leaf range (post-prune)",
                    )),
                }
            }
            Err(err) => Err(store_mixed_root_err(err)),
        }
    }

    /// Truncate leaves and metadata at `pos` (ACID reorg).
    ///
    /// Resets [`Self::sync_tip_height`] to `0` (sync invalidated until the next
    /// [`Self::append_drained`]) and recomputes the segment-freeze cursor.
    pub fn truncate_from_tree_position(&self, pos: TreePosition) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        Self::truncate_internals(&txn, pos, BlockHeight(0))?;
        txn.commit()?;
        Ok(())
    }

    /// Shared truncation core: partition delete on the leaf tables,
    /// frozen/pinned segment-row rollback (F9), freeze-cursor recompute,
    /// and leaf-count/tip reset — inside the caller's transaction, so
    /// [`Self::truncate_from_tree_position`] (`new_tip = 0`: sync
    /// invalidated) and [`Self::rollback_to_fork`] (`new_tip = fork`)
    /// share one implementation. Two truncation bodies would let the F9
    /// freeze-awareness drift apart.
    fn truncate_internals(
        txn: &redb::WriteTransaction,
        pos: TreePosition,
        new_tip: BlockHeight,
    ) -> Result<(), StoreError> {
        let pos = pos.0;
        // Bounds check inside the write txn (one snapshot); the caller
        // dropping the uncommitted txn on error aborts it.
        let current_leaf_count = {
            let meta = txn.open_table(META_TABLE)?;
            let v = meta.get(META_LEAF_COUNT)?;
            v.map(|g| g.value()).unwrap_or(0)
        };
        if pos > current_leaf_count {
            return Err(StoreError::InvalidTruncate {
                pos,
                leaf_count: current_leaf_count,
            });
        }
        {
            let e = leaves_per_segment() as u64;
            if pos > 0 && !pos.is_multiple_of(e) {
                let leaves = txn.open_table(LEAVES_TABLE)?;
                let seg_start = ((pos - 1) / e) * e;
                for p in seg_start..pos {
                    if leaves.get(TreePosition(p))?.is_none() {
                        return Err(StoreError::TruncatedIntoPrunedRange { pos: p });
                    }
                }
            }
        }
        {
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            delete_pos_range_batched(&mut leaves, &mut leaf_meta, TreePosition(pos))?;
        }
        {
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            let e = leaves_per_segment() as u64;
            if pos == 0 {
                delete_seg_keys_batched(&mut frozen, SegmentId(0))?;
            } else {
                let max_segment = (pos - 1) / e;
                delete_seg_keys_batched(
                    &mut frozen,
                    SegmentId(u32::try_from(max_segment + 1).expect("segment range fits u32")),
                )?;
                // Drop frozen segment that partially overlaps the truncation boundary.
                if !pos.is_multiple_of(e) {
                    let partial_id = (pos - 1) / e;
                    frozen.remove(SegmentId(
                        u32::try_from(partial_id).expect("segment id fits u32"),
                    ))?;
                }
            }
        }
        {
            let mut owned = txn.open_table(OWNED_IDENTITIES_TABLE)?;
            delete_pos_keys_batched(&mut owned, TreePosition(pos))?;
        }
        {
            let mut pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            let e = leaves_per_segment() as u64;
            if pos == 0 {
                delete_seg_keys_batched(&mut pinned, SegmentId(0))?;
            } else {
                let max_segment = (pos - 1) / e;
                delete_seg_keys_batched(
                    &mut pinned,
                    SegmentId(u32::try_from(max_segment + 1).expect("segment range fits u32")),
                )?;
                if !pos.is_multiple_of(e) {
                    let partial_id = (pos - 1) / e;
                    pinned.remove(SegmentId(
                        u32::try_from(partial_id).expect("segment id fits u32"),
                    ))?;
                }
            }
        }
        let next_freeze_seg = recompute_next_freeze_seg(txn, pos)?;
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_LEAF_COUNT, &pos)?;
            meta.insert(META_SYNC_TIP, &new_tip.0)?;
            meta.insert(META_NEXT_FREEZE_SEG, &next_freeze_seg)?;
        }
        Ok(())
    }

    /// Roll the store back to `fork_height` after a reorg, in one ACID
    /// write txn (CT3_SYNC.md R1-Q3, amended two-class form):
    ///
    /// 1. **Partition search (pruned-range-safe, P1/F7).** Drained rows
    ///    are maturity-sorted in position order (the P7 invariant), so the
    ///    cut point is `partition_point(maturity >
    ///    drained_through(fork_height))` — the *first* index of an
    ///    equal-maturity run. A store synced through block `F` has drained
    ///    leaves through `F - 1`; leaves maturing exactly at `F` enter on
    ///    connection of block `F + 1` and must be pending after rollback.
    ///    Probes run over the present suffix `[pruned frontier, leaf_count)`
    ///    only, so a post-prune store can never `None`-probe. A partition
    ///    resolving at a non-zero frontier means the cut lands at/below pruned rows:
    ///    [`StoreError::TruncatedIntoPrunedRange`], before any write.
    ///    (Intentionally conservative when `partition == frontier > 0`
    ///    would be a valid exact-boundary cut: pruned segments are buried
    ///    beyond `SPENDABLE_AGE + 720`, so no plausible fork makes that
    ///    cut valid — rejecting unconditionally avoids reasoning about
    ///    rows that no longer exist. Do not "fix" this.)
    /// 2. **Read-before-delete migration.** The truncated suffix is read
    ///    in full (leaf bytes + meta, including `creation_height`) before
    ///    any delete — `leaf_meta` alone does not carry the leaf bytes.
    /// 3. [`Self::truncate_internals`] — shared with
    ///    [`Self::truncate_from_tree_position`], so frozen/pinned segment
    ///    rollback (F9) and the freeze-cursor recompute cannot drift; the
    ///    tip resets to `fork_height` (not 0 — the store is still synced,
    ///    just shorter).
    /// 4. Migrated rows re-enter the pending table (collision-checked,
    ///    same discipline as [`Self::append_block_deltas`]).
    /// 5. Pending rows with `creation_height > fork_height` are deleted —
    ///    the uniform class-(a) filter, catching orphaned-block outputs
    ///    whether they were still pending or just migrated. Class (b)
    ///    (created on the shared prefix, drained on the orphaned suffix)
    ///    survives by composition: migrated in step 4, passes the filter,
    ///    re-drains on re-sync.
    ///
    /// `fork_height` above the synced tip is a caller bug
    /// ([`StoreError::InvalidRollback`]); there is nothing above the tip
    /// to roll back.
    pub fn rollback_to_fork(&self, fork_height: BlockHeight) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        let (sync_tip, leaf_count) = {
            let meta = txn.open_table(META_TABLE)?;
            let tip = meta.get(META_SYNC_TIP)?.map(|v| v.value()).unwrap_or(0);
            let count = meta.get(META_LEAF_COUNT)?.map(|v| v.value()).unwrap_or(0);
            (tip, count)
        };
        if fork_height.0 > sync_tip {
            return Err(StoreError::InvalidRollback {
                fork_height: fork_height.0,
                sync_tip,
            });
        }

        // Steps 1–2 under a scoped read of the leaf tables.
        let (partition, migrated) = {
            let leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            let leaves = txn.open_table(LEAVES_TABLE)?;
            // Pruned frontier: lowest present meta position. Prune only
            // ever removes a prefix of frozen segments (pin_segment has no
            // production caller, so interior holes cannot occur); an empty
            // table degenerates to frontier == leaf_count and the search
            // range is empty.
            let frontier = match leaf_meta.iter()?.next().transpose()? {
                Some((key, _)) => key.value().0,
                None => leaf_count,
            };
            let maturity_at = |pos: u64| -> Result<u64, StoreError> {
                let row = leaf_meta
                    .get(TreePosition(pos))?
                    .ok_or(StoreError::CorruptMeta(
                        "hole in present suffix during partition search",
                    ))?;
                Ok(decode_stored_leaf_meta(row.value())?.maturity.0)
            };
            // partition_point over [frontier, leaf_count): first present
            // position with maturity > drained_through(fork). Maturity is
            // non-decreasing (P7), so this lands on the first index of an
            // equal-maturity run (F7). Height 0 saturates at cutoff 0; no
            // real leaf has maturity 0, so genesis rollback still truncates
            // the whole drained tree.
            let drain_cutoff = fork_height.0.saturating_sub(1);
            let mut lo = frontier;
            let mut hi = leaf_count;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if maturity_at(mid)? > drain_cutoff {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            let partition = lo;
            if partition == frontier && frontier > 0 {
                return Err(StoreError::TruncatedIntoPrunedRange { pos: frontier });
            }
            // Read-before-delete: reconstitute full pending rows from the
            // suffix while both tables still hold it.
            let mut migrated = Vec::with_capacity(
                usize::try_from(leaf_count - partition).expect("suffix fits usize"),
            );
            for pos in (partition..leaf_count).map(TreePosition) {
                let meta_row = leaf_meta
                    .get(pos)?
                    .ok_or(StoreError::CorruptMeta("missing leaf meta in suffix"))?;
                let stored = decode_stored_leaf_meta(meta_row.value())?;
                let leaf_row = leaves
                    .get(pos)?
                    .ok_or(StoreError::CorruptMeta("missing leaf bytes in suffix"))?;
                migrated.push(LeafEntry {
                    gindex: stored.gindex,
                    maturity: stored.maturity,
                    creation_height: stored.creation_height,
                    leaf: *leaf_row.value(),
                    identity: stored.identity,
                });
            }
            (partition, migrated)
        };

        // Step 3: shared truncation core (F9 freeze-aware), tip = fork.
        Self::truncate_internals(&txn, TreePosition(partition), fork_height)?;

        // Steps 4–5: migrate to pending, then the uniform class-(a) filter.
        {
            let mut pending = txn.open_table(PENDING_TABLE)?;
            for entry in &migrated {
                if pending.get(entry.gindex)?.is_some() {
                    return Err(StoreError::PendingGindexCollision {
                        gindex: entry.gindex.0,
                    });
                }
                pending.insert(entry.gindex, &encode_pending(entry))?;
            }
            let mut orphaned = Vec::new();
            for row in pending.iter()? {
                let (key, value) = row?;
                if decode_pending(value.value())?.creation_height > fork_height {
                    orphaned.push(key.value());
                }
            }
            for gindex in orphaned {
                pending.remove(gindex)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Pin segment `id` so [`Self::prune_frozen`] retains its full leaf bytes.
    ///
    /// Pin before pruning any segment whose full chunk contents may be needed
    /// later (root queries below the frozen boundary, or store-backed branch
    /// reads). Path assembly today rebuilds branches from the client's
    /// replay-held entries, so pruning does not break it; pinning is the
    /// store-level escape hatch if that ever changes.
    pub fn pin_segment(&self, id: SegmentId) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            pinned.insert(id, &1u32)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Prune frozen, unpinned segments down to their `R_k` records.
    ///
    /// Leaf bytes at `owned_positions` are copied into the owned-identities
    /// table before removal — the owned *leaf record* is retained, not the
    /// surrounding chunk. Root composition over a pruned segment uses the
    /// frozen `R_k`; anything needing a pruned segment's full chunk contents
    /// must have pinned it first ([`Self::pin_segment`]). All leaf bytes are
    /// reconstructible by chain replay regardless.
    pub fn prune_frozen(&self, owned_positions: &[TreePosition]) -> Result<(), StoreError> {
        let owned: std::collections::BTreeSet<TreePosition> =
            owned_positions.iter().copied().collect();
        let txn = self.db.begin_write()?;
        let e = leaves_per_segment() as u64;
        let frozen_ids: Vec<SegmentId> = {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            frozen
                .iter()?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?
        };
        let pinned: std::collections::BTreeSet<SegmentId> = {
            let pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            pinned
                .iter()?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        };
        {
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            let mut owned_tbl = txn.open_table(OWNED_IDENTITIES_TABLE)?;
            for seg_id in frozen_ids {
                if pinned.contains(&seg_id) {
                    continue;
                }
                let start = u64::from(seg_id.0) * e;
                let end = start + e;
                for pos in (start..end).map(TreePosition) {
                    let leaf_bytes = match leaves.get(pos)? {
                        Some(leaf) => *leaf.value(),
                        None => continue,
                    };
                    if owned.contains(&pos) {
                        owned_tbl.insert(pos, &leaf_bytes)?;
                    }
                    leaves.remove(pos)?;
                    drop(leaf_meta.remove(pos)?);
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Read frozen segment record, if present.
    pub fn frozen_segment(&self, id: SegmentId) -> Result<Option<FrozenSegmentRecord>, StoreError> {
        let txn = self.db.begin_read()?;
        let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
        Ok(frozen.get(id)?.map(|v| decode_frozen_segment(v.value())))
    }

    /// Recompute the boundary-adjacent frozen segment's `R_k`.
    ///
    /// The freeze cursor names the next segment to freeze, so `cursor - 1`
    /// is the highest frozen row and the rollback-boundary witness CT-3c
    /// checks after `rollback_to_fork`. This is intentionally O(one
    /// segment), not a full-store scan.
    pub(crate) fn verify_frozen_tail(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_read()?;
        let next_freeze_seg = {
            let meta = txn.open_table(META_TABLE)?;
            meta.get(META_NEXT_FREEZE_SEG)?
                .map(|v| v.value())
                .unwrap_or(0)
        };
        if next_freeze_seg == 0 {
            return Ok(());
        }

        let segment = SegmentId(u32::try_from(next_freeze_seg - 1).expect("segment id fits u32"));
        let record = {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            match frozen.get(segment)? {
                Some(row) => decode_frozen_segment(row.value()),
                None => return Err(StoreError::FrozenSegmentRecordMissing { segment }),
            }
        };
        let e = leaves_per_segment() as u64;
        let start = u64::from(segment.0) * e;
        let leaves = read_leaf_bytes_range_read(&txn, start, start + e)?;
        let recomputed = recompute_segment_r_k(&leaves).map_err(store_mixed_root_err)?;
        if recomputed != record.r_k {
            return Err(StoreError::FrozenSegmentRkMismatch {
                segment,
                expected: record.r_k,
                recomputed,
            });
        }
        Ok(())
    }
}

fn delete_pos_keys_batched<V: redb::Value>(
    table: &mut redb::Table<'_, TreePosition, V>,
    start: TreePosition,
) -> Result<(), StoreError> {
    loop {
        let batch: Vec<TreePosition> = table
            .range(start..)?
            .take(TRUNCATE_DELETE_BATCH)
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()?;
        if batch.is_empty() {
            break;
        }
        for key in batch {
            table.remove(key)?;
        }
    }
    Ok(())
}

fn delete_pos_range_batched(
    leaves: &mut redb::Table<'_, TreePosition, &[u8; 128]>,
    leaf_meta: &mut redb::Table<'_, TreePosition, &[u8; 192]>,
    start: TreePosition,
) -> Result<(), StoreError> {
    loop {
        let batch: Vec<TreePosition> = leaves
            .range(start..)?
            .take(TRUNCATE_DELETE_BATCH)
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()?;
        if batch.is_empty() {
            break;
        }
        for key in batch {
            leaves.remove(key)?;
            drop(leaf_meta.remove(key)?);
        }
    }
    Ok(())
}

fn delete_seg_keys_batched<V: redb::Value>(
    table: &mut redb::Table<'_, SegmentId, V>,
    start: SegmentId,
) -> Result<(), StoreError> {
    loop {
        let batch: Vec<SegmentId> = table
            .range(start..)?
            .take(TRUNCATE_DELETE_BATCH)
            .map(|r| r.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()?;
        if batch.is_empty() {
            break;
        }
        for key in batch {
            table.remove(key)?;
        }
    }
    Ok(())
}

fn recompute_next_freeze_seg(
    txn: &redb::WriteTransaction,
    leaf_count: u64,
) -> Result<u64, StoreError> {
    let e = leaves_per_segment() as u64;
    let complete_segments = leaf_count / e;
    let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
    let mut next = 0u64;
    for seg_k in 0..complete_segments {
        let segment_id = SegmentId(u32::try_from(seg_k).expect("segment id fits u32"));
        if frozen.get(segment_id)?.is_some() {
            next = seg_k + 1;
        } else {
            break;
        }
    }
    Ok(next)
}

/// Whether `leaf` is four canonical Selene scalars, judged by the same
/// primitive the root hot path uses (`hash_grow_selene` fails on any
/// non-canonical child scalar). One Selene hash per leaf — negligible next
/// to the root recomputation each appended leaf already participates in.
fn leaf_bytes_are_canonical(leaf: &[u8; 128]) -> bool {
    let mut scalars = [[0u8; 32]; SCALARS_PER_LEAF];
    for (scalar, chunk) in scalars.iter_mut().zip(leaf.chunks_exact(32)) {
        scalar.copy_from_slice(chunk);
    }
    hash_grow_selene(&selene_hash_init(), 0, &[0u8; 32], &scalars).is_some()
}

fn read_drain_height(txn: &redb::WriteTransaction, tree_pos: u64) -> Result<u64, StoreError> {
    let meta = txn.open_table(LEAF_META_TABLE)?;
    let m = meta
        .get(TreePosition(tree_pos))?
        .ok_or(StoreError::CorruptMeta("missing leaf meta"))?;
    let stored = decode_stored_leaf_meta(m.value())?;
    Ok(stored.maturity.0.saturating_add(1))
}

/// Metadata persisted in `LEAF_META_TABLE` (leaf bytes live in `LEAVES_TABLE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredLeafMeta {
    gindex: Gindex,
    maturity: BlockHeight,
    creation_height: BlockHeight,
    identity: crate::types::OutputIdentity,
}

fn read_leaf_bytes_range(
    txn: &redb::WriteTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    let leaves = txn.open_table(LEAVES_TABLE)?;
    let cap = usize::try_from(end - start).expect("leaf range fits usize");
    let mut out = Vec::with_capacity(cap);
    for pos in (start..end).map(TreePosition) {
        let leaf = leaves
            .get(pos)?
            .ok_or(StoreError::CorruptMeta("missing leaf"))?;
        out.push(*leaf.value());
    }
    Ok(out)
}

fn read_leaf_bytes_range_read(
    txn: &redb::ReadTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    let leaves = txn.open_table(LEAVES_TABLE)?;
    let cap = usize::try_from(end - start).expect("leaf range fits usize");
    let mut out = Vec::with_capacity(cap);
    for pos in (start..end).map(TreePosition) {
        let leaf = leaves
            .get(pos)?
            .ok_or(StoreError::CorruptMeta("missing leaf"))?;
        out.push(*leaf.value());
    }
    Ok(out)
}

fn encode_frozen_segment(rec: &FrozenSegmentRecord) -> [u8; 56] {
    let mut buf = [0u8; 56];
    buf[..32].copy_from_slice(&rec.r_k);
    buf[32..40].copy_from_slice(&rec.end_tree_pos.0.to_be_bytes());
    buf[40..48].copy_from_slice(&rec.end_block_height.0.to_be_bytes());
    buf[48..56].copy_from_slice(&rec.frozen_at_height.0.to_be_bytes());
    buf
}

fn decode_frozen_segment(buf: &[u8; 56]) -> FrozenSegmentRecord {
    let mut r_k = [0u8; 32];
    r_k.copy_from_slice(&buf[..32]);
    FrozenSegmentRecord {
        r_k,
        end_tree_pos: TreePosition(u64::from_be_bytes(buf[32..40].try_into().expect("8 bytes"))),
        end_block_height: BlockHeight(u64::from_be_bytes(buf[40..48].try_into().expect("8 bytes"))),
        frozen_at_height: BlockHeight(u64::from_be_bytes(buf[48..56].try_into().expect("8 bytes"))),
    }
}

fn encode_leaf_meta(entry: &LeafEntry) -> [u8; 192] {
    let mut buf = [0u8; 192];
    buf[0..8].copy_from_slice(&entry.gindex.0.to_be_bytes());
    buf[8..16].copy_from_slice(&entry.maturity.0.to_be_bytes());
    buf[16..48].copy_from_slice(&entry.identity.output_key);
    match entry.identity.commitment {
        Some(c) => {
            buf[48] = 1;
            buf[49..81].copy_from_slice(&c);
        }
        None => buf[48] = 0,
    }
    buf[81..113].copy_from_slice(&entry.identity.h_pqc);
    buf[113] = encode_target(&entry.identity.target);
    if let TargetKind::StakedKey { lock_blocks } = entry.identity.target {
        buf[114..122].copy_from_slice(&lock_blocks.to_be_bytes());
    }
    // Schema v2: creation_height in the formerly-free range. The value
    // stays `&[u8; 192]` (TypeName unchanged), which is exactly why the
    // schema_version cell exists — redb cannot see this layout change.
    buf[122..130].copy_from_slice(&entry.creation_height.0.to_be_bytes());
    buf
}

fn decode_stored_leaf_meta(buf: &[u8; 192]) -> Result<StoredLeafMeta, StoreError> {
    let gindex = Gindex(u64::from_be_bytes(buf[0..8].try_into().expect("8 bytes")));
    let maturity = BlockHeight(u64::from_be_bytes(buf[8..16].try_into().expect("8 bytes")));
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&buf[16..48]);
    let commitment = match buf[48] {
        0 => None,
        1 => {
            let mut c = [0u8; 32];
            c.copy_from_slice(&buf[49..81]);
            Some(c)
        }
        _ => return Err(StoreError::CorruptMeta("invalid leaf commitment tag")),
    };
    let mut h_pqc = [0u8; 32];
    h_pqc.copy_from_slice(&buf[81..113]);
    let target = decode_target(buf[113], &buf[114..122])?;
    let creation_height = BlockHeight(u64::from_be_bytes(
        buf[122..130].try_into().expect("8 bytes"),
    ));
    Ok(StoredLeafMeta {
        gindex,
        maturity,
        creation_height,
        identity: crate::types::OutputIdentity {
            output_key,
            commitment,
            h_pqc,
            target,
        },
    })
}

/// Pending-row codec: `leaf[128] || encode_leaf_meta[192]` — the same
/// encoders as the drained tables, so a row migrates between pending and
/// drained without re-encoding (one layout, two tables).
fn encode_pending(entry: &LeafEntry) -> [u8; 320] {
    let mut buf = [0u8; 320];
    buf[..128].copy_from_slice(&entry.leaf);
    buf[128..].copy_from_slice(&encode_leaf_meta(entry));
    buf
}

/// Decode a pending row back to a [`LeafEntry`], corruption-loud: the
/// meta slice goes through the validating leaf-meta decoder, and the leaf
/// bytes are re-checked canonical (they were validated at write time, so
/// a failure here is store corruption, not caller error).
fn decode_pending(buf: &[u8; 320]) -> Result<LeafEntry, StoreError> {
    let mut leaf = [0u8; 128];
    leaf.copy_from_slice(&buf[..128]);
    if !leaf_bytes_are_canonical(&leaf) {
        return Err(StoreError::CorruptMeta("non-canonical pending leaf bytes"));
    }
    let meta: &[u8; 192] = buf[128..].try_into().expect("192-byte meta slice");
    let stored = decode_stored_leaf_meta(meta)?;
    Ok(LeafEntry {
        gindex: stored.gindex,
        maturity: stored.maturity,
        creation_height: stored.creation_height,
        leaf,
        identity: stored.identity,
    })
}

fn encode_target(target: &TargetKind) -> u8 {
    match target {
        TargetKind::TaggedKey => 0,
        TargetKind::Key => 1,
        TargetKind::StakedKey { .. } => 2,
        TargetKind::Other => 3,
    }
}

fn store_mixed_root_err(err: MixedRootError) -> StoreError {
    match err {
        MixedRootError::InvalidLeafScalars => {
            StoreError::CorruptMeta("invalid persisted leaf scalars")
        }
        other => StoreError::MixedComposition(other),
    }
}

fn decode_target(tag: u8, extra: &[u8]) -> Result<TargetKind, StoreError> {
    Ok(match tag {
        0 => TargetKind::TaggedKey,
        1 => TargetKind::Key,
        2 => {
            let lock_blocks = u64::from_be_bytes(extra[..8].try_into().expect("8 bytes"));
            TargetKind::StakedKey { lock_blocks }
        }
        3 => TargetKind::Other,
        _ => return Err(StoreError::CorruptMeta("bad target tag")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::leaves_per_segment;
    use crate::types::OutputIdentity;
    use ciphersuite::{
        group::ff::{Field, PrimeField},
        Ciphersuite,
    };
    use helioselene::Selene;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn sample_entry(gindex: u64, maturity: u64) -> LeafEntry {
        LeafEntry {
            gindex: Gindex(gindex),
            maturity: BlockHeight(maturity),
            // Coinbase-shaped offset; tests that exercise the rollback
            // creation-height filter construct entries explicitly.
            creation_height: BlockHeight(maturity.saturating_sub(60)),
            leaf: [1u8; 128],
            identity: OutputIdentity {
                output_key: [1u8; 32],
                commitment: Some([2u8; 32]),
                h_pqc: [3u8; 32],
                target: TargetKind::TaggedKey,
            },
        }
    }

    #[test]
    fn append_drained_rejects_non_canonical_leaf_bytes() {
        // Invalid scalars are rejected at write time (loud failure at the
        // storage boundary), and the failed batch leaves no partial state.
        let store = LeafStore::open_ephemeral().unwrap();
        let mut bad = sample_entry(1, 0);
        bad.leaf = [0xff; 128];
        let err = store
            .append_drained(&[sample_entry(0, 0), bad], BlockHeight(1))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidLeafBytes { batch_index: 1 }
        ));
        assert_eq!(
            store.leaf_count().unwrap(),
            0,
            "aborted batch must not partially land"
        );
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(0));
    }

    #[test]
    fn leaf_meta_round_trips_creation_height() {
        // Schema-v2 round trip: creation_height survives encode/decode at
        // its `buf[122..130]` slot alongside every pre-existing field —
        // the rollback two-class filter (CT3_SYNC.md R1-Q3/F4) depends on
        // this value, so a silent zero here would misclassify every leaf
        // as genesis-created.
        let mut entry = sample_entry(7, 130);
        entry.creation_height = BlockHeight(70);
        let stored = decode_stored_leaf_meta(&encode_leaf_meta(&entry)).unwrap();
        assert_eq!(stored.gindex, Gindex(7));
        assert_eq!(stored.maturity, BlockHeight(130));
        assert_eq!(stored.creation_height, BlockHeight(70));
        assert_eq!(stored.identity, entry.identity);
    }

    /// Pending rows currently persisted, in key (gindex) order.
    fn pending_gindexes(store: &LeafStore) -> Vec<u64> {
        let txn = store.db.begin_read().unwrap();
        let pending = txn.open_table(PENDING_TABLE).unwrap();
        pending
            .iter()
            .unwrap()
            .map(|row| row.unwrap().0.value().0)
            .collect()
    }

    #[test]
    fn block_deltas_cycle_pending_rows_through_drain() {
        // Ingest shape: block N adds pending rows; a later block drains
        // one of them (remove from pending + append to leaves) in a
        // single transaction.
        let store = LeafStore::open_ephemeral().unwrap();
        let a = sample_entry(3, 70);
        let b = sample_entry(4, 71);
        store
            .append_block_deltas(&[], &[a, b], &[], BlockHeight(10))
            .unwrap();
        assert_eq!(pending_gindexes(&store), vec![3, 4]);
        assert_eq!(store.leaf_count().unwrap(), 0);

        store
            .append_block_deltas(&[a], &[], &[Gindex(3)], BlockHeight(70))
            .unwrap();
        assert_eq!(pending_gindexes(&store), vec![4]);
        assert_eq!(store.leaf_count().unwrap(), 1);
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(70));
    }

    #[test]
    fn block_deltas_reject_pending_gindex_collision_and_abort() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(&[], &[sample_entry(5, 70)], &[], BlockHeight(10))
            .unwrap();
        // Colliding insert rides with a drained append: the whole txn must
        // abort — the drained leaf cannot land either.
        let err = store
            .append_block_deltas(
                &[sample_entry(1, 61)],
                &[sample_entry(5, 99)],
                &[],
                BlockHeight(11),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::PendingGindexCollision { gindex: 5 }
        ));
        assert_eq!(store.leaf_count().unwrap(), 0, "aborted txn left no trace");
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(10));
    }

    #[test]
    fn block_deltas_reject_missing_pending_removal_and_abort() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(&[], &[sample_entry(7, 70)], &[], BlockHeight(10))
            .unwrap();
        let err = store
            .append_block_deltas(&[], &[], &[Gindex(8)], BlockHeight(11))
            .unwrap_err();
        assert!(matches!(err, StoreError::PendingRowMissing { gindex: 8 }));
        assert_eq!(
            pending_gindexes(&store),
            vec![7],
            "aborted txn left pending intact"
        );
    }

    #[test]
    fn block_deltas_reject_non_canonical_pending_leaf() {
        let store = LeafStore::open_ephemeral().unwrap();
        let mut bad = sample_entry(2, 70);
        bad.leaf = [0xFFu8; 128];
        let err = store
            .append_block_deltas(&[sample_entry(1, 61)], &[bad], &[], BlockHeight(10))
            .unwrap_err();
        // batch_index counts drained first, then pending_added.
        assert!(matches!(
            err,
            StoreError::InvalidLeafBytes { batch_index: 1 }
        ));
        assert_eq!(store.leaf_count().unwrap(), 0, "aborted txn left no trace");
    }

    #[test]
    fn block_deltas_all_empty_advance_tip_and_freeze_clock() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(&[], &[], &[], BlockHeight(42))
            .unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(42));
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert!(pending_gindexes(&store).is_empty());
    }

    #[test]
    fn clear_empties_pending_table() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(&[], &[sample_entry(9, 70)], &[], BlockHeight(10))
            .unwrap();
        assert_eq!(pending_gindexes(&store), vec![9]);
        store.clear().unwrap();
        assert!(
            pending_gindexes(&store).is_empty(),
            "stale pending rows would corrupt a from_blocks rebuild"
        );
    }

    #[test]
    fn resume_reads_round_trip_pending_and_drained() {
        // Resume contract: what append_block_deltas wrote is exactly what
        // the two read paths return, field-for-field, in order.
        let store = LeafStore::open_ephemeral().unwrap();
        let drained = [sample_entry(0, 60), sample_entry(1, 61)];
        let pending = [sample_entry(5, 90), sample_entry(3, 80)];
        store
            .append_block_deltas(&drained, &pending, &[], BlockHeight(61))
            .unwrap();

        assert_eq!(store.read_drained_entries().unwrap(), drained.to_vec());
        // Pending returns in gindex (key) order regardless of insert order.
        assert_eq!(
            store.read_pending_candidates().unwrap(),
            vec![pending[1], pending[0]]
        );
    }

    #[test]
    fn read_drained_rejects_maturity_regression() {
        // The P7 monotonicity check: a batch persisted out of drain order
        // (a caller bug — the client sorts by (maturity, gindex)) must be
        // rejected at resume, not silently fed to the rollback partition
        // search that assumes sortedness.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 70), sample_entry(1, 61)], BlockHeight(70))
            .unwrap();
        let err = store.read_drained_entries().unwrap_err();
        assert!(matches!(err, StoreError::CorruptMeta(_)));
    }

    #[test]
    fn read_drained_rejects_key_set_asymmetry() {
        // Fault injection (test-only): every production path writes and
        // deletes leaves/leaf_meta in lockstep, so asymmetry can only be
        // store corruption — manufactured here by deleting one meta row
        // directly to prove the detector fires.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 60), sample_entry(1, 61)], BlockHeight(61))
            .unwrap();
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(LEAF_META_TABLE).unwrap();
                meta.remove(TreePosition(1)).unwrap();
            }
            txn.commit().unwrap();
        }
        let err = store.read_drained_entries().unwrap_err();
        assert!(matches!(err, StoreError::CorruptMeta(_)));
    }

    /// `sample_entry` with an explicit creation height (the rollback
    /// two-class partition filters on it).
    fn entry_created_at(gindex: u64, maturity: u64, created: u64) -> LeafEntry {
        let mut entry = sample_entry(gindex, maturity);
        entry.creation_height = BlockHeight(created);
        entry
    }

    #[test]
    fn rollback_partitions_two_classes() {
        // Fork at 100. Store state before rollback:
        //   drained: g0 (created 10, matured 70)   — shared prefix, stays
        //            g1 (created 40, matured 101)  — class (b): created on
        //              the shared prefix, drained on the orphaned suffix →
        //              must re-enter pending
        //            g2 (created 101, matured 161) — class (a) drained:
        //              created in an orphaned block → deleted entirely
        //   pending: g3 (created 90, matured 150)  — survives the filter
        //            g4 (created 102, matured 162) — class (a) pending →
        //              deleted
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[
                    entry_created_at(0, 70, 10),
                    entry_created_at(1, 101, 40),
                    entry_created_at(2, 161, 101),
                ],
                &[entry_created_at(3, 150, 90), entry_created_at(4, 162, 102)],
                &[],
                BlockHeight(161),
            )
            .unwrap();

        store.rollback_to_fork(BlockHeight(100)).unwrap();

        let drained = store.read_drained_entries().unwrap();
        assert_eq!(drained, vec![entry_created_at(0, 70, 10)]);
        // Pending = {g1 migrated back, g3 untouched}; g2/g4 filtered out.
        assert_eq!(
            store.read_pending_candidates().unwrap(),
            vec![entry_created_at(1, 101, 40), entry_created_at(3, 150, 90)]
        );
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(100));
        assert_eq!(store.leaf_count().unwrap(), 1);
    }

    #[test]
    fn rollback_at_tip_is_clean_noop() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[entry_created_at(0, 69, 10)],
                &[entry_created_at(1, 150, 60)],
                &[],
                BlockHeight(70),
            )
            .unwrap();
        store.rollback_to_fork(BlockHeight(70)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 1);
        assert_eq!(store.read_pending_candidates().unwrap().len(), 1);
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(70));
    }

    #[test]
    fn rollback_above_tip_is_invalid() {
        let store = LeafStore::open_ephemeral().unwrap();
        store.append_drained(&[], BlockHeight(50)).unwrap();
        let err = store.rollback_to_fork(BlockHeight(51)).unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidRollback {
                fork_height: 51,
                sync_tip: 50
            }
        ));
    }

    /// Full logical state through every public read path — drained rows,
    /// pending rows, leaf count, sync tip, root, and the first frozen
    /// record. Equality of two snapshots is the abort-leaves-no-trace /
    /// rollback-equals-replay comparator (CT-3a plan §6 P8/P6).
    type Snapshot = (
        Vec<LeafEntry>,
        Vec<LeafEntry>,
        u64,
        BlockHeight,
        [u8; 32],
        Option<FrozenSegmentRecord>,
    );

    fn logical_snapshot(store: &LeafStore) -> Snapshot {
        let count = store.leaf_count().unwrap();
        (
            store.read_drained_entries().unwrap(),
            store.read_pending_candidates().unwrap(),
            count,
            store.sync_tip_height().unwrap(),
            store.root_at_count(count).unwrap(),
            store.frozen_segment(SegmentId(0)).unwrap(),
        )
    }

    #[test]
    fn rollback_lands_on_first_of_equal_maturity_run() {
        // F7: drained rows 1..=3 share maturity 101 (a multi-leaf drain
        // bucket — Tier A never produces this, one coinbase per block).
        // The partition for fork 100 must land on the FIRST of the run;
        // landing anywhere inside it would leave rows with maturity > fork
        // in the tree.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[
                    entry_created_at(0, 50, 0),
                    entry_created_at(1, 101, 20),
                    entry_created_at(2, 101, 30),
                    entry_created_at(3, 101, 40),
                    entry_created_at(4, 120, 44),
                ],
                &[],
                &[],
                BlockHeight(120),
            )
            .unwrap();
        store.rollback_to_fork(BlockHeight(100)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 1, "cut at first of the run");
        assert_eq!(
            store.read_drained_entries().unwrap(),
            vec![entry_created_at(0, 50, 0)]
        );
        // The whole run (created on the shared prefix) re-enters pending.
        assert_eq!(
            store
                .read_pending_candidates()
                .unwrap()
                .iter()
                .map(|e| e.gindex.0)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn rollback_to_genesis_migrates_and_filters() {
        // fork == 0 ⇒ partition at 0 (every maturity > 0): the whole tree
        // truncates, all drained rows migrate, and only creation_height == 0
        // outputs (the genesis block's own) survive the filter.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[entry_created_at(0, 60, 0), entry_created_at(1, 65, 5)],
                &[],
                &[],
                BlockHeight(65),
            )
            .unwrap();
        store.rollback_to_fork(BlockHeight(0)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(0));
        assert_eq!(
            store.read_pending_candidates().unwrap(),
            vec![entry_created_at(0, 60, 0)]
        );
    }

    #[test]
    fn rollback_on_empty_store_is_noop() {
        // Also pins the sync_tip empty-vs-height-0 semantics (§6 verify-at-
        // impl): a fresh store reports tip 0 — indistinguishable from
        // "synced through height 0" — and that overload is harmless here:
        // fork 0 ≤ tip 0 passes validation and every step degenerates to a
        // no-op on empty tables.
        let store = LeafStore::open_ephemeral().unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(0));
        store.rollback_to_fork(BlockHeight(0)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert!(store.read_pending_candidates().unwrap().is_empty());
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(0));
    }

    #[test]
    fn rollback_without_truncation_still_filters_pending() {
        // partition == leaf_count (no drained row matured past the fork):
        // nothing truncates or migrates, but the creation_height filter
        // still runs — a pending output created in an orphaned block must
        // not survive just because the drained tree was untouched.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[entry_created_at(0, 50, 0)],
                &[entry_created_at(1, 140, 80), entry_created_at(2, 130, 20)],
                &[],
                BlockHeight(100),
            )
            .unwrap();
        store.rollback_to_fork(BlockHeight(70)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 1, "no truncation");
        assert_eq!(
            store.read_pending_candidates().unwrap(),
            vec![entry_created_at(2, 130, 20)],
            "orphaned-creation pending row filtered, prefix row kept"
        );
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(70));
    }

    #[test]
    fn rollback_below_pruned_frontier_rejects_without_panic() {
        // P1: prune segment 0, then ask for a fork below the frontier. The
        // partition search must probe only the present suffix (a naive
        // position-probing search would None-probe a hole and panic) and
        // reject with TruncatedIntoPrunedRange before any write.
        let store = LeafStore::open_ephemeral().unwrap();
        let e = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        let mut entries: Vec<LeafEntry> = (0..e).map(|i| entry_created_at(i, 50, 10)).collect();
        entries.push(entry_created_at(e, 5_000, 4_000));
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(
            store.frozen_segment(SegmentId(0)).unwrap().is_some(),
            "segment 0 must be frozen for the prune to bite"
        );
        store.prune_frozen(&[]).unwrap();

        let err = store.rollback_to_fork(BlockHeight(40)).unwrap_err();
        assert!(matches!(
            err,
            StoreError::TruncatedIntoPrunedRange { pos } if pos == e
        ));
        // Error-before-write: the store is untouched.
        assert_eq!(store.leaf_count().unwrap(), e + 1);
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(10_000));
    }

    #[test]
    fn rollback_across_frozen_segment_drops_freeze_rows() {
        // F9: a rollback truncating through a frozen-but-unpruned segment
        // must drop its freeze record and rewind the freeze cursor —
        // otherwise a post-rollback resume recomposes the root against a
        // stale R_k.
        let store = LeafStore::open_ephemeral().unwrap();
        let e = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        let entries: Vec<LeafEntry> = (0..e).map(|i| entry_created_at(i, 100, 10)).collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());

        store.rollback_to_fork(BlockHeight(50)).unwrap();
        assert!(
            store.frozen_segment(SegmentId(0)).unwrap().is_none(),
            "freeze record rolled back with its segment"
        );
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert_eq!(
            store.read_pending_candidates().unwrap().len(),
            usize::try_from(e).expect("fits usize"),
            "shared-prefix rows all migrate"
        );
        // Cursor rewind, observed through the production freeze path:
        // re-draining a full segment must freeze it again. A stale cursor
        // would skip segment 0 silently.
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
    }

    #[test]
    fn verify_frozen_tail_rejects_corrupt_r_k() {
        // Build the frozen row through the real freeze path; only the final
        // row mutation is test-only corruption of the persisted metadata.
        let store = LeafStore::open_ephemeral().unwrap();
        let e = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        let entries: Vec<LeafEntry> = (0..e).map(|i| entry_created_at(i, 50, 0)).collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        let mut record = store
            .frozen_segment(SegmentId(0))
            .unwrap()
            .expect("segment 0 frozen");
        record.r_k[0] ^= 1;
        let txn = store.db.begin_write().unwrap();
        {
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE).unwrap();
            frozen
                .insert(SegmentId(0), &encode_frozen_segment(&record))
                .unwrap();
        }
        txn.commit().unwrap();

        let err = store.verify_frozen_tail().unwrap_err();
        assert!(matches!(
            err,
            StoreError::FrozenSegmentRkMismatch {
                segment: SegmentId(0),
                ..
            }
        ));
    }

    #[test]
    fn verify_frozen_tail_rejects_missing_cursor_row() {
        // Build cursor + row through the real freeze path, then remove just
        // the row. A cursor claiming segment 0 is frozen with no row is
        // corruption, not a clean "nothing to verify" state.
        let store = LeafStore::open_ephemeral().unwrap();
        let e = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        let entries: Vec<LeafEntry> = (0..e).map(|i| entry_created_at(i, 50, 0)).collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
        let txn = store.db.begin_write().unwrap();
        {
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE).unwrap();
            drop(frozen.remove(SegmentId(0)).unwrap());
        }
        txn.commit().unwrap();

        let err = store.verify_frozen_tail().unwrap_err();
        assert!(matches!(
            err,
            StoreError::FrozenSegmentRecordMissing {
                segment: SegmentId(0)
            }
        ));
    }

    #[test]
    fn failed_block_deltas_leave_logical_state_identical() {
        // P8: a delta whose drained append is valid but whose pending
        // insert is non-canonical aborts the whole txn. The snapshot
        // comparison over every public read path turns "atomicity is
        // structural" into a checked property.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_block_deltas(
                &[entry_created_at(0, 50, 0)],
                &[entry_created_at(5, 140, 80)],
                &[],
                BlockHeight(90),
            )
            .unwrap();
        let before = logical_snapshot(&store);

        let mut bad = entry_created_at(6, 150, 91);
        bad.leaf = [0xFFu8; 128];
        let err = store
            .append_block_deltas(
                &[entry_created_at(1, 95, 35)],
                &[bad],
                &[Gindex(5)],
                BlockHeight(95),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidLeafBytes { batch_index: 1 }
        ));
        assert_eq!(
            logical_snapshot(&store),
            before,
            "aborted txn must leave no trace in any table"
        );
    }

    fn random_canonical_leaf(rng: &mut ChaCha20Rng) -> [u8; 128] {
        let mut leaf = [0u8; 128];
        for chunk in leaf.chunks_mut(32) {
            let repr = <Selene as Ciphersuite>::F::random(&mut *rng).to_repr();
            chunk.copy_from_slice(repr.as_ref());
        }
        leaf
    }

    fn random_entry(rng: &mut ChaCha20Rng, gindex: u64, maturity: u64, creation: u64) -> LeafEntry {
        let mut output_key = [0u8; 32];
        rng.fill_bytes(&mut output_key);
        let mut h_pqc = [0u8; 32];
        rng.fill_bytes(&mut h_pqc);
        let commitment = if rng.next_u32().is_multiple_of(2) {
            let mut c = [0u8; 32];
            rng.fill_bytes(&mut c);
            Some(c)
        } else {
            None
        };
        let target = match rng.next_u32() % 4 {
            0 => TargetKind::TaggedKey,
            1 => TargetKind::Key,
            2 => TargetKind::StakedKey {
                lock_blocks: u64::from(rng.next_u32()),
            },
            _ => TargetKind::Other,
        };
        LeafEntry {
            gindex: Gindex(gindex),
            maturity: BlockHeight(maturity),
            creation_height: BlockHeight(creation),
            leaf: random_canonical_leaf(rng),
            identity: OutputIdentity {
                output_key,
                commitment,
                h_pqc,
                target,
            },
        }
    }

    #[test]
    fn random_entries_round_trip_meta_and_pending_codecs() {
        // Deterministic codec property test (rand_chacha, no new deps):
        // decode∘encode is identity for leaf_meta and pending rows across
        // random entries covering every TargetKind variant. Leaf bytes are
        // genuine random Selene field elements, not masked bytes, so the
        // canonical re-check in decode_pending runs on representative input.
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        for i in 0..64u64 {
            let creation = u64::from(rng.next_u32());
            let gindex = u64::from(rng.next_u32());
            let maturity = creation.saturating_add(u64::from(rng.next_u32() % 1_000_000));
            let entry = random_entry(&mut rng, gindex, maturity, creation);
            let meta = encode_leaf_meta(&entry);
            let stored = decode_stored_leaf_meta(&meta).unwrap();
            assert_eq!(stored.gindex, entry.gindex, "iteration {i}");
            assert_eq!(stored.maturity, entry.maturity);
            assert_eq!(stored.creation_height, entry.creation_height);
            assert_eq!(stored.identity, entry.identity);
            assert_eq!(decode_pending(&encode_pending(&entry)).unwrap(), entry);
        }
    }

    #[test]
    fn rollback_equals_prefix_replay_property() {
        // P6: derive, don't fabricate. A random block sequence is driven
        // through append_block_deltas (which enforces drain-order maturity
        // monotonicity and gindex disjointness by construction); rolling
        // back must equal replaying the prefix through the same write API.
        // The 150_000 lock class never drains inside the window — the
        // direct pending-table comparison covers rows no drain-order or
        // root assertion would ever touch (rider 1).
        struct SimBlock {
            height: u64,
            drained: Vec<LeafEntry>,
            added: Vec<LeafEntry>,
            removed: Vec<Gindex>,
        }

        fn replay_prefix(blocks: &[SimBlock], fork: u64) -> LeafStore {
            let store = LeafStore::open_ephemeral().unwrap();
            for b in blocks.iter().filter(|b| b.height <= fork) {
                store
                    .append_block_deltas(&b.drained, &b.added, &b.removed, BlockHeight(b.height))
                    .unwrap();
            }
            store
        }

        fn assert_disjoint(store: &LeafStore) {
            let drained: std::collections::BTreeSet<u64> = store
                .read_drained_entries()
                .unwrap()
                .iter()
                .map(|e| e.gindex.0)
                .collect();
            let pending: std::collections::BTreeSet<u64> = store
                .read_pending_candidates()
                .unwrap()
                .iter()
                .map(|e| e.gindex.0)
                .collect();
            assert!(drained.is_disjoint(&pending));
        }

        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let locks = [10u64, 60, 200, 150_000];
        let store = LeafStore::open_ephemeral().unwrap();
        let mut live_pending: std::collections::BTreeMap<u64, LeafEntry> =
            std::collections::BTreeMap::new();
        let mut next_gindex = 0u64;
        let mut blocks = Vec::new();
        for height in 1..=80u64 {
            let mut added = Vec::new();
            for _ in 0..(rng.next_u32() % 3) {
                let lock = locks[(rng.next_u32() as usize) % locks.len()];
                let entry = random_entry(&mut rng, next_gindex, height + lock, height);
                next_gindex += 1;
                live_pending.insert(entry.gindex.0, entry);
                added.push(entry);
            }
            let due: Vec<u64> = live_pending
                .values()
                .filter(|e| e.maturity.0 == height)
                .map(|e| e.gindex.0)
                .collect();
            let drained: Vec<LeafEntry> = due
                .iter()
                .map(|g| live_pending.remove(g).expect("due row is live"))
                .collect();
            let removed: Vec<Gindex> = drained.iter().map(|e| e.gindex).collect();
            store
                .append_block_deltas(&drained, &added, &removed, BlockHeight(height))
                .unwrap();
            blocks.push(SimBlock {
                height,
                drained,
                added,
                removed,
            });
        }
        assert!(
            store.leaf_count().unwrap() > 0,
            "fixture must actually drain"
        );
        assert_disjoint(&store);

        // First rollback, then a second deeper one on the same store —
        // sequential reorgs compose.
        for fork in [55u64, 21] {
            store.rollback_to_fork(BlockHeight(fork)).unwrap();
            let fresh = replay_prefix(&blocks, fork);
            assert_eq!(
                logical_snapshot(&store),
                logical_snapshot(&fresh),
                "rollback to {fork} must equal prefix replay"
            );
            assert_disjoint(&store);
        }
    }

    #[test]
    fn decode_leaf_meta_rejects_invalid_commitment_tag() {
        let mut buf = encode_leaf_meta(&sample_entry(0, 0));
        buf[48] = 2;
        let err = decode_stored_leaf_meta(&buf).unwrap_err();
        assert!(matches!(err, StoreError::CorruptMeta(_)));
    }

    #[test]
    fn append_and_truncate_round_trip() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0), sample_entry(1, 0)], BlockHeight(1))
            .unwrap();
        assert_eq!(store.leaf_count().unwrap(), 2);
        store.truncate_from_tree_position(TreePosition(1)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 1);
    }

    #[test]
    fn pin_and_prune_smoke() {
        let store = LeafStore::open_ephemeral().unwrap();
        store.pin_segment(SegmentId(0)).unwrap();
        store.prune_frozen(&[]).unwrap();
    }

    #[test]
    fn truncate_to_zero_clears_frozen_segments() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
        store.truncate_from_tree_position(TreePosition(0)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_none());
    }

    #[test]
    fn append_empty_still_advances_sync_tip_and_freeze() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, BlockHeight(100)).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(100));
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_none());
        store.append_drained(&[], BlockHeight(10_000)).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(10_000));
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
    }

    #[test]
    fn truncate_to_zero_clears_stale_pins() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        store.pin_segment(SegmentId(0)).unwrap();
        store.truncate_from_tree_position(TreePosition(0)).unwrap();
        store.append_drained(&entries, BlockHeight(20_000)).unwrap();
        store.prune_frozen(&[]).unwrap();
        let txn = store.db.begin_read().unwrap();
        let leaves = txn.open_table(LEAVES_TABLE).unwrap();
        assert!(
            leaves.get(TreePosition(0)).unwrap().is_none(),
            "stale pin must not block prune"
        );
    }

    #[test]
    fn truncate_invalidates_sync_tip() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0)], BlockHeight(500))
            .unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(500));
        store.truncate_from_tree_position(TreePosition(0)).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(0));
    }

    #[test]
    fn truncate_into_pruned_segment_rejects() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        store.prune_frozen(&[]).unwrap();
        let pos_in_seg = e / 2;
        let err = store
            .truncate_from_tree_position(TreePosition(
                u64::try_from(pos_in_seg).expect("position fits u64"),
            ))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::TruncatedIntoPrunedRange { pos }
            if pos < u64::try_from(e).expect("segment size fits u64")
        ));
    }

    #[test]
    fn append_drained_sync_tip_is_monotonic() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0)], BlockHeight(100))
            .unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(100));
        store.append_drained(&[], BlockHeight(50)).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(100));
    }

    #[test]
    fn root_at_count_rejects_request_beyond_stored() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
            .unwrap();
        let err = store.root_at_count(2).unwrap_err();
        assert!(matches!(
            err,
            StoreError::LeafCountOutOfBounds {
                requested: 2,
                stored: 1
            }
        ));
    }

    #[test]
    fn truncate_beyond_leaf_count_rejects() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
            .unwrap();
        let err = store
            .truncate_from_tree_position(TreePosition(2))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidTruncate {
                pos: 2,
                leaf_count: 1
            }
        ));
        assert_eq!(store.leaf_count().unwrap(), 1);
    }

    /// Delegation-parity KAT: every typed key's byte layout, fixed width,
    /// round-trip, and key ordering are byte-identical to the inner
    /// primitive's redb impl. This is the property the
    /// `redb_delegated_key!` macro exists to guarantee — range scans and
    /// batched range-deletes behave exactly as the pre-retrofit raw-`u64`
    /// tables did.
    #[test]
    fn typed_key_delegation_parity() {
        use redb::{Key as _, Value as _};

        fn check_u64<T>(wrap: fn(u64) -> T)
        where
            T: redb::Key + for<'a> redb::Value<SelfType<'a> = T> + PartialEq + core::fmt::Debug,
        {
            let samples = [0u64, 1, 2, 60, 61, u64::MAX - 1, u64::MAX];
            assert_eq!(T::fixed_width(), u64::fixed_width());
            for &a in &samples {
                let wrapped_a = wrap(a);
                let bytes = T::as_bytes(&wrapped_a);
                assert_eq!(bytes.as_ref(), u64::as_bytes(&a).as_ref());
                assert_eq!(T::from_bytes(bytes.as_ref()), wrap(a));
                for &b in &samples {
                    let wrapped_b = wrap(b);
                    let rhs = T::as_bytes(&wrapped_b);
                    assert_eq!(
                        T::compare(bytes.as_ref(), rhs.as_ref()),
                        u64::compare(u64::as_bytes(&a).as_ref(), u64::as_bytes(&b).as_ref()),
                    );
                }
            }
        }

        check_u64::<TreePosition>(TreePosition);
        check_u64::<BlockHeight>(BlockHeight);
        check_u64::<Gindex>(Gindex);

        // SegmentId wraps u32; same parity properties against the u32 impl.
        let samples = [0u32, 1, 2, u32::MAX - 1, u32::MAX];
        assert_eq!(
            <SegmentId as redb::Value>::fixed_width(),
            u32::fixed_width()
        );
        for &a in &samples {
            let bytes = <SegmentId as redb::Value>::as_bytes(&SegmentId(a));
            assert_eq!(bytes.as_ref(), u32::as_bytes(&a).as_ref());
            assert_eq!(
                <SegmentId as redb::Value>::from_bytes(bytes.as_ref()),
                SegmentId(a)
            );
            for &b in &samples {
                let rhs = <SegmentId as redb::Value>::as_bytes(&SegmentId(b));
                assert_eq!(
                    <SegmentId as redb::Key>::compare(bytes.as_ref(), rhs.as_ref()),
                    u32::compare(u32::as_bytes(&a).as_ref(), u32::as_bytes(&b).as_ref()),
                );
            }
        }
    }

    /// The typed-key point: redb refuses to open a table whose stored key
    /// type disagrees, so a gindex can never index the position-keyed
    /// leaves table (and vice versa) — the mix-up is a loud open error,
    /// not silent cross-keyed reads.
    #[test]
    fn typed_key_table_type_guard_fires() {
        const WRONG_KEY_LEAVES: TableDefinition<Gindex, &[u8; 128]> =
            TableDefinition::new("leaves");

        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
            .unwrap();
        let txn = store.db.begin_read().unwrap();
        let err = txn.open_table(WRONG_KEY_LEAVES).unwrap_err();
        assert!(
            matches!(err, redb::TableError::TableTypeMismatch { .. }),
            "expected TableTypeMismatch, got: {err:?}"
        );
    }

    /// Unique on-disk path for file-backed open tests (stdlib only; no
    /// tempfile dependency). The caller removes the file.
    fn temp_store_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "shekyl-curve-tree-{tag}-{}-{n}.redb",
            std::process::id()
        ))
    }

    /// Schema-version guard (stamp-on-create-only contract):
    ///
    /// - a freshly created store is stamped and reopens clean;
    /// - a version-1-shaped store fails open with
    ///   `SchemaVersionMismatch { found: 1, expected: SCHEMA_VERSION }`;
    /// - the failed open mutates nothing — a second open fails
    ///   identically (no stamp-in-passing), and after re-stamping the
    ///   data is intact (error-without-mutation at the open boundary).
    ///
    /// Scoped exception to the real-path rule: the v1 layout cannot be
    /// produced through the current init path (it stamps the current
    /// [`SCHEMA_VERSION`] by design, and the code that produced v1 stores
    /// no longer exists in-tree).
    /// The fixture is fabricated by deleting the `schema_version` cell in
    /// a test-only transaction — a plain `META_TABLE` u64 cell, not a
    /// codec side channel; the test subject is the open check itself.
    #[test]
    fn schema_version_guard_rejects_v1_without_mutation() {
        let path = temp_store_path("schema-guard");

        // Fresh create: stamped, reopens clean, data persists.
        {
            let store = LeafStore::open(&path).unwrap();
            store
                .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
                .unwrap();
        }
        {
            let store = LeafStore::open(&path).unwrap();
            assert_eq!(store.leaf_count().unwrap(), 1);
        }

        // Fabricate the implicit-v1 shape (see doc comment for the
        // scoped exception rationale).
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META_TABLE).unwrap();
                meta.remove(META_SCHEMA_VERSION).unwrap();
            }
            txn.commit().unwrap();
        }

        // The mismatch fires, twice: the first failed open must not have
        // stamped the store to the current version in passing.
        for _ in 0..2 {
            let err = LeafStore::open(&path).unwrap_err();
            assert!(
                matches!(
                    err,
                    StoreError::SchemaVersionMismatch {
                        found: IMPLICIT_SCHEMA_VERSION,
                        expected: SCHEMA_VERSION,
                    }
                ),
                "expected SchemaVersionMismatch(found=1, expected={SCHEMA_VERSION}), got: {err:?}"
            );
        }

        // Error-without-mutation: re-stamp (test-only txn) and the data
        // written before the fabricated downgrade is untouched.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META_TABLE).unwrap();
                meta.insert(META_SCHEMA_VERSION, &SCHEMA_VERSION).unwrap();
            }
            txn.commit().unwrap();
        }
        {
            let store = LeafStore::open(&path).unwrap();
            assert_eq!(store.leaf_count().unwrap(), 1);
            assert_eq!(store.sync_tip_height().unwrap(), BlockHeight(1));
        }

        std::fs::remove_file(&path).unwrap();
    }

    /// A CT-3a-window (version-2) store fails open. Its byte layout is
    /// identical to v3 — `TypeName` and the codecs cannot see the
    /// difference — but its pending table was never maintained (the
    /// CT-3a-era client wrote through the `append_drained` wrapper), so
    /// resuming from it would silently drop every undrained leaf. The
    /// version cell is exactly the guard for this contract-only drift.
    ///
    /// Scoped exception to the real-path rule (same rationale as the v1
    /// guard test above): the current init path stamps v3 by design, so
    /// the v2 shape is fabricated by rewriting the plain `META_TABLE`
    /// version cell in a test-only transaction — the test subject is the
    /// open check, not a codec.
    #[test]
    fn schema_version_guard_rejects_ct3a_window_v2_store() {
        let path = temp_store_path("schema-guard-v2");

        // Create through the real path (stamped v3, drained row present),
        // then downgrade the version cell to the CT-3a stamp.
        {
            let store = LeafStore::open(&path).unwrap();
            store
                .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
                .unwrap();
        }
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META_TABLE).unwrap();
                meta.insert(META_SCHEMA_VERSION, &CT3A_SCHEMA_VERSION)
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        // The mismatch fires, twice (no stamp-in-passing on the failed
        // open), naming the found version so the operator sees "delete
        // and re-sync", not a reconstruction mystery.
        for _ in 0..2 {
            let err = LeafStore::open(&path).unwrap_err();
            assert!(
                matches!(
                    err,
                    StoreError::SchemaVersionMismatch {
                        found: CT3A_SCHEMA_VERSION,
                        expected: SCHEMA_VERSION,
                    }
                ),
                "expected SchemaVersionMismatch(found={CT3A_SCHEMA_VERSION}, \
                 expected={SCHEMA_VERSION}), got: {err:?}"
            );
        }

        std::fs::remove_file(&path).unwrap();
    }
}
