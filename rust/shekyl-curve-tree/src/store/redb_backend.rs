// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! redb-backed `LeafStore` tables and transactional operations.

use std::path::Path;
use std::sync::Arc;

use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::segment::{leaves_per_segment, segment_freeze_eligible, SegmentId};
use crate::store::ops::{
    full_build_root, mixed_composition_root, recompute_segment_r_k, MixedRootError,
};
use crate::types::{BlockHeight, Gindex, LeafEntry, TargetKind, TreePosition};
use shekyl_fcmp::tree::{hash_grow_selene, selene_hash_init, SCALARS_PER_LEAF};

const LEAVES_TABLE: TableDefinition<TreePosition, &[u8; 128]> = TableDefinition::new("leaves");
/// Width of one stored leaf, for byte arithmetic. The `LEAVES_TABLE` value
/// type is the source of truth; this is the same number where a `usize` is
/// wanted rather than a type.
const LEAF_BYTES: usize = 128;
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
/// retires that shape with a typed error. Version 4 retires the claim-era
/// `StakedKey` target (tag 2 in the `leaf_meta` target byte + its
/// `lock_blocks` extra at bytes 114..122): a ≤3 store may contain tag-2
/// rows this build cannot represent. Pre-genesis disposition for any
/// mismatch: delete the store and re-sync (`15-deletion-and-debt.mdc` —
/// no in-Shekyl migration code).
const SCHEMA_VERSION: u64 = 4;

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

/// Outcome of [`LeafStore::pin_segment_for_serving`] — the three states a
/// serve-set member can actually be in, decided in one write transaction so
/// a concurrent [`LeafStore::prune_frozen`] cannot land between the check
/// and the pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentPin {
    /// Frozen, leaf bytes present, pin recorded: servable now, and
    /// [`LeafStore::prune_frozen`] will retain it.
    PinnedServable,
    /// Not frozen yet, pin recorded anyway. Pinning ahead of the freeze is
    /// what makes the freeze unable to race a prune — without it there is a
    /// window in which a bonded shard freezes, gets pruned, and can never
    /// be served again. Not servable until it freezes (no committed `R_k`).
    PinnedNotYetFrozen,
    /// Frozen, but the leaf bytes were already pruned — **no pin recorded**,
    /// because a pin cannot bring bytes back. The store must be rebuilt by
    /// chain replay before this segment can be served. Reported rather than
    /// silently succeeding: a pin that "worked" on absent bytes is exactly
    /// how a serving persona reaches its challenge epoch believing it is
    /// healthy.
    AlreadyPruned,
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

/// A **read-only** handle on the store, for the persona serving path.
///
/// The store is a single-writer redb database, and in the wallet that
/// single writer is the `CurveTreeActor` — its message loop is what
/// serializes writes, in place of an explicit lock. The serving loop runs
/// concurrently with block ingest and holds a body reader open for the
/// seconds a 3.33 MB rendezvous transfer takes, so handing it the store
/// itself would put a second writer beside the one the actor exists to be.
/// redb would not corrupt anything, but the two would contend on the write
/// lock, and the actor's structural guarantee would become a convention
/// nobody is checking.
///
/// So the serving side gets *this* instead: the same `Arc<LeafStore>`,
/// with only [`Self::open_frozen_segment_body`] reachable through it.
/// redb readers are MVCC snapshots and run concurrently with the writer,
/// so nothing is given up — a read-only reader is all the serving loop
/// ever needed. The point is that it is now the only thing it *can* do:
/// there is no `&LeafStore` behind this handle to reach a write through,
/// which is what makes "the serving host does not write to the store" a
/// property of the types rather than a rule in a doc.
///
/// Minted by `CurveTreeClient::serving_reader`, which is the object the
/// actor owns.
#[derive(Clone)]
pub struct ServingReader {
    store: Arc<LeafStore>,
}

impl ServingReader {
    /// Wrap a store handle in the read-only view.
    #[must_use]
    pub fn new(store: Arc<LeafStore>) -> Self {
        Self { store }
    }

    /// The serving read — see [`LeafStore::open_frozen_segment_body`] for
    /// the full contract (this is a pure forward).
    ///
    /// # Errors
    ///
    /// Exactly [`LeafStore::open_frozen_segment_body`]'s.
    pub fn open_frozen_segment_body(
        &self,
        id: SegmentId,
    ) -> Result<Option<FrozenSegmentBody>, StoreError> {
        self.store.open_frozen_segment_body(id)
    }
}

// The store handle carries no secret (the curve tree is public on-chain
// material), but there is nothing useful to print either.
impl std::fmt::Debug for ServingReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServingReader").finish_non_exhaustive()
    }
}

/// Chunked reader over a frozen segment's leaf bytes — the body a persona
/// serves for one shard, from [`LeafStore::open_frozen_segment_body`].
///
/// **Chunked rather than one `Vec`** because the serving loop holds one
/// reader per in-flight connection. Materialising a whole segment would
/// make that endpoint's concurrency cap a multiple of ~3.33 MB resident —
/// a bound the rule-76 provisioning floor cannot pay, and one nothing in
/// the serving contract admits to. Peak cost here is one chunk, so the cap
/// bounds egress and descriptors, which is what it claims to bound.
///
/// Each chunk is one ordered `range` walk in its own read transaction. A
/// fresh snapshot per chunk is right for the case that matters — a pinned
/// segment cannot be pruned out from under the reader — and it keeps no
/// snapshot pinned open for the seconds a rendezvous transfer takes.
pub struct FrozenSegmentBody {
    store: Arc<LeafStore>,
    /// Next unread leaf position.
    next: u64,
    /// One past the segment's last leaf position.
    end: u64,
}

impl FrozenSegmentBody {
    /// Bytes not yet read. Before the first [`Self::next_chunk`] this is
    /// the whole body — the wire `content-length`, known without touching
    /// a leaf, which is what lets the response head go out before any
    /// store read.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        usize::try_from(self.end - self.next).expect("segment length fits usize") * LEAF_BYTES
    }

    /// Next body chunk of at most `max_bytes`, or `None` once the segment
    /// has been read to the end.
    ///
    /// `max_bytes` is rounded down to whole leaves — the body is a leaf
    /// array, so a partial leaf is never a useful read unit — and at least
    /// one leaf is always taken, so any positive `max_bytes` makes
    /// progress.
    ///
    /// # Errors
    ///
    /// Store failure, or [`StoreError::CorruptMeta`] for a hole in a
    /// segment whose servability [`LeafStore::open_frozen_segment_body`]
    /// already established. Past that check a hole means the store changed
    /// under a validated segment — corruption, or a prune of a segment
    /// being served without a pin. Both are "no longer servable", so the
    /// pruned/corrupt distinction the open call draws is not re-drawn per
    /// chunk on a snapshot that cannot answer it.
    pub fn next_chunk(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        if self.next >= self.end {
            return Ok(None);
        }
        let leaves_wanted = u64::try_from((max_bytes / LEAF_BYTES).max(1)).expect("chunk fits u64");
        let stop = self.end.min(self.next + leaves_wanted);
        let txn = self.store.db.begin_read()?;
        let table = txn.open_table(LEAVES_TABLE)?;
        let mut out = Vec::with_capacity(
            usize::try_from(stop - self.next).expect("chunk fits usize") * LEAF_BYTES,
        );
        scan_leaf_range(&table, self.next, stop, missing_leaf, |leaf| {
            out.extend_from_slice(leaf);
        })?;
        self.next = stop;
        Ok(Some(out))
    }
}

impl std::fmt::Debug for FrozenSegmentBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrozenSegmentBody")
            .field("remaining_bytes", &self.remaining_bytes())
            .finish_non_exhaustive()
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
    /// A frozen segment's leaf bytes were requested (the persona serving
    /// read) but [`LeafStore::prune_frozen`] already discarded them. The
    /// serving persona must [`LeafStore::pin_segment_for_serving`] its
    /// serve-set before any prune runs — typed so the misconfiguration is
    /// loud at read time instead of surfacing as a silently unservable
    /// shard (and, an epoch later, a slash).
    ///
    /// Raised **only** for a segment that is not pinned. `prune_frozen`
    /// skips pinned segments, so missing bytes under a pin are corruption
    /// ([`Self::CorruptMeta`]) and must not be reported here: this error
    /// names a remedy — pin the serve-set — that would provably do nothing
    /// for a segment that is already pinned.
    FrozenSegmentPruned {
        /// The frozen segment whose leaf bytes are gone.
        id: SegmentId,
    },
    /// A [`LeafStore::pin_serve_set`] member does not fit the store's `u32`
    /// [`SegmentId`] space, so it cannot name a segment in *any* store — a
    /// construction bug in whatever built the serve-set, not a freeze race.
    /// Refused rather than skipped: silently dropping a member would report
    /// a serve-set as fully pinned while a shard the persona is bonded to
    /// serve was never covered, which is the same silent-slash shape the
    /// pin exists to close.
    UnrepresentableShardId {
        /// The illegal shard id.
        shard_id: u64,
    },
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

impl StoreError {
    /// `true` iff this wraps redb's
    /// [`DatabaseAlreadyOpen`](redb::Error::DatabaseAlreadyOpen) — the
    /// single-writer lock is held by another live handle to the same file.
    ///
    /// This is the **only transient** open failure: it clears the instant the
    /// holding [`crate::CurveTreeClient`] drops (the `close → reopen` / respawn
    /// lock-release lag — see [`crate::ClientError::is_already_open`]). Every
    /// other variant is a standing condition — corruption, schema mismatch, I/O,
    /// a permission error — that re-opening cannot fix, so callers must surface
    /// those immediately rather than poll-retrying out a grace window.
    #[must_use]
    pub fn is_already_open(&self) -> bool {
        matches!(self, StoreError::Redb(e) if matches!(**e, redb::Error::DatabaseAlreadyOpen))
    }
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

    /// Test-only wrapper for appending drained leaves and advancing sync tip.
    ///
    /// Production ingest must use [`Self::append_block_deltas`] so drained
    /// and pending tables stay disjoint and resume-exact. This wrapper keeps
    /// CT-1/CT-2-era store KATs byte-identical without leaving a production
    /// path that can bypass pending-table maintenance.
    #[cfg(test)]
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

    /// Start of the **contiguous** present-leaf run ending at `leaf_count`.
    ///
    /// [`Self::prune_frozen`] skips pinned segments, and pinning has a
    /// production caller now — the persona serve-set, via
    /// [`Self::pin_segment_for_serving`] — so "lowest present position" and
    /// "start of a contiguous run" are no longer the same number: a pinned
    /// segment below a pruned one is an island with a hole above it. The
    /// partition search in [`Self::rollback_to_fork`] probes arbitrary
    /// positions by bisection and must never land in that hole, so the
    /// frontier is taken one position above the **highest** pruned segment.
    /// Islands below it are simply not searched; a fork that deep is
    /// rejected by the `partition == frontier` guard, which is the same
    /// conservative answer pruned rows already got.
    ///
    /// Prune removes an unpinned frozen segment's whole range in one
    /// transaction, so a segment's first position is an exact
    /// pruned/present discriminant and walking frozen ids downwards can
    /// stop at the first hole. With nothing pruned this degenerates to the
    /// lowest present position (0 for a store that has never pruned), and
    /// an empty table to `leaf_count` — an empty search range.
    fn present_suffix_start(
        txn: &redb::WriteTransaction,
        leaf_meta: &impl ReadableTable<TreePosition, &'static [u8; 192]>,
        leaf_count: u64,
    ) -> Result<u64, StoreError> {
        let e = leaves_per_segment() as u64;
        let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
        for row in frozen.iter()?.rev() {
            let seg_start = u64::from(row?.0.value().0) * e;
            if leaf_meta.get(TreePosition(seg_start))?.is_none() {
                return Ok(seg_start + e);
            }
        }
        Ok(match leaf_meta.iter()?.next().transpose()? {
            Some((key, _)) => key.value().0,
            None => leaf_count,
        })
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
    ///    Probes run over the **contiguous** present suffix
    ///    `[pruned frontier, leaf_count)` only, so a post-prune store can
    ///    never `None`-probe — see `present_suffix_start`, which
    ///    earns that word now that pinning (persona serving) lets prune
    ///    leave present segments *below* pruned ones. A partition
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
    /// 3. `truncate_internals` — shared with
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
            let frontier = Self::present_suffix_start(&txn, &leaf_meta, leaf_count)?;
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

    /// Pin segment `id` so [`Self::prune_frozen`] retains its full leaf
    /// bytes, and report whether the segment is actually servable.
    ///
    /// **Primary consumer: persona serving.** A bonded serve-set must be
    /// pinned before any prune runs; otherwise
    /// [`Self::open_frozen_segment_body`] returns
    /// [`StoreError::FrozenSegmentPruned`] and the persona cannot answer
    /// challenges (the silent-slash precursor). Secondary: any other reader
    /// that needs a frozen segment's leaf bytes across prune (root queries
    /// below the frozen boundary, store-backed branch reads). Path assembly
    /// today rebuilds branches from the client's replay-held entries, so it
    /// does not require pins.
    ///
    /// The pin is recorded for a segment that has **not frozen yet**
    /// ([`SegmentPin::PinnedNotYetFrozen`]) — deliberately. Bonding before
    /// freeze is legal (`bond_post.rs`), and a pin taken in advance is what
    /// removes the freeze-then-prune race; without it, correctness would
    /// depend on a lifecycle re-pin trigger firing between the two, which
    /// makes an availability guarantee out of a scheduling accident. A
    /// re-pin after freeze is then an observability call — it reports
    /// [`SegmentPin::PinnedServable`] — not a correctness one. (One case
    /// still needs it: [`Self::rollback_to_fork`] drops pins above the
    /// truncation boundary along with the rows they named.)
    ///
    /// Check, pin, and commit share one write transaction, so a prune
    /// cannot commit between deciding "frozen and present" and recording
    /// the pin.
    ///
    /// # Errors
    ///
    /// Store failure. A pruned segment is [`SegmentPin::AlreadyPruned`],
    /// not an error — the caller decides how loud that is.
    pub fn pin_segment_for_serving(&self, id: SegmentId) -> Result<SegmentPin, StoreError> {
        let txn = self.db.begin_write()?;
        let outcome = {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            if frozen.get(id)?.is_none() {
                SegmentPin::PinnedNotYetFrozen
            } else {
                // Prune removes a segment's whole leaf range in one
                // transaction, so the first position is an exact
                // pruned/present discriminant — no full-segment scan.
                let leaves = txn.open_table(LEAVES_TABLE)?;
                let start = u64::from(id.0) * leaves_per_segment() as u64;
                if leaves.get(TreePosition(start))?.is_none() {
                    SegmentPin::AlreadyPruned
                } else {
                    SegmentPin::PinnedServable
                }
            }
        };
        if outcome != SegmentPin::AlreadyPruned {
            let mut pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            pinned.insert(id, &1u32)?;
        }
        txn.commit()?;
        Ok(outcome)
    }

    /// Pin a whole serve-set, returning each member's outcome paired with
    /// its shard id, in the caller's order.
    ///
    /// Shard ids are segment indices — "shard" and "frozen segment" are the
    /// same object — so this is [`Self::pin_segment_for_serving`] over a
    /// list, plus the `u64` → [`SegmentId`] narrowing the wire form needs.
    ///
    /// [`SegmentPin::AlreadyPruned`] is *returned*, not raised: it is a
    /// fact about the store, and what to do about a pruned member is a
    /// serving-policy question (`shekyl-p-host` refuses the whole set)
    /// deliberately not decided here.
    ///
    /// Members are validated **before** any pin is attempted, so an
    /// unrepresentable id cannot leave the pin state a partial function of
    /// an invalid input. Pinning is idempotent, so a call interrupted by a
    /// store fault is re-covered by re-calling; pins already written stay
    /// written.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnrepresentableShardId`] for a member outside the
    /// `u32` id space, plus any [`Self::pin_segment_for_serving`] failure.
    pub fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, StoreError> {
        let ids = shard_ids
            .iter()
            .map(|&shard_id| {
                u32::try_from(shard_id)
                    .map(|id| (shard_id, SegmentId(id)))
                    .map_err(|_| StoreError::UnrepresentableShardId { shard_id })
            })
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|(shard_id, id)| self.pin_segment_for_serving(id).map(|pin| (shard_id, pin)))
            .collect()
    }

    /// Prune frozen, unpinned segments down to their `R_k` records.
    ///
    /// Leaf bytes at `owned_positions` are copied into the owned-identities
    /// table before removal — the owned *leaf record* is retained, not the
    /// surrounding chunk. Root composition over a pruned segment uses the
    /// frozen `R_k`; anything needing a pruned segment's full chunk contents
    /// must have pinned it first ([`Self::pin_segment_for_serving`]). All leaf bytes are
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

    /// Open a chunked reader over **frozen** segment `id`'s leaf bytes in
    /// tree order — the persona serving read
    /// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §2: the witness pulls the entire
    /// shard and verifies it against the committed `R_k`, so the served
    /// unit is exactly this chunk).
    ///
    /// `Ok(None)` when the segment is not frozen: an unfrozen segment has
    /// no committed `R_k`, so it can be neither challenged nor
    /// content-verified — there is nothing coherent to serve. (Bonding
    /// deliberately does not require freeze, `bond_post.rs`; serving does.)
    ///
    /// **Servability is decided here, before the caller commits to a
    /// response.** That is what lets the serving loop pick 404-or-200 with
    /// no bytes written yet, so store health stays unprobeable; a reader
    /// that only discovered missing bytes mid-body would leak it as a
    /// truncated `200`.
    ///
    /// # Errors
    ///
    /// [`StoreError::FrozenSegmentPruned`] when the segment froze but
    /// [`Self::prune_frozen`] already discarded its bytes — the serving
    /// persona must [`Self::pin_segment_for_serving`] its serve-set before
    /// any prune. Missing bytes under a **pinned** segment are
    /// [`StoreError::CorruptMeta`] instead: prune skips pins, so pinning
    /// again — the remedy `FrozenSegmentPruned` names — provably would not
    /// help.
    pub fn open_frozen_segment_body(
        self: &Arc<Self>,
        id: SegmentId,
    ) -> Result<Option<FrozenSegmentBody>, StoreError> {
        let e = leaves_per_segment() as u64;
        let start = u64::from(id.0) * e;
        {
            let txn = self.db.begin_read()?;
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            if frozen.get(id)?.is_none() {
                return Ok(None);
            }
            let pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?.get(id)?.is_some();
            let leaves = txn.open_table(LEAVES_TABLE)?;
            if leaves.get(TreePosition(start))?.is_none() {
                return Err(if pinned {
                    StoreError::CorruptMeta("pinned frozen segment is missing leaf bytes")
                } else {
                    StoreError::FrozenSegmentPruned { id }
                });
            }
        }
        Ok(Some(FrozenSegmentBody {
            store: Arc::clone(self),
            next: start,
            end: start + e,
        }))
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

        // `verify_frozen_tail` runs on the rollback path against persisted
        // metadata, so a corrupt `META_NEXT_FREEZE_SEG` must surface as a
        // structured error rather than panic — the function exists to detect
        // corruption, not to trust it. (`next_freeze_seg >= 1` here, so the
        // subtraction cannot underflow.)
        let segment = SegmentId(
            u32::try_from(next_freeze_seg - 1)
                .map_err(|_| StoreError::CorruptMeta("freeze segment counter exceeds u32"))?,
        );
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

/// What a hole in a leaf range means everywhere except the serving read's
/// servability check: store corruption, naming the position.
fn missing_leaf(_pos: TreePosition) -> StoreError {
    StoreError::CorruptMeta("missing leaf")
}

/// The one ordered leaf-range walk every bulk reader goes through.
///
/// A single `range` scan rather than a point get per position: these
/// readers run over whole segments (`leaves_per_segment()` = 25 992
/// leaves), where the difference is one b-tree descent against ~26 000 of
/// them. The caller supplies what a hole means and how the bytes
/// accumulate — a leaf array for root recomposition, flat bytes for the
/// wire — so there is one loop and no second copy of the hole logic.
fn scan_leaf_range(
    leaves: &impl ReadableTable<TreePosition, &'static [u8; 128]>,
    start: u64,
    end: u64,
    missing: impl Fn(TreePosition) -> StoreError,
    mut take: impl FnMut(&[u8; 128]),
) -> Result<(), StoreError> {
    // A range walk *skips* absent keys rather than yielding a `None`, so
    // holes are detected by position: the first key that is not the one
    // expected names the missing position exactly, and a walk that ends
    // short names the first missing tail position.
    let mut expected = start;
    for row in leaves.range(TreePosition(start)..TreePosition(end))? {
        let (key, value) = row?;
        if key.value().0 != expected {
            return Err(missing(TreePosition(expected)));
        }
        take(value.value());
        expected += 1;
    }
    if expected != end {
        return Err(missing(TreePosition(expected)));
    }
    Ok(())
}

/// Bulk leaf read into a leaf array, for the root/recompute paths.
fn read_leaf_bytes_range_in(
    leaves: &impl ReadableTable<TreePosition, &'static [u8; 128]>,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    let mut out = Vec::with_capacity(usize::try_from(end - start).expect("leaf range fits usize"));
    scan_leaf_range(leaves, start, end, missing_leaf, |leaf| out.push(*leaf))?;
    Ok(out)
}

fn read_leaf_bytes_range(
    txn: &redb::WriteTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    read_leaf_bytes_range_in(&txn.open_table(LEAVES_TABLE)?, start, end)
}

fn read_leaf_bytes_range_read(
    txn: &redb::ReadTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    read_leaf_bytes_range_in(&txn.open_table(LEAVES_TABLE)?, start, end)
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
        // Tag 2 was the claim-era `StakedKey { lock_blocks }` (schema ≤ 3);
        // retired with the claim-era cutover, never reassigned.
        TargetKind::Key => 1,
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

fn decode_target(tag: u8, _extra: &[u8]) -> Result<TargetKind, StoreError> {
    Ok(match tag {
        0 => TargetKind::TaggedKey,
        1 => TargetKind::Key,
        // 2 was the claim-era StakedKey; a schema-4 store never contains it
        // (the schema gate refuses ≤3 stores before decode reaches here).
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
        let target = match rng.next_u32() % 3 {
            0 => TargetKind::TaggedKey,
            1 => TargetKind::Key,
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
            // Production drain convention (CT-2 KAT, owned by
            // `CurveTreeClient::drained_through`): the block at height H
            // drains rows with maturity == H - 1 (inclusive cutoff H - 1).
            // The fixture used to drain maturity == H, which diverged from
            // the pinned mapping at exactly a fork boundary — invisible
            // until a random pattern put a maturity on a fork height.
            let due: Vec<u64> = live_pending
                .values()
                .filter(|e| e.maturity.0 + 1 == height)
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
            let a = logical_snapshot(&store);
            let b = logical_snapshot(&fresh);
            if a != b {
                // Set-level diff: a raw Snapshot assert is unreadable.
                let g = |v: &[LeafEntry]| v.iter().map(|e| e.gindex.0).collect::<Vec<_>>();
                eprintln!("fork={fork}");
                eprintln!("drained rollback={:?} replay={:?}", g(&a.0), g(&b.0));
                eprintln!("pending rollback={:?} replay={:?}", g(&a.1), g(&b.1));
                eprintln!("count {} vs {}, tip {:?} vs {:?}", a.2, b.2, a.3, b.3);
            }
            assert_eq!(a, b, "rollback to {fork} must equal prefix replay");
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
        assert_eq!(
            store.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::PinnedNotYetFrozen,
            "a bonded shard is pinned before it freezes, so no prune can slip \
             between the freeze and a re-pin"
        );
        store.prune_frozen(&[]).unwrap();
    }

    /// A full segment of *distinct* canonical leaves — uniform bytes would
    /// let a stride/offset bug in the serving read still hash to the right
    /// `R_k`, so the fixture varies the first scalar lane per leaf.
    fn distinct_segment_entries() -> Vec<LeafEntry> {
        (0..leaves_per_segment())
            .map(|i| {
                let gindex = u64::try_from(i).expect("index fits u64");
                let mut entry = sample_entry(gindex, 0);
                entry.leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
                entry
            })
            .collect()
    }

    /// Drain a segment body the way the serving loop does — in chunks far
    /// smaller than a segment, so the assertions run against the
    /// multi-chunk path rather than a single lucky read — and check that
    /// the length declared before the first read is the length delivered.
    fn serve_body(store: &Arc<LeafStore>, id: SegmentId) -> Vec<u8> {
        let mut body = store
            .open_frozen_segment_body(id)
            .expect("open body")
            .expect("segment is frozen");
        let declared = body.remaining_bytes();
        let mut out = Vec::new();
        while let Some(chunk) = body.next_chunk(4096).expect("chunk") {
            out.extend_from_slice(&chunk);
        }
        assert_eq!(
            out.len(),
            declared,
            "content-length is declared before any leaf is read; the body must match it"
        );
        out
    }

    #[test]
    fn serving_read_is_frozen_only_and_matches_the_committed_r_k() {
        let store = Arc::new(LeafStore::open_ephemeral().unwrap());
        // Unfrozen segment: refuse with None — no committed R_k, nothing
        // coherent to serve.
        assert!(store
            .open_frozen_segment_body(SegmentId(0))
            .unwrap()
            .is_none());

        store
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        let body = serve_body(&store, SegmentId(0));
        assert_eq!(body.len(), leaves_per_segment() * LEAF_BYTES);

        // The axis the serving path lives on: recomputing R_k from the
        // *served* bytes must reproduce the committed record — exactly the
        // check a witness runs on the far side of the rendezvous, chunking
        // flat wire bytes back into leaves as the witness must.
        let leaves: Vec<[u8; LEAF_BYTES]> = body
            .chunks_exact(LEAF_BYTES)
            .map(|c| c.try_into().expect("leaf-sized chunk"))
            .collect();
        let recomputed = crate::store::ops::recompute_segment_r_k(&leaves).unwrap();
        let record = store.frozen_segment(SegmentId(0)).unwrap().unwrap();
        assert_eq!(recomputed, record.r_k);
    }

    #[test]
    fn pin_serve_set_reports_each_member_and_refuses_an_unrepresentable_id() {
        // A whole serve-set in one call: a frozen member, a member bonded
        // before its segment froze, and a pruned one. All three are
        // *reported* — the store states facts, and the serving host decides
        // which of them is disqualifying.
        let store = Arc::new(LeafStore::open_ephemeral().unwrap());
        store
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        assert_eq!(
            store.pin_serve_set(&[0, 1]).unwrap(),
            vec![
                (0, SegmentPin::PinnedServable),
                (1, SegmentPin::PinnedNotYetFrozen)
            ],
            "outcomes come back paired with their shard ids, in caller order"
        );

        let pruned = Arc::new(LeafStore::open_ephemeral().unwrap());
        pruned
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        pruned.prune_frozen(&[]).unwrap();
        assert_eq!(
            pruned.pin_serve_set(&[0]).unwrap(),
            vec![(0, SegmentPin::AlreadyPruned)],
            "a pruned member is a reported state, not a store-level error"
        );

        // An id outside SegmentId space cannot name a segment in any store,
        // so it is a construction bug — and it is refused *before* any pin
        // runs, so a bad set cannot leave the store half-pinned.
        let refused = Arc::new(LeafStore::open_ephemeral().unwrap());
        refused
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        let bad = u64::from(u32::MAX) + 1;
        assert!(matches!(
            refused.pin_serve_set(&[0, bad]),
            Err(StoreError::UnrepresentableShardId { shard_id }) if shard_id == bad
        ));
        // Segment 0 is valid and came first: if the loop had pinned as it
        // walked, this prune would spare it. It does not.
        refused.prune_frozen(&[]).unwrap();
        assert!(
            matches!(
                refused.open_frozen_segment_body(SegmentId(0)),
                Err(StoreError::FrozenSegmentPruned { id: SegmentId(0) })
            ),
            "the valid member of a refused set must not have been pinned"
        );
    }

    #[test]
    fn serving_read_names_the_pruned_case_and_a_pin_prevents_it() {
        // Unpinned: prune discards the bytes, and the serving read surfaces
        // the misconfiguration as a typed error instead of a silent miss.
        let store = Arc::new(LeafStore::open_ephemeral().unwrap());
        store
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        store.prune_frozen(&[]).unwrap();
        assert!(matches!(
            store.open_frozen_segment_body(SegmentId(0)),
            Err(StoreError::FrozenSegmentPruned { id: SegmentId(0) })
        ));

        // Pinned: the same sequence keeps the segment fully servable.
        let pinned = Arc::new(LeafStore::open_ephemeral().unwrap());
        pinned
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        assert_eq!(
            pinned.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::PinnedServable
        );
        pinned.prune_frozen(&[]).unwrap();
        assert_eq!(
            serve_body(&pinned, SegmentId(0)).len(),
            leaves_per_segment() * LEAF_BYTES
        );
    }

    #[test]
    fn pinning_a_pruned_segment_reports_it_rather_than_claiming_success() {
        // The silent-slash shape, inverted: the bytes are gone *before* the
        // serve-set is pinned (serve-set changed after a prune, restart
        // after an unpinned prune, bond on an already-pruned segment).
        // Pinning cannot bring them back, so a `Pinned` answer here would
        // let startup validation pass on a shard that can never be served
        // — and the persona would learn that from a slash.
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        store.prune_frozen(&[]).unwrap();
        assert_eq!(
            store.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::AlreadyPruned
        );
        // No pin was recorded, so the answer does not drift on a retry: a
        // pin over absent bytes would make the *second* call report the
        // segment servable purely because the first one wrote a row.
        assert_eq!(
            store.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::AlreadyPruned
        );
    }

    #[test]
    fn missing_bytes_under_a_pin_are_corruption_not_a_pinning_remedy() {
        // `prune_frozen` skips pinned segments, so a hole under a pin is
        // provably not a prune. Reporting `FrozenSegmentPruned` would hand
        // the operator a remedy — pin the serve-set — that succeeds,
        // changes nothing, and leaves the shard returning 404 until the
        // bond is slashed.
        let store = Arc::new(LeafStore::open_ephemeral().unwrap());
        store
            .append_drained(&distinct_segment_entries(), BlockHeight(10_000))
            .unwrap();
        assert_eq!(
            store.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::PinnedServable
        );

        // Injected corruption: no store operation can produce this state,
        // which is the point — it is the class the error must not conflate.
        let txn = store.db.begin_write().unwrap();
        {
            let mut leaves = txn.open_table(LEAVES_TABLE).unwrap();
            drop(leaves.remove(TreePosition(0)).unwrap());
        }
        txn.commit().unwrap();

        assert!(matches!(
            store.open_frozen_segment_body(SegmentId(0)),
            Err(StoreError::CorruptMeta(_))
        ));
    }

    #[test]
    fn rollback_survives_a_pinned_segment_below_a_pruned_one() {
        // The serving startup sequence makes the present leaves
        // *discontiguous*: pin the serve-set, prune the rest, and segment 0
        // survives below the hole segment 1 leaves behind. The partition
        // search bisects arbitrary positions, so a frontier taken as
        // "lowest present position" walks straight into that hole and the
        // wallet can never roll back across a reorg again.
        let store = Arc::new(LeafStore::open_ephemeral().unwrap());
        let e = u64::try_from(leaves_per_segment()).expect("segment size fits u64");
        let mut entries: Vec<LeafEntry> = (0..e).map(|i| entry_created_at(i, 50, 10)).collect();
        entries.extend((e..2 * e).map(|i| entry_created_at(i, 60, 20)));
        // Unfrozen tail, two leaves so the cut can land strictly above the
        // frontier rather than on it (an exact-frontier cut is rejected by
        // design and would not exercise the search).
        entries.push(entry_created_at(2 * e, 100, 20));
        entries.push(entry_created_at(2 * e + 1, 5_000, 4_000));
        store.append_drained(&entries, BlockHeight(10_000)).unwrap();
        assert!(
            store.frozen_segment(SegmentId(1)).unwrap().is_some(),
            "both segments must freeze for segment 0 to become an island"
        );

        assert_eq!(
            store.pin_segment_for_serving(SegmentId(0)).unwrap(),
            SegmentPin::PinnedServable
        );
        store.prune_frozen(&[]).unwrap();

        store.rollback_to_fork(BlockHeight(4_500)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 2 * e + 1);
        assert_eq!(
            serve_body(&store, SegmentId(0)).len(),
            leaves_per_segment() * LEAF_BYTES,
            "the pinned shard stays servable across the reorg — the point of the pin"
        );
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
        store.pin_segment_for_serving(SegmentId(0)).unwrap();
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

    /// The exact boundary the claim-era cutover advertises: a v3 store (the
    /// immediately-prior production layout, the one most likely to be
    /// encountered) is refused, because it can hold tag-2 `StakedKey` leaf
    /// rows this v4 build cannot represent. Pins the `<= 3` refusal so a
    /// future range/shim refactor cannot silently start accepting v3.
    #[test]
    fn schema_version_guard_rejects_prior_v3_store() {
        let path = temp_store_path("schema-guard-v3");

        // Build through the real path, then stamp the version cell back to 3.
        {
            let store = LeafStore::open(&path).unwrap();
            store
                .append_drained(&[sample_entry(0, 0)], BlockHeight(1))
                .unwrap();
        }
        const PRIOR_V3: u64 = 3;
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META_TABLE).unwrap();
                meta.insert(META_SCHEMA_VERSION, &PRIOR_V3).unwrap();
            }
            txn.commit().unwrap();
        }

        for _ in 0..2 {
            let err = LeafStore::open(&path).unwrap_err();
            assert!(
                matches!(
                    err,
                    StoreError::SchemaVersionMismatch {
                        found: PRIOR_V3,
                        expected: SCHEMA_VERSION,
                    }
                ),
                "expected SchemaVersionMismatch(found=3, expected={SCHEMA_VERSION}), got: {err:?}"
            );
        }

        std::fs::remove_file(&path).unwrap();
    }
}
