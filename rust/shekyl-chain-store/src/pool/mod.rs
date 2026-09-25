// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction pool's store — DRS-E1 S-POOL (`DRS_E1_SPOOL.md`;
//! Round 1 RULED 2026-09-24, `SPL-Q1`, `SPL-Q2`, `SPL-Q4`, `SPL-Q5`,
//! `SPL-Q8`).
//!
//! **A second file, not a table set in the chain store.** `DAEMON_REDB_STORE.md`
//! §5.1 ruled that the pool does not live in the consensus store file: pool
//! state is not consensus state and not reconstructible from blocks, so its
//! relay-timing residue must not share free pages with the chain's tables,
//! and the file may be discarded wholesale. [`PoolStore`] is that file —
//! its own `redb::Database`, its own header, its own three tables
//! ([`schema`]) — in the same crate as [`crate::store::ChainStore`] so the
//! two share one codec vocabulary, one batch shape and one set of gates
//! (`SPL-Q2`). The two files never share a transaction, and the type system
//! says so by giving them different handles.
//!
//! # Seven operations (§3.2)
//!
//! Writes, inside [`PoolStore::write`]'s closure on a [`PoolBatch`]:
//! **P1** [`insert`](PoolBatch::insert), **P2** [`update`](PoolBatch::update),
//! **P3** [`remove`](PoolBatch::remove). Reads, on a [`PoolSnapshot`]:
//! **P4** [`record`](PoolSnapshot::record), **P5** [`blob`](PoolSnapshot::blob),
//! **P6** [`len`](PoolSnapshot::len), **P7** [`entries`](PoolSnapshot::entries).
//! None of them classifies (applies a `RelayCategory`), orders by fee,
//! parses a transaction, decides eviction or holds an index: those are the
//! pool's (E5), and the C++ `tx_memory_pool` rebuilds every one of its
//! in-memory structures from a full enumeration at `init` (SPL-9), so P7 is
//! the only enumeration the store needs to offer.
//!
//! # The write API is the closure, on purpose (SPL-16)
//!
//! `LockedTXN`, the C++ pool's transactional wrapper, aborts on uncommitted
//! exit — and `get_relayable_transactions` once returned without
//! `lock.commit()`, silently rolling back every Dandelion++ relay-timestamp
//! write on every invocation (origin-disclosure class). A Rust batch held
//! by a caller who can `return` early, with a `Drop` that aborts, is the
//! same defect in a new language. So the batch is handed only to a
//! [`PoolStore::write`] closure: the store constructs it, runs the closure,
//! commits on `Ok` and aborts on `Err` or unwind. *Forgetting to commit is
//! unrepresentable.* This is [`ChainStore::write`](crate::store::ChainStore::write)'s
//! shape (`RELAY_STATE_REFERENCE_SHAPES.md` §1).
//!
//! # Two files, two commits (SPL-7, `SPL-Q5`)
//!
//! A block connect that takes a transaction out of the pool is two commits
//! in two files, and no cross-file transaction is offered because none can
//! be made. The contract E5 inherits: **the chain commits first, the pool
//! second**, and the pool **reconciles against the chain at open** — a crash
//! between the two leaves a mined transaction still in the pool, which
//! reconciliation removes; the other order would remove it from the pool
//! before it was in a block, losing it. Reconciliation is E5's (it is
//! admission's knowledge — the key-image set), and it is *new* work: the
//! C++ `init` never reads the chain's `spent_keys`.
//!
//! # The header, and the one case that recreates (`SPL-Q8`)
//!
//! A fresh file is sealed with the crate's `SCHEMA_VERSION` in its own
//! header cell. On reopen the cell is read first. A sealed pool file at
//! **another** version is **recreated** — the file is discardable by ruling
//! and has no corpus to rebuild from — and [`PoolOpen::Recreated`] tells the
//! caller so it can say so in one log line. Everything else is
//! **refused, never deleted** ([`StoreCannot::PoolFileForeign`]): a path that
//! is not a redb database, a database without the header table or cell, a
//! cell that does not decode. A wrong `--data-dir`, a foreign file or a
//! tampered one is an operator's to look at, not the store's to erase.
//!
//! # Durability
//!
//! [`DURABILITY`](crate::store::DURABILITY) and two-phase commit, the same
//! as the chain file (`SPL-Q4`): "discardable" is about what the file may be
//! *made* to lose, not about accepting a torn one. One durability policy,
//! applied per file; BENCH measures the pool's write rate (SPL-13).

pub mod schema;

pub use crate::codec::{
    ArrivedPhase, BlockRef, Origin, OriginatedPhase, PoolRecord, Readiness, RelayState,
    Responsibility,
};
pub use schema::PoolTxBytes;

use std::path::Path;

use redb::{
    Database, ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableHandle, WriteTransaction,
};
use shekyl_store_codec::{BlobKind, Canonical, Raw};
use shekyl_types::TxHash;

use crate::codec::{PropertyCellBytes, SchemaVersion, SCHEMA_VERSION};
use crate::store::{
    CellFault, EngineError, PoolCannot, StoreCannot, StoreError, StoreInvariant, DURABILITY,
    TWO_PHASE_COMMIT,
};

use schema::{POOL_BLOB, POOL_HEADER, POOL_META};

/// The header cell that carries the layout version the file was sealed at.
pub const POOL_VERSION_KEY: &str = "pool_schema_version";

/// The pool file's cache: 64 MiB. A pool is a few thousand transactions at
/// most; the chain file's 1 GiB would be a reservation nothing uses.
pub const POOL_CACHE_SIZE: usize = 64 * 1024 * 1024;

/// How [`PoolStore::create`] arrived at an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolOpen {
    /// No file existed; one was created and sealed at [`SCHEMA_VERSION`].
    Created,
    /// A sealed file at the current version was opened.
    Opened,
    /// A sealed file at another version was **recreated** (`SPL-Q8`): the
    /// old file was removed and a fresh one sealed. `from` is the version
    /// the old file carried — the caller's one log line names it.
    Recreated {
        /// The layout the discarded file was sealed at.
        from: SchemaVersion,
    },
}

/// The pool file. One writer, many readers; see the module doc.
pub struct PoolStore {
    db: Database,
}

impl core::fmt::Debug for PoolStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolStore").finish_non_exhaustive()
    }
}

/// What the header said about an existing file.
enum Header {
    Current,
    Other(SchemaVersion),
}

impl PoolStore {
    /// Create, open, or recreate the pool file at `path` (module doc, §"The
    /// header").
    ///
    /// # Errors
    ///
    /// [`EngineError::Open`] if the path cannot be created or a redb file
    /// cannot be opened for an engine reason; [`StoreCannot::PoolFileForeign`]
    /// if the path holds something this store neither wrote nor may
    /// recreate; [`EngineError::Storage`] / [`EngineError::Commit`] if the
    /// seal cannot be written. A fresh file the seal fails on is removed
    /// again.
    pub fn create(path: impl AsRef<Path>) -> Result<(Self, PoolOpen), StoreError> {
        let path = path.as_ref();
        let mut builder = redb::Builder::new();
        builder.set_cache_size(POOL_CACHE_SIZE);
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => Self::seal_fresh(&builder, file, path).map(|s| (s, PoolOpen::Created)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let db = match builder.open(path) {
                    Ok(db) => db,
                    // Not a redb database (or a torn one redb refuses to
                    // repair): refused, not recreated — the store cannot tell
                    // its own torn file from a foreign one by looking, and
                    // deleting on that basis is the automatic wipe `SPL-Q8`
                    // declined.
                    Err(redb::DatabaseError::Storage(
                        redb::StorageError::Corrupted(_) | redb::StorageError::Io(_),
                    )) => return Err(StoreCannot::PoolFileForeign.into()),
                    Err(e) => return Err(EngineError::Open(e).into()),
                };
                match Self::read_header(&db)? {
                    Header::Current => Ok((Self { db }, PoolOpen::Opened)),
                    Header::Other(from) => {
                        // Release the engine's file lock before removing.
                        drop(db);
                        std::fs::remove_file(path).map_err(|e| {
                            EngineError::Open(redb::DatabaseError::Storage(e.into()))
                        })?;
                        let file = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open(path)
                            .map_err(|e| {
                                EngineError::Open(redb::DatabaseError::Storage(e.into()))
                            })?;
                        Self::seal_fresh(&builder, file, path)
                            .map(|s| (s, PoolOpen::Recreated { from }))
                    }
                }
            }
            Err(e) => Err(EngineError::Open(redb::DatabaseError::Storage(e.into())).into()),
        }
    }

    fn seal_fresh(
        builder: &redb::Builder,
        file: std::fs::File,
        path: &Path,
    ) -> Result<Self, StoreError> {
        let sealed = (|| {
            let db = builder.create_file(file).map_err(EngineError::Open)?;
            let txn = arm_write(&db)?;
            {
                let mut header = txn.open_table(POOL_HEADER).map_err(EngineError::Table)?;
                header
                    .insert(
                        POOL_VERSION_KEY,
                        Raw::<PropertyCellBytes>::new(&SCHEMA_VERSION.encode()),
                    )
                    .map_err(EngineError::Storage)?;
                // Both tables exist from the first commit, so a reader never
                // has to read *absent table* as *empty pool* (SCR-17's rule).
                txn.open_table(POOL_META).map_err(EngineError::Table)?;
                txn.open_table(POOL_BLOB).map_err(EngineError::Table)?;
            }
            txn.commit().map_err(EngineError::Commit)?;
            Ok::<_, StoreError>(Self { db })
        })();
        match sealed {
            Ok(store) => Ok(store),
            Err(e) => {
                // The path exists only because `create_new` just made it; do
                // not leave a headerless file for the next open to refuse.
                drop(std::fs::remove_file(path));
                Err(e)
            }
        }
    }

    /// Read the header of an existing file, and — at the current version —
    /// verify the sealed table set. Absence or an undecodable cell, or a
    /// current-version seal over a missing or re-typed table, is
    /// [`StoreCannot::PoolFileForeign`]: not this store's file, and not one
    /// it may recreate.
    fn read_header(db: &Database) -> Result<Header, StoreError> {
        let txn = db.begin_read().map_err(EngineError::BeginRead)?;
        let table = match txn.open_table(POOL_HEADER) {
            Ok(t) => t,
            Err(
                redb::TableError::TableDoesNotExist(_) | redb::TableError::TableTypeMismatch { .. },
            ) => return Err(StoreCannot::PoolFileForeign.into()),
            Err(e) => return Err(EngineError::Table(e).into()),
        };
        let Some(cell) = table.get(POOL_VERSION_KEY).map_err(EngineError::Storage)? else {
            return Err(StoreCannot::PoolFileForeign.into());
        };
        let Ok(found) = SchemaVersion::decode(cell.value().bytes()) else {
            return Err(StoreCannot::PoolFileForeign.into());
        };
        if found != SCHEMA_VERSION {
            // Another layout recreates, whatever its table set: the seal is
            // this store's, the version is not, and the file is discardable.
            return Ok(Header::Other(found));
        }
        // The seal at this version created both tables (`seal_fresh`), so a
        // current-version file that lacks one — or holds one under another
        // type — is not one this store left behind: tampered or torn.
        // Refused and kept (`SPL-Q8`); the chain store's `verify_sealed_tables`
        // posture. Without this, such a file opens as `Opened` and fails at
        // the first op as a bare engine error (Copilot, PR #851).
        require_sealed_table(&txn, POOL_META)?;
        require_sealed_table(&txn, POOL_BLOB)?;
        Ok(Header::Current)
    }

    /// Run `f` inside a write batch and commit if it returns `Ok`. The
    /// **only** way to reach a [`PoolBatch`] (module doc, SPL-16).
    ///
    /// # Errors
    ///
    /// [`EngineError::BeginWrite`] / [`EngineError::Durability`] if the
    /// engine refuses to begin; whatever `f` returns, in which case the
    /// batch is aborted and nothing lands; [`EngineError::Commit`] if the
    /// engine could not commit.
    pub fn write<R, E, F>(&self, f: F) -> Result<R, E>
    where
        E: From<StoreError>,
        F: FnOnce(&mut PoolBatch<'_>) -> Result<R, E>,
    {
        let txn = arm_write(&self.db)?;
        let mut batch = PoolBatch {
            txn: Some(txn),
            _store: core::marker::PhantomData,
        };
        let outcome = f(&mut batch);
        batch.complete(outcome)
    }

    /// Begin a read snapshot. Concurrent with a live write batch.
    ///
    /// # Errors
    ///
    /// [`EngineError::BeginRead`] if the engine refuses.
    pub fn begin_read(&self) -> Result<PoolSnapshot, StoreError> {
        let txn = self.db.begin_read().map_err(EngineError::BeginRead)?;
        Ok(PoolSnapshot { txn })
    }
}

/// A current-version file's data table must open under the type the seal
/// wrote. Missing or re-typed is [`StoreCannot::PoolFileForeign`].
fn require_sealed_table<K, V>(
    txn: &ReadTransaction,
    definition: redb::TableDefinition<'_, K, V>,
) -> Result<(), StoreError>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    match txn.open_table(definition) {
        Ok(_) => Ok(()),
        Err(
            redb::TableError::TableDoesNotExist(_) | redb::TableError::TableTypeMismatch { .. },
        ) => Err(StoreCannot::PoolFileForeign.into()),
        Err(e) => Err(EngineError::Table(e).into()),
    }
}

fn arm_write(db: &Database) -> Result<WriteTransaction, StoreError> {
    let mut txn = db.begin_write().map_err(EngineError::BeginWrite)?;
    txn.set_durability(DURABILITY)
        .map_err(EngineError::Durability)?;
    txn.set_two_phase_commit(TWO_PHASE_COMMIT);
    Ok(txn)
}

/// A write batch on the pool file — handed only to a [`PoolStore::write`]
/// closure, never returned to a caller (SPL-16).
#[must_use = "a PoolBatch is only ever handed to a `PoolStore::write` closure"]
pub struct PoolBatch<'s> {
    txn: Option<WriteTransaction>,
    _store: core::marker::PhantomData<&'s PoolStore>,
}

impl core::fmt::Debug for PoolBatch<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolBatch").finish_non_exhaustive()
    }
}

impl PoolBatch<'_> {
    fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("a live batch holds its transaction until complete")
    }

    /// **P1.** Insert a new entry: both rows, in this batch.
    ///
    /// # Errors
    ///
    /// [`PoolCannot::AlreadyHeld`] if the pool holds `txid` (the C++
    /// `MDB_KEYEXIST` throw, typed and non-fatal — the pool upserts by
    /// removing first); [`PoolCannot::EmptyBlob`] if `blob` is empty;
    /// [`PoolCannot::NullFcmpCache`] if the record's verification cache is
    /// the null hash; [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if
    /// `txid` has a row in one table and not the other.
    pub fn insert(
        &mut self,
        txid: TxHash,
        record: &PoolRecord,
        blob: &[u8],
    ) -> Result<(), StoreError> {
        PoolTxBytes::well_formed(blob).map_err(|_| PoolCannot::EmptyBlob)?;
        refuse_null_cache(record)?;
        let key = txid.to_bytes();
        let mut meta = self
            .txn()
            .open_table(POOL_META)
            .map_err(EngineError::Table)?;
        let mut blobs = self
            .txn()
            .open_table(POOL_BLOB)
            .map_err(EngineError::Table)?;
        let has_meta = meta.get(key).map_err(EngineError::Storage)?.is_some();
        let has_blob = blobs.get(key).map_err(EngineError::Storage)?.is_some();
        match pair(has_meta, has_blob) {
            Pair::Held => return Err(PoolCannot::AlreadyHeld.into()),
            Pair::Absent => {}
            Pair::Unpaired => return Err(StoreInvariant::PoolEntryUnpaired { txid }.into()),
        }
        meta.insert(key, record.encoded().as_encoded())
            .map_err(EngineError::Storage)?;
        blobs
            .insert(key, Raw::<PoolTxBytes>::new(blob))
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// **P2.** Overwrite an entry's record. The blob is immutable for the
    /// entry's life; the origin is permanent.
    ///
    /// # Errors
    ///
    /// [`PoolCannot::NotHeld`] if the pool does not hold `txid`;
    /// [`PoolCannot::OriginChanged`] if [`PoolRecord::origin`] differs from
    /// the stored one (§92.4, `SPL-Q9`); [`PoolCannot::PhaseNotForward`] if
    /// the phase is neither the stored phase nor a forward step of
    /// [`RelayState::upgrade`](crate::codec::RelayState::upgrade);
    /// [`PoolCannot::NullFcmpCache`] if the verification cache is the null
    /// hash; [`StoreInvariant::CellCorrupt`] if the stored row does not decode.
    pub fn update(&mut self, txid: &TxHash, record: &PoolRecord) -> Result<(), StoreError> {
        refuse_null_cache(record)?;
        let key = txid.to_bytes();
        let mut meta = self
            .txn()
            .open_table(POOL_META)
            .map_err(EngineError::Table)?;
        let stored = {
            let Some(guard) = meta.get(key).map_err(EngineError::Storage)? else {
                return Err(PoolCannot::NotHeld.into());
            };
            guard.value().decode().map_err(|cause| {
                StoreError::from(StoreInvariant::CellCorrupt {
                    key: POOL_META.name(),
                    fault: CellFault::Undecodable(cause),
                })
            })?
        };
        if stored.origin() != record.origin() {
            return Err(PoolCannot::OriginChanged.into());
        }
        if !stored.relay_state.accepts(record.relay_state) {
            return Err(PoolCannot::PhaseNotForward.into());
        }
        meta.insert(key, record.encoded().as_encoded())
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// **P3.** Remove an entry: both rows. Idempotent — an absent entry is
    /// not an error (the C++ ignores `MDB_NOTFOUND` on each).
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn remove(&mut self, txid: &TxHash) -> Result<(), StoreError> {
        let key = txid.to_bytes();
        let mut meta = self
            .txn()
            .open_table(POOL_META)
            .map_err(EngineError::Table)?;
        let mut blobs = self
            .txn()
            .open_table(POOL_BLOB)
            .map_err(EngineError::Table)?;
        meta.remove(key).map_err(EngineError::Storage)?;
        blobs.remove(key).map_err(EngineError::Storage)?;
        Ok(())
    }

    fn complete<R, E: From<StoreError>>(mut self, outcome: Result<R, E>) -> Result<R, E> {
        let txn = self.txn.take().expect("complete runs once");
        match outcome {
            Ok(r) => {
                txn.commit()
                    .map_err(|e| StoreError::from(EngineError::Commit(e)))?;
                Ok(r)
            }
            Err(e) => {
                // Dropping the transaction aborts it; the store decided, not
                // a caller's early return (SPL-16).
                drop(txn);
                Err(e)
            }
        }
    }
}

/// Whether the two rows of one key are both present, both absent, or split.
#[derive(Clone, Copy)]
enum Pair {
    Absent,
    Held,
    Unpaired,
}

fn pair(has_meta: bool, has_blob: bool) -> Pair {
    match (has_meta, has_blob) {
        (false, false) => Pair::Absent,
        (true, true) => Pair::Held,
        (true, false) | (false, true) => Pair::Unpaired,
    }
}

fn refuse_null_cache(record: &PoolRecord) -> Result<(), StoreError> {
    if record.has_null_fcmp_cache() {
        Err(PoolCannot::NullFcmpCache.into())
    } else {
        Ok(())
    }
}

/// A read snapshot of the pool file.
pub struct PoolSnapshot {
    txn: ReadTransaction,
}

impl core::fmt::Debug for PoolSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolSnapshot").finish_non_exhaustive()
    }
}

/// One enumerated entry (P7): the hash and its record. The blob is a second
/// read the consumer asks for ([`PoolEntry::blob`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolEntry {
    /// The transaction.
    pub txid: TxHash,
    /// Its record.
    pub record: PoolRecord,
}

impl PoolEntry {
    /// The entry's transaction bytes, from the same snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if the meta row this
    /// entry came from has no blob row — the C++ `DB_ERROR("Failed to find
    /// txpool tx blob to match metadata")`, named. [`PoolSnapshot::blob`]
    /// reports the same fault, including a blob row with no meta row.
    pub fn blob(&self, snapshot: &PoolSnapshot) -> Result<Vec<u8>, StoreError> {
        snapshot
            .blob(&self.txid)?
            .ok_or_else(|| StoreInvariant::PoolEntryUnpaired { txid: self.txid }.into())
    }
}

impl PoolSnapshot {
    fn meta(
        &self,
    ) -> Result<ReadOnlyTable<[u8; 32], shekyl_store_codec::Coded<PoolRecord>>, StoreError> {
        self.txn
            .open_table(POOL_META)
            .map_err(|e| EngineError::Table(e).into())
    }

    fn blobs(
        &self,
    ) -> Result<ReadOnlyTable<[u8; 32], shekyl_store_codec::Blob<PoolTxBytes>>, StoreError> {
        self.txn
            .open_table(POOL_BLOB)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// **P4.** The entry's record, or `None` if the pool does not hold it.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::CellCorrupt`] (SI-7) if the row does not decode.
    pub fn record(&self, txid: &TxHash) -> Result<Option<PoolRecord>, StoreError> {
        let table = self.meta()?;
        let Some(guard) = table.get(txid.to_bytes()).map_err(EngineError::Storage)? else {
            return Ok(None);
        };
        guard.value().decode().map(Some).map_err(|cause| {
            StoreInvariant::CellCorrupt {
                key: POOL_META.name(),
                fault: CellFault::Undecodable(cause),
            }
            .into()
        })
    }

    /// **P5.** The entry's transaction bytes, unparsed, or `None` if neither
    /// row holds `txid`. No category parameter: the filter is
    /// `record(h)?.filter(|r| r.matches(cat))` at the caller (SPL-3).
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if exactly one of the
    /// two rows holds `txid`. Engine faults otherwise.
    pub fn blob(&self, txid: &TxHash) -> Result<Option<Vec<u8>>, StoreError> {
        let key = txid.to_bytes();
        let meta_held = self
            .meta()?
            .get(key)
            .map_err(EngineError::Storage)?
            .is_some();
        let bytes = self
            .blobs()?
            .get(key)
            .map_err(EngineError::Storage)?
            .map(|guard| guard.value().bytes().to_vec());
        match pair(meta_held, bytes.is_some()) {
            Pair::Absent => Ok(None),
            Pair::Held => Ok(bytes),
            Pair::Unpaired => Err(StoreInvariant::PoolEntryUnpaired { txid: *txid }.into()),
        }
    }

    /// **P6.** How many entries the pool holds. A per-class count is the
    /// caller's fold over [`entries`](Self::entries) — the C++ already
    /// scanned for it.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn len(&self) -> Result<u64, StoreError> {
        self.meta()?
            .len()
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// Whether the pool holds no entry.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        self.len().map(|n| n == 0)
    }

    /// **P7.** Every entry, in key order, each with its record. The class
    /// filter and any early exit are the consumer's; the blob is
    /// [`PoolEntry::blob`], a second read on demand.
    ///
    /// # Errors
    ///
    /// Opening the table; per item, [`StoreInvariant::CellCorrupt`] for a
    /// row that does not decode.
    pub fn entries(
        &self,
    ) -> Result<impl Iterator<Item = Result<PoolEntry, StoreError>> + '_, StoreError> {
        let table = self.meta()?;
        let range = table.range::<[u8; 32]>(..).map_err(EngineError::Storage)?;
        Ok(range.map(|item| {
            let (k, v) = item.map_err(EngineError::Storage)?;
            let txid = TxHash::from_bytes(k.value());
            let record = v.value().decode().map_err(|cause| {
                StoreError::from(StoreInvariant::CellCorrupt {
                    key: POOL_META.name(),
                    fault: CellFault::Undecodable(cause),
                })
            })?;
            Ok(PoolEntry { txid, record })
        }))
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
