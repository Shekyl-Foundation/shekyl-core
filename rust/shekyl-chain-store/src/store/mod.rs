// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store lifecycle and the write-transaction surface (DRS-E1 increment 1,
//! surface **S-TXN**).
//!
//! S-TXN is first because every other surface depends on it
//! ([`DAEMON_REDB_STORE.md`](../../../../docs/design/DAEMON_REDB_STORE.md)
//! §4's extraction order). This module opens the database, arms its
//! commit policy, and hands out the write handle. Table *identity* is
//! consulted only to honour [`ApplyPolicy`];
//! codecs live elsewhere.
//!
//! # The write handle is a possession type, and that is the point
//!
//! `BlockchainLMDB` keeps its write transaction in a raw member pointer
//! and dereferences `*m_write_txn` at **129** sites with no guard at the
//! dereference (DRS-W3). [`WriteBatch`] makes the precondition
//! unrepresentable: it cannot be null, table access goes through it (never
//! a raw `WriteTransaction`), and [`commit`](WriteBatch::commit) /
//! [`abort`](WriteBatch::abort) consume it.
//!
//! A second live batch is a typed [`StoreError::WriteInProgress`], not
//! redb's blocking `begin_write`. Same-thread re-entry would otherwise
//! deadlock. The C++ is **not** the same shape, and saying so precisely is
//! the point: `BlockchainLMDB::batch_start` **returns `false`** for a
//! second batch (`m_batch_active` or `m_write_batch_txn` set,
//! `db_lmdb.cpp:4103`/`:4105`) and two core callers *spin* on that; it
//! **throws** only when a non-batch `m_write_txn` is live (`:4108`). This
//! store refuses with a typed error and never spins — DRS-W17.
//!
//! # Durability is declared, never inherited
//!
//! **DRS-D9** takes the strictest practical durability, and **Tier-A A4**
//! requires it be *explicit* — "not library default by omission". redb
//! 4.1.0's `Durability` default **is** [`Durability::Immediate`], so a
//! test that merely observed durable commits would pass whether or not
//! this crate set anything. The policy is therefore a declared constant
//! applied to every write transaction.
//!
//! Immediate fsync is not the whole policy. redb's default commit is
//! 1-phase with xxhash checksums; [`TWO_PHASE_COMMIT`] enables the
//! engine's 2-phase algorithm, which is the stricter recovery option it
//! offers. Cache size is the same A4 shape on the axis A5 measures:
//! [`CACHE_SIZE`] is redb's 1 GiB default made explicit so a future
//! engine bump cannot change RSS by omission. The *number* reopens
//! against DRS-BENCH peak-RSS, never to "go faster" (§5.2).
//!
//! # The header is checked before anything else (increment 2)
//!
//! A fresh file is **sealed** in its first transaction with the layout
//! version and the creating session's provenance; an existing file has
//! both read back — in a read transaction, so a stale file is never
//! stamped current in passing — before any table is opened. A file with no
//! version cell is not one this binary wrote and is refused
//! ([`StoreError::SchemaVersionAbsent`]); a file at another version is
//! refused in both directions ([`StoreError::SchemaVersionMismatch`]). The
//! answer to either is a rebuild from the block corpus
//! (`DAEMON_REDB_STORE.md` §11), never a migrator.

mod error;
mod header;
mod read;
mod shared;
mod write;

pub use error::{CellFault, StoreError};
pub use read::ReadSnapshot;
pub use write::WriteBatch;

use std::path::Path;

use redb::{Database, Durability, ReadOnlyDatabase, ReadableDatabase, WriteTransaction};

use crate::apply_policy::ApplyPolicy;
use crate::provenance::Provenance;

use shared::Shared;

/// The durability every write transaction is armed with (DRS-D9, Tier-A A4).
pub const DURABILITY: Durability = Durability::Immediate;

/// Two-phase commit is armed on every write transaction.
///
/// redb's 1-phase default fsyncs, then relies on xxhash to pick a commit
/// slot after a crash. The engine documents a remaining attacker who
/// controls flush order, can crash during `fsync`, knows the file, and
/// can put arbitrary data in a write txn — all four are true of a
/// consensus store taking network blocks. 2-phase is the stricter
/// algorithm it offers; lying disks remain out of scope (redb says so).
pub const TWO_PHASE_COMMIT: bool = true;

/// Cache the engine is opened with.
///
/// The value is redb 4.1.0's own default (1 GiB) made explicit so a
/// future redb bump cannot change RSS by omission (A4's shape, on the
/// axis A5 measures). Reopen the number against DRS-BENCH peak-RSS,
/// never to "go faster".
pub const CACHE_SIZE: usize = 1024 * 1024 * 1024;

/// The daemon's consensus store.
///
/// Opening is the only way to get one, so there is no "closed" state to
/// check against: `close` in the C++ surface is this value being dropped.
///
/// **Read-only is the engine's mode, not a flag this code checks.** redb
/// has a real [`ReadOnlyDatabase`]; a `bool` on top of `Database::create`
/// would still create the file if absent.
pub struct ChainStore {
    backend: Backend,
    apply_policy: ApplyPolicy,
    shared: Shared,
}

enum Backend {
    Writable(Database),
    ReadOnly(ReadOnlyDatabase),
}

impl core::fmt::Debug for ChainStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainStore")
            .field("read_only", &self.is_read_only())
            .field("apply_policy", &self.apply_policy)
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl ChainStore {
    /// Create or open the store at `path` for reading and writing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file cannot be created or opened; the
    /// header refusals listed on [`with_apply_policy`](Self::with_apply_policy).
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::with_apply_policy(path, ApplyPolicy::default())
    }

    /// Create or open the store with an explicit [`ApplyPolicy`].
    ///
    /// The policy is this **session's** intent, taken at construction so a
    /// run cannot change it halfway through. What the *file* has been
    /// written under is [`provenance`](Self::provenance): a fresh file is
    /// sealed with this policy's stubbed set, and a stubbed session's
    /// commits widen an existing file's record. Only a file whose
    /// provenance is [`Provenance::FULL`] is parity evidence — a `Full`
    /// session over a tainted file does not clean it.
    ///
    /// # Errors
    ///
    /// [`StoreError::EmptyApplyStub`] if the policy stubs no families —
    /// checked before the path is touched; [`StoreError::Open`] if the file
    /// cannot be created or opened; on an existing file,
    /// [`StoreError::SchemaVersionAbsent`],
    /// [`StoreError::SchemaVersionMismatch`] or
    /// [`StoreError::CellCorrupt`] if its header is not one this binary
    /// can vouch for. A fresh file the engine refuses to take, or that
    /// cannot be sealed, is removed again, so a failed create does not
    /// leave a headerless file the next open refuses.
    pub fn with_apply_policy(
        path: impl AsRef<Path>,
        apply_policy: ApplyPolicy,
    ) -> Result<Self, StoreError> {
        apply_policy
            .reject_empty_stub()
            .map_err(|crate::apply_policy::EmptyApplyStub| StoreError::EmptyApplyStub)?;
        // Fresh-vs-existing is decided by the SAME syscall that claims the
        // path, never by a separate probe: `create_new` either creates the
        // file atomically (fresh) or fails with AlreadyExists (reopen). An
        // earlier draft checked `exists()` first and then called `create`,
        // which also opens existing files -- a creator racing between the
        // two would have sealed a file it did not create. redb's own
        // `create` does exactly this open-with-create and hands the file to
        // `create_file`, so a 0-byte file is the path it knows.
        let mut builder = redb::Builder::new();
        builder.set_cache_size(CACHE_SIZE);
        let path = path.as_ref();
        let (db, provenance) = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => match create_sealed(&builder, file, apply_policy) {
                Ok(fresh) => fresh,
                Err(e) => {
                    // The path exists only because `create_new` just made
                    // it. Whatever refused after that -- the engine taking
                    // the file or the seal -- must not leave it behind for
                    // the next open to refuse as an existing store with no
                    // header. `create_sealed` has dropped its `Database` by
                    // the time we get here, so the file is unlocked.
                    drop(std::fs::remove_file(path));
                    return Err(e);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let db = builder.create(path).map_err(StoreError::Open)?;
                let provenance = header::verify(&db.begin_read().map_err(StoreError::BeginRead)?)?;
                (db, provenance)
            }
            Err(e) => return Err(StoreError::Open(redb::DatabaseError::Storage(e.into()))),
        };
        Ok(Self {
            backend: Backend::Writable(db),
            apply_policy,
            shared: Shared::new(provenance),
        })
    }

    /// The policy this session was opened under.
    #[must_use]
    pub const fn apply_policy(&self) -> ApplyPolicy {
        self.apply_policy
    }

    /// What the file's rows were written under, as persisted in it.
    ///
    /// Read from the `apply_policy` cell at open and widened in step with
    /// every stubbed commit this handle makes. This — not
    /// [`apply_policy`](Self::apply_policy) — is what an artifact stamps.
    ///
    /// # The mirror is exact, and why
    ///
    /// The cell only ever widens, and only a committed stubbed batch widens
    /// it. While this handle is live no other handle can commit: redb holds
    /// an exclusive `flock` on the file for the life of a writable
    /// `Database` and a shared one for a read-only handle
    /// (`redb-4.1.0/src/tree_store/page_store/file_backend/optimized.rs:27`,
    /// read at the pinned source), so a second writable open — from this
    /// process or another — is refused with
    /// [`redb::DatabaseError::DatabaseAlreadyOpen`] rather than admitted,
    /// and a read-only handle excludes every writer for as long as it
    /// exists. The value this method returns is therefore the file's value,
    /// not a cached approximation of it. Platforms where the lock is
    /// `Unsupported` (none the daemon targets; redb proceeds unlocked and
    /// warns) inherit redb's own contract that the operator keeps one
    /// process on the file.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        self.shared.provenance()
    }

    /// Open an **existing** store without the ability to write.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file is absent or cannot be opened; the
    /// same header refusals as [`with_apply_policy`](Self::with_apply_policy).
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = redb::Builder::new()
            .set_cache_size(CACHE_SIZE)
            .open_read_only(path)
            .map_err(StoreError::Open)?;
        let provenance = header::verify(&db.begin_read().map_err(StoreError::BeginRead)?)?;
        Ok(Self {
            backend: Backend::ReadOnly(db),
            // A read-only handle writes nothing, so its session policy is
            // vacuously Full; the file's history is `provenance`.
            apply_policy: ApplyPolicy::Full,
            shared: Shared::new(provenance),
        })
    }

    /// Whether this store refuses writes.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self.backend, Backend::ReadOnly(_))
    }

    /// Begin a write batch. The **only** way to obtain a [`WriteBatch`].
    ///
    /// # Errors
    ///
    /// [`StoreError::ReadOnly`] if the store was opened read-only;
    /// [`StoreError::WriteInProgress`] if a batch is already live;
    /// [`StoreError::BeginWrite`] or [`StoreError::Durability`] if the
    /// engine refuses.
    pub fn begin_batch(&self) -> Result<WriteBatch<'_>, StoreError> {
        let Backend::Writable(db) = &self.backend else {
            return Err(StoreError::ReadOnly);
        };
        if !self.shared.try_hold_write() {
            return Err(StoreError::WriteInProgress);
        }
        match arm_write(db) {
            Ok(txn) => Ok(WriteBatch::new(txn, self.apply_policy, &self.shared)),
            Err(e) => {
                self.shared.release_write();
                Err(e)
            }
        }
    }

    /// Begin a read snapshot. Concurrent with a live write batch.
    ///
    /// # Errors
    ///
    /// [`StoreError::BeginRead`] if the engine refuses.
    pub fn begin_read(&self) -> Result<ReadSnapshot<'_>, StoreError> {
        match &self.backend {
            Backend::Writable(db) => db.begin_read(),
            Backend::ReadOnly(db) => db.begin_read(),
        }
        .map(ReadSnapshot::new)
        .map_err(StoreError::BeginRead)
    }
}

fn arm_write(db: &Database) -> Result<WriteTransaction, StoreError> {
    let mut txn = db.begin_write().map_err(StoreError::BeginWrite)?;
    txn.set_durability(DURABILITY)
        .map_err(StoreError::Durability)?;
    txn.set_two_phase_commit(TWO_PHASE_COMMIT);
    Ok(txn)
}

/// Hand a just-created, still-empty file to the engine and seal its header
/// in the first transaction, under the same durability every batch
/// commits with.
///
/// Everything that can fail between `create_new` and a usable store runs
/// here, so the caller has exactly one place to undo the creation. On
/// `Err` the `Database` is dropped before returning, releasing the
/// engine's file lock so the caller's `remove_file` can succeed.
fn create_sealed(
    builder: &redb::Builder,
    file: std::fs::File,
    policy: ApplyPolicy,
) -> Result<(Database, Provenance), StoreError> {
    let db = builder.create_file(file).map_err(StoreError::Open)?;
    let txn = arm_write(&db)?;
    let provenance = header::seal(&txn, policy)?;
    txn.commit().map_err(StoreError::Commit)?;
    Ok((db, provenance))
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "header_tests.rs"]
mod header_tests;
