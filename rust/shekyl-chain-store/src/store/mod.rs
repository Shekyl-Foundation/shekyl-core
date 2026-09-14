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
//! consulted only to honour [`ApplyPolicy`](crate::apply_policy::ApplyPolicy);
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

mod error;
mod read;
mod write;

pub use error::StoreError;
pub use read::ReadSnapshot;
pub use write::WriteBatch;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use redb::{Database, Durability, ReadOnlyDatabase, ReadableDatabase, WriteTransaction};

use crate::apply_policy::ApplyPolicy;

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
    write_held: AtomicBool,
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
            .finish_non_exhaustive()
    }
}

impl ChainStore {
    /// Create or open the store at `path` for reading and writing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file cannot be created or opened.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::with_apply_policy(path, ApplyPolicy::default())
    }

    /// Create or open the store with an explicit [`ApplyPolicy`].
    ///
    /// Anything but [`ApplyPolicy::Full`] produces a run whose comparator
    /// output is **not** parity evidence. The policy is taken at
    /// construction rather than per call, so a run cannot change its own
    /// provenance halfway through.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file cannot be created or opened;
    /// [`StoreError::EmptyApplyStub`] if the policy stubs no families.
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
        // two would have been stamped `Full` over rows it never wrote.
        // redb's own `create` does exactly this open-with-create and hands
        // the file to `create_file`, so a 0-byte file is the path it knows.
        let mut builder = redb::Builder::new();
        builder.set_cache_size(CACHE_SIZE);
        let (db, fresh) = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.as_ref())
        {
            Ok(file) => (builder.create_file(file).map_err(StoreError::Open)?, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                (builder.create(path).map_err(StoreError::Open)?, false)
            }
            Err(e) => return Err(StoreError::Open(redb::DatabaseError::Storage(e.into()))),
        };
        // A caller cannot assert `Full` over rows it did not write: on an
        // existing file, Full is downgraded to Unknown (fail-closed until
        // the policy is persisted). Non-Full policies stand -- they are
        // already not evidence, and a stubbed reopen is a legitimate run.
        let apply_policy = match (fresh, apply_policy) {
            (false, ApplyPolicy::Full) => ApplyPolicy::Unknown,
            (_, p) => p,
        };
        Ok(Self {
            backend: Backend::Writable(db),
            apply_policy,
            write_held: AtomicBool::new(false),
        })
    }

    /// The policy this store was opened under.
    #[must_use]
    pub const fn apply_policy(&self) -> ApplyPolicy {
        self.apply_policy
    }

    /// Open an **existing** store without the ability to write.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file is absent or cannot be opened.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = redb::Builder::new()
            .set_cache_size(CACHE_SIZE)
            .open_read_only(path)
            .map_err(StoreError::Open)?;
        Ok(Self {
            backend: Backend::ReadOnly(db),
            // A read-only handle is always a reopen, and no policy is
            // persisted yet, so it can never vouch for what it finds.
            apply_policy: ApplyPolicy::Unknown,
            write_held: AtomicBool::new(false),
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
        if self
            .write_held
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(StoreError::WriteInProgress);
        }
        match arm_write(db) {
            Ok(txn) => Ok(WriteBatch::new(txn, self.apply_policy, &self.write_held)),
            Err(e) => {
                self.write_held.store(false, Ordering::Release);
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

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
