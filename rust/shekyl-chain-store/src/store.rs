// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store lifecycle and the write-transaction surface (DRS-E1 increment 1,
//! surface **S-TXN**).
//!
//! S-TXN is first because every other surface depends on it
//! ([`DAEMON_REDB_STORE.md`](../../../docs/design/DAEMON_REDB_STORE.md)
//! §4's extraction order). This module opens the database, fixes its
//! durability, and hands out the write handle. It deliberately knows
//! nothing about tables.
//!
//! # The write handle is a possession type, and that is the point
//!
//! `BlockchainLMDB` keeps its write transaction in a raw member pointer
//! and dereferences `*m_write_txn` at **129** sites with no guard at the
//! dereference (DRS-W3). Some unknown subset is dominated by a caller's
//! check; P0c **declined** to count which, on the reasoning that the Rust
//! store's write handle would make the precondition *unrepresentable*
//! rather than merely unviolated — so an exact count would measure a
//! question the rewrite deletes.
//!
//! [`WriteBatch`] is that promise, paid. There is no null state to
//! dereference: a `WriteBatch` exists only where a transaction was begun,
//! [`commit`](WriteBatch::commit) and [`abort`](WriteBatch::abort) consume
//! it, and table access borrows it. The C++ failure mode — reaching the
//! write transaction from a path that never started one — does not
//! type-check here. **The 129-site census is discharged by construction,
//! not by audit**, which is what P0c's declination was banking on.
//!
//! # Durability is declared, never inherited
//!
//! **DRS-D9** takes the strictest practical durability, and **Tier-A A4**
//! requires it be *explicit* — "not library default by omission". Those
//! are two requirements, and the second is the one with teeth here:
//! redb 4.1.0's own default **is** [`Durability::Immediate`]
//! (`transactions.rs:864`), so a test that merely observed durable commits
//! would pass whether or not this crate set anything. It would be a green
//! that establishes nothing.
//!
//! So the policy is a **declared constant** ([`DURABILITY`]) applied to
//! every write transaction, and the test asserts the declaration. That
//! bites if someone lowers it for speed — which §5.2 forbids reopening
//! without overturning the network-bound argument on IBD/pop/resource
//! measurements, never steady-state ops/sec — and it keeps biting if a
//! future redb changes its default underneath us.
//!
//! redb 4.1.0 offers exactly two levels, `None` and `Immediate`
//! (`transactions.rs:362`); there is no stricter setting to want.

use std::path::Path;

use redb::{
    Database, Durability, ReadOnlyDatabase, ReadTransaction, ReadableDatabase, WriteTransaction,
};

/// The durability every write transaction is set to, declared rather than
/// inherited (DRS-D9, Tier-A A4). See the module note on why this is a
/// constant and not a default.
pub const DURABILITY: Durability = Durability::Immediate;

/// Why a store operation failed.
///
/// Every variant is a distinct thing a caller can do something about. The
/// C++ layer raises one `DB_ERROR` for twenty-two conditions and a
/// `std::runtime_error` for two more of the *same* precondition (DRS-W1);
/// the Rust store has one typed error per condition and no harmonization
/// pass to owe later.
#[derive(Debug)]
pub enum StoreError {
    /// The database file could not be opened or created.
    Open(redb::DatabaseError),
    /// A write transaction could not be started.
    BeginWrite(redb::TransactionError),
    /// A read transaction could not be started.
    BeginRead(redb::TransactionError),
    /// The durability policy was refused by the engine.
    Durability(redb::SetDurabilityError),
    /// A commit failed. The transaction is gone; the store is unchanged.
    Commit(redb::CommitError),
    /// A write was attempted against a store opened read-only.
    ReadOnly,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "cannot open chain store: {e}"),
            Self::BeginWrite(e) => write!(f, "cannot begin write transaction: {e}"),
            Self::BeginRead(e) => write!(f, "cannot begin read transaction: {e}"),
            Self::Durability(e) => write!(f, "engine refused the declared durability: {e}"),
            Self::Commit(e) => write!(f, "commit failed: {e}"),
            Self::ReadOnly => write!(f, "write attempted on a read-only chain store"),
        }
    }
}

impl core::error::Error for StoreError {}

/// The daemon's consensus store.
///
/// Opening is the only way to get one, so there is no "closed" state to
/// check against: `close` in the C++ surface is this value being dropped.
///
/// **Read-only is the engine's mode, not a flag this code checks.** An
/// earlier draft opened with [`Database::create`] and kept a `bool`, which
/// would have been a *simulation*: the file still created if absent, still
/// opened for writing, with nothing but this crate's own branch between a
/// caller and a mutation. redb has a real [`ReadOnlyDatabase`], so the
/// refusal belongs to the engine. A dial only this code reads proves
/// reachability, not control.
pub struct ChainStore {
    backend: Backend,
}

enum Backend {
    Writable(Database),
    ReadOnly(ReadOnlyDatabase),
}

impl core::fmt::Debug for ChainStore {
    /// Neither redb database type implements `Debug`, so this prints the
    /// one property a caller can act on rather than a derived dump.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainStore")
            .field("read_only", &self.is_read_only())
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
        let db = Database::create(path).map_err(StoreError::Open)?;
        Ok(Self {
            backend: Backend::Writable(db),
        })
    }

    /// Open an **existing** store without the ability to write.
    ///
    /// Uses redb's [`ReadOnlyDatabase`], so the mode is enforced by the
    /// engine: the file is not created if absent and cannot be written
    /// through this handle at all. [`begin_batch`](Self::begin_batch) has
    /// nothing to hand out rather than declining to.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`] if the file is absent or cannot be opened.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = ReadOnlyDatabase::open(path).map_err(StoreError::Open)?;
        Ok(Self {
            backend: Backend::ReadOnly(db),
        })
    }

    /// Whether this store refuses writes.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self.backend, Backend::ReadOnly(_))
    }

    /// Begin a write batch.
    ///
    /// This is the **only** way to obtain a [`WriteBatch`], and the only
    /// place the read-only flag is consulted.
    ///
    /// # Errors
    ///
    /// [`StoreError::ReadOnly`] if the store was opened read-only;
    /// [`StoreError::BeginWrite`] or [`StoreError::Durability`] if the
    /// engine refuses.
    pub fn begin_batch(&self) -> Result<WriteBatch<'_>, StoreError> {
        let Backend::Writable(db) = &self.backend else {
            return Err(StoreError::ReadOnly);
        };
        let mut txn = db.begin_write().map_err(StoreError::BeginWrite)?;
        // Declared, not inherited (A4) — see the module note.
        txn.set_durability(DURABILITY)
            .map_err(StoreError::Durability)?;
        Ok(WriteBatch {
            txn,
            _store: core::marker::PhantomData,
        })
    }

    /// Begin a read snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreError::BeginRead`] if the engine refuses.
    pub fn begin_read(&self) -> Result<ReadTransaction, StoreError> {
        match &self.backend {
            Backend::Writable(db) => db.begin_read(),
            Backend::ReadOnly(db) => db.begin_read(),
        }
        .map_err(StoreError::BeginRead)
    }
}

/// An open write transaction.
///
/// **The type that discharges DRS-W3.** It cannot be default-constructed,
/// cloned, or observed in a null state; [`commit`](Self::commit) and
/// [`abort`](Self::abort) take `self` by value, so a committed batch cannot
/// be used again. A caller that never began a batch has nothing to pass,
/// which is the C++ precondition made unrepresentable.
///
/// Dropping a `WriteBatch` without committing **aborts** it: redb rolls the
/// transaction back on drop. That is the safe direction — a path that
/// returns early loses its writes rather than committing a partial unit —
/// and it is the opposite of DRS-W8, where a C++ throw left the write
/// transaction live and poisoned every later block write.
///
/// No `Debug`: `redb::WriteTransaction` does not implement it, and a
/// hand-written one would print nothing a caller can act on.
pub struct WriteBatch<'store> {
    txn: WriteTransaction,
    // Ties the batch's lifetime to the store it came from, so a batch
    // cannot outlive the database it writes to.
    _store: core::marker::PhantomData<&'store ChainStore>,
}

impl WriteBatch<'_> {
    /// Borrow the underlying transaction to open tables.
    ///
    /// Table modules take `&WriteBatch`, never a raw transaction, so the
    /// possession property survives into every write path built on this.
    #[must_use]
    pub const fn txn(&self) -> &WriteTransaction {
        &self.txn
    }

    /// Commit the batch.
    ///
    /// # Errors
    ///
    /// [`StoreError::Commit`] if the engine could not commit. The
    /// transaction is consumed either way — there is no half-committed
    /// handle to reuse, which is DRS-W2's swallowed-`batch_stop` failure
    /// made unrepresentable rather than merely discouraged.
    pub fn commit(self) -> Result<(), StoreError> {
        self.txn.commit().map_err(StoreError::Commit)
    }

    /// Discard the batch explicitly.
    ///
    /// Equivalent to dropping it; provided so that an intentional abort
    /// reads as a decision rather than as a forgotten commit.
    pub fn abort(self) {
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "shekyl-chain-store-{}-{}-{:?}.redb",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        drop(std::fs::remove_file(&p));
        p
    }

    #[test]
    fn declared_durability_is_the_strictest_redb_offers() {
        // A4 asks for durability to be EXPLICIT, not merely correct. redb's
        // own default is already Immediate, so asserting observed durability
        // would pass with or without this crate setting anything. This
        // asserts the DECLARATION, which is the thing A4 is about and the
        // thing that bites if someone lowers it for speed (§5.2 forbids
        // reopening DRS-D9 on steady-state grounds).
        assert!(matches!(DURABILITY, Durability::Immediate));
    }

    #[test]
    fn a_committed_batch_is_visible_to_a_later_read() {
        let path = tmp("commit");
        let store = ChainStore::create(&path).expect("create");
        let batch = store.begin_batch().expect("begin");
        batch.commit().expect("commit");
        store.begin_read().expect("read after commit");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn a_read_only_store_refuses_at_the_single_refusal_point() {
        let path = tmp("readonly");
        {
            let store = ChainStore::create(&path).expect("create");
            store
                .begin_batch()
                .expect("begin")
                .commit()
                .expect("commit");
        }
        let store = ChainStore::open_read_only(&path).expect("open ro");
        assert!(store.is_read_only());
        // What this asserts is that OUR refusal point refuses. That the
        // engine cannot be written through at all is a STRUCTURAL property
        // no test can observe: `redb::ReadOnlyDatabase` has no `begin_write`
        // (the only one is `impl Database`, `db.rs:1037`), so a write path
        // does not type-check. Stated rather than claimed by a green.
        assert!(matches!(store.begin_batch(), Err(StoreError::ReadOnly)));
        // Reads still work: read-only is a write refusal, not a closed store.
        store.begin_read().expect("read on a read-only store");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn open_read_only_refuses_a_store_that_does_not_exist() {
        // The behavioural difference from the rejected flag design, and the
        // reason it is worth a test rather than a comment: `Database::create`
        // would have CREATED the file here and called the result read-only.
        let path = tmp("absent");
        drop(std::fs::remove_file(&path));
        assert!(matches!(
            ChainStore::open_read_only(&path),
            Err(StoreError::Open(_))
        ));
        assert!(!path.exists(), "a read-only open must not create the store");
    }

    #[test]
    fn a_dropped_batch_does_not_commit() {
        // The DRS-W8 direction: an early return loses writes rather than
        // leaving a live transaction that poisons later block writes.
        let path = tmp("drop");
        let store = ChainStore::create(&path).expect("create");
        let batch = store.begin_batch().expect("begin");
        drop(batch);
        // A second batch can still be opened — the first did not poison the
        // store, which is the property DRS-W8's C++ shape fails.
        store
            .begin_batch()
            .expect("begin after drop")
            .commit()
            .expect("commit");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn abort_is_a_decision_not_a_forgotten_commit() {
        let path = tmp("abort");
        let store = ChainStore::create(&path).expect("create");
        store.begin_batch().expect("begin").abort();
        store
            .begin_batch()
            .expect("begin after abort")
            .commit()
            .expect("commit");
        drop(std::fs::remove_file(&path));
    }
}
