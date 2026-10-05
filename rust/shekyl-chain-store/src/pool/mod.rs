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
//! **refused, never deleted** ([`StoreCannot::PoolFileForeign`](crate::store::StoreCannot::PoolFileForeign)): a path that
//! is not a redb database, a database without the header table or cell, a
//! cell that does not decode. A wrong `--data-dir`, a foreign file or a
//! tampered one is an operator's to look at, not the store's to erase.
//!
//! # Durability
//!
//! [`DURABILITY`] and two-phase commit, the same
//! as the chain file (`SPL-Q4`): "discardable" is about what the file may be
//! *made* to lose, not about accepting a torn one. One durability policy,
//! applied per file; BENCH measures the pool's write rate (SPL-13).

//!
//! # Layout of this module
//!
//! The chain store's own shape: [`PoolStore`] (this file) is the handle and
//! the two transaction entry points; `header` seals and verifies the file's
//! header; `write` is [`PoolBatch`] and P1–P3; `read` is [`PoolSnapshot`],
//! [`PoolEntry`] and P4–P7; [`schema`] is the three tables.

pub mod schema;

mod header;
mod read;
mod write;

pub use crate::codec::{
    ArrivedPhase, BlockRef, Origin, OriginatedPhase, PoolRecord, Readiness, RelayRefusal,
    RelayState, Responsibility,
};
pub use header::{PoolOpen, POOL_VERSION_KEY};
pub use read::{PoolEntry, PoolSnapshot};
pub use schema::PoolTxBytes;
pub use write::PoolBatch;

use std::path::Path;

use redb::{Database, ReadableDatabase, TableHandle, WriteTransaction};
use shekyl_store_codec::CodecError;

use crate::store::{
    CellFault, EngineError, StoreError, StoreInvariant, DURABILITY, TWO_PHASE_COMMIT,
};

/// The pool file's cache: 64 MiB. A pool is a few thousand transactions at
/// most; the chain file's 1 GiB would be a reservation nothing uses.
pub const POOL_CACHE_SIZE: usize = 64 * 1024 * 1024;

/// The pool file. One writer, many readers; see the module doc.
pub struct PoolStore {
    db: Database,
}

impl core::fmt::Debug for PoolStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolStore").finish_non_exhaustive()
    }
}

impl PoolStore {
    /// Create, open, or recreate the pool file at `path` (module doc, §"The
    /// header").
    ///
    /// # Errors
    ///
    /// [`EngineError::Open`] if the path cannot be created or a redb file
    /// cannot be opened for an engine reason;
    /// [`StoreCannot::PoolFileForeign`](crate::store::StoreCannot::PoolFileForeign)
    /// if the path holds something this store neither wrote nor may
    /// recreate; [`EngineError::Storage`] / [`EngineError::Commit`] if the
    /// seal cannot be written. A fresh file the seal fails on is removed
    /// again.
    pub fn create(path: impl AsRef<Path>) -> Result<(Self, PoolOpen), StoreError> {
        header::open_or_create(path.as_ref()).map(|(db, how)| (Self { db }, how))
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
        F: FnOnce(&mut PoolBatch) -> Result<R, E>,
    {
        let mut batch = PoolBatch::new(arm_write(&self.db)?);
        let outcome = f(&mut batch);
        batch.complete(outcome)
    }

    /// Begin a read snapshot. Concurrent with a live write batch.
    ///
    /// # Errors
    ///
    /// [`EngineError::BeginRead`] if the engine refuses.
    pub fn begin_read(&self) -> Result<PoolSnapshot, StoreError> {
        self.db
            .begin_read()
            .map(PoolSnapshot::new)
            .map_err(|e| EngineError::BeginRead(e).into())
    }
}

/// Begin a write transaction under the store's durability policy — the
/// seal's and every batch's.
fn arm_write(db: &Database) -> Result<WriteTransaction, StoreError> {
    let mut txn = db.begin_write().map_err(EngineError::BeginWrite)?;
    txn.set_durability(DURABILITY)
        .map_err(EngineError::Durability)?;
    txn.set_two_phase_commit(TWO_PHASE_COMMIT);
    Ok(txn)
}

/// A `pool_meta` row that does not decode — SI-7, the table named as the
/// cell. One constructor, so the three readers of that row fault alike.
fn undecodable_meta(cause: CodecError) -> StoreError {
    StoreInvariant::CellCorrupt {
        key: schema::POOL_META.name(),
        fault: CellFault::Undecodable(cause),
    }
    .into()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
