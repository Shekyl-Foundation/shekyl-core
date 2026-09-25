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
//! a raw `WriteTransaction`), and it exists only inside a
//! [`write`](ChainStore::write) closure — `Ok` commits it, `Err` or an
//! unwind drops it, and drop aborts.
//!
//! # One transaction, one brand (C2-R8 Q3, DRS-E1 increment 2.5)
//!
//! The closure is higher-ranked over the batch's brand lifetime `'id`
//! (`for<'id> FnOnce(&mut WriteBatch<'_, 'id>)`), so every `write` call
//! mints a batch no other call can name. A value typed with one batch's
//! brand — the view a validator reads from it, the `ChainValid<'id>` the
//! validator mints against that view — cannot be presented to another
//! batch: the two `'id`s are distinct and invariant, and the handoff does
//! not compile. Validation and apply therefore run against **the same
//! transaction** by construction, which is what the ruling requires and
//! what a one-thread block processor would otherwise let someone forget
//! the first time a parallel read is added. One-live-write below is a
//! liveness property only; the TOCTOU guarantee rests on the brand.
//!
//! A second live batch is a typed [`StoreCannot::WriteInProgress`], not
//! redb's blocking `begin_write`. Same-thread re-entry would otherwise
//! deadlock. The C++ is **not** the same shape, and saying so precisely is
//! the point: `BlockchainLMDB::batch_start` **returns `false`** for a
//! second batch (`m_batch_active` or `m_write_batch_txn` set,
//! `db_lmdb.cpp:4103`/`:4105`) and two core callers *spin* on that; it
//! **throws** only when a non-batch `m_write_txn` is live (`:4108`). This
//! store refuses with a typed error and never spins — DRS-W17.
//!
//! # Two verbs, and a violation poisons the batch (C2-R8 §7.3, Q2)
//!
//! Keyed tables open through the batch as an [`InsertTable`] (fatal on a
//! present key; the `SI-` row is bound at open) or an [`UpsertTable`]
//! (overwrite, declared). Typed `properties` cells are registers and go
//! through [`upsert_property`](WriteBatch::upsert_property). Any invariant
//! violation seen through the batch — a refused `insert`, a cell that will
//! not decode — arms a latch `complete` checks on **both** the `Ok` and
//! `Err` arms, so a closure that swallows one, or maps it to a different
//! error, still lands nothing: `write` returns the violation.
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
//! ([`StoreCannot::SchemaVersionAbsent`]); a file at another version is
//! refused in both directions ([`StoreCannot::SchemaVersionMismatch`]). The
//! answer to either is a rebuild from the block corpus
//! (`DAEMON_REDB_STORE.md` §11), never a migrator.

mod alt;
mod alt_reads;
mod archival_reads;
mod at_index;
mod chain_reads;
mod connect;
mod curve_reads;
mod error;
mod halt;
mod header;
mod invariant;
mod keyed;
mod output_reads;
mod pop;
mod read;
mod shared;
mod tx_reads;
pub(crate) mod undo;
mod view;
mod write;

pub use alt_reads::AltEntry;
pub use archival_reads::{PassCount, ServedShard};
pub use at_index::AtIndex;
pub use connect::{ConnectFacts, Connected, DeletedBy, Fact, Origin};
pub use error::{
    AltCannot, CellFault, EngineError, ErrorClass, LeafDensity, PoolCannot, StoreCannot,
    StoreError, StoreInvariant, UndoFault,
};
pub use halt::ConnectState;
pub use keyed::{InsertOnce, InsertTable, KeyedTable, Overwrite, UpsertTable};
pub use output_reads::RecordedOutput;
pub use pop::Popped;
pub use read::{RangeItem, RawBlockBytes, ReadSnapshot, RecordedBlockBody, TipState, TxWalkItem};
pub use tx_reads::{Prunable, SegmentBytes, TxLocation, TxRecord};
pub use undo::Restorable;
pub use view::BatchView;
pub use write::WriteBatch;

use std::path::Path;

use redb::{Database, Durability, ReadOnlyDatabase, ReadableDatabase, WriteTransaction};

use crate::apply_policy::ApplyPolicy;
use crate::codec::SettlementEpochBlocks;
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
    settlement_epoch_blocks: SettlementEpochBlocks,
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
            .field("settlement_epoch_blocks", &self.settlement_epoch_blocks)
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl ChainStore {
    /// Create or open the store at `path` for reading and writing, under
    /// the settlement-epoch schedule `epoch` (a fresh file is pinned to it;
    /// an existing file must have been built under it).
    ///
    /// # Errors
    ///
    /// [`EngineError::Open`] if the file cannot be created or opened; the
    /// header refusals listed on [`with_apply_policy`](Self::with_apply_policy).
    pub fn create(
        path: impl AsRef<Path>,
        epoch: SettlementEpochBlocks,
    ) -> Result<Self, StoreError> {
        Self::with_apply_policy(path, ApplyPolicy::default(), epoch)
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
    /// `epoch` is the settlement-epoch schedule this session runs under
    /// (the caller's — `shekyl-archival-retention`'s effective value; the
    /// store never reads the environment). A fresh file is **pinned** to it
    /// in the seal; an existing file's pin must equal it (SCW-2).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::EmptyApplyStub`] if the policy stubs no families —
    /// checked before the path is touched; [`EngineError::Open`] if the file
    /// cannot be created or opened, including an existing file that is not
    /// a redb database (refused unread and unwritten, never initialized);
    /// on an existing database, [`StoreCannot::SchemaVersionAbsent`],
    /// [`StoreCannot::SchemaVersionMismatch`],
    /// [`StoreCannot::SettlementEpochMismatch`] or
    /// [`StoreInvariant::CellCorrupt`] if its header is not one this binary
    /// can vouch for. A fresh file the engine refuses to take, or that
    /// cannot be sealed, is removed again, so a failed create does not
    /// leave a headerless file the next open refuses.
    pub fn with_apply_policy(
        path: impl AsRef<Path>,
        apply_policy: ApplyPolicy,
        epoch: SettlementEpochBlocks,
    ) -> Result<Self, StoreError> {
        apply_policy
            .reject_empty_stub()
            .map_err(|crate::apply_policy::EmptyApplyStub| StoreCannot::EmptyApplyStub)?;
        // Fresh-vs-existing is decided by the SAME syscall that claims the
        // path, never by a separate probe: `create_new` either creates the
        // file atomically (fresh) or fails with AlreadyExists (reopen). An
        // earlier draft checked `exists()` first and then called `create`,
        // which also opens existing files -- a creator racing between the
        // two would have sealed a file it did not create. redb's own
        // `create` does exactly this open-with-create and hands the file to
        // `create_file`, so a 0-byte file is the path it knows.
        //
        // The reopen arm is therefore `open`, which never creates and never
        // initializes (`redb-4.1.0/src/db.rs:1196`; an empty file is
        // `InvalidData`, `page_manager.rs:171`). With `create` there, a
        // path removed between AlreadyExists and the open -- or an empty
        // file some other process left -- would be initialized as a fresh,
        // unsealed database and then refused by `verify`, leaving behind
        // exactly the headerless file the fresh arm's cleanup exists to
        // prevent. Only the `create_new` winner initializes a file.
        let mut builder = redb::Builder::new();
        builder.set_cache_size(CACHE_SIZE);
        let path = path.as_ref();
        let (db, provenance) = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => match create_sealed(&builder, file, apply_policy, epoch) {
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
                let db = builder.open(path).map_err(EngineError::Open)?;
                let provenance =
                    header::verify(&db.begin_read().map_err(EngineError::BeginRead)?, epoch)?;
                (db, provenance)
            }
            Err(e) => return Err(EngineError::Open(redb::DatabaseError::Storage(e.into())).into()),
        };
        Ok(Self {
            backend: Backend::Writable(db),
            apply_policy,
            settlement_epoch_blocks: epoch,
            shared: Shared::new(provenance),
        })
    }

    /// The settlement-epoch schedule this file is pinned to — equal to the
    /// session's by construction, since a mismatch refuses the open.
    #[must_use]
    pub const fn settlement_epoch_blocks(&self) -> SettlementEpochBlocks {
        self.settlement_epoch_blocks
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
    /// it. Two locks make the in-memory copy the file's value:
    ///
    /// - **Across handles.** redb holds an exclusive `flock` on the file for
    ///   the life of a writable `Database` and a shared one for a read-only
    ///   handle (`redb-4.1.0/src/tree_store/page_store/file_backend/optimized.rs:27`,
    ///   read at the pinned source). A second writable open — this process
    ///   or another — is [`redb::DatabaseError::DatabaseAlreadyOpen`]; a
    ///   read-only handle excludes every writer for as long as it exists.
    ///   Platforms where the lock is `Unsupported` (none the daemon targets;
    ///   redb proceeds unlocked and warns) inherit redb's own contract that
    ///   the operator keeps one process on the file.
    /// - **Inside this handle.** The mirror's only mutator holds its write
    ///   lock across the engine commit and the assignment, and publishes
    ///   nothing if the commit fails. This method takes the matching read
    ///   lock, so a concurrent stamp can neither see the file as tainted
    ///   while the mirror still says [`Provenance::FULL`], nor the reverse.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        self.shared.provenance()
    }

    /// Open an **existing** store without the ability to write.
    ///
    /// The schedule pin is checked here too: a reader interprets
    /// epoch-derived rows, so a reader under the wrong schedule is as
    /// mislabeled as a writer.
    ///
    /// # Errors
    ///
    /// [`EngineError::Open`] if the file is absent or cannot be opened; the
    /// same header refusals as [`with_apply_policy`](Self::with_apply_policy).
    pub fn open_read_only(
        path: impl AsRef<Path>,
        epoch: SettlementEpochBlocks,
    ) -> Result<Self, StoreError> {
        let db = redb::Builder::new()
            .set_cache_size(CACHE_SIZE)
            .open_read_only(path)
            .map_err(EngineError::Open)?;
        let provenance = header::verify(&db.begin_read().map_err(EngineError::BeginRead)?, epoch)?;
        Ok(Self {
            backend: Backend::ReadOnly(db),
            // A read-only handle writes nothing, so its session policy is
            // vacuously Full; the file's history is `provenance`.
            apply_policy: ApplyPolicy::Full,
            settlement_epoch_blocks: epoch,
            shared: Shared::new(provenance),
        })
    }

    /// Whether the writer is live or halted (`DAEMON_REDB_STORE.md` §3.6.2).
    ///
    /// A `connect` or `pop` that hit a store invariant halts the writer for
    /// the life of this handle: every later [`write`](Self::write) is
    /// refused with [`StoreCannot::WriterHalted`], reads stay open, and the
    /// tip a wallet refreshes against carries the halt
    /// (`shekyl-rpc-types::chain::ConnectState`, wired at cutover). Not
    /// persisted: a restart re-derives it by rerunning the belts, so a
    /// repaired file is not refused by a stale latch.
    #[must_use]
    pub fn connect_state(&self) -> ConnectState {
        match self.shared.halted() {
            None => ConnectState::Live,
            Some((at_height, row)) => ConnectState::Halted {
                at_height: shekyl_types::BlockHeight::from_raw(at_height),
                row,
            },
        }
    }

    /// Whether this store refuses writes.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self.backend, Backend::ReadOnly(_))
    }

    /// Run `f` inside a write batch and commit if it returns `Ok`. The
    /// **only** way to reach a [`WriteBatch`].
    ///
    /// The closure is higher-ranked over the batch's brand `'id`, so the
    /// batch it is handed — and every value typed with that brand — is
    /// distinct from any other call's:
    ///
    /// ```compile_fail,E0521
    /// use shekyl_chain_store::store::{ChainStore, StoreError, WriteBatch};
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// fn same_batch<'id>(_: &WriteBatch<'_, 'id>, _: &WriteBatch<'_, 'id>) {}
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|outer| {
    ///     store.write(|inner| -> Result<(), StoreError> {
    ///         same_batch(outer, inner);
    ///         Ok(())
    ///     })
    /// });
    /// ```
    ///
    /// (Two batches can never be *live* together on one store — the inner
    /// call would be [`StoreCannot::WriteInProgress`] — but the point of the
    /// brand is that the handoff is refused before anything runs.)
    ///
    /// `Err` from the closure drops the batch, and drop aborts: nothing the
    /// closure wrote lands. There is no separate abort verb; an abort that
    /// the engine fails to complete is not lost either — redb latches the
    /// storage failure and refuses the next `begin_write` with
    /// `StorageError::PreviousIo` (`redb-4.1.0/src/transactions.rs:2084`,
    /// `db.rs:1410`, read at the pinned source), which the next `write`
    /// surfaces as [`EngineError::BeginWrite`].
    ///
    /// `E` is any error the caller's closure may return, provided the
    /// store's own failures convert into it; a closure that only ever
    /// returns `Ok` names it (`Ok::<_, StoreError>(())`).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::ReadOnly`] if the store was opened read-only;
    /// [`StoreCannot::WriterHalted`] if a prior connect, pop, or branded
    /// view hit a store invariant (the slot is claimed before that look,
    /// so a halt cannot land between the check and the claim);
    /// [`StoreCannot::WriteInProgress`] if a batch is already live;
    /// [`EngineError::BeginWrite`] or [`EngineError::Durability`] if the
    /// engine refuses to begin; whatever `f` returns, **except** that
    /// [`StoreError::InvariantViolated`] wins if any invariant violation
    /// was seen through the batch — even one `f` caught, or mapped to a
    /// different `Err`; at commit, [`EngineError::Commit`] if the engine
    /// could not commit, or [`StoreInvariant::CellCorrupt`] /
    /// [`EngineError::Storage`] if the provenance cell could not be read
    /// back or widened. In every `Err` case the batch is aborted and
    /// nothing lands.
    pub fn write<R, E, F>(&self, f: F) -> Result<R, E>
    where
        E: From<StoreError>,
        F: for<'id> FnOnce(&mut WriteBatch<'_, 'id>) -> Result<R, E>,
    {
        let Backend::Writable(db) = &self.backend else {
            return Err(StoreError::from(StoreCannot::ReadOnly).into());
        };
        // Slot first, then halt, while holding: a load-then-CAS lets the
        // live batch halt and drop between the two looks.
        if let Err(cannot) = self.shared.admit_write() {
            return Err(StoreError::from(cannot).into());
        }
        let txn = match arm_write(db) {
            Ok(txn) => txn,
            Err(e) => {
                self.shared.release_write();
                return Err(e.into());
            }
        };
        // From here the batch owns the write slot: its Drop releases it on
        // every exit, including `complete` and an unwind out of `f`.
        let mut batch = WriteBatch::new(txn, self.apply_policy, &self.shared);
        let outcome = f(&mut batch);
        batch.complete(outcome)
    }

    /// Open a write batch, run `f`, and **abort**.
    ///
    /// The producer's read of the chain (`TemplateFacts`): it needs the
    /// validator's [`WriteBatch::chain_view`] — the same body, the same
    /// poison latch — and it must not commit. An invariant the closure
    /// observes still halts the writer, exactly as [`Self::write`] does;
    /// an unpoisoned `Ok` drops the transaction. A connect or a pop inside
    /// `f` is rolled back with it.
    ///
    /// # Errors
    ///
    /// The same admission and engine errors as [`Self::write`]. An armed
    /// invariant is returned in place of `f`'s own error and the writer
    /// halts. Nothing is committed.
    pub fn inspect<R, E, F>(&self, f: F) -> Result<R, E>
    where
        E: From<StoreError>,
        F: for<'id> FnOnce(&mut WriteBatch<'_, 'id>) -> Result<R, E>,
    {
        let Backend::Writable(db) = &self.backend else {
            return Err(StoreError::from(StoreCannot::ReadOnly).into());
        };
        if let Err(cannot) = self.shared.admit_write() {
            return Err(StoreError::from(cannot).into());
        }
        let txn = match arm_write(db) {
            Ok(txn) => txn,
            Err(e) => {
                self.shared.release_write();
                return Err(e.into());
            }
        };
        let mut batch = WriteBatch::new(txn, self.apply_policy, &self.shared);
        let outcome = f(&mut batch);
        batch.abandon(outcome)
    }

    /// Begin a read snapshot. Concurrent with a live write batch.
    ///
    /// # Errors
    ///
    /// [`EngineError::BeginRead`] if the engine refuses.
    pub fn begin_read(&self) -> Result<ReadSnapshot<'_>, StoreError> {
        match &self.backend {
            Backend::Writable(db) => db.begin_read(),
            Backend::ReadOnly(db) => db.begin_read(),
        }
        .map(|txn| ReadSnapshot::new(txn, self))
        .map_err(|e| EngineError::BeginRead(e).into())
    }
}

fn arm_write(db: &Database) -> Result<WriteTransaction, StoreError> {
    let mut txn = db.begin_write().map_err(EngineError::BeginWrite)?;
    txn.set_durability(DURABILITY)
        .map_err(EngineError::Durability)?;
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
    epoch: SettlementEpochBlocks,
) -> Result<(Database, Provenance), StoreError> {
    let db = builder.create_file(file).map_err(EngineError::Open)?;
    let txn = arm_write(&db)?;
    let provenance = header::seal(&txn, policy, epoch)?;
    txn.commit().map_err(EngineError::Commit)?;
    Ok((db, provenance))
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "header_tests.rs"]
mod header_tests;

#[cfg(test)]
#[path = "undo_tests.rs"]
mod undo_tests;

#[cfg(test)]
#[path = "view_tests.rs"]
mod view_tests;

#[cfg(test)]
#[path = "connect_fixtures.rs"]
mod connect_fixtures;

#[cfg(test)]
#[path = "connect_tests.rs"]
mod connect_tests;

#[cfg(test)]
#[path = "connect_ruleset_tests.rs"]
mod connect_ruleset_tests;

#[cfg(test)]
#[path = "refuse_corrupt_tests.rs"]
mod refuse_corrupt_tests;

/// The mock is reconciled against the real view (E6 slice 2 F11): every
/// landed rule, both stages, identical verdicts and coverage over
/// `BatchView` and the rules crate's `MockChain`.
#[cfg(test)]
#[path = "conformance_tests.rs"]
mod conformance_tests;

#[cfg(test)]
#[path = "pop_tests.rs"]
mod pop_tests;

#[cfg(test)]
#[path = "amendments_tests.rs"]
mod amendments_tests;

#[cfg(test)]
#[path = "read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "curve_read_tests.rs"]
mod curve_read_tests;

#[cfg(test)]
#[path = "archival_read_tests.rs"]
mod archival_read_tests;

#[cfg(test)]
#[path = "alt_tests.rs"]
mod alt_tests;
#[cfg(test)]
#[path = "output_read_tests.rs"]
mod output_read_tests;
#[cfg(test)]
#[path = "tx_read_tests.rs"]
mod tx_read_tests;
