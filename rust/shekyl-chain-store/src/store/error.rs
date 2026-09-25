// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed failures for the S-TXN surface, **classed**.
//!
//! C2-R8 Q2 (§3.1) rules three error classes for the store, and the class is
//! the thing a caller acts on: an invariant violation halts connect, a
//! refusal is retried or handed to the operator, an engine failure is
//! neither. So the class is **structural** — the outer variant of
//! [`StoreError`] — rather than a table beside the code. A `match` on
//! `StoreError` cannot forget a class, [`StoreError::class`] is a projection
//! rather than a judgement, and `STORE_INVARIANT_REGISTER.md` §3 is read off
//! these three enums instead of maintained against them.
//!
//! - [`EngineError`] — the redb layer failed and the operation did not
//!   happen. Nothing about the store's contents is implied.
//! - [`StoreCannot`] — a refusal **before** the write: a capability the
//!   store does not have in this session or for this file. Not a verdict on
//!   any block; not incoherence. Whether it is retryable is per variant, and
//!   [`StoreCannot::WriteInProgress`] in particular is not.
//! - [`StoreInvariant`] — an `SI-` row broke at the write. Fatal; the
//!   validator has a hole or the file is corrupt.
//!
//! No variant is a consensus verdict and none ever will be: this crate does
//! not name the verdict type (conversion-ban clause 2,
//! `check_store_error_conversion_ban.py`), and the invariant arm is never
//! caught and re-shaped into one (clause 3).
//!
//! One variant per condition a caller can act on. The C++ layer raises one
//! `DB_ERROR` for twenty-two conditions and a `std::runtime_error` for two
//! more of the *same* precondition (DRS-W1); there is no harmonization pass
//! to owe later.

use crate::apply_policy::ArchivalFamily;
use shekyl_chain_rules::RuleSet;
use shekyl_types::{BlockHash, TxHash};

use crate::codec::{SchemaVersion, SettlementEpochBlocks};

pub use super::invariant::{CellFault, LeafDensity, StoreInvariant, UndoFault};

/// Why a store operation failed, by class.
///
/// The outer variant is the class. Each inner type is self-describing in its
/// `Display`, so this wrapper is transparent: it adds no message and no
/// `source` link of its own.
#[derive(Debug)]
pub enum StoreError {
    /// The engine failed; the operation did not happen.
    Engine(EngineError),
    /// The store refused before writing; nothing is implied about the file
    /// or the block.
    Cannot(StoreCannot),
    /// A store invariant broke at the write. **Fatal.** The variant names
    /// the `SI-` row; the caller halts, it does not convert.
    InvariantViolated(StoreInvariant),
}

/// The three classes, for a caller that acts on the class and not the
/// variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// [`StoreError::Engine`].
    Engine,
    /// [`StoreError::Cannot`].
    Cannot,
    /// [`StoreError::InvariantViolated`].
    Invariant,
}

impl StoreError {
    /// Which of the three classes this failure is.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        match self {
            Self::Engine(_) => ErrorClass::Engine,
            Self::Cannot(_) => ErrorClass::Cannot,
            Self::InvariantViolated(_) => ErrorClass::Invariant,
        }
    }
}

impl From<EngineError> for StoreError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

impl From<StoreCannot> for StoreError {
    fn from(e: StoreCannot) -> Self {
        Self::Cannot(e)
    }
}

impl From<StoreInvariant> for StoreError {
    fn from(e: StoreInvariant) -> Self {
        Self::InvariantViolated(e)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Engine(e) => e.fmt(f),
            Self::Cannot(e) => e.fmt(f),
            Self::InvariantViolated(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Engine(e) => e.source(),
            Self::Cannot(e) => e.source(),
            Self::InvariantViolated(e) => e.source(),
        }
    }
}

/// The redb layer failed. The operation did not happen; the store is as it
/// was.
#[derive(Debug)]
pub enum EngineError {
    /// The database file could not be opened or created.
    Open(redb::DatabaseError),
    /// A write transaction could not be started.
    ///
    /// Also where a storage fault during a batch's abort-on-drop surfaces:
    /// redb latches it and refuses the next `begin_write` with
    /// `StorageError::PreviousIo` (see [`ChainStore::write`](super::ChainStore::write)).
    BeginWrite(redb::TransactionError),
    /// A read transaction could not be started.
    BeginRead(redb::TransactionError),
    /// The durability policy was refused by the engine.
    Durability(redb::SetDurabilityError),
    /// A commit failed. The transaction is gone; the store is unchanged.
    Commit(redb::CommitError),
    /// Opening a table failed.
    Table(redb::TableError),
    /// A row read or write failed inside the engine.
    Storage(redb::StorageError),
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "cannot open chain store: {e}"),
            Self::BeginWrite(e) => write!(f, "cannot begin write transaction: {e}"),
            Self::BeginRead(e) => write!(f, "cannot begin read transaction: {e}"),
            Self::Durability(e) => write!(f, "engine refused the declared durability: {e}"),
            Self::Commit(e) => write!(f, "commit failed: {e}"),
            Self::Table(e) => write!(f, "cannot open table: {e}"),
            Self::Storage(e) => write!(f, "engine storage error: {e}"),
        }
    }
}

impl core::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Open(e) => Some(e),
            Self::BeginWrite(e) | Self::BeginRead(e) => Some(e),
            Self::Durability(e) => Some(e),
            Self::Commit(e) => Some(e),
            Self::Table(e) => Some(e),
            Self::Storage(e) => Some(e),
        }
    }
}

/// The store refused **before** the write.
///
/// A capability the store lacks in this session (read-only, a live writer)
/// or for this file (another layout version). It is not a verdict on any
/// block — the block was not judged — and not a coherence failure — the
/// file is as it was. The third class exists so a refusal is never mapped
/// onto either of the other two (C2-R8 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreCannot {
    /// The file exists but carries no `schema_version` cell.
    ///
    /// **Not a store this binary wrote** — §11.1(a): *absent reads as
    /// refuse, not as version 1*. There is no implicit-version affordance
    /// because pre-genesis there is no store that predates the cell. The
    /// answer is a rebuild from the block corpus (§11), never a repair.
    SchemaVersionAbsent,
    /// The file was written under a different layout version.
    ///
    /// Newer refuses and older refuses too (§11.1(a)); there is no
    /// migration ladder and none will be written. An incompatible file is
    /// not an incoherent one, which is why this is a refusal and not
    /// [`StoreInvariant::CellCorrupt`]. Rebuild.
    SchemaVersionMismatch {
        /// The version the file carries.
        found: SchemaVersion,
        /// The version this binary reads and writes.
        expected: SchemaVersion,
    },
    /// The store file's header table is not this layout's: redb refused
    /// `properties` with a stored type name other than the one this binary
    /// declares, before any cell could be read. A file written under
    /// another layout — §11.1(a)'s "older refuses too", reached one step
    /// earlier than [`Self::SchemaVersionMismatch`] because the version
    /// cell itself sits in the table whose type moved (§11.1(f)). Not
    /// format detection (rule 15 — there is no probe under a legacy
    /// definition): the engine's refusal, named. Rebuild.
    LayoutForeign {
        /// The version this binary reads and writes.
        expected: SchemaVersion,
    },
    /// A value handed to a typed table's `insert` / `upsert` is not the
    /// width its shape declares. Unreachable through `Canonical::encoded`
    /// (the width is the codec's, snapshot-pinned); reachable only through
    /// redb's own `Value::from_bytes`, which is a public trait method.
    /// Refused here as a `Result`, because the alternative is redb's
    /// `LeafBuilder::append` assertion — a panic that poisons the
    /// transaction lock (`codec::shape` module docs, *`fixed_width` is a
    /// layout choice*).
    RowWidth {
        /// The table.
        table: &'static str,
        /// The width the value shape declares.
        expected: usize,
        /// The width handed in.
        actual: usize,
    },
    /// A value handed to a typed table's `insert` / `upsert` is not a
    /// well-formed row of that table's shape. Unreachable through
    /// `Canonical::encoded` / a `BlobKind` the chain itself serialized;
    /// reachable through redb's public `Value::from_bytes`. The width
    /// mismatch is [`Self::RowWidth`]; this arm is everything else — a
    /// variable-width codec that does not decode, a blob that does not
    /// parse. Refused as a `Result` so it never becomes SI-7: the file
    /// was not written.
    RowIllFormed {
        /// The table.
        table: &'static str,
        /// Why [`Restorable::well_formed`](super::undo::Restorable::well_formed)
        /// refused.
        reason: &'static str,
    },
    /// The raw `properties` table was requested on the write side.
    ///
    /// Its cells are typed ([`PropertyCell`](crate::codec::PropertyCell))
    /// and written through
    /// [`WriteBatch::upsert_property`](super::WriteBatch::upsert_property), whose
    /// bound admits chain-state cells only. A raw handle would let a string
    /// overwrite `schema_version` or clear the provenance record, so there
    /// is none.
    PropertiesAreTyped,
    /// A write was attempted against a store opened read-only.
    ReadOnly,
    /// A write batch is already live on this store.
    ///
    /// redb's `begin_write` **blocks** until the in-progress writer finishes.
    /// A `write` while another batch is live. **This is a contract
    /// violation, not contention — do not retry it.** `write_held` is an
    /// invariant guard on the declared one-live-write contract, released in
    /// `WriteBatch::drop`; it is not a queue, and this error does not mean
    /// "try again later". A caller that wraps it in a retry loop has wrapped
    /// a bug, and the loop will appear to work.
    ///
    /// **Port-boundary divergence, recorded as DRS-W17** in
    /// `LMDB_WRITE_ATOMICITY_AUDIT.md` §9: the C++ `batch_start()` returns
    /// `bool`, and two core callers *spin* on it —
    /// `blockchain.cpp:6553` `while (!(stop_batch = m_db->batch_start(..)))`
    /// and `:6743` likewise. Those loops must **not** be transliterated to
    /// `while store.write(..).is_err()`. Serialization of writers is owned by
    /// the core layer above the store (`m_blockchain_lock`,
    /// `CRITICAL_REGION_LOCAL1` at `blockchain.cpp:277`), which is why the
    /// C++ never actually contends there; LMDB's own writer mutex sits below
    /// that and is never reached by a second thread. No state diff can see
    /// this divergence — it is a concurrency property, not a stored one — so
    /// it lives in the register rather than in any comparator.
    WriteInProgress,
    /// [`ApplyPolicy::stubbed`](crate::apply_policy::ApplyPolicy::stubbed)
    /// was given an empty family list, which is `Full` wearing a non-parity
    /// stamp.
    EmptyApplyStub,
    /// This family's apply is stubbed under the store's policy, so the write
    /// path must not open its table (opening a write table creates it).
    FamilyStubbed(ArchivalFamily),
    /// A pop-journal recording for `height` was begun in this batch and
    /// dropped without being sealed, so the chain-state writes it recorded
    /// would land with no `undo_log` row to reverse them. The batch refuses
    /// to commit. Only the store's own `connect` begins a recording, so
    /// this names a bug in that path, never a caller's misuse.
    UndoUnsealed {
        /// The height whose recording was abandoned.
        height: u64,
    },
    /// The file was built under a different settlement-epoch schedule than
    /// this session's (S-CHAIN-W SCW-2).
    ///
    /// Persisted join epochs and serve-credit windows would be silently
    /// mislabeled under the other schedule, so the open is refused with the
    /// remedy named — reopen under the pinned schedule, or use a fresh data
    /// directory. A refusal, not [`StoreInvariant::CellCorrupt`]: the file is
    /// coherent, the session is wrong for it.
    SettlementEpochMismatch {
        /// The schedule the file was built under.
        pinned: SettlementEpochBlocks,
        /// The schedule this session runs.
        session: SettlementEpochBlocks,
    },
    /// A `ChainValid` judged under one rule set was handed to `connect` at
    /// a height where another is in force (S-CHAIN-W §3.1, SCW-16).
    ///
    /// A capability refusal, not a verdict: the block may be valid under the
    /// rules it was judged by — it was handed to the wrong height. The
    /// driver resolves height → rule set (`RuleSchedule::rules_at`); the
    /// store only compares.
    RuleSetNotInForce {
        /// The height the block would have been recorded at.
        height: u64,
        /// The rule set the verdict was minted under — the set, not its id:
        /// two Fakechain sets share `RuleSetId::GENESIS`, and the refusal
        /// must be able to say which differed (RD-Q10).
        judged: RuleSet,
        /// The rule set the caller says is in force at `height`.
        in_force: RuleSet,
    },
    /// `pop` on a store with no block recorded.
    ChainEmpty,
    /// `pop` at `tip` cannot run: the height is below the pop floor
    /// (S-CHAIN-W §5.4, SCW-7).
    ///
    /// Genesis is never poppable (`floor ≥ 1`), and a height whose
    /// `undo_log` row the retention prune has deleted is below `floor` —
    /// the lowest surviving row. A capability limit, never a verdict: a
    /// legal reorg deeper than the undo-log retention lands here, which is
    /// why that retention must be ≥ `D_max` (PDM-Q11).
    PopBelowFloor {
        /// The current tip.
        tip: u64,
        /// The lowest poppable height.
        floor: u64,
    },
    /// A `connect` or `pop` on this store hit a store invariant, and the
    /// writer is halted until the process restarts (`DAEMON_REDB_STORE.md`
    /// §3.6.2). Reads stay open. Re-derived on restart, not persisted; the
    /// operator path is the engine's check or a rebuild from the block
    /// corpus.
    WriterHalted {
        /// The height the halting connect or pop was working at.
        at_height: u64,
        /// The belt that caught it.
        row: StoreInvariant,
    },
    /// A judged transaction's ct base carries fewer commitments than its
    /// prefix has outputs, so there is no commitment to record for output
    /// `index` (`output_amounts`).
    ///
    /// The wire parser sizes the base arrays by the output count, so a
    /// parsed transaction cannot reach this; a hand-built candidate can,
    /// until the 4.H shape rows land in the validator. Refused, never
    /// recorded with a zero commitment.
    OutputWithoutCommitment {
        /// The transaction.
        tx: TxHash,
        /// The `vout` position with no commitment.
        index: u64,
    },
    /// A pool-store refusal (DRS-E1 S-POOL, `DRS_E1_SPOOL.md` §3.2) — the
    /// pool's decisions on its own file, none of them a fault in it.
    Pool(PoolCannot),
    /// The pool file at `path` is not one this store can vouch for **and**
    /// not one it may recreate: not a redb database, a database with no
    /// pool header, or a header that does not decode. Only a sealed pool
    /// file at *another layout version* is recreated (`SPL-Q8` as ruled);
    /// everything else is refused, never deleted — a wrong `--data-dir`, a
    /// foreign file or a tampered one is an operator's to look at.
    PoolFileForeign,
    /// An alt-chain store refusal (DRS-E1 S-ALT, `DRS_E1_SALT.md` §3.2) —
    /// the store's decisions on `alt_blocks`, none of them a fault in it.
    Alt(AltCannot),
}

/// The alt-chain store's typed refusals — decisions, not faults
/// (`StoreCannot`'s shape; `DRS_E1_SALT.md` §3.4).
///
/// Both are **caller-contract violations** made visible (`SAL-Q3` as ruled):
/// the caller states what it expected of the table, and the store says when
/// the table disagrees, instead of doing something silently different.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltCannot {
    /// `insert_alt_block` of a hash the store already holds — CEN-K3's
    /// belt (`MDB_NODUPDATA`), re-specified as the one typed refusal (SAL-4).
    AlreadyHeld,
    /// `remove_alt_block` of a hash the store does not hold. Removing what
    /// is not held is a caller-contract violation — L14's insert-versus-upsert
    /// ruling applied to a remove — not an idempotent no-op.
    NotHeld,
    /// `insert_alt_block` whose key is not the hash of the block it stores.
    /// The key is the alt block's identity and the record does not carry a
    /// second one, so the store verifies the one it is given — the belt
    /// class `chain_reads::block_body` applies to a blob against
    /// `block_info.hash`. The C++ trusted the caller (`blockchain.cpp:2359`).
    IdentityMismatch {
        /// The key the caller supplied.
        key: BlockHash,
        /// What the block bytes hash to.
        actual: BlockHash,
    },
}

/// The pool store's typed refusals — the pool's decisions, not faults
/// (`StoreCannot`'s shape; `DRS_E1_SPOOL.md` §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolCannot {
    /// `insert` of a transaction the pool already holds. The pool decides
    /// whether to upsert by removing first, as the C++ `add_tx` does.
    AlreadyHeld,
    /// `update` of a transaction the pool does not hold.
    NotHeld,
    /// `insert` with no transaction bytes: a pool entry is a transaction.
    EmptyBlob,
    /// `update` whose relay state does not
    /// [`follow`](crate::codec::RelayState::follows) the stored one — the
    /// ratchet's verdict, carried as the type gave it: a changed provenance
    /// (§92.4, `SPL-Q9`), a phase that is not the stored one or a forward
    /// step, a responsibility re-armed after observation disarmed it.
    Relay(crate::codec::RelayRefusal),
    /// `fcmp_cache` is the all-zero null hash. Absence is `None`; the null
    /// hash is not a verification (SPL-10).
    NullFcmpCache,
}

impl core::fmt::Display for StoreCannot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SchemaVersionAbsent => write!(
                f,
                "chain store carries no schema_version cell: not a store this binary wrote; \
                 rebuild from the block corpus"
            ),
            Self::SchemaVersionMismatch { found, expected } => write!(
                f,
                "chain store is {found} but this binary is {expected}: no migration ladder \
                 exists; rebuild from the block corpus"
            ),
            Self::LayoutForeign { expected } => write!(
                f,
                "chain store's header table is not layout {expected}'s: written by another \
                 layout; no migration ladder exists; rebuild from the block corpus"
            ),
            Self::RowWidth {
                table,
                expected,
                actual,
            } => write!(
                f,
                "`{table}` row is {actual} byte(s); its value shape is fixed at {expected}: \
                 refused before the engine"
            ),
            Self::RowIllFormed { table, reason } => write!(
                f,
                "`{table}` row is not well-formed ({reason}): refused before the engine"
            ),
            Self::PropertiesAreTyped => write!(
                f,
                "the properties table has no raw write handle: use upsert_property on a typed cell"
            ),
            Self::ReadOnly => write!(f, "write attempted on a read-only chain store"),
            Self::WriteInProgress => {
                write!(f, "a write batch is already live on this chain store")
            }
            Self::EmptyApplyStub => write!(
                f,
                "stubbed apply policy with no families is Full wearing a non-parity stamp"
            ),
            Self::FamilyStubbed(family) => write!(
                f,
                "apply of {} is stubbed under this store's policy",
                family.table()
            ),
            Self::UndoUnsealed { height } => write!(
                f,
                "the pop-journal recording for height {height} was dropped unsealed; the batch \
                 will not commit chain-state writes that have no undo row"
            ),
            Self::RuleSetNotInForce {
                height,
                judged,
                in_force,
            } => write!(
                f,
                "the block was judged under rule set {judged:?} but rule set {in_force:?} is in \
                 force at height {height}; re-validate under the rule set in force"
            ),
            Self::ChainEmpty => f.write_str("pop on a chain store with no block recorded"),
            Self::PopBelowFloor { tip, floor } => write!(
                f,
                "cannot pop height {tip}: the pop floor is {floor} (genesis is never poppable; \
                 below the surviving undo log a reorg is beyond this store's retention)"
            ),
            Self::WriterHalted { at_height, row } => write!(
                f,
                "the chain store's writer is halted since height {at_height} ({row}); reads stay \
                 open; restart after the check or rebuild from the block corpus"
            ),
            Self::OutputWithoutCommitment { tx, index } => write!(
                f,
                "transaction {tx:?} output {index} has no commitment in its ct base; the store \
                 records nothing for it"
            ),
            Self::SettlementEpochMismatch { pinned, session } => write!(
                f,
                "this data directory was built with settlement epochs of {pinned} but this \
                 session runs {session}: persisted join epochs and serve-credit windows would be \
                 silently mislabeled; reopen under the pinned schedule or use a fresh data directory"
            ),
            Self::Pool(cannot) => write!(f, "pool store: {cannot}"),
            Self::Alt(cannot) => write!(f, "alt-chain store: {cannot}"),
            Self::PoolFileForeign => f.write_str(
                "pool file is not one this store wrote and not one it may recreate (no redb \
                 database, no pool header, or a header that does not decode): refused, not \
                 deleted — check the path, or remove the file deliberately",
            ),
        }
    }
}

impl core::error::Error for StoreCannot {}

impl core::fmt::Display for PoolCannot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyHeld => f.write_str("insert of a transaction the pool already holds"),
            Self::NotHeld => f.write_str("update of a transaction the pool does not hold"),
            Self::EmptyBlob => f.write_str("insert with no transaction bytes"),
            Self::Relay(refusal) => {
                write!(f, "update whose relay state does not follow: {refusal}")
            }
            Self::NullFcmpCache => {
                f.write_str("fcmp verification cache is the null hash; absence is None")
            }
        }
    }
}

impl core::error::Error for PoolCannot {}

impl From<PoolCannot> for StoreError {
    fn from(cannot: PoolCannot) -> Self {
        Self::Cannot(StoreCannot::Pool(cannot))
    }
}

impl core::fmt::Display for AltCannot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyHeld => f.write_str("insert of an alt block the store already holds"),
            Self::NotHeld => f.write_str("remove of an alt block the store does not hold"),
            Self::IdentityMismatch { key, actual } => write!(
                f,
                "insert of an alt block under key {key} whose bytes hash to {actual}"
            ),
        }
    }
}

impl core::error::Error for AltCannot {}

impl From<AltCannot> for StoreError {
    fn from(cannot: AltCannot) -> Self {
        Self::Cannot(StoreCannot::Alt(cannot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CodecError;

    /// One value per class, and the class each is.
    fn specimens() -> [(StoreError, ErrorClass); 3] {
        [
            (
                StoreError::Engine(EngineError::Table(redb::TableError::TableDoesNotExist(
                    "t".into(),
                ))),
                ErrorClass::Engine,
            ),
            (StoreCannot::ReadOnly.into(), ErrorClass::Cannot),
            (
                StoreInvariant::CellCorrupt {
                    key: "k",
                    fault: CellFault::Absent,
                }
                .into(),
                ErrorClass::Invariant,
            ),
        ]
    }

    #[test]
    fn class_is_the_outer_variant() {
        for (e, class) in specimens() {
            assert_eq!(e.class(), class, "{e:?}");
        }
    }

    #[test]
    fn the_lifts_land_in_their_own_class() {
        // `From` is the only way `?` reaches `StoreError`; each inner type
        // must land in its own arm and no other.
        let engine: StoreError =
            EngineError::Commit(redb::CommitError::Storage(redb::StorageError::PreviousIo)).into();
        assert!(matches!(engine, StoreError::Engine(EngineError::Commit(_))));
        let cannot: StoreError = StoreCannot::WriteInProgress.into();
        assert!(matches!(
            cannot,
            StoreError::Cannot(StoreCannot::WriteInProgress)
        ));
        let inv: StoreError = StoreInvariant::CellCorrupt {
            key: "k",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "probe",
                reason: "test",
            }),
        }
        .into();
        assert!(matches!(
            inv,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt { key: "k", .. })
        ));
    }

    #[test]
    fn the_wrapper_is_transparent() {
        // Display and source both pass through; the class adds no second
        // line to an error chain.
        use core::error::Error as _;
        for (e, _) in specimens() {
            let inner_display = match &e {
                StoreError::Engine(i) => i.to_string(),
                StoreError::Cannot(i) => i.to_string(),
                StoreError::InvariantViolated(i) => i.to_string(),
            };
            assert_eq!(e.to_string(), inner_display);
        }
        let inv = StoreError::from(StoreInvariant::CellCorrupt {
            key: "k",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "probe",
                reason: "test",
            }),
        });
        assert!(inv.source().is_some(), "an undecodable cell has a cause");
        let absent = StoreError::from(StoreInvariant::CellCorrupt {
            key: "k",
            fault: CellFault::Absent,
        });
        assert!(
            absent.source().is_none(),
            "an absent cell is the root cause"
        );
    }

    #[test]
    fn an_invariant_names_its_register_row() {
        let si7 = StoreInvariant::CellCorrupt {
            key: "apply_policy",
            fault: CellFault::Absent,
        };
        assert_eq!(si7.row(), 7);
        let shown = si7.to_string();
        assert!(shown.starts_with("SI-7 violated: "), "{shown}");
        assert!(shown.contains("`apply_policy`"), "{shown}");
    }
}
