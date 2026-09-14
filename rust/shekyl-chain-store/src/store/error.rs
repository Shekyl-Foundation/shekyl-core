// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed failures for the S-TXN surface.
//!
//! One variant per condition a caller can act on. The C++ layer raises one
//! `DB_ERROR` for twenty-two conditions and a `std::runtime_error` for two
//! more of the *same* precondition (DRS-W1); there is no harmonization pass
//! to owe later.

use crate::apply_policy::ArchivalFamily;
use crate::codec::{CodecError, SchemaVersion};

/// Why a store operation failed.
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
    /// An explicit abort failed. The transaction is gone either way.
    Abort(redb::StorageError),
    /// Opening a table failed.
    Table(redb::TableError),
    /// A row read or write failed inside the engine.
    Storage(redb::StorageError),
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
    /// migration ladder and none will be written. Rebuild.
    SchemaVersionMismatch {
        /// The version the file carries.
        found: SchemaVersion,
        /// The version this binary reads and writes.
        expected: SchemaVersion,
    },
    /// A typed `properties` cell is present but does not decode, or a
    /// header cell the seal always writes is missing.
    ///
    /// Codecs are strict (`codec` module docs), so this is never "an older
    /// layout" — that is [`SchemaVersionMismatch`](Self::SchemaVersionMismatch).
    /// Both header cells land in the seal's one transaction, so a store with
    /// a valid `schema_version` and a broken `apply_policy` was modified by
    /// something other than this crate. Rebuild.
    CellCorrupt {
        /// The cell's key.
        key: &'static str,
        /// What is wrong with it.
        fault: CellFault,
    },
    /// The raw `properties` table was requested on the write side.
    ///
    /// Its cells are typed ([`PropertyCell`](crate::codec::PropertyCell))
    /// and written through
    /// [`WriteBatch::put_property`](super::WriteBatch::put_property), whose
    /// bound admits chain-state cells only. A raw handle would let a string
    /// overwrite `schema_version` or clear the provenance record, so there
    /// is none.
    PropertiesAreTyped,
    /// A write was attempted against a store opened read-only.
    ReadOnly,
    /// A write batch is already live on this store.
    ///
    /// redb's `begin_write` **blocks** until the in-progress writer finishes.
    /// A `begin_batch` while another batch is live. **This is a contract
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
    /// `while begin_batch().is_err()`. Serialization of writers is owned by
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
}

/// What is wrong with a typed `properties` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellFault {
    /// The cell is not in the table.
    Absent,
    /// The cell's bytes are not an encoding of its value type.
    Undecodable(CodecError),
}

impl core::fmt::Display for CellFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("absent"),
            Self::Undecodable(e) => write!(f, "undecodable ({e})"),
        }
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "cannot open chain store: {e}"),
            Self::BeginWrite(e) => write!(f, "cannot begin write transaction: {e}"),
            Self::BeginRead(e) => write!(f, "cannot begin read transaction: {e}"),
            Self::Durability(e) => write!(f, "engine refused the declared durability: {e}"),
            Self::Commit(e) => write!(f, "commit failed: {e}"),
            Self::Abort(e) => write!(f, "abort failed: {e}"),
            Self::Table(e) => write!(f, "cannot open table: {e}"),
            Self::Storage(e) => write!(f, "engine storage error: {e}"),
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
            Self::CellCorrupt { key, fault } => write!(
                f,
                "chain store properties cell `{key}` is {fault}: the file was modified \
                 outside this crate; rebuild from the block corpus"
            ),
            Self::PropertiesAreTyped => write!(
                f,
                "the properties table has no raw write handle: use put_property on a typed cell"
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
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Open(e) => Some(e),
            Self::BeginWrite(e) | Self::BeginRead(e) => Some(e),
            Self::Durability(e) => Some(e),
            Self::Commit(e) => Some(e),
            Self::Abort(e) | Self::Storage(e) => Some(e),
            Self::Table(e) => Some(e),
            Self::CellCorrupt {
                fault: CellFault::Undecodable(e),
                ..
            } => Some(e),
            Self::CellCorrupt {
                fault: CellFault::Absent,
                ..
            }
            | Self::SchemaVersionAbsent
            | Self::SchemaVersionMismatch { .. }
            | Self::PropertiesAreTyped
            | Self::ReadOnly
            | Self::WriteInProgress
            | Self::EmptyApplyStub
            | Self::FamilyStubbed(_) => None,
        }
    }
}
