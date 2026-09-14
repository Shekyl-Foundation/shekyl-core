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
    /// A write was attempted against a store opened read-only.
    ReadOnly,
    /// A write batch is already live on this store.
    ///
    /// redb's `begin_write` **blocks** until the in-progress writer finishes.
    /// A second `begin_batch` on the same thread would deadlock; this error
    /// is the C++ `DB_ERROR_TXN_START` shape, not that wait.
    WriteInProgress,
    /// [`ApplyPolicy::stubbed`](crate::apply_policy::ApplyPolicy::stubbed)
    /// was given an empty family list, which is `Full` wearing a non-parity
    /// stamp.
    EmptyApplyStub,
    /// This family's apply is stubbed under the store's policy, so the write
    /// path must not open its table (opening a write table creates it).
    FamilyStubbed(ArchivalFamily),
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
            Self::Abort(e) => Some(e),
            Self::Table(e) => Some(e),
            Self::ReadOnly
            | Self::WriteInProgress
            | Self::EmptyApplyStub
            | Self::FamilyStubbed(_) => None,
        }
    }
}
