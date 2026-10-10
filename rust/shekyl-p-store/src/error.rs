// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Store faults. The serve loop collapses every one of these to a 503;
//! variants exist for the local counter and the fill driver's log.

/// Why a body-store read or write could not complete.
#[derive(Debug)]
pub enum StoreError {
    /// redb could not open, read, or write.
    Backend {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
    /// An existing file's schema byte is not this crate's.
    Schema {
        /// What the file carried.
        found: u8,
    },
    /// A sealed chunk failed authentication after servability was
    /// settled. The response head may already be on the wire; the loop
    /// can only close.
    Corrupt {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
}

impl StoreError {
    pub(crate) fn backend(err: impl std::fmt::Debug) -> Self {
        Self::Backend {
            detail: format!("{err:?}"),
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { detail } | Self::Corrupt { detail } => {
                write!(f, "persona body store failed: {detail}")
            }
            Self::Schema { found } => {
                write!(
                    f,
                    "persona body store schema {found} is not {SCHEMA_VERSION}"
                )
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<redb::DatabaseError> for StoreError {
    fn from(err: redb::DatabaseError) -> Self {
        Self::backend(err)
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(err: redb::TransactionError) -> Self {
        Self::backend(err)
    }
}

impl From<redb::TableError> for StoreError {
    fn from(err: redb::TableError) -> Self {
        Self::backend(err)
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(err: redb::StorageError) -> Self {
        Self::backend(err)
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(err: redb::CommitError) -> Self {
        Self::backend(err)
    }
}

/// Bumped when the table layout changes. An existing file with any
/// other byte is refused, not migrated (`15-deletion-and-debt`:
/// pre-genesis the path is delete-and-rebuild).
pub(crate) const SCHEMA_VERSION: u8 = 1;
