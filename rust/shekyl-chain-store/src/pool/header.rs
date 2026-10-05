// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file's header: creation, the seal, and what an existing file's
//! header decides (`DRS_E1_SPOOL.md` `SPL-Q8`, with the precondition from
//! PR #851's review).
//!
//! A fresh file is sealed with the crate's `SCHEMA_VERSION` in its own cell
//! and both data tables created, in one transaction, so a reader never has
//! to read *absent table* as *empty pool*. On reopen the cell is read first:
//! a seal at **another** version **recreates** the file (it is discardable
//! by ruling and has no corpus to rebuild from); a seal at the current
//! version must sit over both tables under their declared types, or the
//! file is not one this store left behind. Everything that is not a sealed
//! pool file is **refused and kept**.

use std::path::Path;

use redb::{Database, ReadTransaction, ReadableDatabase, TableDefinition};
use shekyl_store_codec::{Canonical, Raw};

use crate::codec::{PropertyCellBytes, SchemaVersion, SCHEMA_VERSION};
use crate::store::{EngineError, StoreCannot, StoreError};

use super::schema::{POOL_BLOB, POOL_HEADER, POOL_META};
use super::{arm_write, POOL_CACHE_SIZE};

/// The header cell that carries the layout version the file was sealed at.
pub const POOL_VERSION_KEY: &str = "pool_schema_version";

/// How [`PoolStore::create`](super::PoolStore::create) arrived at an open
/// file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolOpen {
    /// No file existed; one was created and sealed at [`SCHEMA_VERSION`].
    Created,
    /// A sealed file at the current version, over its sealed tables, was
    /// opened.
    Opened,
    /// A sealed file at another version was **recreated** (`SPL-Q8`): the
    /// old file was removed and a fresh one sealed. `from` is the version
    /// the old file carried — the caller's one log line names it.
    Recreated {
        /// The layout the discarded file was sealed at.
        from: SchemaVersion,
    },
}

/// What an existing file's header decides.
enum Header {
    /// Sealed at the current version, over its sealed tables.
    Current,
    /// Sealed at another version: recreate.
    Other(SchemaVersion),
}

/// The one entry point: claim `path` if it is free, else read what is there.
///
/// Fresh-vs-existing is decided by the same syscall that claims the path
/// (`create_new`), never by a separate probe — the chain store's rule
/// (`store/mod.rs`), for the same reason: only the `create_new` winner
/// initializes a file, so a path removed between two looks, or an empty
/// file another process left, is never sealed by a creator that did not
/// create it.
pub(super) fn open_or_create(path: &Path) -> Result<(Database, PoolOpen), StoreError> {
    let mut builder = redb::Builder::new();
    builder.set_cache_size(POOL_CACHE_SIZE);
    match create_new(path) {
        Ok(file) => seal_fresh(&builder, file, path).map(|db| (db, PoolOpen::Created)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let db = match builder.open(path) {
                Ok(db) => db,
                Err(e) if open_is_foreign(&e) => return Err(StoreCannot::PoolFileForeign.into()),
                Err(e) => return Err(EngineError::Open(e).into()),
            };
            match read_header(&db)? {
                Header::Current => Ok((db, PoolOpen::Opened)),
                Header::Other(from) => {
                    // Release the engine's file lock before removing.
                    drop(db);
                    std::fs::remove_file(path).map_err(io_open)?;
                    let file = create_new(path).map_err(io_open)?;
                    seal_fresh(&builder, file, path).map(|db| (db, PoolOpen::Recreated { from }))
                }
            }
        }
        Err(e) => Err(io_open(e).into()),
    }
}

fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

fn io_open(e: std::io::Error) -> EngineError {
    EngineError::Open(redb::DatabaseError::Storage(e.into()))
}

/// Hand a just-created, empty file to the engine and seal it in its first
/// transaction. On `Err` the file is removed again, so a failed create does
/// not leave a headerless file the next open refuses as foreign.
fn seal_fresh(
    builder: &redb::Builder,
    file: std::fs::File,
    path: &Path,
) -> Result<Database, StoreError> {
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
            txn.open_table(POOL_META).map_err(EngineError::Table)?;
            txn.open_table(POOL_BLOB).map_err(EngineError::Table)?;
        }
        txn.commit().map_err(EngineError::Commit)?;
        Ok::<_, StoreError>(db)
    })();
    if sealed.is_err() {
        drop(std::fs::remove_file(path));
    }
    sealed
}

/// Read the header of an existing file, and — at the current version —
/// verify the sealed table set. Absence or an undecodable cell, or a
/// current-version seal over a missing or re-typed table, is
/// [`StoreCannot::PoolFileForeign`].
fn read_header(db: &Database) -> Result<Header, StoreError> {
    let txn = db.begin_read().map_err(EngineError::BeginRead)?;
    let table = match txn.open_table(POOL_HEADER) {
        Ok(t) => t,
        Err(e) if table_is_foreign(&e) => return Err(StoreCannot::PoolFileForeign.into()),
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
    // The seal at this version created both tables, so a current-version
    // file that lacks one — or holds one under another type — is not one
    // this store left behind: tampered or torn. Without this it opened as
    // `Opened` and failed at the first op as a bare engine error.
    require_sealed_table(&txn, POOL_META)?;
    require_sealed_table(&txn, POOL_BLOB)?;
    Ok(Header::Current)
}

/// Whether `err` means "these bytes are not a pool database".
///
/// redb reports a magic mismatch, and an empty file opened rather than
/// created, as `Io(InvalidData)` (`page_manager` / `open_empty_file`);
/// `Corrupted` is the same answer once a header has been read and rejected.
/// Any other `Io` — permissions, a full disk — is an engine failure, not a
/// cue to delete the file.
fn open_is_foreign(err: &redb::DatabaseError) -> bool {
    match err {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => true,
        redb::DatabaseError::Storage(redb::StorageError::Io(io)) => {
            io.kind() == std::io::ErrorKind::InvalidData
        }
        _ => false,
    }
}

/// Whether a table error means the file's table set is not the seal's.
const fn table_is_foreign(err: &redb::TableError) -> bool {
    matches!(
        err,
        redb::TableError::TableDoesNotExist(_) | redb::TableError::TableTypeMismatch { .. }
    )
}

/// A current-version file's data table must open under the type the seal
/// wrote. Missing or re-typed is [`StoreCannot::PoolFileForeign`].
fn require_sealed_table<K, V>(
    txn: &ReadTransaction,
    definition: TableDefinition<'_, K, V>,
) -> Result<(), StoreError>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    match txn.open_table(definition) {
        Ok(_) => Ok(()),
        Err(e) if table_is_foreign(&e) => Err(StoreCannot::PoolFileForeign.into()),
        Err(e) => Err(EngineError::Table(e).into()),
    }
}
