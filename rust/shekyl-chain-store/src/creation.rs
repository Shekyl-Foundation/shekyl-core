// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A file's creation that a power loss cut off: what is left at the path,
//! and how an open finishes it instead of refusing it.
//!
//! Both stores create their file in three durable steps: `create_new`
//! claims the path, the engine initializes the file (its header, then its
//! magic number, each flushed), and the store seals it in its first
//! transaction. PB-S2's first power-loss replay (2026-11-01,
//! `DAEMON_REDB_STORE.md` §1.3a) found a node that could not start again
//! after a cut between any two of them. What each cut leaves is
//! recognizable, and none of it holds anything to lose:
//!
//! - **The engine never finished initializing.** The file is empty, or its
//!   magic slot is unwritten: redb writes the magic only after the rest of
//!   the header is durable, and every later header write carries it, so an
//!   unwritten magic is a file nothing was ever committed to. The engine
//!   refuses such a file as invalid data. [`take_unfinished_init`] claims
//!   it and empties it, so the caller can initialize and seal it.
//! - **The engine finished, the seal did not.** A valid database with no
//!   table at all ([`no_table`]). The caller seals it in place.
//!
//! A file with any table and no seal, or with bytes and another magic, is
//! not a creation of this crate's and stays refused.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use redb::{Database, ReadableDatabase};

use crate::store::{EngineError, StoreError};

/// redb's magic number, the first bytes of every file it initialized
/// (`redb-4.1.0/src/tree_store/page_store/header.rs`, `MAGICNUMBER`).
const ENGINE_MAGIC_LEN: usize = 9;

/// The file at `path`, claimed and emptied, if the engine never finished
/// initializing it: empty, or with its magic slot unwritten. `None` for
/// anything else, including a file another process holds (its exclusive
/// lock is the engine's; a holder is a live creator or a live store).
///
/// # Errors
///
/// The file could not be opened, read, locked for a reason other than a
/// holder, or emptied.
pub(crate) fn take_unfinished_init(path: &Path) -> std::io::Result<Option<File>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(e)) => return Err(e),
    }
    let mut slot = [0u8; ENGINE_MAGIC_LEN];
    let len = file.metadata()?.len();
    if len > 0 {
        if len < ENGINE_MAGIC_LEN as u64 {
            file.unlock()?;
            return Ok(None);
        }
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut slot)?;
        if slot.iter().any(|&b| b != 0) {
            file.unlock()?;
            return Ok(None);
        }
        file.set_len(0)?;
        file.sync_all()?;
    }
    file.seek(SeekFrom::Start(0))?;
    // The engine takes its own lock on this handle; release ours first so
    // the two never meet on one descriptor.
    file.unlock()?;
    Ok(Some(file))
}

/// The database holds no table at all: the engine's first commit and
/// nothing after it, which is a creation stopped before its seal.
///
/// # Errors
///
/// A read transaction could not begin or the table list could not be read.
pub(crate) fn no_table(db: &Database) -> Result<bool, StoreError> {
    let txn = db.begin_read().map_err(EngineError::BeginRead)?;
    let none = txn
        .list_tables()
        .map_err(EngineError::Storage)?
        .next()
        .is_none()
        && txn
            .list_multimap_tables()
            .map_err(EngineError::Storage)?
            .next()
            .is_none();
    Ok(none)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shekyl-creation-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir
    }

    #[test]
    fn an_empty_file_and_an_unwritten_magic_are_claimed_and_nothing_else_is() {
        let empty = tmp("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(take_unfinished_init(&empty).unwrap().is_some(), "empty");

        let unwritten = tmp("unwritten");
        let mut bytes = vec![0u8; 4096];
        bytes[9] = 4;
        std::fs::write(&unwritten, &bytes).unwrap();
        let file = take_unfinished_init(&unwritten)
            .unwrap()
            .expect("unwritten magic");
        assert_eq!(file.metadata().unwrap().len(), 0, "emptied for the engine");

        let foreign = tmp("foreign");
        std::fs::write(&foreign, b"this is not a redb file, and it is somebody's").unwrap();
        assert!(
            take_unfinished_init(&foreign).unwrap().is_none(),
            "foreign kept"
        );
        assert_eq!(
            std::fs::read(&foreign).unwrap(),
            b"this is not a redb file, and it is somebody's",
            "untouched"
        );

        let store = tmp("store");
        drop(redb::Database::create(&store).unwrap());
        let before = std::fs::read(&store).unwrap();
        assert!(
            take_unfinished_init(&store).unwrap().is_none(),
            "an initialized file"
        );
        assert_eq!(std::fs::read(&store).unwrap(), before, "untouched");

        let held = tmp("held");
        std::fs::write(&held, b"").unwrap();
        let holder = std::fs::OpenOptions::new().write(true).open(&held).unwrap();
        holder.lock().unwrap();
        assert!(
            take_unfinished_init(&held).unwrap().is_none(),
            "a holder's file"
        );

        for p in [&empty, &unwritten, &foreign, &store, &held] {
            drop(std::fs::remove_file(p));
        }
    }
}
