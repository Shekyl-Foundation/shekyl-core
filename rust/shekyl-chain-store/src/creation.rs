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
//! recognizable:
//!
//! - **The engine never finished initializing.** The file is empty, or it
//!   is no longer than an initialization writes ([`ENGINE_INIT_LEN`]) and
//!   its magic slot is unwritten: redb writes the magic only after the rest
//!   of the header is durable (pinned by
//!   `the_engine_writes_its_magic_last_within_the_bound`). The engine
//!   refuses such a file as invalid data. [`set_aside_unfinished_init`]
//!   moves it aside, never deleting it, so the caller creates a fresh file
//!   at the path and an operator can still inspect the one set aside.
//! - **The engine finished, the seal did not.** A valid database with no
//!   table at all ([`no_table`]). The caller seals it in place: nothing is
//!   removed, only the seal added.
//!
//! A file longer than the bound, with any other magic, or with any table
//! and no seal, is not a creation this crate can prove it made, and stays
//! refused, byte for byte.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase};

use crate::store::{EngineError, StoreError};

/// The length of redb's magic number, the first bytes of every file it
/// initialized (`redb-4.1.0/src/tree_store/page_store/header.rs`,
/// `MAGICNUMBER`).
const ENGINE_MAGIC_LEN: usize = 9;

/// The most bytes redb's initialization writes, at the default page and
/// region size both stores use: a file whose magic is unwritten is no
/// longer than this, and a store that has committed anything past its seal
/// is longer. Pinned against the engine in `Cargo.lock` by
/// `the_engine_writes_its_magic_last_within_the_bound`.
pub(crate) const ENGINE_INIT_LEN: u64 = 1_056_768;

/// Whether `file`, of length `len`, is what an initialization cut off
/// leaves: empty, or within [`ENGINE_INIT_LEN`] with its magic slot
/// unwritten.
fn unfinished_init(file: &mut File, len: u64) -> std::io::Result<bool> {
    if len == 0 {
        return Ok(true);
    }
    if len < ENGINE_MAGIC_LEN as u64 || len > ENGINE_INIT_LEN {
        return Ok(false);
    }
    let mut slot = [0u8; ENGINE_MAGIC_LEN];
    file.read_exact(&mut slot)?;
    Ok(slot.iter().all(|&b| b == 0))
}

/// Move the file at `path` aside if the engine never finished initializing
/// it, and return where it went: `<name>.unfinished-<unix seconds>`, with a
/// counter if that name is taken, so no earlier file is ever replaced. The
/// move is flushed to the directory. `None`, and the file untouched, for
/// anything else, including a file another process holds (its lock is the
/// engine's: a live creator or a live store).
///
/// # Errors
///
/// The file could not be opened, read or locked for a reason other than a
/// holder, or the move failed.
pub(crate) fn set_aside_unfinished_init(path: &Path) -> std::io::Result<Option<PathBuf>> {
    {
        let mut file = File::open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        let len = file.metadata()?.len();
        let unfinished = unfinished_init(&mut file, len)?;
        file.unlock()?;
        if !unfinished {
            return Ok(None);
        }
        // Closed before the move: a file open elsewhere cannot be renamed
        // on every platform.
    }
    let aside = aside_path(path)?;
    std::fs::rename(path, &aside)?;
    sync_parent(path)?;
    Ok(Some(aside))
}

/// The first `<name>.unfinished-<unix seconds>[-<n>]` beside `path` that
/// does not exist.
fn aside_path(path: &Path) -> std::io::Result<PathBuf> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    for n in 0u32.. {
        let suffix = if n == 0 {
            format!("{name}.unfinished-{secs}")
        } else {
            format!("{name}.unfinished-{secs}-{n}")
        };
        let candidate = path.with_file_name(suffix);
        if !candidate.try_exists()? {
            return Ok(candidate);
        }
    }
    unreachable!("an unbounded counter finds a free name")
}

/// Flush the directory holding `path`, so a rename in it is durable. Unix
/// only: elsewhere a directory cannot be opened to flush.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
    use std::sync::{Arc, Mutex};

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shekyl-creation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn untouched(path: &Path) -> (Vec<u8>, std::time::SystemTime) {
        (
            std::fs::read(path).unwrap(),
            std::fs::metadata(path).unwrap().modified().unwrap(),
        )
    }

    #[test]
    fn an_unfinished_init_is_moved_aside_and_nothing_else_is_touched() {
        // Empty, and an unwritten magic within the bound: moved aside,
        // bytes intact under the new name.
        let mut unwritten = vec![0u8; 4096];
        unwritten[9] = 4;
        for (label, bytes) in [("empty", Vec::new()), ("unwritten", unwritten)] {
            let path = tmp(label);
            std::fs::write(&path, &bytes).unwrap();
            let aside = set_aside_unfinished_init(&path)
                .unwrap()
                .unwrap_or_else(|| panic!("{label}: set aside"));
            assert!(!path.exists(), "{label}: the path is free");
            assert_eq!(std::fs::read(&aside).unwrap(), bytes, "{label}: kept");
            let name = aside.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with(&format!("{label}.unfinished-")), "{name}");
        }

        // A second set-aside in the same second takes the next name, never
        // the first one's.
        let path = tmp("twice");
        std::fs::write(&path, b"").unwrap();
        let first = set_aside_unfinished_init(&path).unwrap().unwrap();
        std::fs::write(&path, b"").unwrap();
        let second = set_aside_unfinished_init(&path).unwrap().unwrap();
        assert_ne!(first, second);
        assert!(first.exists() && second.exists());

        // The design review's guard: a zeroed magic slot on a file longer
        // than an initialization writes is a store whose first sector is
        // gone, not an unfinished init. Refused, byte for byte. Red edit:
        // drop the length bound from `unfinished_init`.
        let path = tmp("zeroed-long");
        let mut long = vec![0u8; usize::try_from(ENGINE_INIT_LEN).unwrap() + 4096];
        long[ENGINE_MAGIC_LEN..ENGINE_MAGIC_LEN + 4].copy_from_slice(&[4, 0, 0, 0]);
        long[600_000] = 0xAB;
        std::fs::write(&path, &long).unwrap();
        let before = untouched(&path);
        assert!(set_aside_unfinished_init(&path).unwrap().is_none());
        assert_eq!(untouched(&path), before, "left byte for byte");

        // Foreign bytes, an initialized database, and a file someone holds.
        let foreign = tmp("foreign");
        std::fs::write(&foreign, b"this is not a redb file, and it is somebody's").unwrap();
        let store = tmp("store");
        drop(redb::Database::create(&store).unwrap());
        for path in [&foreign, &store] {
            let before = untouched(path);
            assert!(set_aside_unfinished_init(path).unwrap().is_none());
            assert_eq!(untouched(path), before, "{}", path.display());
        }
        let held = tmp("held");
        std::fs::write(&held, b"").unwrap();
        let holder = File::open(&held).unwrap();
        holder.lock().unwrap();
        assert!(set_aside_unfinished_init(&held).unwrap().is_none(), "held");
        assert!(held.exists());
    }

    /// The engine's storage as it stood at each flush.
    #[derive(Debug, Default)]
    struct Recorded {
        bytes: Vec<u8>,
        at_flush: Vec<Vec<u8>>,
    }

    #[derive(Debug, Default, Clone)]
    struct Recording(Arc<Mutex<Recorded>>);

    impl redb::StorageBackend for Recording {
        fn len(&self) -> Result<u64, std::io::Error> {
            Ok(self.0.lock().unwrap().bytes.len() as u64)
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
            let r = self.0.lock().unwrap();
            let at = usize::try_from(offset).unwrap();
            out.copy_from_slice(&r.bytes[at..at + out.len()]);
            Ok(())
        }

        fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
            self.0
                .lock()
                .unwrap()
                .bytes
                .resize(usize::try_from(len).unwrap(), 0);
            Ok(())
        }

        fn sync_data(&self) -> Result<(), std::io::Error> {
            let mut r = self.0.lock().unwrap();
            let snapshot = r.bytes.clone();
            r.at_flush.push(snapshot);
            Ok(())
        }

        fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
            let mut r = self.0.lock().unwrap();
            let at = usize::try_from(offset).unwrap();
            if r.bytes.len() < at + data.len() {
                r.bytes.resize(at + data.len(), 0);
            }
            r.bytes[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    /// The recognition rests on the engine's write order: the magic last,
    /// after the rest of the header is flushed, and the file no longer than
    /// [`ENGINE_INIT_LEN`] until then. Recorded at every flush of an
    /// initialization under the engine in `Cargo.lock`: every state a power
    /// loss can leave before the magic is durable is one
    /// [`set_aside_unfinished_init`] recognizes. A future engine that wrote
    /// its magic earlier, or grew the file further first, fails here.
    #[test]
    fn the_engine_writes_its_magic_last_within_the_bound() {
        let recording = Recording::default();
        drop(
            redb::Builder::new()
                .create_with_backend(recording.clone())
                .expect("an initialization"),
        );
        let r = recording.0.lock().unwrap();
        let magic_at = r
            .at_flush
            .iter()
            .position(|state| {
                state.len() >= ENGINE_MAGIC_LEN && state[..ENGINE_MAGIC_LEN].iter().any(|&b| b != 0)
            })
            .expect("the magic is flushed");
        assert!(magic_at > 0, "the header is flushed before the magic");
        for state in &r.at_flush[..magic_at] {
            assert!(
                state.len() < ENGINE_MAGIC_LEN || state[..ENGINE_MAGIC_LEN].iter().all(|&b| b == 0),
                "the magic before its flush"
            );
            assert!(
                state.len() as u64 <= ENGINE_INIT_LEN,
                "{} bytes",
                state.len()
            );
        }
        assert_eq!(
            r.at_flush[magic_at].len() as u64,
            ENGINE_INIT_LEN,
            "an initialization's length is the bound"
        );
    }
}
