// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A file written beside its destination and renamed over it.
//!
//! The console key, the public bundle and a service's rendezvous record
//! land this way. A reader sees the previous bytes or the new ones, and
//! the journal stays until the rename, so a later start can finish a
//! commit that already names that journal. The journal's name is the
//! destination's file name plus [`.new`](JOURNAL_SUFFIX), one rule for
//! every caller.

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Appended to a destination's file name to name its journal.
const JOURNAL_SUFFIX: &str = ".new";

/// Mode of a file only its owner may read.
#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;

/// Mode of a file every account may read and only the owner may write.
#[cfg(unix)]
const WORLD_READABLE_MODE: u32 = 0o644;

/// Who may read the file the journal becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    /// The daemon's account alone (`0600`, and on Windows the owner-only
    /// labelled descriptor).
    OwnerOnly,
    /// Every account may read it. A service's rendezvous record.
    WorldReadable,
}

/// The journal a destination will be replaced from. Dropping it leaves the
/// journal: a crash between the write and the rename is what a later start
/// finishes, and deleting it here would erase that.
#[derive(Debug)]
pub(crate) struct StagedWrite {
    staged: PathBuf,
    live: PathBuf,
}

impl StagedWrite {
    /// Write `bytes` to the journal of `live`, replacing a journal already
    /// there. `live` itself is not touched.
    ///
    /// # Errors
    ///
    /// The journal could not be removed, created or written.
    pub(crate) fn create(live: &Path, bytes: &[u8], access: Access) -> std::io::Result<Self> {
        let staged = staged_path(live);
        match std::fs::remove_file(&staged) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        write_new(&staged, bytes, access)?;
        Ok(Self {
            staged,
            live: live.to_path_buf(),
        })
    }

    /// Rename the journal over the destination.
    ///
    /// # Errors
    ///
    /// The rename failed. The journal is left for a later start.
    pub(crate) fn commit(self) -> std::io::Result<()> {
        std::fs::rename(&self.staged, &self.live)
    }

    /// Remove the journal. The destination is left as it is.
    ///
    /// # Errors
    ///
    /// The journal could not be removed.
    pub(crate) fn discard(self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.staged) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Where `live`'s journal is written.
pub(crate) fn staged_path(live: &Path) -> PathBuf {
    let mut name = live.file_name().unwrap_or(OsStr::new("")).to_os_string();
    name.push(JOURNAL_SUFFIX);
    live.with_file_name(name)
}

/// Create `path` as a new file and write `bytes` to it.
///
/// # Errors
///
/// The create, the write or the sync failed. An existing path is an error.
pub(crate) fn write_new(path: &Path, bytes: &[u8], access: Access) -> std::io::Result<()> {
    let mut file = create(path, access)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn create(path: &Path, access: Access) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mode = match access {
        Access::OwnerOnly => OWNER_ONLY_MODE,
        Access::WorldReadable => WORLD_READABLE_MODE,
    };
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

#[cfg(windows)]
fn create(path: &Path, access: Access) -> std::io::Result<std::fs::File> {
    match access {
        // The same owner-only, no-read-up descriptor a key file requires
        // (RT-O34), set in the creating call.
        Access::OwnerOnly => {
            shekyl_win_sec::rendezvous::create_rendezvous_file(path).map_err(std::io::Error::other)
        }
        Access::WorldReadable => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path),
    }
}
