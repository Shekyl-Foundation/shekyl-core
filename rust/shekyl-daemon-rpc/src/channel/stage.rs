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
//!
//! **Durable at each step.** A new file's bytes are synced, and then its
//! directory, before [`write_new`] returns; a rename is followed by a sync
//! of its directory before [`StagedWrite::commit`] returns. A store
//! transaction that names a journal (the console key's) therefore never
//! outlives the journal across a power loss. Unix syncs the directory;
//! Windows has no directory handle to sync, and the file's own flush is
//! the platform's whole durability step
//! ([`shekyl_daemon_config::marker::sync_dir`], the daemon's one rule).
//!
//! **The mode is set, not requested.** On Unix the creating call's mode is
//! filtered by the umask, so the file's mode is then set to exactly its
//! [`Access`]: a service's rendezvous record is readable by every account
//! under any umask.

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};

use shekyl_daemon_config::marker::sync_dir;

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

    /// Rename the journal over the destination, and make the rename
    /// durable.
    ///
    /// # Errors
    ///
    /// The rename failed, and the journal is left for a later start; or the
    /// directory could not be synced after it.
    pub(crate) fn commit(self) -> std::io::Result<()> {
        std::fs::rename(&self.staged, &self.live)?;
        sync_dir(parent(&self.live))
    }

    /// Adopt the journal a previous process left beside `live`.
    ///
    /// The bytes are not rewritten. [`Self::commit`] renames the journal
    /// over `live` and syncs the directory; [`Self::discard`] removes it.
    /// A path that is missing, or that is not a file, is an error: a
    /// symbolic link is not renamed over the key.
    ///
    /// # Errors
    ///
    /// The journal is not there, or it is not a file.
    pub(crate) fn resume(live: &Path) -> std::io::Result<Self> {
        let staged = staged_path(live);
        let meta = std::fs::symlink_metadata(&staged)?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the journal is not a file",
            ));
        }
        Ok(Self {
            staged,
            live: live.to_path_buf(),
        })
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

/// Create `path` as a new file with `access`, write `bytes` to it, and make
/// the file and its directory entry durable.
///
/// # Errors
///
/// The create, the write or a sync failed. An existing path is an error.
pub(crate) fn write_new(path: &Path, bytes: &[u8], access: Access) -> std::io::Result<()> {
    let mut file = create(path, access)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_dir(parent(path))
}

/// The directory `path` is in.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// `O_EXCL` with the mode in the creating call, so the file is never wider
/// than `access`; then the mode set exactly, because the umask may have
/// narrowed it.
#[cfg(unix)]
fn create(path: &Path, access: Access) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mode = match access {
        Access::OwnerOnly => OWNER_ONLY_MODE,
        Access::WorldReadable => WORLD_READABLE_MODE,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(file)
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// Set in the child this test starts: the directory it writes in.
    const CHILD_DIR: &str = "SHEKYL_STAGE_UMASK_CHILD_DIR";

    /// A world-readable file is readable by every account whatever the
    /// umask, and an owner-only one stays the owner's. The umask is the
    /// process's, so the writes run in a child of this test binary under
    /// umask 077. Red edit: drop the `set_permissions` in `create`, and the
    /// record published through its journal is 0600.
    #[test]
    fn the_mode_is_the_access_under_any_umask() {
        if let Some(dir) = std::env::var_os(CHILD_DIR) {
            let dir = PathBuf::from(dir);
            rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
            StagedWrite::create(&dir.join("record"), b"public", Access::WorldReadable)
                .expect("the journal")
                .commit()
                .expect("the rename");
            write_new(&dir.join("key"), b"private", Access::OwnerOnly).expect("the key");
            return;
        }
        let dir = tempfile::tempdir().expect("a directory");
        let status = std::process::Command::new(std::env::current_exe().expect("this binary"))
            .args([
                "--exact",
                "channel::stage::tests::the_mode_is_the_access_under_any_umask",
                "--test-threads",
                "1",
            ])
            .env(CHILD_DIR, dir.path())
            .status()
            .expect("the child runs");
        assert!(status.success(), "{status}");
        let mode = |name: &str| {
            std::fs::metadata(dir.path().join(name))
                .expect("written")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("record"), WORLD_READABLE_MODE);
        assert_eq!(mode("key"), OWNER_ONLY_MODE);
        assert!(!staged_path(&dir.path().join("record")).exists());
    }
}

#[cfg(test)]
mod resume_tests {
    use super::*;

    /// A journal a previous process left is the same writer: commit renames
    /// it over the live file, discard removes it, and a path that is not a
    /// file is not adopted. Red edit: rename in `console::reconcile` with
    /// `std::fs::rename` and skip `resume`, and a symlink journal replaces
    /// the key.
    #[test]
    fn a_resumed_journal_commits_and_discards_and_a_link_is_refused() {
        let dir = tempfile::tempdir().expect("a directory");
        let live = dir.path().join("key");
        std::fs::write(&live, b"old").unwrap();
        let journal = staged_path(&live);
        std::fs::write(&journal, b"new").unwrap();
        StagedWrite::resume(&live)
            .expect("the journal")
            .commit()
            .expect("the rename");
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!journal.exists());

        std::fs::write(&journal, b"stray").unwrap();
        StagedWrite::resume(&live)
            .expect("the stray journal")
            .discard()
            .expect("the removal");
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!journal.exists());
        assert!(StagedWrite::resume(&live).is_err(), "nothing to adopt");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&live, &journal).unwrap();
            assert!(
                StagedWrite::resume(&live).is_err(),
                "a link is not a journal"
            );
        }
    }
}
