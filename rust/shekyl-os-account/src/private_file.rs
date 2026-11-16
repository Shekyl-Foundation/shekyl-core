// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Files this account alone may read, and files it publishes for every
//! account to read (`docs/design/RPC_CHANNEL.md` §5, §7.1; RT-O34).
//!
//! A channel key, a console key and an enrolled set are each readable by
//! the account that holds them alone: created `0600` with `O_EXCL` on Unix,
//! and on Windows with an owner-only descriptor and the no-read-up label set
//! in the creating call (`CreateFileW`, RT-P8's finding), never tightened
//! afterwards. A file anyone else can read is refused when it is read, never
//! repaired: whoever can read it holds the key. The daemon, the tunnel and a
//! CLI on another host write and read their keys through this module, one
//! rule for all three.
//!
//! **A staged write** lands a file beside its destination and renames it
//! over it ([`StagedWrite`]). A reader sees the previous bytes or the new
//! ones, and the journal stays until the rename, so a later start can finish
//! a commit that already names that journal. The journal's name is the
//! destination's file name plus [`.new`](JOURNAL_SUFFIX), one rule for every
//! caller.
//!
//! **Durable at each step.** A new file's bytes are synced, and then its
//! directory, before [`write_new`] returns; a rename is followed by a sync
//! of its directory before [`StagedWrite::commit`] returns. A store
//! transaction that names a journal (the console key's) therefore never
//! outlives the journal across a power loss. Unix syncs the directory;
//! Windows has no directory handle to sync, and the file's own flush is
//! the platform's whole durability step ([`sync_dir`]).
//!
//! **The mode is set, not requested.** On Unix the creating call's mode is
//! filtered by the umask, so the file's mode is then set to exactly its
//! [`Access`]: a service's rendezvous record is readable by every account
//! under any umask.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Appended to a destination's file name to name its journal.
const JOURNAL_SUFFIX: &str = ".new";

/// Mode of a file only its owner may read.
#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;

/// Mode of a file every account may read and only the owner may write.
#[cfg(unix)]
const WORLD_READABLE_MODE: u32 = 0o644;

/// Who may read a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// This account alone (`0600`, and on Windows the owner-only labelled
    /// descriptor).
    OwnerOnly,
    /// Every account may read it; only this one may write it. A service's
    /// rendezvous record.
    WorldReadable,
}

/// Why a private file cannot be used.
#[derive(Debug)]
pub enum PrivateFileError {
    /// It could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Someone other than this account can read it, it is not this
    /// account's, or it is a link.
    Exposed(PathBuf, String),
}

impl std::fmt::Display for PrivateFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Exposed(path, why) => write!(
                f,
                "{} {why}; only this account may read it, so it is refused, not repaired",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PrivateFileError {}

/// The bytes of the private file at `path`, checked to be this account's
/// alone; `None` when there is none.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when it cannot be read;
/// [`PrivateFileError::Exposed`] when another account can read it, it is
/// not this account's, or it is a link.
pub fn read_private(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, PrivateFileError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PrivateFileError::Io(path.to_path_buf(), e)),
    };
    check_private(path)?;
    Ok(Some(bytes))
}

/// Write `bytes` to a new file at `path`, readable by this account alone,
/// created that way in one call. Refuses a path that already exists.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when the create or the write fails.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), PrivateFileError> {
    write_new(path, bytes, Access::OwnerOnly)
        .map_err(|error| PrivateFileError::Io(path.to_path_buf(), error))
}

/// Replace the file at `path` with `bytes`, readable by this account alone.
/// The bytes are the file's journal until the rename, so a reader sees the
/// old bytes or the new ones.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when a step fails.
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), PrivateFileError> {
    let journal = StagedWrite::create(path, bytes, Access::OwnerOnly)
        .map_err(|error| PrivateFileError::Io(staged_path(path), error))?;
    journal
        .commit()
        .map_err(|error| PrivateFileError::Io(path.to_path_buf(), error))
}

/// Whether only this account can read `path`: a file, not a link, owned by
/// this account, with no group or other access bits.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when it cannot be read;
/// [`PrivateFileError::Exposed`] otherwise.
#[cfg(unix)]
pub fn check_private(path: &Path) -> Result<(), PrivateFileError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| PrivateFileError::Io(path.to_path_buf(), e))?;
    let exposed = |why: String| Err(PrivateFileError::Exposed(path.to_path_buf(), why));
    if meta.file_type().is_symlink() {
        return exposed("is a symbolic link".to_owned());
    }
    let me = crate::effective_uid();
    if meta.uid() != me {
        return exposed(format!(
            "is owned by uid {}, not this account (uid {me})",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return exposed(format!("has mode {mode:04o}"));
    }
    Ok(())
}

/// Whether only this account can read `path`: its owner-only descriptor
/// and its no-read-up label.
///
/// # Errors
///
/// [`PrivateFileError::Exposed`] when it is not.
#[cfg(windows)]
pub fn check_private(path: &Path) -> Result<(), PrivateFileError> {
    shekyl_win_sec::rendezvous::check_owner_only_labelled(path)
        .map_err(|e| PrivateFileError::Exposed(path.to_path_buf(), e.to_string()))
}

/// Make `dir`'s entries durable.
///
/// # Errors
///
/// The directory could not be opened or synced.
#[cfg(unix)]
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Make `dir`'s entries durable. Windows has no directory handle to sync;
/// the rename is durable on its own once the file was.
///
/// # Errors
///
/// None on Windows; the Unix arm's signature.
#[cfg(windows)]
pub fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The journal a destination will be replaced from. Dropping it leaves the
/// journal: a crash between the write and the rename is what a later start
/// finishes, and deleting it here would erase that.
#[derive(Debug)]
pub struct StagedWrite {
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
    pub fn create(live: &Path, bytes: &[u8], access: Access) -> std::io::Result<Self> {
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
    pub fn commit(self) -> std::io::Result<()> {
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
    pub fn resume(live: &Path) -> std::io::Result<Self> {
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
    pub fn discard(self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.staged) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Where `live`'s journal is written.
#[must_use]
pub fn staged_path(live: &Path) -> PathBuf {
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
pub fn write_new(path: &Path, bytes: &[u8], access: Access) -> std::io::Result<()> {
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
fn create(path: &Path, access: Access) -> std::io::Result<File> {
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
fn create(path: &Path, access: Access) -> std::io::Result<File> {
    match access {
        // The owner-only, no-read-up descriptor a key file requires
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
    const CHILD_DIR: &str = "SHEKYL_PRIVATE_FILE_UMASK_CHILD_DIR";

    /// A world-readable file is readable by every account whatever the
    /// umask, and an owner-only one stays the owner's. The umask is the
    /// process's, so the writes run in a child of this test binary under
    /// umask 077. Red edit: drop the `set_permissions` in `create`, and the
    /// record published through its journal is 0600.
    #[test]
    fn the_mode_is_the_access_under_any_umask() {
        if let Some(dir) = std::env::var_os(CHILD_DIR) {
            let dir = PathBuf::from(dir);
            #[allow(unsafe_code, reason = "umask has no safe wrapper in std")]
            // SAFETY: no preconditions; this child runs one test on one thread.
            unsafe {
                libc::umask(0o077);
            }
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
                "private_file::tests::the_mode_is_the_access_under_any_umask",
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

    /// A private file is written owner-only and reads back; one another
    /// account can read is refused. Red edit: drop the mode test in
    /// `check_private`, and the 0640 file is read.
    #[test]
    fn a_private_file_is_the_accounts_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        assert!(read_private(&path).unwrap().is_none());
        write_private(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, OWNER_ONLY_MODE);
        assert_eq!(read_private(&path).unwrap().unwrap().as_slice(), b"secret");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_private(&path),
            Err(PrivateFileError::Exposed(..))
        ));
    }

    /// A replacement lands whole, private, over the old bytes, and leaves
    /// no journal.
    #[test]
    fn a_replacement_is_private_and_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        write_private(&path, b"old").unwrap();
        replace_private(&path, b"new").unwrap();
        assert_eq!(read_private(&path).unwrap().unwrap().as_slice(), b"new");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[cfg(test)]
mod resume_tests {
    use super::*;

    /// A journal a previous process left is the same writer: commit renames
    /// it over the live file, discard removes it, and a path that is not a
    /// file is not adopted. Red edit: make `resume` accept any path, and a
    /// symlink journal replaces the key.
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
