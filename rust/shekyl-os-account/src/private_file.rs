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
//! over it ([`StagedWrite`]), and [`StagedWrite::commit`] is the one place
//! that replaces a file (Rick, 2026-11-18). A reader sees the previous bytes
//! or the new ones. The staged file's name is the destination's file name
//! plus [`.new`](JOURNAL_SUFFIX), one rule for every caller, and what
//! becomes of it is its kind, in the type:
//!
//! - a [`Journal`] is named by a store transaction (the console key's), so
//!   it stays until the rename: a start resumes it ([`StagedWrite::resume`])
//!   and a failure never discards it;
//! - a [`Replace`] is named by nothing (a rendezvous record, the console
//!   leg's name, the bundle, a key file), so one left behind is removed
//!   when the next start writes that file again ([`StagedWrite::create`];
//!   each is written at every start that uses it), and a failed commit
//!   removes its own.
//!
//! **The wait.** On Windows a reader that holds the staged file open
//! without delete sharing (an antivirus scanner, a search indexer) fails
//! the rename's open with a sharing violation. [`StagedWrite::commit`]
//! retries that open, and nothing else, until [`REPLACE_WAIT`]; past it the
//! commit is [`CommitError::HeldOpen`]. No caller retries anything.
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
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Appended to a destination's file name to name its staged file.
const JOURNAL_SUFFIX: &str = ".new";

/// How long [`StagedWrite::commit`] waits for another program to let go of
/// the staged file, 2 s. That a wait exists is Rick's ruling (2026-11-18);
/// its length is this lane's **Assumption**. Basis: a reader
/// that opens a fresh file without delete sharing (Defender's real-time
/// scan, the Windows Search indexer, a backup agent) holds a file of a few
/// hundred bytes for a single read. The reproduction that found the hazard
/// held each staged file for 50 ms, and the wait is forty times that. A
/// reader that holds it longer is not scanning a fresh file; the start
/// refuses and names it ([`CommitError::HeldOpen`]). Re-derived when a
/// Windows host measures a scanner's hold.
pub const REPLACE_WAIT: Duration = Duration::from_secs(2);

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
    /// A service's console file. On Unix this is mode `0600`, which the
    /// owning account and the superuser can read. On Windows the owner may
    /// read and write it and BUILTIN\Administrators may read it, with the
    /// no-read-up label set in the creating call.
    Console,
}

/// Why a private file cannot be used.
#[derive(Debug)]
pub enum PrivateFileError {
    /// It could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Someone other than this account can read it, it is not this
    /// account's, or it is a link.
    Exposed(PathBuf, String),
    /// Another program held the staged file open past [`REPLACE_WAIT`].
    HeldOpen(HeldOpen),
}

impl From<CommitError> for PrivateFileError {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::HeldOpen(held) => Self::HeldOpen(held),
            CommitError::Io(path, error) => Self::Io(path, error),
        }
    }
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
            Self::HeldOpen(held) => held.fmt(f),
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
    read_checked(path, check_private)
}

/// The bytes of a service's console file at `path`: the owning account, or
/// an administrator of this machine ([`Access::Console`]). `None` when
/// there is none. A file another account can read is refused.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when it cannot be read;
/// [`PrivateFileError::Exposed`] when it is a link, another account can
/// read it, or the caller is neither its owner nor an administrator.
pub fn read_console(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, PrivateFileError> {
    read_checked(path, check_console)
}

fn read_checked(
    path: &Path,
    check: fn(&Path) -> Result<(), PrivateFileError>,
) -> Result<Option<Zeroizing<Vec<u8>>>, PrivateFileError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PrivateFileError::Io(path.to_path_buf(), e)),
    };
    check(path)?;
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
    replace(path, bytes, Access::OwnerOnly)
}

/// Replace the console file at `path` with `bytes` ([`Access::Console`]).
///
/// # Errors
///
/// [`PrivateFileError::Io`] when a step fails.
pub fn replace_console(path: &Path, bytes: &[u8]) -> Result<(), PrivateFileError> {
    replace(path, bytes, Access::Console)
}

fn replace(path: &Path, bytes: &[u8], access: Access) -> Result<(), PrivateFileError> {
    StagedWrite::<Replace>::create(path, bytes, access)?
        .commit()
        .map_err(PrivateFileError::from)
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
    check_unix(path, false)
}

/// Whether `path` is a service's console file this process may read: mode
/// `0600`, not a link, owned by this account or read by the superuser.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when it cannot be read;
/// [`PrivateFileError::Exposed`] otherwise.
#[cfg(unix)]
pub fn check_console(path: &Path) -> Result<(), PrivateFileError> {
    check_unix(path, true)
}

#[cfg(unix)]
fn check_unix(path: &Path, allow_superuser: bool) -> Result<(), PrivateFileError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| PrivateFileError::Io(path.to_path_buf(), e))?;
    let exposed = |why: String| Err(PrivateFileError::Exposed(path.to_path_buf(), why));
    if meta.file_type().is_symlink() {
        return exposed("is a symbolic link".to_owned());
    }
    let me = crate::effective_uid();
    let superuser = allow_superuser && me == 0;
    if meta.uid() != me && !superuser {
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

/// Whether `path` is a service's console file: protected, no-read-up, and
/// readable by its owner and by administrators of this machine.
///
/// # Errors
///
/// [`PrivateFileError::Exposed`] when it is not.
#[cfg(windows)]
pub fn check_console(path: &Path) -> Result<(), PrivateFileError> {
    shekyl_win_sec::rendezvous::check_console_labelled(path)
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

/// A staged file named by a store transaction (the console key's): it is
/// resumed at a start, and a failure never discards it.
#[derive(Debug)]
pub enum Journal {}

/// A staged file named by nothing (a rendezvous record, the console leg's
/// name, the bundle, a key file): one left behind is removed when the next
/// start writes the file again, and a failed commit removes its own.
#[derive(Debug)]
pub enum Replace {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Journal {}
    impl Sealed for super::Replace {}
}

/// What a staged file is: [`Journal`] or [`Replace`].
pub trait Kind: sealed::Sealed {
    /// Whether a failed commit removes the staged file.
    const REMOVED_ON_FAILURE: bool;
}

impl Kind for Journal {
    const REMOVED_ON_FAILURE: bool = false;
}

impl Kind for Replace {
    const REMOVED_ON_FAILURE: bool = true;
}

/// Another program held a staged file open past [`REPLACE_WAIT`], so it
/// could not be renamed over its destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldOpen {
    /// The file another program held: the staged file, or the live one.
    pub held: PathBuf,
    /// The file the replace was to write.
    pub live: PathBuf,
    /// Whether the held file may instead be one that is not writable: the
    /// classic rename (FAT32, exFAT) answers both with an access denial.
    pub or_unwritable: bool,
}

impl std::fmt::Display for HeldOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cause = if self.or_unwritable {
            "was held open by another program, or is not writable,"
        } else {
            "was held open by another program"
        };
        write!(
            f,
            "{} {cause} for more than {} s, so {} could not be replaced",
            self.held.display(),
            REPLACE_WAIT.as_secs(),
            self.live.display()
        )
    }
}

impl std::error::Error for HeldOpen {}

/// Why [`StagedWrite::commit`] failed.
#[derive(Debug)]
pub enum CommitError {
    /// Another program held the staged file open past [`REPLACE_WAIT`].
    HeldOpen(HeldOpen),
    /// A step failed, at this path.
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeldOpen(held) => held.fmt(f),
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<CommitError> for std::io::Error {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::HeldOpen(held) => std::io::Error::other(held),
            CommitError::Io(_, error) => error,
        }
    }
}

/// A file staged beside its destination, of kind `K`. Dropping it leaves
/// the staged file: a crash between the write and the rename leaves it
/// too, and the kind says what a later start does with it.
#[derive(Debug)]
pub struct StagedWrite<K: Kind> {
    staged: PathBuf,
    live: PathBuf,
    /// The one deadline the leftover's removal, the source's open and the
    /// rename share: [`REPLACE_WAIT`] from the start of the replace.
    deadline: Instant,
    kind: PhantomData<K>,
}

impl<K: Kind> StagedWrite<K> {
    /// Write `bytes` to the staged file of `live`, replacing one already
    /// there: for a [`Replace`], the one a crashed process left behind. A
    /// [`Journal`]'s is replaced only after the start's reconcile has
    /// committed or set aside what its store names. `live` itself is not
    /// touched.
    ///
    /// # Errors
    ///
    /// [`CommitError::HeldOpen`] when another program held a leftover
    /// staged file past [`REPLACE_WAIT`]; [`CommitError::Io`] when it could
    /// not be removed, or the new one created or written.
    pub fn create(live: &Path, bytes: &[u8], access: Access) -> Result<Self, CommitError> {
        let deadline = Instant::now() + REPLACE_WAIT;
        let staged = staged_path(live);
        remove_leftover(&staged, live, deadline)?;
        write_new(&staged, bytes, access)
            .map_err(|error| CommitError::Io(staged.clone(), error))?;
        Ok(Self {
            staged,
            live: live.to_path_buf(),
            deadline,
            kind: PhantomData,
        })
    }

    /// Rename the staged file over the destination, and make the rename
    /// durable. The one place a file is replaced: on Windows a reader that
    /// holds the staged file or the live one without delete sharing is
    /// waited for until the replace's one deadline, and nothing else is
    /// retried.
    ///
    /// # Errors
    ///
    /// [`CommitError::HeldOpen`] past the wait; [`CommitError::Io`] when the
    /// rename or the directory's sync failed. A [`Journal`] is left for a
    /// later start; a [`Replace`]'s staged file is removed, and a removal
    /// that fails too is left to the next start's [`StagedWrite::create`].
    pub fn commit(self) -> Result<(), CommitError> {
        if let Err(error) = rename_over(&self.staged, &self.live, self.deadline) {
            if K::REMOVED_ON_FAILURE {
                // The reader that held the rename may hold the removal too;
                // the next start's create is the cleanup that always runs.
                drop(remove_if_present(&self.staged));
            }
            return Err(error);
        }
        sync_dir(parent(&self.live)).map_err(|error| CommitError::Io(self.live.clone(), error))
    }
}

impl StagedWrite<Journal> {
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
            deadline: Instant::now() + REPLACE_WAIT,
            kind: PhantomData,
        })
    }

    /// Remove a journal a start found its store does not name. The
    /// destination is left as it is. Never a failure's response: a failed
    /// commit keeps its journal.
    ///
    /// # Errors
    ///
    /// The journal could not be removed.
    pub fn discard(self) -> std::io::Result<()> {
        remove_if_present(&self.staged)
    }
}

/// Remove `path`; absent is done.
fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Remove a leftover staged file before a new one is written.
#[cfg(unix)]
fn remove_leftover(staged: &Path, _live: &Path, _deadline: Instant) -> Result<(), CommitError> {
    remove_if_present(staged).map_err(|error| CommitError::Io(staged.to_path_buf(), error))
}

/// Remove a leftover staged file before a new one is written, waiting
/// until `deadline` for a reader that holds it
/// ([`shekyl_win_sec::replace::remove`]).
#[cfg(windows)]
fn remove_leftover(staged: &Path, live: &Path, deadline: Instant) -> Result<(), CommitError> {
    shekyl_win_sec::replace::remove(staged, deadline)
        .map_err(|error| windows_fault(error, staged, live))
}

/// Rename `staged` over `live`.
#[cfg(unix)]
fn rename_over(staged: &Path, live: &Path, _deadline: Instant) -> Result<(), CommitError> {
    std::fs::rename(staged, live).map_err(|error| CommitError::Io(live.to_path_buf(), error))
}

/// Rename `staged` over `live` through the one Windows file replace
/// ([`shekyl_win_sec::replace::replace`]), which waits until `deadline`
/// for a reader that holds either file.
#[cfg(windows)]
fn rename_over(staged: &Path, live: &Path, deadline: Instant) -> Result<(), CommitError> {
    shekyl_win_sec::replace::replace(staged, live, deadline)
        .map_err(|error| windows_fault(error, staged, live))
}

/// The commit's error for a Windows replace's, naming the file held.
#[cfg(windows)]
fn windows_fault(
    error: shekyl_win_sec::replace::ReplaceError,
    staged: &Path,
    live: &Path,
) -> CommitError {
    use shekyl_win_sec::replace::{Held, ReplaceError};
    match error {
        ReplaceError::HeldOpen(held) => CommitError::HeldOpen(HeldOpen {
            held: match held {
                Held::Staged => staged.to_path_buf(),
                Held::Live | Held::LiveOrUnwritable => live.to_path_buf(),
            },
            live: live.to_path_buf(),
            or_unwritable: held == Held::LiveOrUnwritable,
        }),
        ReplaceError::Io(error) => CommitError::Io(live.to_path_buf(), error),
    }
}

/// Where `live`'s staged file is written.
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
        Access::OwnerOnly | Access::Console => OWNER_ONLY_MODE,
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
        Access::Console => {
            shekyl_win_sec::rendezvous::create_console_file(path).map_err(std::io::Error::other)
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
            StagedWrite::<Replace>::create(&dir.join("record"), b"public", Access::WorldReadable)
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

    /// The superuser reads a service-owned console file. Another account's
    /// mode `0600` file is refused to anyone else, and a mode that admits
    /// the group is refused to the superuser too. Red edit: drop
    /// `allow_superuser` in `check_unix`, and this read fails.
    #[test]
    fn an_administrator_reads_a_service_owned_console_file() {
        if crate::effective_uid() != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc-console.key");
        write_private(&path, b"console").unwrap();
        std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
        assert!(
            read_private(&path).is_err(),
            "a personal key stays this account's"
        );
        assert_eq!(read_console(&path).unwrap().unwrap().as_slice(), b"console");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_console(&path),
            Err(PrivateFileError::Exposed(..))
        ));
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

/// Each kind across a crash, planted as a crash leaves it: the staged file
/// written beside a live one, with no process to commit it.
#[cfg(test)]
mod crash_tests {
    use super::*;

    /// A failed commit, every platform: the destination is a directory
    /// with an entry, which no rename replaces.
    fn unreplaceable(live: &Path) {
        std::fs::create_dir(live).unwrap();
        std::fs::write(live.join("entry"), b"x").unwrap();
    }

    /// A journal left by a crash is resumed and committed at the next
    /// start, and a commit that fails keeps it for the start after. Red
    /// edit: make `Journal::REMOVED_ON_FAILURE` true, and the console key a
    /// store transaction already names is lost.
    #[test]
    fn a_journal_survives_a_crash_and_a_failed_commit() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("rpc-console.key");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(staged_path(&live), b"new").unwrap();
        StagedWrite::<Journal>::resume(&live)
            .expect("the crash's journal")
            .commit()
            .expect("the rename");
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path(&live).exists());

        let blocked = dir.path().join("blocked");
        unreplaceable(&blocked);
        std::fs::write(staged_path(&blocked), b"named").unwrap();
        let failed = StagedWrite::<Journal>::resume(&blocked).unwrap().commit();
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read(staged_path(&blocked)).unwrap(),
            b"named",
            "a failed commit keeps its journal"
        );
    }

    /// A replace left by a crash is removed by the next start's write and
    /// never becomes the live file; a commit that fails removes its own.
    /// Red edit: make `Replace::REMOVED_ON_FAILURE` false, and a failed
    /// publish leaves its `.new` behind, as the Windows rendezvous did.
    #[test]
    fn a_replace_is_cleared_after_a_crash_and_removed_when_its_commit_fails() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"live").unwrap();
        std::fs::write(staged_path(&live), b"left behind").unwrap();
        StagedWrite::<Replace>::create(&live, b"next start", Access::WorldReadable)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"next start");
        assert!(!staged_path(&live).exists());

        let blocked = dir.path().join("blocked");
        unreplaceable(&blocked);
        let failed = StagedWrite::<Replace>::create(&blocked, b"new", Access::OwnerOnly)
            .unwrap()
            .commit();
        assert!(matches!(failed, Err(CommitError::Io(..))), "{failed:?}");
        assert!(
            !staged_path(&blocked).exists(),
            "a failed commit removes its own staged file"
        );
    }
}

/// The wait on Windows: a reader of the staged file without delete sharing
/// (a scanner, an indexer) is waited for, and one that outstays the wait is
/// [`CommitError::HeldOpen`].
#[cfg(all(test, windows))]
mod wait_tests {
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::Instant;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    use super::*;

    /// Open `path` as a scanner does, sharing read alone, and keep it open
    /// for `hold` on another thread. Returns once the file is held.
    fn hold(path: &Path, hold: Duration) -> std::thread::JoinHandle<()> {
        hold_sharing(path, hold, FILE_SHARE_READ)
    }

    /// [`hold`], sharing `share`.
    fn hold_sharing(path: &Path, hold: Duration, share: u32) -> std::thread::JoinHandle<()> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(share)
            .open(path)
            .unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(hold);
            drop(file);
        })
    }

    /// A reader that lets go within the wait does not fail the commit, and
    /// leaves no staged file. Red edit: drop the retry, and the commit is a
    /// sharing violation (the Windows rendezvous's os error 32).
    #[test]
    fn a_reader_shorter_than_the_wait_is_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let staged = StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable).unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT / 10);
        staged.commit().expect("the reader let go within the wait");
        reader.join().unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path(&live).exists());
    }

    /// A reader that outstays the wait is `HeldOpen`, after the wait and
    /// not before; the next start's write replaces what was left. Red edit: return the sharing
    /// violation as `Io`, and the start's refusal blames the directory.
    #[test]
    fn a_reader_past_the_wait_is_held_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged = StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable).unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT * 2);
        let began = Instant::now();
        let failed = staged.commit();
        assert!(began.elapsed() >= REPLACE_WAIT);
        assert!(
            matches!(&failed, Err(CommitError::HeldOpen(held)) if held.held == staged_path(&live)),
            "{failed:?}"
        );
        reader.join().unwrap();
        // The removal on failure ran while the reader still held the file,
        // so the next start's write is what clears it.
        StagedWrite::<Replace>::create(&live, b"next start", Access::WorldReadable)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"next start");
        assert!(!staged_path(&live).exists());
    }

    /// A reader of the destination does not hold the commit: the rename
    /// moves the name and the reader keeps the old bytes (POSIX
    /// semantics). Red edit: commit through `std::fs::rename`, and a
    /// destination read without delete sharing fails it.
    #[test]
    fn a_reader_of_the_destination_does_not_hold_the_commit() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let reader = hold_sharing(
            &live,
            REPLACE_WAIT / 2,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        );
        StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable)
            .unwrap()
            .commit()
            .expect("the destination's reader does not hold the rename");
        reader.join().unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
    }

    /// A leftover staged file a reader holds at the next start is waited
    /// for within the replace's deadline, and past it is `HeldOpen` naming
    /// the staged file. Red edit: remove the leftover with a bare
    /// `remove_file`, and a scanner holding it fails the start at once.
    #[test]
    fn a_held_leftover_is_waited_for_and_past_the_wait_named() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(staged_path(&live), b"left behind").unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT / 4);
        StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable)
            .expect("the leftover's reader let go within the wait")
            .commit()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");

        std::fs::write(staged_path(&live), b"left behind").unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT * 2);
        let failed = StagedWrite::<Replace>::create(&live, b"newer", Access::WorldReadable);
        assert!(
            matches!(&failed, Err(CommitError::HeldOpen(held)) if held.held == staged_path(&live)),
            "{failed:?}"
        );
        reader.join().unwrap();
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"new",
            "the live file is untouched"
        );
    }

    /// A reader that holds the live file without delete sharing fails the
    /// rename with a sharing violation (measured 2026-11-18). One that lets
    /// go within the deadline is waited for and the commit lands; one that
    /// outstays it is `HeldOpen` naming the live file, which keeps its old
    /// bytes. Red edit: return the rename's sharing violation at once, and
    /// a scanner reading the published record fails the next start.
    #[test]
    fn a_destination_held_without_delete_sharing_is_waited_for_and_past_the_wait_named() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let staged = StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable).unwrap();
        let reader = hold(&live, REPLACE_WAIT / 4);
        staged
            .commit()
            .expect("the live file's reader let go within the wait");
        reader.join().unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");

        let staged =
            StagedWrite::<Replace>::create(&live, b"newer", Access::WorldReadable).unwrap();
        let reader = hold(&live, REPLACE_WAIT * 2);
        let failed = staged.commit();
        assert!(
            matches!(&failed, Err(CommitError::HeldOpen(held)) if held.held == live),
            "{failed:?}"
        );
        reader.join().unwrap();
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"new",
            "the live file keeps its bytes"
        );
        assert!(
            !staged_path(&live).exists(),
            "the failed replace removed its own staged file"
        );
    }
}
