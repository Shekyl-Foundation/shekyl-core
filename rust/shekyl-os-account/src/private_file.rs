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
//! plus `.new`, one rule for every caller, and what
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
//! **The creating handle on Windows** (Rick, 2026-11-18). A staged file
//! this process writes is created write-through, with its descriptor, and
//! held by that one handle until the commit has renamed it, flushed it and
//! closed it (`shekyl_win_sec::replace::Staged`). Another program that
//! opens it without delete sharing (an antivirus scanner, a search indexer)
//! fails its own open while the handle is held, so the commit never waits
//! on the staged file. It waits, until [`REPLACE_WAIT`], only on a reader
//! that holds the live file, and on a leftover staged file being removed;
//! a journal a previous process left ([`StagedWrite::resume`]) is reopened
//! for its rename, and that open waits too. Past the wait the commit is
//! [`CommitError::HeldOpen`]. A live file whose read-only attribute is set
//! refuses the rename at once, [`CommitError::ReadOnly`], which no wait
//! changes (Rick, 2026-11-19). No caller retries anything.
//!
//! **Durable at each step.** A new file's bytes are synced, and then its
//! directory, before [`write_new`] returns. On Unix a rename is followed by
//! a sync of its directory before [`StagedWrite::commit`] returns, and a
//! commit that returns is [`Durability::Durable`]. Windows has no directory
//! to sync ([`sync_dir`]): the rename is a request on the write-through
//! handle, which NTFS documents flushing with it, and the commit reports
//! [`Durability::Durable`] only on a local NTFS volume, on the POSIX rename,
//! with the flush after the rename returned; a network drive whatever file
//! system it reports, any other file system, and a resumed journal
//! (reopened, not write-through), is [`Durability::Unconfirmed`] with its
//! reason (`shekyl_win_sec::replace`'s module docs cite the documentation).
//! A store transaction that names a journal (the console key's) therefore
//! never outlives the journal across a power loss.
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

/// How long a replace waits for another program to let go of a file it
/// needs (a leftover staged file, a resumed journal, the live file), 2 s. That a wait exists is Rick's ruling (2026-11-18);
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

/// The mode a plain create asks for, which the umask then narrows.
#[cfg(unix)]
const DEFAULT_CREATE_MODE: u32 = 0o666;

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
    /// This account's own file, mode `0600` on Unix like [`Self::OwnerOnly`];
    /// on Windows the directory's inherited ACL, where `OwnerOnly` sets an
    /// owner-only descriptor and the no-read-up label. A wallet's files and
    /// its preferences, whose protection on Windows is the profile folder's
    /// (a conversion changes no file's protection; Rick, 2026-11-18).
    Private,
    /// What a plain create gives: the mode the umask leaves on Unix, the
    /// inherited ACL on Windows. The data directory's marker, the dialer's
    /// address store, the vanguard state and the rebaseline traces.
    Default,
}

/// What another program may do with a staged file while this process
/// holds it, between its create and its commit. Windows alone enforces it,
/// on the creating handle; on Unix nothing does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Sharing {
    /// Read it, and nothing else: the default, every staged file but one.
    /// Delete is not shared because the creating handle holds delete
    /// access to rename the file, and write is not shared because no other
    /// writer has any business in a file this process is about to rename
    /// into place (Rick, 2026-11-18).
    #[default]
    Read,
    /// Read and write it. Only the wallet's keys file during password
    /// rotation (`shekyl-engine-file`'s `atomic_write_file_with`): its hook
    /// locks the staged file through a second handle, opened for reading
    /// and writing, before the rename, so the keys-file lock follows the
    /// file the path is about to name. Read sharing alone refuses that
    /// open. Delete is still not shared.
    ReadWrite,
}

/// What [`replace`] did.
#[derive(Debug)]
pub enum Replaced {
    /// The live file already held exactly these bytes and passed its
    /// reader's access check: nothing was staged, nothing renamed.
    Unchanged,
    /// The bytes were staged and renamed into place, with this durability.
    Written(Durability),
}

/// Whether a commit's rename is known to survive a power loss.
#[derive(Debug)]
pub enum Durability {
    /// On Unix the rename and its directory's sync; on Windows NTFS, the
    /// POSIX rename through the write-through creating handle, and the
    /// flush after it (module docs).
    Durable,
    /// The rename landed; that it survives a power loss is not confirmed.
    Unconfirmed(Unconfirmed),
}

/// Why a rename that landed is not reported durable. Windows alone gives
/// these: on Unix a failed directory sync is [`CommitError::Unsynced`].
#[derive(Debug)]
pub enum Unconfirmed {
    /// The volume is a network drive, which is never durable whatever file
    /// system it reports (Rick, 2026-11-19): this is the name it reports.
    Remote(String),
    /// The volume's file system is not NTFS: this is its name (`FAT32`,
    /// `exFAT`, `ReFS`, ...).
    FileSystem(String),
    /// The volume is local and NTFS, but it refused the POSIX rename and
    /// the classic one renamed the file.
    ClassicRename,
    /// The flush after the rename failed.
    Flush(std::io::Error),
    /// The volume could not be queried, for its device or its file system.
    VolumeUnread(std::io::Error),
    /// A journal a previous process left, renamed through a handle reopened
    /// on it, which is not write-through.
    Reopened,
}

impl Unconfirmed {
    /// The volume's file system, when that is the reason.
    #[must_use]
    pub fn file_system(&self) -> Option<&str> {
        match self {
            Self::FileSystem(name) => Some(name),
            Self::Remote(_)
            | Self::ClassicRename
            | Self::Flush(_)
            | Self::VolumeUnread(_)
            | Self::Reopened => None,
        }
    }
}

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(name) => write!(
                f,
                "the volume is a network drive (it reports {name}), where no replace is \
                 confirmed to survive a power loss"
            ),
            Self::FileSystem(name) => write!(
                f,
                "the volume is {name}, where Windows does not confirm that a replaced file \
                 survives a power loss; only NTFS does"
            ),
            Self::ClassicRename => f.write_str(
                "the volume refused the rename that keeps a file's readers working, so the \
                 replace was not confirmed",
            ),
            Self::Flush(error) => write!(f, "the flush after the rename failed: {error}"),
            Self::VolumeUnread(error) => {
                write!(f, "the volume could not be queried: {error}")
            }
            Self::Reopened => f.write_str(
                "a file left by an earlier start was renamed through a handle that does not \
                 write through",
            ),
        }
    }
}

/// Why a private file cannot be used.
#[derive(Debug)]
pub enum PrivateFileError {
    /// It could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Someone other than this account can read it, it is not this
    /// account's, or it is a link.
    Exposed(PathBuf, String),
    /// Another program held a file the replace needs open past
    /// [`REPLACE_WAIT`].
    HeldOpen(HeldOpen),
    /// The file's read-only attribute is set, and the replace was refused
    /// for it (Windows).
    ReadOnly(PathBuf),
}

impl From<CommitError> for PrivateFileError {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::HeldOpen(held) => Self::HeldOpen(held),
            CommitError::ReadOnly(path) => Self::ReadOnly(path),
            CommitError::Io { path, error, .. } | CommitError::Unsynced(path, error) => {
                Self::Io(path, error)
            }
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
            Self::ReadOnly(path) => read_only(f, path),
        }
    }
}

impl std::error::Error for PrivateFileError {}

/// The sentence for a live file whose read-only attribute refused its
/// replace.
fn read_only(f: &mut std::fmt::Formatter<'_>, path: &Path) -> std::fmt::Result {
    write!(
        f,
        "{} is read-only, so it could not be replaced",
        path.display()
    )
}

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
/// [`replace`] tells whether the file was written, and with what
/// durability.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when a step fails.
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<Replaced, PrivateFileError> {
    Ok(replace(path, bytes, Access::OwnerOnly)?)
}

/// Replace the console file at `path` with `bytes` ([`Access::Console`]),
/// and say whether it was written, and with what durability, as
/// [`replace`] does.
///
/// # Errors
///
/// [`PrivateFileError::Io`] when a step fails.
pub fn replace_console(path: &Path, bytes: &[u8]) -> Result<Replaced, PrivateFileError> {
    Ok(replace(path, bytes, Access::Console)?)
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

/// Does nothing on Windows: Windows documents no user-mode flush of a
/// directory (`FlushFileBuffers` takes a file, or a volume with
/// administrative rights), so a rename's durability is not settled here
/// but in the one Windows replace, `shekyl_win_sec::replace`.
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

/// Another program held a staged file or the live one open past
/// [`REPLACE_WAIT`], so the staged file could not be renamed over its
/// destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldOpen {
    /// The file another program held: the staged file, or the live one.
    pub held: PathBuf,
    /// The file the replace was to write.
    pub live: PathBuf,
}

impl std::fmt::Display for HeldOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} was held open by another program for more than {} s, so {} could not be replaced",
            self.held.display(),
            REPLACE_WAIT.as_secs(),
            self.live.display()
        )
    }
}

impl std::error::Error for HeldOpen {}

/// The step of a replace that failed with the disk's error
/// ([`CommitError::Io`]). The steps after a rename lands are not failures:
/// they are the [`Durability`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Removing a leftover staged file, or creating, writing or syncing
    /// the new one.
    Write,
    /// Syncing the staged file's directory before the rename (Unix).
    FolderSync,
    /// The rename over the live file.
    Rename,
}

impl Step {
    /// The step's name, as the wallet RPC's `data.step` spells it (Rick,
    /// 2026-11-19).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::FolderSync => "folder-sync",
            Self::Rename => "rename",
        }
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why [`StagedWrite::create`] or [`StagedWrite::commit`] failed.
#[derive(Debug)]
pub enum CommitError {
    /// Another program held a file the replace needs (a leftover or resumed
    /// staged file, or the live one) open past [`REPLACE_WAIT`].
    HeldOpen(HeldOpen),
    /// The live file's read-only attribute is set, and the rename was
    /// refused for it at once (Windows; Rick, 2026-11-19). The live file is
    /// untouched.
    ReadOnly(PathBuf),
    /// `step` failed, at `path`.
    Io {
        /// The step that failed.
        step: Step,
        /// The file the step was on.
        path: PathBuf,
        /// The disk's error.
        error: std::io::Error,
    },
    /// The rename landed, but the directory's sync after it failed: the
    /// new file is in place, its survival of an immediate crash
    /// unconfirmed.
    Unsynced(PathBuf, std::io::Error),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeldOpen(held) => held.fmt(f),
            Self::ReadOnly(path) => read_only(f, path),
            Self::Io { path, error, .. } => write!(f, "{}: {error}", path.display()),
            Self::Unsynced(path, error) => write!(
                f,
                "{} was replaced, but its directory could not be synced: {error}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<CommitError> for std::io::Error {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::HeldOpen(held) => std::io::Error::other(held),
            CommitError::ReadOnly(path) => std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is read-only, so it could not be replaced",
                    path.display()
                ),
            ),
            CommitError::Io { error, .. } | CommitError::Unsynced(_, error) => error,
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
    /// The creating handle, write-through, held until the commit closes it;
    /// `None` for a journal a previous process left ([`Self::resume`]).
    #[cfg(windows)]
    handle: Option<shekyl_win_sec::replace::Staged>,
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
    /// not be removed, or the new one created, written or synced, with its
    /// [`Step`].
    pub fn create(live: &Path, bytes: &[u8], access: Access) -> Result<Self, CommitError> {
        Self::create_with(live, bytes, access, Sharing::Read)
    }

    /// [`Self::create`], the staged file shared with other programs as
    /// `sharing` says until the commit. Every caller but the wallet's
    /// password rotation uses [`Self::create`], which shares read only
    /// ([`Sharing`]).
    ///
    /// # Errors
    ///
    /// Exactly [`Self::create`]'s.
    pub fn create_with(
        live: &Path,
        bytes: &[u8],
        access: Access,
        sharing: Sharing,
    ) -> Result<Self, CommitError> {
        let deadline = Instant::now() + REPLACE_WAIT;
        let staged = staged_path(live);
        remove_leftover(&staged, live, deadline)?;
        let failed = |step: Step| {
            let path = staged.clone();
            move |error| CommitError::Io { step, path, error }
        };
        #[cfg(unix)]
        {
            // Unix has no sharing modes: any process this account runs may
            // open the staged file, as it may any of this account's files.
            let _: Sharing = sharing;
            let mut file = create(&staged, access).map_err(failed(Step::Write))?;
            file.write_all(bytes).map_err(failed(Step::Write))?;
            file.sync_all().map_err(failed(Step::Write))?;
            sync_dir(parent(&staged)).map_err(failed(Step::FolderSync))?;
        }
        #[cfg(windows)]
        let handle = write_staged(&staged, bytes, access, sharing).map_err(failed(Step::Write))?;
        Ok(Self {
            staged,
            live: live.to_path_buf(),
            deadline,
            #[cfg(windows)]
            handle: Some(handle),
            kind: PhantomData,
        })
    }

    /// Rename the staged file over the destination, and make the rename
    /// durable where the platform can say so. The one place a file is
    /// replaced: on Windows a reader that holds the live file without
    /// delete sharing is waited for until the replace's one deadline (and,
    /// for a resumed journal, one that holds the journal), and nothing else
    /// is retried.
    ///
    /// # Errors
    ///
    /// [`CommitError::HeldOpen`] past the wait; [`CommitError::ReadOnly`]
    /// when the live file's read-only attribute refused the rename;
    /// [`CommitError::Io`] when the rename failed ([`Step::Rename`]);
    /// [`CommitError::Unsynced`] when the directory's sync
    /// after it failed (Unix). A [`Journal`] is left for a later start; a
    /// [`Replace`]'s staged file is removed, and a removal that fails too is
    /// left to the next start's [`StagedWrite::create`]. What happens after
    /// a Windows rename lands is never an error: it is the [`Durability`].
    pub fn commit(self) -> Result<Durability, CommitError> {
        #[cfg(windows)]
        if let Some(handle) = self.handle {
            use shekyl_win_sec::replace::OnFailure;
            let on_failure = if K::REMOVED_ON_FAILURE {
                OnFailure::Remove
            } else {
                OnFailure::Keep
            };
            return handle
                .commit(&self.live, self.deadline, on_failure)
                .map(durability_of)
                .map_err(|error| windows_fault(error, &self.staged, &self.live, Step::Rename));
        }
        if let Err(error) = rename_over(&self.staged, &self.live, self.deadline) {
            if K::REMOVED_ON_FAILURE {
                // The reader that held the rename may hold the removal too;
                // the next start's create is the cleanup that always runs.
                drop(remove_if_present(&self.staged));
            }
            return Err(error);
        }
        #[cfg(windows)]
        {
            Ok(Durability::Unconfirmed(Unconfirmed::Reopened))
        }
        #[cfg(unix)]
        {
            sync_dir(parent(&self.live))
                .map(|()| Durability::Durable)
                .map_err(|error| CommitError::Unsynced(self.live.clone(), error))
        }
    }

    /// Remove the staged file without renaming it; the destination is left
    /// as it is. On Windows a staged file this process created is deleted
    /// through its creating handle.
    ///
    /// # Errors
    ///
    /// The staged file could not be removed.
    pub fn discard(self) -> std::io::Result<()> {
        #[cfg(windows)]
        if let Some(handle) = self.handle {
            return handle.discard();
        }
        remove_if_present(&self.staged)
    }
}

impl StagedWrite<Journal> {
    /// Adopt the journal a previous process left beside `live`.
    ///
    /// The bytes are not rewritten. [`Self::commit`] renames the journal
    /// over `live` and syncs the directory (on Windows through a handle
    /// reopened on it, reported [`Unconfirmed::Reopened`]); [`Self::discard`]
    /// removes it, which a start does to a journal its store does not name.
    /// Never a failure's response: a failed commit keeps its journal.
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
            #[cfg(windows)]
            handle: None,
            kind: PhantomData,
        })
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
    remove_if_present(staged).map_err(|error| CommitError::Io {
        step: Step::Write,
        path: staged.to_path_buf(),
        error,
    })
}

/// Remove a leftover staged file before a new one is written, waiting
/// until `deadline` for a reader that holds it
/// ([`shekyl_win_sec::replace::remove`]).
#[cfg(windows)]
fn remove_leftover(staged: &Path, live: &Path, deadline: Instant) -> Result<(), CommitError> {
    shekyl_win_sec::replace::remove(staged, deadline)
        .map_err(|error| windows_fault(error, staged, live, Step::Write))
}

/// Rename `staged` over `live`.
#[cfg(unix)]
// CLIPPY: disallowed_methods — this is the one Unix file replace.
#[allow(
    clippy::disallowed_methods,
    reason = "the one Unix file replace: rename(2) over the destination, which every replace in the tree goes through (Rick, 2026-11-18)"
)]
fn rename_over(staged: &Path, live: &Path, _deadline: Instant) -> Result<(), CommitError> {
    std::fs::rename(staged, live).map_err(|error| CommitError::Io {
        step: Step::Rename,
        path: live.to_path_buf(),
        error,
    })
}

/// Rename a resumed journal `staged` over `live` through the one Windows
/// file replace's reopening path ([`shekyl_win_sec::replace::replace`]),
/// which waits until `deadline` for a reader that holds either file.
#[cfg(windows)]
fn rename_over(staged: &Path, live: &Path, deadline: Instant) -> Result<(), CommitError> {
    shekyl_win_sec::replace::replace(staged, live, deadline)
        .map_err(|error| windows_fault(error, staged, live, Step::Rename))
}

/// A Windows commit's durability, in this module's terms.
#[cfg(windows)]
fn durability_of(durability: shekyl_win_sec::replace::Durability) -> Durability {
    use shekyl_win_sec::replace::{Durability as Win, Unconfirmed as Why};
    match durability {
        Win::Durable => Durability::Durable,
        Win::Unconfirmed(why) => Durability::Unconfirmed(match why {
            Why::Remote(name) => Unconfirmed::Remote(name),
            Why::FileSystem(name) => Unconfirmed::FileSystem(name),
            Why::ClassicRename => Unconfirmed::ClassicRename,
            Why::Flush(error) => Unconfirmed::Flush(error),
            Why::VolumeUnread(error) => Unconfirmed::VolumeUnread(error),
        }),
    }
}

/// Create the staged file `path` through the write-through creating handle
/// with `access`'s descriptor and `sharing`, write `bytes` through it and
/// flush them.
#[cfg(windows)]
fn write_staged(
    path: &Path,
    bytes: &[u8],
    access: Access,
    sharing: Sharing,
) -> std::io::Result<shekyl_win_sec::replace::Staged> {
    use shekyl_win_sec::replace::{StagedDescriptor, StagedSharing};
    let descriptor = match access {
        // The owner-only, no-read-up descriptor a key file requires
        // (RT-O34), set in the creating call.
        Access::OwnerOnly => StagedDescriptor::RendezvousFile,
        Access::Console => StagedDescriptor::ConsoleFile,
        Access::WorldReadable | Access::Private | Access::Default => StagedDescriptor::Inherited,
    };
    let sharing = match sharing {
        Sharing::Read => StagedSharing::Read,
        Sharing::ReadWrite => StagedSharing::ReadWrite,
    };
    let staged = shekyl_win_sec::replace::create_staged_with(path, descriptor, sharing)?;
    let mut file = staged.file();
    file.write_all(bytes)?;
    staged.sync()?;
    Ok(staged)
}

/// The commit's error for a Windows replace's at `step`, naming the file
/// held.
#[cfg(windows)]
fn windows_fault(
    error: shekyl_win_sec::replace::ReplaceError,
    staged: &Path,
    live: &Path,
    step: Step,
) -> CommitError {
    use shekyl_win_sec::replace::{Held, ReplaceError};
    match error {
        ReplaceError::HeldOpen(held) => CommitError::HeldOpen(HeldOpen {
            held: match held {
                Held::Staged => staged.to_path_buf(),
                Held::Live => live.to_path_buf(),
            },
            live: live.to_path_buf(),
        }),
        ReplaceError::ReadOnly => CommitError::ReadOnly(live.to_path_buf()),
        ReplaceError::Io(error) => CommitError::Io {
            step,
            path: match step {
                Step::Rename => live.to_path_buf(),
                Step::Write | Step::FolderSync => staged.to_path_buf(),
            },
            error,
        },
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
        Access::OwnerOnly | Access::Console | Access::Private => OWNER_ONLY_MODE,
        Access::WorldReadable => WORLD_READABLE_MODE,
        // The umask decides, as a plain create's does.
        Access::Default => {
            return std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(DEFAULT_CREATE_MODE)
                .open(path);
        }
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
        Access::WorldReadable | Access::Private | Access::Default => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path),
    }
}

/// Whether `path` passes the access check its readers make for `access`:
/// a regular file, not a link, of this account, with the mode its kind
/// gives. A file that fails is rewritten, which restores its protection.
#[cfg(unix)]
fn holds_access(path: &Path, access: Access) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match access {
        Access::OwnerOnly => check_private(path).is_ok(),
        Access::Console => check_console(path).is_ok(),
        Access::WorldReadable | Access::Private | Access::Default => {
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return false;
            };
            let mode = meta.permissions().mode() & 0o777;
            meta.file_type().is_file()
                && meta.uid() == crate::effective_uid()
                && match access {
                    Access::WorldReadable => mode == WORLD_READABLE_MODE,
                    Access::Private => mode & 0o077 == 0,
                    _ => true,
                }
        }
    }
}

/// Whether `path` passes the access check its readers make for `access`:
/// the labelled descriptors for a key and the console, and for the rest a
/// regular file that nobody but this account and the platform's own
/// principals may write.
#[cfg(windows)]
fn holds_access(path: &Path, access: Access) -> bool {
    match access {
        Access::OwnerOnly => check_private(path).is_ok(),
        Access::Console => check_console(path).is_ok(),
        Access::WorldReadable | Access::Private | Access::Default => {
            std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
                && shekyl_win_sec::dacl::write_grantees(path).is_ok_and(|grantees| {
                    grantees
                        .iter()
                        .all(|g| *g == shekyl_win_sec::dacl::Grantee::Permitted)
                })
        }
    }
}

/// The bytes of `live` when it is a regular file, read through a handle
/// that never blocks and is checked before a byte is read: on Unix the
/// open is non-blocking and does not follow a link, so a FIFO with no
/// writer, a device or a link at the destination is "not unchanged" at
/// once, and the staged rename replaces that entry as it would any other
/// (Copilot, #1439: a FIFO at a rebaseline output hung the comparison).
fn read_regular(live: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let mut file = opts.open(live).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut held = Vec::new();
    file.read_to_end(&mut held).ok()?;
    Some(held)
}

/// Replace the file at `live` with `bytes`, as `access` gives: the one
/// replace path (Rick, 2026-11-18). A live file that already holds exactly
/// these bytes and passes its reader's access check is left alone: no
/// staged file, no rename. One that matches in bytes but fails the check
/// is replaced, which restores its protection.
///
/// An unchanged file still has its directory synced, so a skip never
/// leaves an earlier rename of the same bytes unsynced (Rick, 2026-11-18).
/// A written one reports its commit's [`Durability`].
///
/// **Not the wallet's path** (Rick, 2026-11-18). The wallet's files are
/// written through [`StagedWrite`] directly, never skipped: its save
/// reports `Durability::Confirmed`, which authorises a broadcast, and a
/// skip after an earlier same-bytes write whose directory sync failed would
/// report that write confirmed without making it so; and the skip's
/// comparison would read the sealed wallet file into a buffer nothing wipes
/// on every save.
///
/// # Errors
///
/// [`CommitError`], as [`StagedWrite::create`] and [`StagedWrite::commit`];
/// [`CommitError::Unsynced`] when an unchanged file's directory could not
/// be synced.
pub fn replace(live: &Path, bytes: &[u8], access: Access) -> Result<Replaced, CommitError> {
    let unchanged = read_regular(live).is_some_and(|held| held == bytes);
    if unchanged && holds_access(live, access) {
        sync_dir(parent(live)).map_err(|error| CommitError::Unsynced(live.to_path_buf(), error))?;
        return Ok(Replaced::Unchanged);
    }
    let durability = StagedWrite::<Replace>::create(live, bytes, access)?.commit()?;
    Ok(Replaced::Written(durability))
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

    /// A replace whose live file already holds the bytes and passes its
    /// access check touches nothing: no staged file, the same inode, the
    /// same modification time. Red edit: drop the unchanged check in
    /// `replace`, and the second write stages and renames a new inode.
    #[test]
    fn an_unchanged_rewrite_touches_nothing() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("rpc-channel.bundle");
        assert!(matches!(
            replace(&live, b"bundle", Access::Console).unwrap(),
            Replaced::Written(Durability::Durable)
        ));
        let before = std::fs::metadata(&live).unwrap();
        assert!(matches!(
            replace(&live, b"bundle", Access::Console).unwrap(),
            Replaced::Unchanged
        ));
        let after = std::fs::metadata(&live).unwrap();
        assert_eq!(before.ino(), after.ino(), "the file was not replaced");
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert!(!staged_path(&live).exists());
        assert!(matches!(
            replace(&live, b"changed", Access::Console).unwrap(),
            Replaced::Written(_)
        ));
        assert_eq!(std::fs::read(&live).unwrap(), b"changed");
    }

    /// A FIFO with no writer at the destination is replaced by a regular
    /// file at once: the unchanged-write comparison opens non-blocking and
    /// reads only a regular file. Red edit: compare through a plain
    /// `std::fs::read`, and the replace blocks on the FIFO until this
    /// test's deadline (Copilot, #1439, a FIFO at a rebaseline output).
    #[test]
    fn a_fifo_at_the_destination_is_replaced_without_blocking() {
        use std::os::unix::fs::FileTypeExt;
        const WITHIN: std::time::Duration = std::time::Duration::from_secs(10);
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("trace.bin");
        let live_c = std::ffi::CString::new(live.to_str().unwrap()).unwrap();
        #[allow(unsafe_code, reason = "mkfifo has no safe wrapper in std")]
        // SAFETY: `live_c` is a NUL-terminated path; mkfifo only reads it.
        let made = unsafe { libc::mkfifo(live_c.as_ptr(), 0o600) };
        assert_eq!(made, 0, "the FIFO");
        let (done, finished) = std::sync::mpsc::channel();
        let target = live.clone();
        std::thread::spawn(move || {
            drop(done.send(replace(&target, b"trace", Access::Default)));
        });
        let replaced = finished
            .recv_timeout(WITHIN)
            .expect("the replace hung on the FIFO")
            .expect("the replace");
        assert!(matches!(replaced, Replaced::Written(_)), "{replaced:?}");
        assert!(!std::fs::symlink_metadata(&live)
            .unwrap()
            .file_type()
            .is_fifo());
        assert_eq!(std::fs::read(&live).unwrap(), b"trace");
    }

    /// A file whose bytes match but whose mode was loosened is replaced,
    /// which restores the mode. Red edit: skip on the bytes alone, and the
    /// key stays readable by the group.
    #[test]
    fn a_loosened_mode_with_unchanged_bytes_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("key");
        replace(&live, b"secret", Access::OwnerOnly).unwrap();
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            replace(&live, b"secret", Access::OwnerOnly).unwrap(),
            Replaced::Written(_)
        ));
        let mode = std::fs::metadata(&live).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, OWNER_ONLY_MODE);
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

    /// A journal this process created whose commit fails is kept, on every
    /// platform: on Windows the creating handle's failure path leaves it.
    /// Red edit: have the Windows commit always remove on failure, and the
    /// console key a store transaction already names is lost.
    #[test]
    fn a_created_journal_survives_a_failed_commit() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        unreplaceable(&blocked);
        let failed = StagedWrite::<Journal>::create(&blocked, b"named", Access::Default)
            .unwrap()
            .commit();
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read(staged_path(&blocked)).unwrap(),
            b"named",
            "a failed commit keeps its journal"
        );
    }

    /// A replace's failure names the step that failed (Rick, 2026-11-19:
    /// the wallet's `data.step`): a staged file that cannot be created is
    /// the write, a rename that is refused the rename. The create fails in
    /// a directory that does not exist, which holds for root too. Red edit:
    /// tag the create's failure `Step::Rename`, and the first assertion
    /// fails.
    #[test]
    fn a_failed_replace_names_its_step() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing").join("record");
        let failed = StagedWrite::<Replace>::create(&missing, b"new", Access::Private);
        assert!(
            matches!(
                failed,
                Err(CommitError::Io {
                    step: Step::Write,
                    ..
                })
            ),
            "{failed:?}"
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
        assert!(
            matches!(
                failed,
                Err(CommitError::Io {
                    step: Step::Rename,
                    ..
                })
            ),
            "{failed:?}"
        );
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

    /// A journal a previous process left is renamed through a reopened
    /// handle, and a reader of it that lets go within the wait does not
    /// fail the commit; the commit reports the rename unconfirmed. Red edit:
    /// drop the source wait in `shekyl_win_sec::replace::replace`, and the
    /// commit is a sharing violation (the Windows rendezvous's os error 32).
    #[test]
    fn a_reader_of_a_resumed_journal_shorter_than_the_wait_is_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(staged_path(&live), b"new").unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT / 10);
        let durability = StagedWrite::<Journal>::resume(&live)
            .unwrap()
            .commit()
            .expect("the reader let go within the wait");
        reader.join().unwrap();
        assert!(
            matches!(durability, Durability::Unconfirmed(Unconfirmed::Reopened)),
            "{durability:?}"
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path(&live).exists());
    }

    /// A reader of a resumed journal that outstays the wait is `HeldOpen`,
    /// after the wait and not before, and the journal is kept for the next
    /// start. Red edit: return the sharing violation as `Io`, and the
    /// start's refusal blames the directory.
    #[test]
    fn a_reader_of_a_resumed_journal_past_the_wait_is_held_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(staged_path(&live), b"new").unwrap();
        let reader = hold(&staged_path(&live), REPLACE_WAIT * 2);
        let began = Instant::now();
        let failed = StagedWrite::<Journal>::resume(&live).unwrap().commit();
        assert!(began.elapsed() >= REPLACE_WAIT);
        assert!(
            matches!(&failed, Err(CommitError::HeldOpen(held)) if held.held == staged_path(&live)),
            "{failed:?}"
        );
        reader.join().unwrap();
        assert_eq!(std::fs::read(staged_path(&live)).unwrap(), b"new");
    }

    /// A staged file this process writes is held by its creating handle
    /// until the commit: a watcher that opens it without delete sharing
    /// fails its own open, and the commit does not wait. Red edit: close
    /// the creating handle after the write and rename through a reopened
    /// one, and the watcher holds the commit until the wait ends.
    #[test]
    fn a_watcher_of_a_staged_write_fails_its_own_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged = StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable).unwrap();
        let watcher = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(staged_path(&live))
            .unwrap_err();
        assert!(
            shekyl_win_sec::replace::is_sharing_violation(&watcher),
            "{watcher}"
        );
        let began = Instant::now();
        staged.commit().unwrap();
        assert!(began.elapsed() < REPLACE_WAIT / 2, "{:?}", began.elapsed());
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
    }

    /// A daemon's staged file ([`StagedWrite::create`]'s default, read
    /// sharing) refuses a second writer, whatever that writer shares, with a
    /// sharing violation, while a reader still opens it. Red edit: share
    /// write by default in `shekyl_win_sec::replace::create_staged`, and the
    /// writer that shares everything opens it.
    #[test]
    fn a_second_writer_cannot_open_a_daemon_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged = StagedWrite::<Replace>::create(&live, b"new", Access::WorldReadable).unwrap();
        for share in [
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SHARE_READ,
            0,
        ] {
            let writer = std::fs::OpenOptions::new()
                .write(true)
                .share_mode(share)
                .open(staged_path(&live))
                .unwrap_err();
            assert!(
                shekyl_win_sec::replace::is_sharing_violation(&writer),
                "share {share:#x}: {writer}"
            );
        }
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(staged_path(&live))
            .expect("a reader that shares everything opens the staged file");
        drop(reader);
        staged.commit().unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
    }

    /// With [`Sharing::ReadWrite`] a writer that shares read, write and
    /// delete opens the staged file, as the wallet's password rotation does
    /// to lock it, and the commit renames the file under that open handle.
    /// Red edit: ignore `sharing` in `write_staged`, and the open is a
    /// sharing violation.
    #[test]
    fn write_sharing_lets_the_rotation_lock_open_the_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged =
            StagedWrite::<Replace>::create_with(&live, b"new", Access::Private, Sharing::ReadWrite)
                .unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(staged_path(&live))
            .expect("write sharing lets the rotation's lock open the staged file");
        staged.commit().unwrap();
        drop(lock);
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
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
