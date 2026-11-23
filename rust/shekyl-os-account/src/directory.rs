// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a path is, as a directory, for this account.
//!
//! The daemon's data directory, a service's data home, the owner's socket
//! directory and every socket listener ask the same questions of a path:
//! it exists, it is not a link, it is a directory, it belongs to an
//! account, and its mode has these permission bits. The questions are read
//! here, once. The judgment that no other account can enter is
//! [`account_alone`]. Exact mode [`crate::OWNER_ONLY_DIR_MODE`]
//! ([`DirectoryFacts::is_owner_only_mode`]) and a group-or-other write bit
//! ([`DirectoryFacts::group_or_other_can_write`]) stay with the callers that
//! ask for those, so a stricter rule is not re-derived as the account-alone
//! one. [`directories_entered`] is the directories one open of a path searches.
//!
//! This is the operating system's account boundary. It is not a consensus
//! rule and not a cryptographic one, and it is the same boundary at the
//! end of the mining era and after the lattice-only transition: a local
//! directory is this account's, or it is not.

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::OWNER_ONLY_DIR_MODE;

/// One component of a path, owned, so a resolution can restart at a link
/// target without borrowing the path it came from.
enum Step {
    Root,
    Parent,
    Name(OsString),
}

fn steps_of(path: &Path) -> VecDeque<Step> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => Some(Step::Root),
            Component::ParentDir => Some(Step::Parent),
            Component::CurDir => None,
            Component::Normal(name) => Some(Step::Name(name.to_os_string())),
            // The variant exists on every platform. Unix paths do not produce it.
            Component::Prefix(prefix) => Some(Step::Name(prefix.as_os_str().to_os_string())),
        })
        .collect()
}

fn join_step(current: &Path, step: &Step) -> PathBuf {
    match step {
        Step::Root => PathBuf::from(OsStr::new("/")),
        Step::Parent => current.join(".."),
        Step::Name(name) => current.join(name),
    }
}

/// How many symbolic links one path resolution follows. Linux's
/// `MAXSYMLINKS`, the most any supported kernel resolves on one lookup.
/// The next link is `ELOOP`.
pub const SYMLINKS_IN_ONE_RESOLUTION: usize = 40;

/// Permission bits of `st_mode`, the file type excluded.
pub const PERMISSION_BITS: u32 = 0o7777;

/// Any permission for the group or for others. A directory with none of
/// these bits cannot be entered by another account.
pub const GROUP_OR_OTHER_ANY: u32 = 0o077;

/// Write permission for the group or for others.
pub const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// `path` as a call that must not follow a link has to name it. `lstat` and
/// `O_NOFOLLOW` both follow a final link named with a trailing `/` or `/.`,
/// so a no-follow call on a directory takes this spelling:
/// [`Path::components`] drops repeated separators and `.` without touching
/// the file system, resolves no link, and keeps `..`.
#[must_use]
pub fn no_follow_spelling(path: &Path) -> PathBuf {
    path.components().collect()
}

/// A directory this account just made came out without all of the owner's
/// permission bits, because the process umask removed them. `mkdir` with
/// [`OWNER_ONLY_DIR_MODE`] can only be narrowed by a umask, and the common ones
/// (`022`, `002`, `027`, `077`) leave it whole. The daemon never changes a mode
/// (Rick, 2026-11-23), so this is a refusal, not a repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UmaskStripsOwner {
    /// The directory that came out short. It is removed again.
    pub dir: PathBuf,
    /// Its permission bits.
    pub mode: u32,
}

impl UmaskStripsOwner {
    /// The owner's digit of the umask, the part that caused this, as `02xx`.
    /// It is read from the new directory's mode. The other digits are not
    /// read: `umask(2)` reads only by writing the process-wide mask, and a
    /// probe asking for group or other bits would hand them to those accounts.
    #[must_use]
    pub fn umask_shown(&self) -> String {
        format!("0{:o}xx", (OWNER_ONLY_DIR_MODE & !self.mode) >> 6)
    }
}

impl fmt::Display for UmaskStripsOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} was created with mode {:04o} because the process umask ({}) removes the owner's own permission",
            self.dir.display(),
            self.mode,
            self.umask_shown()
        )
    }
}

impl std::error::Error for UmaskStripsOwner {}

/// The [`UmaskStripsOwner`] an I/O error from
/// [`crate::create_account_dir_all`] carries, if that is what it was.
#[must_use]
pub fn umask_strips_owner(error: &io::Error) -> Option<&UmaskStripsOwner> {
    error.get_ref()?.downcast_ref()
}

/// Checks a directory this call just made, without following a link and
/// without changing anything: it is a directory, and the umask left the
/// owner's bits. A set-group-ID bit inherited from the parent is not the
/// owner's concern and gives no other account a permission.
///
/// # Errors
///
/// [`UmaskStripsOwner`] (the empty directory is removed first), or
/// `NotADirectory` when something else is at the name.
pub(crate) fn check_made_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(no_follow_spelling(dir))?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let mode = meta.permissions().mode() & PERMISSION_BITS;
    if mode & OWNER_ONLY_DIR_MODE == OWNER_ONLY_DIR_MODE {
        return Ok(());
    }
    // This call's own empty directory; the refusal stands either way.
    drop(std::fs::remove_dir(dir));
    Err(io::Error::other(UmaskStripsOwner {
        dir: dir.to_path_buf(),
        mode,
    }))
}

/// A directory the walk could describe: it exists, it is not a link, and
/// it is a directory. The mode and the owner are for the caller to judge.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryFacts {
    uid: u32,
    mode: u32,
}

impl DirectoryFacts {
    /// Read `path` without following a symbolic link, however it is spelled
    /// ([`no_follow_spelling`]).
    ///
    /// # Errors
    ///
    /// [`DirectoryFault`], when the path is not a directory this walk can
    /// describe.
    pub fn inspect(path: &Path) -> Result<Self, DirectoryFault> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = match std::fs::symlink_metadata(no_follow_spelling(path)) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(DirectoryFault::Missing);
            }
            Err(error) => return Err(DirectoryFault::Unreadable(error)),
        };
        if meta.file_type().is_symlink() {
            return Err(DirectoryFault::SymbolicLink);
        }
        if !meta.is_dir() {
            return Err(DirectoryFault::NotADirectory);
        }
        Ok(Self {
            uid: meta.uid(),
            mode: meta.permissions().mode() & PERMISSION_BITS,
        })
    }

    /// The account that owns the directory.
    #[must_use]
    pub fn uid(self) -> u32 {
        self.uid
    }

    /// The directory's mode, permission bits only.
    #[must_use]
    pub fn mode(self) -> u32 {
        self.mode
    }

    /// Whether `account` owns the directory.
    ///
    /// # Errors
    ///
    /// [`DirectoryFault::OwnedBy`], naming both uids.
    pub fn require_owner(self, account: u32) -> Result<Self, DirectoryFault> {
        if self.uid == account {
            Ok(self)
        } else {
            Err(DirectoryFault::OwnedBy {
                uid: self.uid,
                account,
            })
        }
    }

    /// The mode is [`crate::OWNER_ONLY_DIR_MODE`] exactly: this account can enter,
    /// and the mode carries nothing else (no group or other bit, no set-id
    /// bit).
    #[must_use]
    pub fn is_owner_only_mode(self) -> bool {
        self.mode == OWNER_ONLY_DIR_MODE
    }

    /// Group or other has a permission bit, so another account can enter.
    #[must_use]
    pub fn group_or_other_can_enter(self) -> bool {
        self.mode & GROUP_OR_OTHER_ANY != 0
    }

    /// Group or other has write permission.
    #[must_use]
    pub fn group_or_other_can_write(self) -> bool {
        self.mode & GROUP_OR_OTHER_WRITE != 0
    }

    /// This account owns the directory, and no other account can enter it.
    /// A set-id bit or the sticky bit is not entry.
    ///
    /// # Errors
    ///
    /// [`AccountAloneFault::Walk`] when another account owns it, or
    /// [`AccountAloneFault::OthersCanEnter`] when the group or others have
    /// a permission bit.
    pub fn require_account_alone(self, account: u32) -> Result<Self, AccountAloneFault> {
        match self.require_owner(account) {
            Ok(facts) if !facts.group_or_other_can_enter() => Ok(facts),
            Ok(facts) => Err(AccountAloneFault::OthersCanEnter { mode: facts.mode }),
            Err(fault) => Err(AccountAloneFault::Walk(fault)),
        }
    }
}

/// Read `path` and require it to be `account`'s alone
/// ([`DirectoryFacts::require_account_alone`]). A missing path, a link, a
/// non-directory and an unreadable path are [`AccountAloneFault::Walk`].
///
/// # Errors
///
/// [`AccountAloneFault`].
pub fn account_alone(path: &Path, account: u32) -> Result<DirectoryFacts, AccountAloneFault> {
    match DirectoryFacts::inspect(path) {
        Ok(facts) => facts.require_account_alone(account),
        Err(fault) => Err(AccountAloneFault::Walk(fault)),
    }
}

/// Why [`DirectoryFacts::inspect`] or [`DirectoryFacts::require_owner`] stopped.
#[derive(Debug)]
pub enum DirectoryFault {
    /// Nothing is at the path.
    Missing,
    /// The metadata could not be read.
    Unreadable(io::Error),
    /// The path is a symbolic link.
    SymbolicLink,
    /// The path is not a directory.
    NotADirectory,
    /// Owned by `uid`, and the caller asked for `account`.
    OwnedBy { uid: u32, account: u32 },
}

impl DirectoryFault {
    /// The operator's clause. `shown` is the path, when the sentence names
    /// it; without it the sentence is the form a diagnostic already names
    /// the path around ("it is a symbolic link").
    #[must_use]
    pub fn clause(&self, shown: Option<&str>) -> String {
        match (self, shown) {
            (Self::Missing, Some(path)) => format!("{path} does not exist"),
            (Self::Missing, None) => "it does not exist".to_owned(),
            (Self::Unreadable(error), Some(path)) => format!("{path} cannot be read: {error}"),
            (Self::Unreadable(error), None) => format!("it cannot be read: {error}"),
            (Self::SymbolicLink, Some(path)) => format!("{path} is a symbolic link"),
            (Self::SymbolicLink, None) => {
                "it is a symbolic link; name the directory itself".to_owned()
            }
            (Self::NotADirectory, Some(path)) => format!("{path} is not a directory"),
            (Self::NotADirectory, None) => "it is not a directory".to_owned(),
            (Self::OwnedBy { uid, account }, Some(path)) => {
                format!("{path} is owned by uid {uid}, not this account (uid {account})")
            }
            (Self::OwnedBy { uid, account }, None) => {
                format!("it is owned by uid {uid}, not this account (uid {account})")
            }
        }
    }
}

impl fmt::Display for DirectoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.clause(None))
    }
}

impl std::error::Error for DirectoryFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable(error) => Some(error),
            _ => None,
        }
    }
}

/// Why [`account_alone`] stopped. The walk's fault, or another account can
/// enter. Set-id and the sticky bit are not this.
#[derive(Debug)]
pub enum AccountAloneFault {
    /// [`DirectoryFacts::inspect`] or [`DirectoryFacts::require_owner`] stopped.
    Walk(DirectoryFault),
    /// Group or other has a permission bit. `mode` is the permission bits.
    OthersCanEnter {
        /// The directory's mode, permission bits only.
        mode: u32,
    },
}

impl AccountAloneFault {
    /// The operator's clause. `shown` is the path, when the sentence names
    /// it; without it the sentence is the form a diagnostic already names
    /// the path around ("its mode is …").
    #[must_use]
    pub fn clause(&self, shown: Option<&str>) -> String {
        match self {
            Self::Walk(fault) => fault.clause(shown),
            Self::OthersCanEnter { mode } => match shown {
                Some(path) => {
                    format!("{path} has mode {mode:04o}, so other accounts can enter it")
                }
                None => format!("its mode is {mode:04o}, so other accounts can enter it"),
            },
        }
    }
}

impl fmt::Display for AccountAloneFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.clause(None))
    }
}

impl std::error::Error for AccountAloneFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Walk(fault) => Some(fault),
            Self::OthersCanEnter { .. } => None,
        }
    }
}

/// Why [`directories_entered`] stopped before the path could be opened.
#[derive(Debug)]
pub enum ResolutionFault {
    /// The hop bound was spent at `at`. The kernel would return `ELOOP`.
    Loop {
        /// The link that was not followed.
        at: PathBuf,
    },
    /// `at` could not be read.
    Unreadable {
        /// The component that could not be read.
        at: PathBuf,
        /// The operating system's error.
        error: io::Error,
    },
}

impl ResolutionFault {
    /// The path the resolution stopped at.
    #[must_use]
    pub fn at(&self) -> &Path {
        match self {
            Self::Loop { at } | Self::Unreadable { at, .. } => at,
        }
    }
}

/// Every real directory an open of `path` searches, nearest first.
///
/// One resolution, the way the kernel opens. The path is made absolute,
/// spelled with [`no_follow_spelling`], and each component is read with
/// `lstat`. A directory is recorded when a component is looked up in it. A
/// symbolic link is not recorded; the walk continues at its target and the
/// hop count is this resolution's ([`SYMLINKS_IN_ONE_RESOLUTION`]). The
/// final component is not recorded, so the path itself stays the caller's
/// to judge. A component that is not there yet ends the walk, and so does
/// a component that is a file: neither is a directory an open enters.
///
/// # Errors
///
/// [`ResolutionFault::Loop`] when the hop bound is spent, or
/// [`ResolutionFault::Unreadable`] when a component cannot be read. The
/// working directory being unreadable is the second, at `.`.
pub fn directories_entered(path: &Path) -> Result<Vec<PathBuf>, ResolutionFault> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ResolutionFault::Unreadable {
                at: PathBuf::from("."),
                error,
            })?
            .join(path)
    };
    let mut steps = steps_of(&no_follow_spelling(&absolute));
    let mut current = PathBuf::new();
    let mut hops = 0usize;
    let mut entered = Vec::new();
    let mut seen = HashSet::new();
    while let Some(step) = steps.pop_front() {
        if matches!(step, Step::Root) {
            current = join_step(&current, &step);
            continue;
        }
        if !current.as_os_str().is_empty() && seen.insert(current.clone()) {
            entered.push(current.clone());
        }
        let next = join_step(&current, &step);
        let meta = match std::fs::symlink_metadata(&next) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(ResolutionFault::Unreadable { at: next, error }),
        };
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > SYMLINKS_IN_ONE_RESOLUTION {
                return Err(ResolutionFault::Loop { at: next });
            }
            let target = std::fs::read_link(&next)
                .map_err(|error| ResolutionFault::Unreadable { at: next, error })?;
            let resolved = no_follow_spelling(&current.join(target));
            let rest: Vec<Step> = steps.drain(..).collect();
            steps = steps_of(&resolved);
            steps.extend(rest);
            current = PathBuf::new();
            continue;
        }
        if steps.is_empty() || !meta.is_dir() {
            break;
        }
        current = next;
    }
    entered.reverse();
    Ok(entered)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode_of(dir: &Path) -> u32 {
        std::fs::metadata(dir)
            .expect("metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS
    }

    /// The walk names a missing path, a link and a file as themselves, and
    /// a directory's mode is the permission bits. Red edit: follow the link
    /// (`metadata`) and describe its target.
    #[test]
    fn the_walk_does_not_follow_a_link_and_names_what_the_path_is() {
        let base = tempfile::tempdir().expect("a directory");
        let missing = base.path().join("missing");
        assert!(matches!(
            DirectoryFacts::inspect(&missing),
            Err(DirectoryFault::Missing)
        ));

        let dir = base.path().join("d");
        std::fs::create_dir(&dir).expect("a directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2700)).expect("chmod");
        let facts = DirectoryFacts::inspect(&dir).expect("a directory");
        assert_eq!(facts.mode(), mode_of(&dir));
        assert!(
            !facts.group_or_other_can_enter(),
            "set-id is not group or other"
        );
        assert!(!facts.is_owner_only_mode(), "set-id is not exactly 0700");
        let me = facts.uid();
        facts.require_owner(me).expect("this account");
        let owned_by = facts
            .require_owner(me.wrapping_add(1))
            .expect_err("another account");
        assert!(owned_by.clause(None).contains("owned by uid"), "{owned_by}");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let wider = DirectoryFacts::inspect(&dir).expect("a directory");
        assert!(wider.group_or_other_can_enter());
        assert!(!wider.group_or_other_can_write());

        let link = base.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).expect("a link");
        // `lstat` follows a link spelled with a trailing `/` or `/.`. Red
        // edit: pass `path` to `symlink_metadata` as given.
        let shown = link.display();
        for spelling in [
            link.clone(),
            PathBuf::from(format!("{shown}/")),
            PathBuf::from(format!("{shown}/.")),
            PathBuf::from(format!("{shown}//./")),
        ] {
            assert!(
                matches!(
                    DirectoryFacts::inspect(&spelling),
                    Err(DirectoryFault::SymbolicLink)
                ),
                "{}",
                spelling.display()
            );
        }

        let file = base.path().join("file");
        std::fs::write(&file, b"").expect("a file");
        assert!(matches!(
            DirectoryFacts::inspect(&file),
            Err(DirectoryFault::NotADirectory)
        ));
    }

    /// Set-id and the sticky bit are not another account entering. Group
    /// access is. Red edit: require the mode to be exactly 0700.
    #[test]
    fn account_alone_is_entry_not_the_exact_mode() {
        let base = tempfile::tempdir().expect("a directory");
        let dir = base.path().join("d");
        std::fs::create_dir(&dir).expect("a directory");
        let me = DirectoryFacts::inspect(&dir).expect("a directory").uid();
        for mode in [0o700, 0o2700, 0o1700] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            account_alone(&dir, me).expect("no other account can enter");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let refused = account_alone(&dir, me).expect_err("the group can enter");
        assert_eq!(
            refused.clause(None),
            "its mode is 0750, so other accounts can enter it"
        );
    }

    /// One resolution enters the directory that holds a link and every
    /// directory above where it resolves, and it does not enter the link
    /// or a file. A cycle spends the hop bound. Red edit: record the link
    /// path and stop at the first hop.
    #[test]
    fn one_resolution_enters_both_legs_and_a_cycle_spends_the_bound() {
        let base = tempfile::tempdir().expect("a directory");
        let safe = base.path().join("safe");
        let writable = base.path().join("writable");
        std::fs::create_dir(&safe).expect("safe");
        std::fs::create_dir(&writable).expect("writable");
        let target = writable.join("target");
        std::fs::create_dir(&target).expect("target");
        let link = safe.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        let entered = directories_entered(&link.join("data")).expect("resolved");
        assert!(entered.iter().any(|dir| dir == &writable), "{entered:?}");
        assert!(entered.iter().any(|dir| dir == &safe), "{entered:?}");
        assert!(entered.iter().all(|dir| dir != &link), "{entered:?}");

        let file = safe.join("file");
        std::fs::write(&file, b"").expect("a file");
        let through_file = directories_entered(&file.join("data")).expect("stopped");
        assert!(
            through_file.iter().all(|dir| dir != &file),
            "{through_file:?}"
        );

        let cycle = safe.join("cycle");
        std::os::unix::fs::symlink(&cycle, &cycle).expect("a cycle");
        assert!(
            matches!(
                directories_entered(&cycle.join("data")),
                Err(ResolutionFault::Loop { .. })
            ),
            "a cycle spends the hop bound"
        );
    }
}
