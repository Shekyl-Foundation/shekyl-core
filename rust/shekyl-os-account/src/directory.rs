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
//! here, once. Each caller applies its own mode rule
//! ([`DirectoryFacts::is_owner_only_mode`],
//! [`DirectoryFacts::group_or_other_can_enter`],
//! [`DirectoryFacts::group_or_other_can_write`]), so the rules cannot be
//! collapsed into one mode and cannot be re-derived beside this walk.
//!
//! This is the operating system's account boundary. It is not a consensus
//! rule and not a cryptographic one, and it is the same boundary at the
//! end of the mining era and after the lattice-only transition: a local
//! directory is this account's, or it is not.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::OWNER_ONLY_DIR_MODE;

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
    /// The process umask.
    pub umask: u32,
}

impl fmt::Display for UmaskStripsOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} was created with mode {:04o} because the process umask {:04o} removes the owner's own permission",
            self.dir.display(),
            self.mode,
            self.umask
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

/// The process umask, read from what it does to a directory rather than by
/// setting it: `umask(2)` can only be read by writing it, which is process-wide
/// and races every other thread. `dir` is this call's own name, free again,
/// and is made once more with every permission bit, read, and removed. If that
/// fails, the owner bits `mode` is missing are the part known.
fn umask_from_a_probe(dir: &Path, mode: u32) -> u32 {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    const EVERY_ACCESS_BIT: u32 = 0o777;
    let probed = std::fs::DirBuilder::new()
        .mode(EVERY_ACCESS_BIT)
        .create(dir)
        .and_then(|()| std::fs::symlink_metadata(dir));
    match probed {
        Ok(meta) => {
            drop(std::fs::remove_dir(dir));
            EVERY_ACCESS_BIT & !meta.permissions().mode()
        }
        Err(_) => OWNER_ONLY_DIR_MODE & !mode,
    }
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
        umask: umask_from_a_probe(dir, mode),
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
}
