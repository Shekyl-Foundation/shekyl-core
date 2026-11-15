// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A directory's account facts, read once and judged by the caller.
//!
//! The owner's socket directory, a service's rendezvous directory and a
//! service's data home each ask the same questions — the directory exists,
//! it is not a link, it is a directory, it belongs to this account — and
//! then apply their own rule to the mode. The facts are read here. The
//! mode rule stays with the caller, so the three policies cannot drift
//! apart in the walk and cannot be collapsed into one mode.

use std::path::Path;

/// Permission bits of `st_mode`.
pub(crate) const PERMISSION_BITS: u32 = 0o7777;

/// A directory the account alone may enter.
pub(crate) const ACCOUNT_ONLY_MODE: u32 = 0o700;

/// Write permission for the group or for others.
pub(crate) const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// The account a service refuses to run as.
const ROOT_ACCOUNT: u32 = 0;

/// A directory that passed the shared walk: it exists, it is a directory,
/// it is not a link. The mode and the owner are for the caller to judge.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryAccount {
    uid: u32,
    mode: u32,
}

impl DirectoryAccount {
    /// Read `path`'s account facts.
    ///
    /// # Errors
    ///
    /// [`DirectoryFault`], when the path is not a directory this walk can
    /// describe.
    pub(crate) fn inspect(path: &Path) -> Result<Self, DirectoryFault> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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

    /// The directory's mode, permission bits only.
    #[must_use]
    pub(crate) fn mode(self) -> u32 {
        self.mode
    }

    /// Whether this account owns the directory.
    ///
    /// # Errors
    ///
    /// [`DirectoryFault::OwnedBy`] naming both uids.
    pub(crate) fn require_owner(self, account: u32) -> Result<Self, DirectoryFault> {
        if self.uid == account {
            Ok(self)
        } else {
            Err(DirectoryFault::OwnedBy {
                uid: self.uid,
                account,
            })
        }
    }
}

/// Why the shared walk stopped.
#[derive(Debug)]
pub(crate) enum DirectoryFault {
    /// Nothing is at the path.
    Missing,
    /// The metadata could not be read.
    Unreadable(std::io::Error),
    /// The path is a symbolic link.
    SymbolicLink,
    /// The path is not a directory.
    NotADirectory,
    /// Owned by `uid`, and the caller asked for `account`.
    OwnedBy { uid: u32, account: u32 },
}

impl DirectoryFault {
    /// The operator's clause. `shown` is the path, when the sentence names
    /// it; without it the sentence is the owner's-socket form.
    #[must_use]
    pub(crate) fn clause(&self, shown: Option<&str>) -> String {
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

/// A service runs as an ordinary account.
///
/// # Errors
///
/// The daemon's effective uid is root.
pub(crate) fn require_service_account(account: u32) -> Result<(), String> {
    if account == ROOT_ACCOUNT {
        Err("the daemon runs as root".to_owned())
    } else {
        Ok(())
    }
}
