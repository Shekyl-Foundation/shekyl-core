// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether the account could create or open a path, asked without creating,
//! opening or locking anything (`INPUT_GRAMMAR.md` IG-Q59, IG-F15).
//!
//! The configuration check walks the refusals start makes and leaves the
//! machine as it found it. Start asks the same questions and then creates.
//! On Unix the question goes to the kernel with the effective ids, which is
//! what the file rules in `file.rs` judge by. On Windows the file system is
//! asked what it reports without a handle: existence, kind and the
//! read-only attribute. A DACL that denies the account is not seen here and
//! is found by start's own create or open.

use std::io::{Error, ErrorKind};
use std::path::Path;

/// What the account would need from an existing file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// Opened for appending: the log file.
    Write,
    /// Opened for reading and writing: the lock file.
    ReadWrite,
}

/// Whether `dir` is a directory, or could be created with every missing
/// component above it.
///
/// # Errors
/// The reason, in the operating system's words where it has them.
pub(crate) fn directory_creatable(dir: &Path) -> std::io::Result<()> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(Error::other("not a directory")),
        Err(e) if e.kind() == ErrorKind::NotFound => creatable_below(dir),
        Err(e) => Err(e),
    }
}

/// Whether `file` is a regular file the account could open as `need`
/// asks, or could be created in its directory.
///
/// # Errors
/// The reason, in the operating system's words where it has them.
pub(crate) fn file_openable(file: &Path, need: Need) -> std::io::Result<()> {
    match std::fs::metadata(file) {
        Ok(meta) if meta.is_file() => may_open(file, &meta, need),
        Ok(_) => Err(Error::other("not a regular file")),
        Err(e) if e.kind() == ErrorKind::NotFound => creatable_below(file),
        Err(e) => Err(e),
    }
}

/// Whether a missing `path` could be created: the first existing ancestor
/// is a directory the account may write and search. Everything between is
/// created by the account and so is the account's.
fn creatable_below(path: &Path) -> std::io::Result<()> {
    let mut above = path.parent();
    while let Some(dir) = above {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        match std::fs::metadata(dir) {
            Ok(meta) if meta.is_dir() => return may_create_in(dir),
            Ok(_) => {
                return Err(Error::other(format!(
                    "{} is not a directory",
                    dir.display()
                )))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => above = dir.parent(),
            Err(e) => return Err(e),
        }
    }
    Err(Error::other("no directory above it exists"))
}

#[cfg(unix)]
fn may_create_in(dir: &Path) -> std::io::Result<()> {
    use rustix::fs::{accessat, Access, AtFlags, CWD};
    accessat(
        CWD,
        dir,
        Access::WRITE_OK | Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .map_err(Error::from)
}

#[cfg(unix)]
fn may_open(file: &Path, _meta: &std::fs::Metadata, need: Need) -> std::io::Result<()> {
    use rustix::fs::{accessat, Access, AtFlags, CWD};
    let access = match need {
        Need::Write => Access::WRITE_OK,
        Need::ReadWrite => Access::READ_OK | Access::WRITE_OK,
    };
    accessat(CWD, file, access, AtFlags::EACCESS).map_err(Error::from)
}

/// A directory's read-only attribute means nothing for the entries it may
/// hold; the account's rights on it are found by start's create.
#[cfg(not(unix))]
fn may_create_in(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn may_open(_file: &Path, meta: &std::fs::Metadata, _need: Need) -> std::io::Result<()> {
    if meta.permissions().readonly() {
        return Err(Error::from(ErrorKind::PermissionDenied));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_path_under_a_writable_directory_is_creatable_and_stays_missing() {
        let d = tempfile::tempdir().unwrap();
        let deep = d.path().join("a").join("b").join("c");
        directory_creatable(&deep).unwrap();
        file_openable(&deep.join("f"), Need::ReadWrite).unwrap();
        assert!(!d.path().join("a").exists(), "the probe created nothing");
    }

    #[test]
    fn a_file_where_a_directory_is_expected_is_refused_either_way() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        let e = directory_creatable(&f).unwrap_err();
        assert_eq!(e.to_string(), "not a directory");
        // Below a file: the kernel says so itself where it looks (ENOTDIR),
        // or the walk up finds the file.
        let e = directory_creatable(&f.join("under")).unwrap_err();
        assert!(
            e.to_string().to_lowercase().contains("not a directory"),
            "{e}"
        );
        let e = file_openable(d.path(), Need::Write).unwrap_err();
        assert_eq!(e.to_string(), "not a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_account_cannot_write_refuses_a_creation_below_it() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            // Root writes anywhere; the kernel answers yes, which is correct.
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let sealed = d.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o500)).unwrap();
        let e = directory_creatable(&sealed.join("data")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
        let e = file_openable(&sealed.join("lock"), Need::ReadWrite).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
        // The directory itself exists and is a directory: creatable.
        directory_creatable(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_file_is_judged_by_the_access_asked() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o200)).unwrap();
        file_openable(&f, Need::Write).unwrap();
        let e = file_openable(&f, Need::ReadWrite).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
