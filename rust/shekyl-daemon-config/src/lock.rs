// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The data-directory lock (DC-N1, DC-Q15): `shekyld.lock` at the data
//! directory's root, held through the operating system's file lock for the
//! life of the process and released by the kernel when the process ends,
//! however it ends. The file is never deleted.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, Source};

use crate::probe;

/// The lock file's name.
pub const LOCK_FILE: &str = "shekyld.lock";

/// The held lock. Dropping it releases the lock; the file stays.
#[derive(Debug)]
pub struct Lock {
    /// Held for the life of the lock; the kernel keys the lock to it.
    _held: File,
    data_dir: PathBuf,
}

impl Lock {
    /// The data directory this lock holds.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Whether the account could create the data directory and open the
    /// lock file: the question [`Lock::take`] asks before it creates,
    /// answered without creating, opening or locking (IG-Q59, IG-F15). A
    /// lock another process holds is not asked about: the check runs while
    /// a daemon is up.
    ///
    /// # Errors
    /// `config.data-dir.unusable`, as `take` would refuse.
    pub fn creatable(data_dir: &Path) -> Result<(), Diagnostic> {
        let unusable = Self::unusable(data_dir);
        probe::directory_creatable(data_dir).map_err(&unusable)?;
        probe::file_openable(&data_dir.join(LOCK_FILE), probe::Need::ReadWrite).map_err(unusable)
    }

    fn unusable(data_dir: &Path) -> impl Fn(std::io::Error) -> Diagnostic {
        let shown = data_dir.display().to_string();
        move |e: std::io::Error| {
            Diagnostic::new(Code::DataDirUnusable, Source::Machine)
                .option("data-dir")
                .param("path", shown.clone())
                .param("error", e.to_string())
        }
    }

    /// Creates the data directory if it is missing, then takes the lock.
    /// [`Lock::creatable`] is asked first, so the decision is written once.
    ///
    /// # Errors
    /// `config.data-dir.unusable` when the directory cannot be created or
    /// the lock file cannot be opened; `config.data-dir.locked` when another
    /// process holds the lock.
    pub fn take(data_dir: &Path) -> Result<Self, Diagnostic> {
        Self::creatable(data_dir)?;
        let shown = data_dir.display().to_string();
        let unusable = Self::unusable(data_dir);
        std::fs::create_dir_all(data_dir).map_err(&unusable)?;
        if !data_dir.is_dir() {
            return Err(unusable(std::io::Error::other("not a directory")));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join(LOCK_FILE))
            .map_err(&unusable)?;
        if !try_lock(&file).map_err(&unusable)? {
            return Err(Diagnostic::new(Code::DataDirLocked, Source::Machine)
                .option("data-dir")
                .param("path", shown));
        }
        Ok(Self {
            _held: file,
            data_dir: data_dir.to_path_buf(),
        })
    }
}

/// `true` when the lock was taken, `false` when another process holds it.
#[cfg(unix)]
fn try_lock(file: &File) -> std::io::Result<bool> {
    use rustix::fs::{flock, FlockOperation};
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(windows)]
fn try_lock(file: &File) -> std::io::Result<bool> {
    shekyl_win_sec::lock::try_lock_exclusive(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_is_taken_once_and_refused_to_a_second_holder() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let first = Lock::take(&data).unwrap();
        assert!(data.join(LOCK_FILE).is_file());
        let second = Lock::take(&data).unwrap_err();
        assert_eq!(second.code, Code::DataDirLocked);
        assert!(second.render().contains("another daemon"), "{second}");
        drop(first);
        let again = Lock::take(&data).unwrap();
        assert_eq!(again.data_dir(), data);
        assert!(data.join(LOCK_FILE).is_file(), "the file is never deleted");
    }

    #[test]
    fn creatable_creates_nothing_and_agrees_with_take() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("deep").join("data");
        Lock::creatable(&data).unwrap();
        assert!(!d.path().join("deep").exists(), "the check created nothing");
        let held = Lock::take(&data).unwrap();
        assert!(data.join(LOCK_FILE).is_file());
        // Held by another process or not, the check is the same answer.
        Lock::creatable(&data).unwrap();
        drop(held);
        let f = d.path().join("file");
        std::fs::write(&f, b"x").unwrap();
        let e = Lock::creatable(&f).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable);
        assert_eq!(e.get("error"), Some("not a directory"));
        assert_eq!(Lock::take(&f).unwrap_err().code, Code::DataDirUnusable);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_account_cannot_create_is_refused_before_anything_is_made() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let sealed = d.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o500)).unwrap();
        let data = sealed.join("data");
        let e = Lock::creatable(&data).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable);
        assert_eq!(Lock::take(&data).unwrap_err().code, Code::DataDirUnusable);
        assert!(!data.exists());
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_data_directory_that_is_a_file_is_unusable() {
        let d = tempfile::tempdir().unwrap();
        let not_a_dir = d.path().join("data");
        std::fs::write(&not_a_dir, "").unwrap();
        let e = Lock::take(&not_a_dir).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable);
    }
}
