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

    /// Creates the data directory if it is missing, then takes the lock.
    ///
    /// # Errors
    /// `config.data-dir.unusable` when the directory cannot be created or
    /// the lock file cannot be opened; `config.data-dir.locked` when another
    /// process holds the lock.
    pub fn take(data_dir: &Path) -> Result<Self, Diagnostic> {
        let shown = data_dir.display().to_string();
        let unusable = |e: std::io::Error| {
            Diagnostic::new(Code::DataDirUnusable, Source::Machine)
                .option("data-dir")
                .param("path", shown.clone())
                .param("error", e.to_string())
        };
        std::fs::create_dir_all(data_dir).map_err(unusable)?;
        if !data_dir.is_dir() {
            return Err(unusable(std::io::Error::other("not a directory")));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join(LOCK_FILE))
            .map_err(unusable)?;
        if !try_lock(&file).map_err(unusable)? {
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
    fn a_data_directory_that_is_a_file_is_unusable() {
        let d = tempfile::tempdir().unwrap();
        let not_a_dir = d.path().join("data");
        std::fs::write(&not_a_dir, "").unwrap();
        let e = Lock::take(&not_a_dir).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable);
    }
}
