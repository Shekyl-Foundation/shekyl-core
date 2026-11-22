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
    /// `config.data-dir.unusable` or `config.data-dir.exposed`, as `take`
    /// would refuse.
    pub fn creatable(data_dir: &Path) -> Result<(), Diagnostic> {
        let unusable = Self::unusable(data_dir);
        probe::directory_creatable(data_dir).map_err(&unusable)?;
        Self::owner_only(data_dir)?;
        probe::file_openable(&data_dir.join(LOCK_FILE), probe::Need::ReadWrite).map_err(unusable)
    }

    /// Refuses an existing data directory other accounts can enter
    /// (`config.data-dir.exposed`; Rick, 2026-11-22). It holds the daemon's
    /// keys, a service's console key (the host's administrator) among them,
    /// and the console's socket, so it is the account's alone on its own
    /// account: a directory above it is not counted. The mode is the
    /// operator's to change; the daemon never changes a mode it did not
    /// create. A missing directory passes: [`Lock::take`] creates it
    /// owner-only. Windows has no mode to read here: the keys and the
    /// console's pipe carry owner-only descriptors of their own.
    fn owner_only(data_dir: &Path) -> Result<(), Diagnostic> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::metadata(data_dir) else {
                return Ok(());
            };
            let mode = meta.permissions().mode() & crate::directory::PERMISSION_BITS;
            if meta.is_dir() && mode & crate::directory::GROUP_OR_OTHER_ANY != 0 {
                return Err(Diagnostic::new(Code::DataDirExposed, Source::Machine)
                    .option("data-dir")
                    .param("path", data_dir.display().to_string())
                    .param("mode", format!("{mode:04o}")));
            }
        }
        #[cfg(not(unix))]
        let _ = data_dir;
        Ok(())
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
    /// Every directory it creates, the data home and the network directory
    /// included, is owner-only whatever the umask
    /// (`shekyl_os_account::create_account_dir_all`).
    ///
    /// # Errors
    /// `config.data-dir.unusable` when the directory cannot be created or
    /// the lock file cannot be opened; `config.data-dir.exposed` when it
    /// exists and other accounts can enter it; `config.data-dir.locked`
    /// when another process holds the lock.
    pub fn take(data_dir: &Path) -> Result<Self, Diagnostic> {
        Self::creatable(data_dir)?;
        let shown = data_dir.display().to_string();
        let unusable = Self::unusable(data_dir);
        shekyl_os_account::create_account_dir_all(data_dir).map_err(&unusable)?;
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

    /// The permission bits of `dir`.
    #[cfg(unix)]
    fn mode_of(dir: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(dir).unwrap().permissions().mode() & crate::directory::PERMISSION_BITS
    }

    /// A fresh data directory, and the data home above it, are made
    /// owner-only under the common umask `022`. Red edit: create them with
    /// `create_dir_all` (`0755`).
    #[cfg(unix)]
    #[test]
    fn a_fresh_data_directory_is_created_owner_only_under_umask_022() {
        use rustix::fs::Mode;
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let data = home.join("testnet");
        let previous = rustix::process::umask(Mode::from_raw_mode(0o022));
        let taken = Lock::take(&data);
        rustix::process::umask(previous);
        let _held = taken.unwrap();
        for dir in [&home, &data] {
            assert_eq!(
                mode_of(dir),
                crate::directory::ACCOUNT_ONLY_MODE,
                "{}",
                dir.display()
            );
        }
    }

    /// An existing data directory other accounts can enter is refused, by
    /// the check as by the start, naming the directory and the fix, with
    /// nothing made in it and its mode left as the operator set it. Red
    /// edit: drop the check, and the lock is taken in it.
    #[cfg(unix)]
    #[test]
    fn an_existing_0755_data_directory_is_refused_with_the_named_fix() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        for e in [
            Lock::creatable(&data).unwrap_err(),
            Lock::take(&data).unwrap_err(),
        ] {
            assert_eq!(e.code, Code::DataDirExposed);
            assert_eq!(e.option.as_deref(), Some("data-dir"));
            assert_eq!(e.get("path"), data.to_str());
            assert_eq!(e.get("mode"), Some("0755"));
            let shown = e.render();
            assert!(
                shown.contains(&format!("chmod 700 {}", data.display())),
                "{shown}"
            );
        }
        assert_eq!(mode_of(&data), 0o755, "the daemon does not change it");
        assert!(!data.join(LOCK_FILE).exists(), "nothing is made in it");
        std::fs::set_permissions(
            &data,
            std::fs::Permissions::from_mode(crate::directory::ACCOUNT_ONLY_MODE),
        )
        .unwrap();
        Lock::take(&data).unwrap();
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
