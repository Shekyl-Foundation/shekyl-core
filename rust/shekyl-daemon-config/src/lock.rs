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
    /// `config.data-dir.ancestor-writable`, `config.data-dir.unusable` or
    /// `config.data-dir.exposed`, as `take` would refuse.
    pub fn creatable(data_dir: &Path) -> Result<(), Diagnostic> {
        // First, before anything is made or used: a directory above that
        // another account can write could redirect all of it.
        #[cfg(unix)]
        crate::file::refuse_writable_ancestor(data_dir)?;
        let unusable = Self::unusable(data_dir);
        probe::directory_creatable(data_dir).map_err(&unusable)?;
        // Windows has no mode to read: the keys and the console's pipe carry
        // owner-only descriptors of their own, enforced on every open.
        #[cfg(unix)]
        Self::owner_only(data_dir)?;
        probe::file_openable(&data_dir.join(LOCK_FILE), probe::Need::ReadWrite).map_err(unusable)
    }

    /// Refuses an existing data directory other accounts can enter
    /// (`config.data-dir.exposed`; Rick, 2026-11-22). It holds the daemon's
    /// keys, a service's console key (the host's administrator) among them,
    /// and the console's socket, so it is the account's alone on its own
    /// account. The mode is the operator's to change; the daemon never
    /// changes a mode. A missing directory passes: [`Lock::take`] creates it
    /// owner-only.
    ///
    /// The fact is [`shekyl_os_account::directory::account_alone`]: the same
    /// judgment the socket listeners use, which does not follow a link. A
    /// missing directory passes, because [`Lock::take`] creates it. A
    /// symbolic link, a non-directory, an unreadable path, or another
    /// account's directory is `config.data-dir.unusable`, in that walk's
    /// own clause. Group or other permission is `config.data-dir.exposed`.
    /// A set-id bit or the sticky bit is not entry. Unix only: on Windows
    /// the keys and the console's pipe carry owner-only descriptors of
    /// their own.
    #[cfg(unix)]
    fn owner_only(data_dir: &Path) -> Result<(), Diagnostic> {
        use shekyl_os_account::directory::{account_alone, AccountAloneFault, DirectoryFault};
        match account_alone(data_dir, shekyl_os_account::effective_uid()) {
            Ok(_) | Err(AccountAloneFault::Walk(DirectoryFault::Missing)) => Ok(()),
            Err(AccountAloneFault::Walk(fault)) => Err(Self::unusable_fact(data_dir, &fault)),
            Err(AccountAloneFault::OthersCanEnter { mode }) => {
                Err(Diagnostic::new(Code::DataDirExposed, Source::Machine)
                    .option("data-dir")
                    .param("path", data_dir.display().to_string())
                    .param("mode", format!("{mode:04o}")))
            }
        }
    }

    /// `config.data-dir.unusable` for a fact the shared walk refused. The
    /// clause does not repeat the path: the diagnostic already names it.
    #[cfg(unix)]
    fn unusable_fact(data_dir: &Path, fault: &crate::directory::DirectoryFault) -> Diagnostic {
        Self::unusable(data_dir)(std::io::Error::other(fault.clause(None)))
    }

    /// What a failed create of the data directory is refused as: the umask
    /// by name when that was the cause, otherwise unusable.
    fn create_refusal(data_dir: &Path, error: std::io::Error) -> Diagnostic {
        #[cfg(unix)]
        if let Some(stripped) = shekyl_os_account::directory::umask_strips_owner(&error) {
            return Diagnostic::new(Code::DataDirUmask, Source::Machine)
                .option("data-dir")
                .param("path", stripped.dir.display().to_string())
                .param("mode", format!("{:04o}", stripped.mode))
                .param("umask", stripped.umask_shown());
        }
        Self::unusable(data_dir)(error)
    }

    /// Whether the account could create a file in the data directory, as
    /// the node must for a store that is not there yet. Answered without
    /// creating anything.
    ///
    /// # Errors
    /// The refusal: the kernel's, or the path is not a directory.
    pub fn files_creatable(data_dir: &Path) -> std::io::Result<()> {
        probe::files_creatable_in(data_dir)
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
    /// included, is made owner-only and no mode is changed
    /// (`shekyl_os_account::create_account_dir_all`).
    ///
    /// # Errors
    /// `config.data-dir.ancestor-writable` when another account can write a
    /// directory above it; `config.data-dir.umask` when the umask strips the
    /// owner's bits from a directory it makes; `config.data-dir.unusable`
    /// when the directory cannot be created or the lock file cannot be
    /// opened; `config.data-dir.exposed` when it exists and other accounts
    /// can enter it; `config.data-dir.locked` when another process holds
    /// the lock.
    pub fn take(data_dir: &Path) -> Result<Self, Diagnostic> {
        Self::creatable(data_dir)?;
        let shown = data_dir.display().to_string();
        let unusable = Self::unusable(data_dir);
        shekyl_os_account::create_account_dir_all(data_dir)
            .map_err(|e| Self::create_refusal(data_dir, e))?;
        if !data_dir.is_dir() {
            return Err(unusable(std::io::Error::other("not a directory")));
        }
        // Again after the create: a directory another process made between
        // the check and the create is not this call's, and keeps its mode.
        #[cfg(unix)]
        Self::owner_only(data_dir)?;
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
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
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
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
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
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
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
        std::fs::metadata(dir).unwrap().permissions().mode()
            & shekyl_os_account::directory::PERMISSION_BITS
    }

    /// The refusal for a directory above the data directory, by the check
    /// and by the start, naming `place`, with nothing made.
    #[cfg(unix)]
    fn assert_refused_above(data: &Path, place: &Path, principal: &str) {
        for e in [
            Lock::creatable(data).unwrap_err(),
            Lock::take(data).unwrap_err(),
        ] {
            assert_eq!(e.code, Code::DataDirAncestorWritable, "{e}");
            assert_eq!(e.option.as_deref(), Some("data-dir"));
            assert_eq!(e.get("path"), place.to_str(), "{e}");
            let shown = e.render();
            assert!(shown.contains(principal), "{shown}");
            assert!(
                shown.contains("who is not permitted to change the daemon's data directory"),
                "{shown}"
            );
        }
        assert!(!data.exists(), "nothing is made at {}", data.display());
    }

    /// A directory at `path` with exactly `mode`.
    #[cfg(unix)]
    fn dir_with_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A directory above the data directory that another account can write
    /// refuses, world-writable, sticky world-writable and group-writable
    /// alike, before anything is made. Red edit: skip a sticky directory,
    /// and the data directory is made under it.
    #[cfg(unix)]
    #[test]
    fn a_writable_ancestor_refuses_before_anything_is_made() {
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        for (name, mode, principal) in [
            ("world", 0o777, "world-writable"),
            ("sticky", 0o1777, "world-writable"),
            ("group", 0o770, "its group"),
        ] {
            let above = d.path().join(name);
            dir_with_mode(&above, mode);
            let data = above.join("home").join("testnet");
            assert_refused_above(&data, &above, principal);
            assert!(!above.join("home").exists(), "{name}");
        }
    }

    /// The race Copilot found on #1533: an account that can write a parent
    /// swaps it for a link, and the path lands on a directory of this
    /// account's elsewhere. The start refuses before it makes or changes
    /// anything. Red edit: drop the ancestor check, and the lock file is
    /// made in `elsewhere/child`.
    #[cfg(unix)]
    #[test]
    fn the_ancestor_link_race_is_refused_before_anything_is_made() {
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let writable = d.path().join("writable");
        dir_with_mode(&writable, 0o777);
        let elsewhere = d.path().join("elsewhere");
        dir_with_mode(&elsewhere, 0o700);
        let child = elsewhere.join("child");
        dir_with_mode(&child, 0o750);
        let swapped = writable.join("swapped");
        std::os::unix::fs::symlink(&elsewhere, &swapped).unwrap();

        let e = Lock::take(&swapped.join("child")).unwrap_err();
        assert_eq!(e.code, Code::DataDirAncestorWritable, "{e}");
        assert_eq!(e.get("path"), writable.to_str());
        assert_eq!(mode_of(&child), 0o750, "its mode is not changed");
        assert!(!child.join(LOCK_FILE).exists(), "nothing is made in it");
        assert_refused_above(&swapped.join("new"), &writable, "world-writable");
        assert!(!elsewhere.join("new").exists());
    }

    /// Both legs of a symbolic link are judged: the directory that holds
    /// it, and every directory above where it resolves, through a chain of
    /// links and a relative target too. A link between safe directories
    /// passes. Red edit: judge only the path as spelled, and the links out
    /// of `safe` are accepted.
    #[cfg(unix)]
    #[test]
    fn both_legs_of_a_symbolic_link_are_judged() {
        use std::os::unix::fs::symlink;
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let safe = d.path().join("safe");
        dir_with_mode(&safe, 0o700);
        let target = safe.join("target");
        dir_with_mode(&target, 0o700);
        let writable = d.path().join("writable");
        dir_with_mode(&writable, 0o777);
        let under_writable = writable.join("target");
        dir_with_mode(&under_writable, 0o700);

        // A link inside a writable directory, to a safe target.
        let held = writable.join("held");
        symlink(&target, &held).unwrap();
        assert_refused_above(&held.join("data"), &writable, "world-writable");

        // A link in a safe directory, to a target under a writable one.
        let out = safe.join("out");
        symlink(&under_writable, &out).unwrap();
        assert_refused_above(&out.join("data"), &writable, "world-writable");

        // A chain: safe, through a link held in the writable directory.
        let chain = safe.join("chain");
        symlink(&held, &chain).unwrap();
        assert_refused_above(&chain.join("data"), &writable, "world-writable");

        // A relative target.
        let relative = safe.join("relative");
        symlink("../writable/target", &relative).unwrap();
        let e = Lock::creatable(&relative.join("data")).unwrap_err();
        assert_eq!(e.code, Code::DataDirAncestorWritable, "{e}");

        // Between safe directories, the start goes on.
        let good = safe.join("good");
        symlink(&target, &good).unwrap();
        let _held = Lock::take(&good.join("data")).unwrap();
        assert!(target.join("data").join(LOCK_FILE).is_file());
    }

    /// A chain of links to the configuration file is judged at every link:
    /// `safe/config -> safe/alias -> writable/config`. Red edit: follow only
    /// the first link, and the file is read through `writable`.
    #[cfg(unix)]
    #[test]
    fn a_chain_of_links_to_the_configuration_file_is_judged_to_its_end() {
        use std::os::unix::fs::{symlink, OpenOptionsExt};
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let safe = d.path().join("safe");
        dir_with_mode(&safe, 0o700);
        let writable = d.path().join("writable");
        dir_with_mode(&writable, 0o777);
        let target = writable.join("config.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .unwrap();
        let alias = safe.join("alias.toml");
        symlink(&target, &alias).unwrap();
        let config = safe.join("config.toml");
        symlink(&alias, &config).unwrap();
        let e = crate::file::open(&config, true).unwrap_err();
        assert_eq!(e.code, Code::FilePermissions, "{e}");
        assert_eq!(e.get("path"), writable.to_str());
    }

    /// A file on the path is not a directory to judge, however writable: the
    /// start calls the path unusable. Red edit: keep the file in the walk,
    /// and this reads as a writable ancestor.
    #[cfg(unix)]
    #[test]
    fn a_file_on_the_path_is_unusable_not_a_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let file = d.path().join("file");
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let e = Lock::creatable(&file.join("data")).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable, "{e}");
    }

    /// A cycle of links ends the walk and refuses. Spelled through `..`,
    /// each turn is a longer path, so comparing paths alone would not end
    /// it. Red edit: drop the bound on links followed, and this never
    /// returns.
    #[cfg(unix)]
    #[test]
    fn a_cycle_of_links_above_the_data_directory_is_refused() {
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let safe = d.path().join("safe");
        dir_with_mode(&safe, 0o700);
        let cycle = safe.join("cycle");
        std::os::unix::fs::symlink("../safe/cycle", &cycle).unwrap();
        let e = Lock::creatable(&cycle.join("data")).unwrap_err();
        assert_eq!(e.code, Code::DataDirAncestorWritable, "{e}");
        assert!(e.render().contains("unreadable"), "{e}");
    }

    /// macOS's `/var` is a link to `/private/var`, and both legs are
    /// root's, so a path through it passes. Red edit: refuse any link.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_var_link_passes() {
        assert_eq!(
            std::fs::read_link("/var").unwrap(),
            Path::new("private/var")
        );
        crate::file::refuse_writable_ancestor(Path::new("/var/empty/shekyl-not-made")).unwrap();
    }

    /// Every fixture's real check passes, and this prints what it read: the
    /// CI log's record of the fixture root's ancestors (`nextest.toml` shows
    /// this one test's output on success). A fixture root that stopped
    /// passing would fail every daemon test; this names why.
    #[cfg(unix)]
    #[test]
    fn the_fixture_root_passes_the_real_check() {
        use std::os::unix::fs::MetadataExt;
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let data = d.path().join("data");
        for dir in crate::file::directories_through(&data).unwrap() {
            let meta = std::fs::metadata(&dir).unwrap();
            println!(
                "fixture ancestor: mode {:04o} uid {} {}",
                meta.mode() & shekyl_os_account::directory::PERMISSION_BITS,
                meta.uid(),
                dir.display()
            );
        }
        crate::file::refuse_writable_ancestor(&data).unwrap();
    }

    /// An existing data directory other accounts can enter is refused, by
    /// the check as by the start, naming the directory and the fix, with
    /// nothing made in it and its mode left as the operator set it. Red
    /// edit: drop the check, and the lock is taken in it.
    #[cfg(unix)]
    #[test]
    fn an_existing_0755_data_directory_is_refused_with_the_named_fix() {
        use std::os::unix::fs::PermissionsExt;
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
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
            std::fs::Permissions::from_mode(crate::directory::OWNER_ONLY_DIR_MODE),
        )
        .unwrap();
        Lock::take(&data).unwrap();
    }

    /// A symbolic link is not a data directory, even when it names one this
    /// account owns at mode 0700. `metadata` would follow it and accept it.
    /// Red edit: follow the link, and the start proceeds in the target.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_data_directory_is_unusable() {
        use std::os::unix::fs::PermissionsExt;
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(
            &real,
            std::fs::Permissions::from_mode(crate::directory::OWNER_ONLY_DIR_MODE),
        )
        .unwrap();
        let link = d.path().join("data");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for e in [
            Lock::creatable(&link).unwrap_err(),
            Lock::take(&link).unwrap_err(),
        ] {
            assert_eq!(e.code, Code::DataDirUnusable);
            assert_eq!(e.option.as_deref(), Some("data-dir"));
            let shown = e.render();
            assert!(shown.contains("symbolic link"), "{shown}");
            assert!(!shown.contains("chmod 700"), "{shown}");
        }
        assert!(!link.join(LOCK_FILE).exists());
        assert!(!real.join(LOCK_FILE).exists());
    }

    /// Mode 0600 is this account's alone, so it is not exposed, and it is
    /// still unusable: the account cannot enter a directory with no search
    /// bit. Red edit: treat every mode other than 0700 as exposed.
    #[cfg(unix)]
    #[test]
    fn a_0600_data_directory_is_unusable_not_exposed() {
        use std::os::unix::fs::PermissionsExt;
        // Root searches a directory with no search bit, so nothing refuses.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let data = d.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o600)).unwrap();
        for e in [
            Lock::creatable(&data).unwrap_err(),
            Lock::take(&data).unwrap_err(),
        ] {
            assert_eq!(e.code, Code::DataDirUnusable, "{}", e.render());
        }
        assert_eq!(mode_of(&data), 0o600, "the daemon does not change it");
        assert!(!data.join(LOCK_FILE).exists());
    }

    #[test]
    fn a_data_directory_that_is_a_file_is_unusable() {
        let d = shekyl_os_account::test_fixture::tempdir().unwrap();
        let not_a_dir = d.path().join("data");
        std::fs::write(&not_a_dir, "").unwrap();
        let e = Lock::take(&not_a_dir).unwrap_err();
        assert_eq!(e.code, Code::DataDirUnusable);
    }
}
