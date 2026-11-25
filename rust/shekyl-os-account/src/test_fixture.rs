// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a test keeps a daemon's data directory (Rick, 2026-11-23).
//!
//! The daemon refuses a data directory under a directory another account
//! can write, the system's temporary directory included, and a test does
//! not get an exception. So on Unix a fixture lives under the account's
//! home, in `~/.shekyl-test/<pid>-<name>`, and the real check runs on it. A
//! checkout under a group umask, or a CI workspace another account owns,
//! would not pass that check, so the build's target directory is not used.
//!
//! Each directory carries its test process's pid and is removed when the
//! test ends. One a killed test left behind is removed by the next run,
//! once its pid is no longer running. On Windows the check does not apply
//! and a fixture stays in the temporary directory.
//!
//! Test-only: the feature is enabled on dev-dependency edges alone
//! (`scripts/ci/check_test_only_features.py`).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The directory in the account's home that holds every fixture.
pub const FIXTURE_ROOT_NAME: &str = ".shekyl-test";

/// A test's own directory, removed when the value drops, a panic's unwind
/// included.
#[derive(Debug)]
pub struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        // A failure leaves it for the next run's sweep.
        drop(std::fs::remove_dir_all(&self.path));
    }
}

/// A new owner-only directory for this test, `<pid>-<n>` under the root.
///
/// # Errors
/// The account has no home, or the directory could not be made.
pub fn tempdir() -> io::Result<FixtureDir> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = root()?;
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(crate::OWNER_ONLY_DIR_MODE);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{}-{n}", std::process::id()));
        match builder.create(&path) {
            Ok(()) => return Ok(FixtureDir { path }),
            // A recycled pid's directory the sweep has not reached.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

/// The path of this test process's fixture called `name`, not yet made, for
/// a harness that makes and removes its data directory itself.
///
/// # Errors
/// The account has no home, or the fixture root could not be made.
#[cfg(unix)]
pub fn path(name: &str) -> io::Result<PathBuf> {
    Ok(root()?.join(format!("{}-{name}", std::process::id())))
}

/// The path of this test process's fixture called `name`, not yet made.
///
/// # Errors
/// None on this platform; the signature is the Unix one.
#[cfg(not(unix))]
pub fn path(name: &str) -> io::Result<PathBuf> {
    Ok(root()?.join(format!("{}-{name}", std::process::id())))
}

/// The temporary directory: the data directory's ancestor check is Unix's.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps, reason = "the signature is the Unix one")]
fn root() -> io::Result<PathBuf> {
    Ok(std::env::temp_dir())
}

/// `~/.shekyl-test`, made if missing. The first call in a process removes
/// what dead test processes left there.
#[cfg(unix)]
fn root() -> io::Result<PathBuf> {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    let home = crate::account_home().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "this account has no home directory",
        )
    })?;
    let root = home.join(FIXTURE_ROOT_NAME);
    crate::create_account_dir_all(&root)?;
    SWEPT.call_once(|| sweep(&root));
    Ok(root)
}

/// Removes the fixtures in `root` whose process is gone. A name that is not
/// `<pid>-<name>` is not a fixture and is left alone. A recycled pid only
/// delays a removal to a later run.
#[cfg(unix)]
fn sweep(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(fixture_pid) else {
            continue;
        };
        if !process_is_running(pid) {
            // Another run's sweep may have got there first.
            drop(std::fs::remove_dir_all(entry.path()));
        }
    }
}

/// The pid in a fixture's name.
#[cfg(unix)]
fn fixture_pid(name: &str) -> Option<i32> {
    let (pid, rest) = name.split_once('-')?;
    if rest.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok().filter(|pid| *pid > 0)
}

/// Whether a process with this pid exists. A process another account owns
/// answers `EPERM`, which is still a running process.
#[cfg(unix)]
#[allow(unsafe_code, reason = "kill has no safe wrapper in std")]
fn process_is_running(pid: i32) -> bool {
    // SAFETY: signal 0 delivers nothing; the call only checks the pid, which
    // `fixture_pid` guarantees is positive, so it names one process.
    let answered = unsafe { libc::kill(pid, 0) };
    answered == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn only_a_pid_and_a_name_is_a_fixture() {
        assert_eq!(fixture_pid("123-abc"), Some(123));
        assert_eq!(fixture_pid("123-a-b"), Some(123));
        for not_one in ["abc", "123", "123-", "-abc", "+12-abc", "0-abc", "x1-abc"] {
            assert_eq!(fixture_pid(not_one), None, "{not_one}");
        }
    }

    /// A dead process's directory goes; this process's, and a directory that
    /// is not a fixture, stay. Red edit: drop the liveness test, and this
    /// process's own directory is removed.
    #[test]
    fn the_sweep_removes_only_what_a_dead_process_left() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("a process that ends");
        let dead = child.id();
        child.wait().expect("it ended");
        let left = scratch.path().join(format!("{dead}-left"));
        let mine = scratch.path().join(format!("{}-mine", std::process::id()));
        let other = scratch.path().join("not-a-fixture");
        for dir in [&left, &mine, &other] {
            std::fs::create_dir(dir).expect("made");
        }
        sweep(scratch.path());
        assert!(!left.exists(), "a dead process's fixture");
        assert!(mine.exists(), "this process's fixture");
        assert!(other.exists(), "not a fixture");
    }

    #[test]
    fn a_fixture_is_named_for_this_process_under_the_root_and_removed() {
        let dir = tempdir().expect("a fixture");
        let name = dir
            .path()
            .file_name()
            .expect("a name")
            .to_str()
            .expect("utf8");
        assert_eq!(
            fixture_pid(name),
            Some(i32::try_from(std::process::id()).unwrap())
        );
        let root = crate::account_home()
            .expect("a home")
            .join(FIXTURE_ROOT_NAME);
        assert_eq!(dir.path().parent(), Some(root.as_path()));
        let kept = dir.path().to_path_buf();
        drop(dir);
        assert!(!kept.exists(), "removed when the test ends");
    }
}
