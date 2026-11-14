// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The account's home, from the operating system's account interface
//! (IG-13): the passwd entry on Unix, the local application data folder on
//! Windows. Never `HOME`, `XDG_*` or `%APPDATA%`. The daemon's
//! configuration takes the result as a value (`shekyl_daemon_config::Platform`).
//! Process hardening is [`crate::harden`].

use std::path::PathBuf;

/// The calling account's home directory, or `None` when the account has
/// none or it cannot be read.
#[cfg(unix)]
#[must_use]
pub fn account_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: no preconditions; returns the effective user id.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: `passwd` is plain data; a zeroed value is a valid out-struct
    // for `getpwuid_r` to fill.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `entry`, `buffer` and `found` are live locals of the sizes
    // passed; the call writes the entry's strings into `buffer`, which
    // outlives every read of `entry` below.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut entry,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
            &raw mut found,
        )
    };
    if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points at a NUL-terminated string inside `buffer`.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    if dir.to_bytes().is_empty() {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
}

/// The calling account's local application data folder.
#[cfg(windows)]
#[must_use]
pub fn account_home() -> Option<PathBuf> {
    shekyl_win_sec::known_folder::local_app_data()
}

/// Ignores `SIGPIPE`, so a peer closing a socket mid-write is an error
/// the writer sees, not a signal that ends the process. Called once by the
/// daemon's signal owner at start; the notify runner changes no
/// disposition (DC-F12).
#[cfg(unix)]
pub fn ignore_sigpipe() {
    // SAFETY: `signal(2)` with a constant signal and the `SIG_IGN`
    // constant; it reads and writes no memory of ours.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// `%ProgramData%` on Windows; `None` elsewhere.
#[must_use]
pub fn program_data() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        shekyl_win_sec::known_folder::program_data()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The account's per-user session directory, from the platform's own
/// interface, never `XDG_RUNTIME_DIR` (IG-Q14): `/run/user/<euid>` on Linux
/// when it is a directory (the session, or linger, keeps it), and
/// `confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS. `None` elsewhere and when
/// absent. What is found is only a candidate: the owner's socket asserts
/// its owner and mode before binding (`RPC_CHANNEL.md` §7.1).
#[must_use]
pub fn session_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: no preconditions; returns the effective user id.
        let uid = unsafe { libc::geteuid() };
        let dir = PathBuf::from(format!("/run/user/{uid}"));
        std::fs::symlink_metadata(&dir)
            .is_ok_and(|meta| meta.is_dir())
            .then_some(dir)
    }
    #[cfg(target_os = "macos")]
    {
        darwin_user_temp_dir()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`: the per-user, per-boot temporary
/// directory macOS keeps for the account, with no environment read.
#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = vec![0u8; 1024];
    // SAFETY: `buffer` is a live allocation of the length passed; `confstr`
    // writes at most that many bytes, NUL included, and returns the length
    // it needs.
    let needed = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    };
    if needed == 0 || needed > buffer.len() {
        return None;
    }
    // `needed` counts the terminating NUL.
    buffer.truncate(needed - 1);
    let dir = PathBuf::from(OsStr::from_bytes(&buffer));
    // The interface's spelling ends in a separator; the directory is the
    // same without it.
    Some(dir.components().collect())
}

/// Linux (`RuntimeDirectory=shekyl`). The launch-recipe gate does not
/// read this one; the unit's `RuntimeDirectory` is that check.
const LINUX_SERVICE_RENDEZVOUS: &str = "/run/shekyl";

/// FreeBSD (`contrib/packaging/freebsd/shekyld`). `/var/run` is FreeBSD's;
/// the base system has no `/run`. The launch-recipe gate reads this
/// constant and requires the rc.d script to create it.
const FREEBSD_SERVICE_RENDEZVOUS: &str = "/var/run/shekyl";

/// macOS, created by the installer.
const MACOS_SERVICE_RENDEZVOUS: &str = "/Library/Application Support/Shekyl";

/// The directory under `%ProgramData%` on Windows. The service-manager
/// dispatcher that checks it is RT-W14's and is not built yet; the leaf
/// is named now so the row is not a special case added later.
const WINDOWS_SERVICE_RENDEZVOUS_LEAF: &str = "shekyl";

/// The fixed rendezvous directory for `os` (`std::env::consts::OS`), or
/// `None` when that operating system has no fixed directory. Windows is
/// `None` here: its directory is [`windows_service_rendezvous`].
fn fixed_service_rendezvous(os: &str) -> Option<&'static str> {
    match os {
        "linux" => Some(LINUX_SERVICE_RENDEZVOUS),
        "freebsd" => Some(FREEBSD_SERVICE_RENDEZVOUS),
        "macos" => Some(MACOS_SERVICE_RENDEZVOUS),
        _ => None,
    }
}

/// `%ProgramData%\shekyl`. `program_data` is the known-folder root.
fn windows_service_rendezvous(program_data: &std::path::Path) -> PathBuf {
    program_data.join(WINDOWS_SERVICE_RENDEZVOUS_LEAF)
}

/// The service's rendezvous directory, fixed per platform (`RPC_CHANNEL.md`
/// §7.1): what the installer or the service manager creates, never the
/// daemon. The paths are data, so a test on any host pins every platform.
/// A platform with no row has no directory, and a service start there is
/// refused. Windows is the one derived row, in flight until RT-W14.
#[must_use]
pub fn service_rendezvous() -> Option<PathBuf> {
    if let Some(directory) = fixed_service_rendezvous(std::env::consts::OS) {
        return Some(PathBuf::from(directory));
    }
    program_data().map(|dir| windows_service_rendezvous(&dir))
}

/// Linux: systemd's `StateDirectory` root. The launch-recipe gate reads
/// this constant and requires the packaged unit's `StateDirectory` to be
/// the data home under it, at mode 0700.
const LINUX_SERVICE_PARENT: &str = "/var/lib";

/// FreeBSD (`contrib/packaging/freebsd/shekyld`). The launch-recipe gate
/// reads this constant and requires the rc.d script's prestart to create
/// the data home under it, at mode 0700.
const FREEBSD_SERVICE_PARENT: &str = "/var/db";

/// macOS; the installer creates the data home under it.
const MACOS_SERVICE_PARENT: &str = "/var/db";

/// The fixed parent of a service's data home for `os`
/// (`std::env::consts::OS`), or `None` when that operating system has no
/// fixed one. Windows is `None` here: its parent is [`program_data`].
fn fixed_service_parent(os: &str) -> Option<&'static str> {
    match os {
        "linux" => Some(LINUX_SERVICE_PARENT),
        "freebsd" => Some(FREEBSD_SERVICE_PARENT),
        "macos" => Some(MACOS_SERVICE_PARENT),
        _ => None,
    }
}

/// The machine-wide parent of a service's data home, `shekyl` under it
/// (Rick, 2026-11-14, amending IG-Q36 and `RPC_CHANNEL.md` §7.1):
/// `/var/lib` on Linux, `/var/db` on FreeBSD and macOS, `%ProgramData%` on
/// Windows. The service manager, the rc.d script or the installer creates
/// `shekyl` there; the daemon checks it and never creates it. The paths are
/// data, so a test on any host pins every platform.
#[must_use]
pub fn service_parent() -> Option<PathBuf> {
    fixed_service_parent(std::env::consts::OS)
        .map(PathBuf::from)
        .or_else(program_data)
}

/// This account's and this machine's roots, as the daemon's configuration
/// takes them: the one constructor the daemon's start, the snapshot export
/// and the utilities' default data directory share.
#[must_use]
pub fn current() -> shekyl_daemon_config::Platform {
    shekyl_daemon_config::Platform {
        home: account_home(),
        service_parent: service_parent(),
        session_dir: session_dir(),
        service_rendezvous: service_rendezvous(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The passwd home is absolute and exists for the account the tests
    /// run under; it is read without consulting `HOME`.
    /// On Linux the session directory is `/run/user/<euid>`, or none; it is
    /// never what `XDG_RUNTIME_DIR` says. The test sets that variable to a
    /// directory that exists and is not the session directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_session_directory_is_the_uids_and_not_the_environments() {
        let elsewhere = tempfile::tempdir().expect("a directory");
        // SAFETY: test-only; no other thread in this test binary reads the
        // environment while this test runs (the crate's tests read none).
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", elsewhere.path()) };
        // SAFETY: no preconditions.
        let uid = unsafe { libc::geteuid() };
        let expected = PathBuf::from(format!("/run/user/{uid}"));
        match session_dir() {
            Some(found) => assert_eq!(found, expected),
            None => assert!(!expected.is_dir(), "{} exists", expected.display()),
        }
    }

    #[test]
    fn the_passwd_home_is_an_absolute_existing_directory() {
        let home = account_home().expect("the test account has a passwd entry");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.is_dir(), "{}", home.display());
    }
}

/// The rendezvous and data-home rows, on every host. A `cfg!` ladder would
/// leave FreeBSD's paths unexecuted on the Linux runners, and a second copy of
/// that ladder would stay green when both copies moved together.
#[cfg(test)]
mod service_directories {
    use std::path::{Path, PathBuf};

    use super::{
        fixed_service_parent, fixed_service_rendezvous, program_data, service_parent,
        service_rendezvous, windows_service_rendezvous,
    };

    /// Every platform's directory is the ruled one (`RPC_CHANNEL.md`
    /// §7.1). Red edit: return another FreeBSD path from
    /// `fixed_service_rendezvous` and this fails on a Linux runner.
    /// Windows' leaf is joined here without a Windows host: the
    /// dispatcher that checks the directory is RT-W14's, still unbuilt,
    /// and the path is not dead.
    #[test]
    fn every_platforms_service_rendezvous_directory_is_the_ruled_one() {
        assert_eq!(fixed_service_rendezvous("linux"), Some("/run/shekyl"));
        assert_eq!(fixed_service_rendezvous("freebsd"), Some("/var/run/shekyl"));
        assert_eq!(
            fixed_service_rendezvous("macos"),
            Some("/Library/Application Support/Shekyl")
        );
        assert_eq!(fixed_service_rendezvous("windows"), None);
        assert_eq!(fixed_service_rendezvous("openbsd"), None);
        assert_eq!(
            windows_service_rendezvous(Path::new(r"C:\ProgramData")),
            PathBuf::from(r"C:\ProgramData").join("shekyl")
        );
        let expected = fixed_service_rendezvous(std::env::consts::OS)
            .map(PathBuf::from)
            .or_else(|| program_data().map(|dir| windows_service_rendezvous(&dir)));
        assert_eq!(service_rendezvous(), expected);
    }

    /// Every platform's data-home parent is the ruled one (Rick,
    /// 2026-11-14). Red edit: return another FreeBSD parent from
    /// `fixed_service_parent` and this fails on a Linux runner.
    #[test]
    fn every_platforms_service_data_home_parent_is_the_ruled_one() {
        assert_eq!(fixed_service_parent("linux"), Some("/var/lib"));
        assert_eq!(fixed_service_parent("freebsd"), Some("/var/db"));
        assert_eq!(fixed_service_parent("macos"), Some("/var/db"));
        assert_eq!(fixed_service_parent("windows"), None);
        assert_eq!(fixed_service_parent("openbsd"), None);
        let expected = fixed_service_parent(std::env::consts::OS)
            .map(PathBuf::from)
            .or_else(program_data);
        assert_eq!(service_parent(), expected);
    }
}
