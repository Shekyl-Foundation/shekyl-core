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

/// The service's rendezvous directory, fixed per platform (`RPC_CHANNEL.md`
/// §7.1): what the installer or the service manager creates, never the
/// daemon. On FreeBSD that is the rc.d script's `start_precmd`
/// (`contrib/packaging/freebsd/shekyld`); `/var/run` is FreeBSD's, which has
/// no `/run`.
#[must_use]
pub fn service_rendezvous() -> Option<PathBuf> {
    if cfg!(target_os = "linux") {
        Some(PathBuf::from("/run/shekyl"))
    } else if cfg!(target_os = "freebsd") {
        Some(PathBuf::from("/var/run/shekyl"))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from("/Library/Application Support/Shekyl"))
    } else if cfg!(windows) {
        program_data().map(|pd| pd.join("shekyl"))
    } else {
        None
    }
}

/// This account's and this machine's roots, as the daemon's configuration
/// takes them: the one constructor the daemon's start, the snapshot export
/// and the utilities' default data directory share.
#[must_use]
pub fn current() -> shekyl_daemon_config::Platform {
    shekyl_daemon_config::Platform {
        home: account_home(),
        program_data: program_data(),
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

    /// The service's rendezvous directory is this platform's fixed one
    /// (`RPC_CHANNEL.md` §7.1). Without a directory a service start is
    /// refused on that platform, so a platform left out cannot run a
    /// service at all.
    #[test]
    fn the_service_rendezvous_directory_is_this_platforms() {
        let expected = if cfg!(target_os = "linux") {
            Some("/run/shekyl")
        } else if cfg!(target_os = "freebsd") {
            Some("/var/run/shekyl")
        } else if cfg!(target_os = "macos") {
            Some("/Library/Application Support/Shekyl")
        } else {
            None
        };
        assert_eq!(service_rendezvous(), expected.map(PathBuf::from));
    }

    #[test]
    fn the_passwd_home_is_an_absolute_existing_directory() {
        let home = account_home().expect("the test account has a passwd entry");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.is_dir(), "{}", home.display());
    }
}
