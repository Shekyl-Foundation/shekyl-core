// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The account's home, from the operating system's account interface
//! (IG-13): the passwd entry on Unix, the local application data folder on
//! Windows. Never `HOME`, `XDG_*` or `%APPDATA%`. The daemon's
//! configuration takes the result as a value (`shekyl_daemon_config::Platform`).

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

/// This account's and this machine's roots, as the daemon's configuration
/// takes them: the one constructor the daemon's start, the snapshot export
/// and the utilities' default data directory share.
#[must_use]
pub fn current() -> shekyl_daemon_config::Platform {
    shekyl_daemon_config::Platform {
        home: account_home(),
        program_data: program_data(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The passwd home is absolute and exists for the account the tests
    /// run under; it is read without consulting `HOME`.
    #[test]
    fn the_passwd_home_is_an_absolute_existing_directory() {
        let home = account_home().expect("the test account has a passwd entry");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.is_dir(), "{}", home.display());
    }
}
