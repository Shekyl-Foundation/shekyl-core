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

    let uid = shekyl_os_account::effective_uid();
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
        // The session directory is read where the client that resolves
        // "this computer" reads it (`RPC_CHANNEL.md` RT-15): one reader.
        session_dir: shekyl_os_account::session_dir(),
        service_rendezvous: shekyl_rpc_rendezvous::service_rendezvous(),
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

/// The data-home rows, on every host. A `cfg!` ladder would leave FreeBSD's
/// paths unexecuted on the Linux runners, and a second copy of that ladder
/// would stay green when both copies moved together. The rendezvous rows'
/// test is with the rows, in `shekyl-rpc-rendezvous`.
#[cfg(test)]
mod service_directories {
    use std::path::PathBuf;

    use super::{fixed_service_parent, program_data, service_parent};

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
