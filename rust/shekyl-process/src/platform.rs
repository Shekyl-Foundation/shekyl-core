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

/// This account's and this machine's roots, as the daemon's configuration
/// takes them: the one constructor the daemon's start, the snapshot export
/// and the utilities' default data directory share.
#[must_use]
pub fn current() -> shekyl_daemon_config::Platform {
    shekyl_daemon_config::Platform {
        home: account_home(),
        program_data: program_data(),
        // The session directory is read where the client that resolves
        // "this computer" reads it (`RPC_CHANNEL.md` RT-15): one reader.
        session_dir: shekyl_os_account::session_dir(),
        service_rendezvous: service_rendezvous(),
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

/// The rendezvous rows, on every host. A `cfg!` ladder would leave
/// FreeBSD's path unexecuted on the Linux runners, and a second copy of
/// that ladder would stay green when both copies moved together.
#[cfg(test)]
mod service_rendezvous_directories {
    use std::path::{Path, PathBuf};

    use super::{
        fixed_service_rendezvous, program_data, service_rendezvous, windows_service_rendezvous,
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
}
