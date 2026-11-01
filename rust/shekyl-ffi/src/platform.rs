// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The account's home, from the operating system's account interface
//! (IG-13): the passwd entry on Unix, the local application data folder on
//! Windows. Never `HOME`, `XDG_*` or `%APPDATA%`. The daemon's
//! configuration takes the result as a value (`shekyl_daemon_config::Platform`).
//! Also the process hardening the daemon applies before it reads anything
//! ([`harden_process`], DC-Q21).

use std::path::PathBuf;

/// Why [`harden_process`] could not apply a step: the step's name and the
/// operating system's error. A daemon that cannot apply its hardening does
/// not start (`DAEMON_CONFIG_CUTOVER.md` DC-Q21).
#[derive(Debug)]
pub struct HardenError {
    /// The step that failed, as a reader would name it (`RLIMIT_CORE`,
    /// `PR_SET_DUMPABLE`).
    pub step: &'static str,
    /// The operating system's error.
    pub source: std::io::Error,
}

impl std::fmt::Display for HardenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.step, self.source)
    }
}

impl std::error::Error for HardenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The process hardening, the first statement of `shekyl_daemon::main`
/// (`DAEMON_CONFIG_CUTOVER.md` §2.2, DC-Q21): before an argument is read,
/// a file opened or a key derived, this process declares that a fatal
/// signal ends it without writing its memory to disk and that a
/// same-account process cannot attach to it. The inherited C++ ran its
/// `prctl` after the configuration had been parsed and the data directory
/// opened (DC-F21); here nothing precedes it.
///
/// - Every Unix: `RLIMIT_CORE` soft and hard limits to zero. A raised hard
///   limit cannot be restored by this process afterwards, which is the
///   point.
/// - Linux, in addition: `PR_SET_DUMPABLE` to zero, which also makes
///   `/proc/self` root-owned and refuses `ptrace` from a process that is
///   not root. The daemon reads nothing under `/proc/self` it would lose.
/// - Windows: `SetErrorMode` with `SEM_NOGPFAULTERRORBOX`, so a fault ends
///   the process instead of blocking a headless service on a dialog, and
///   `SEM_FAILCRITICALERRORS` / `SEM_NOOPENFILEERRORBOX`, so a missing
///   volume or file is an error the code sees, not a prompt. Windows Error
///   Reporting's dump collection is excluded at install time
///   (`contrib/packaging/windows/shekyl.nsi`, the `ExcludedApplications`
///   value), because that is a per-machine setting, not a per-process one.
///
/// # Errors
///
/// The step that failed, with the operating system's error. Lowering a
/// limit to zero and clearing the dumpable flag are permitted to every
/// process, so a failure here is a broken platform, and the caller refuses
/// to start rather than run undumpable-in-name-only.
pub fn harden_process() -> Result<(), HardenError> {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit(2)` reads the `rlimit` struct behind a valid
        // pointer to a live local; it writes no memory of ours.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) } != 0 {
            return Err(HardenError {
                step: "RLIMIT_CORE",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(2)` with `PR_SET_DUMPABLE` takes one integer
        // argument; the trailing zeros are the unused arguments the
        // interface documents as ignored for this option.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(HardenError {
                step: "PR_SET_DUMPABLE",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
        };
        // SAFETY: `SetErrorMode` takes a flags word and returns the
        // previous one; it touches no memory of ours and cannot fail.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        }
    }
    Ok(())
}

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

    /// After hardening, the core limit reads back as zero on both bounds:
    /// the process can write no core and cannot raise the limit again.
    #[test]
    fn hardening_zeroes_the_core_limit_on_both_bounds() {
        harden_process().expect("hardening applies to an ordinary process");
        let mut read = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `getrlimit(2)` writes the struct behind a valid pointer
        // to a live local.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut read) };
        assert_eq!(rc, 0);
        assert_eq!((read.rlim_cur, read.rlim_max), (0, 0));
    }

    /// On Linux the dumpable flag reads back clear as well.
    #[cfg(target_os = "linux")]
    #[test]
    fn hardening_clears_the_dumpable_flag() {
        harden_process().expect("hardening applies to an ordinary process");
        // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointer arguments and
        // returns the flag.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }
}
