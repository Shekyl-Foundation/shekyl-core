// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a child of this process inherits: on Unix, its standard input, output
//! and error, and nothing else (`DAEMON_CONFIG_CUTOVER.md` §2.10).
//!
//! Rust opens every descriptor close-on-exec. C++ in the same process does not:
//! Boost.Asio's sockets (the P2P and RPC listeners and sessions), the store's
//! files and whatever a C++ library opens can lack `FD_CLOEXEC`, and each one
//! would pass into an operator's notify command or into the managed Tor.
//! [`StdioOnly::apply`] runs in the child, between `fork` and `exec`, and marks
//! every descriptor from 3 up close-on-exec, so `exec` closes them all.
//!
//! **Marked, not closed.** std reports a failed `exec` to the parent over a
//! close-on-exec descriptor it opened for the spawn (a socket pair on Linux, a
//! pipe elsewhere), and the child asserts that write succeeds. Closing every
//! descriptor in `pre_exec` would close that channel too: a missing program
//! would then read as a spawn that succeeded and a child that aborted. Marking
//! leaves the channel working and the program sees the same table, because
//! `exec` closes every marked descriptor.
//!
//! A descriptor the child must keep (the managed Tor's control end) is cleared
//! again after [`StdioOnly::apply`], in the same `pre_exec`.
//!
//! On Windows there is nothing to add: a child inherits only handles marked
//! inheritable, and the one this process marks (the managed Tor's end) is
//! covered by [`crate::spawn_lock`].

/// Descriptors below this are standard input, output and error.
#[cfg(unix)]
const FIRST_NOT_INHERITED: libc::c_int = 3;

/// The table size assumed when the platform reports none: POSIX's minimum
/// `_POSIX_OPEN_MAX` is 20, and every supported platform's default soft
/// limit is at least 256.
#[cfg(unix)]
const UNREPORTED_TABLE: libc::c_int = 1024;

/// A child that inherits standard input, output and error only.
///
/// Made in the parent, before `fork`: the descriptor table's size is read
/// here, because nothing that allocates or reads `/proc` may run in the child.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct StdioOnly {
    /// One past the highest descriptor number this process can hold.
    table: libc::c_int,
}

#[cfg(unix)]
impl StdioOnly {
    /// Read the table's size for a spawn about to happen.
    ///
    /// A descriptor at or above the size exists only if the limit was lowered
    /// after it was opened. On Linux `close_range` covers it whatever the
    /// limit; elsewhere it is not seen.
    #[must_use]
    pub fn prepare() -> Self {
        Self {
            table: table_size(),
        }
    }

    /// Mark every descriptor from 3 up close-on-exec.
    ///
    /// Async-signal-safe: `close_range` on Linux, otherwise `fcntl` over the
    /// table, and [`std::io::Error::last_os_error`] reads `errno` into an
    /// inline value. Call it from `pre_exec`, in the child.
    ///
    /// # Errors
    ///
    /// The `fcntl` error for a descriptor that is open but could not be
    /// marked. The spawn then fails with it.
    pub fn apply(&self) -> std::io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if mark_by_range() {
            return Ok(());
        }
        self.walk()
    }

    /// Mark the table one descriptor at a time: every platform but Linux,
    /// and a Linux kernel without `close_range`'s close-on-exec flag.
    fn walk(&self) -> std::io::Result<()> {
        for fd in FIRST_NOT_INHERITED..self.table {
            mark(fd)?;
        }
        Ok(())
    }
}

/// Install [`StdioOnly`] on `cmd`.
///
/// For a command whose child keeps nothing beyond standard input, output and
/// error. A launch that keeps a descriptor calls [`StdioOnly::apply`] in its
/// own `pre_exec` and clears that descriptor after it.
#[cfg(unix)]
pub fn stdio_only(cmd: &mut tokio::process::Command) {
    let stdio_only = StdioOnly::prepare();
    // SAFETY: the closure runs in the child between `fork` and `exec`, and
    // [`StdioOnly::apply`] is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || stdio_only.apply());
    }
}

/// Windows: a child inherits only handles marked inheritable (module docs).
#[cfg(windows)]
pub fn stdio_only(_cmd: &mut tokio::process::Command) {}

/// Linux 5.11 and later: one call marks the whole range. `false` on a kernel
/// that predates the call (`ENOSYS`) or its close-on-exec flag (`EINVAL`), or
/// on any other refusal, and the caller walks the table instead.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn mark_by_range() -> bool {
    // The raw call, not glibc's wrapper: the wrapper needs glibc 2.34.
    // SAFETY: `close_range` with `CLOSE_RANGE_CLOEXEC` changes only the
    // close-on-exec flags of this process's descriptors.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_NOT_INHERITED as libc::c_uint,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    marked == 0
}

/// Mark `fd` close-on-exec. A descriptor that is not open is skipped.
#[cfg(unix)]
fn mark(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `fcntl` with `F_GETFD` / `F_SETFD` reads and writes only this
    // descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(());
        }
        return Err(error);
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The descriptor table's size: the soft limit on open files.
#[cfg(unix)]
fn table_size() -> libc::c_int {
    // macOS reports the soft limit through `getdtablesize`, already capped at
    // the per-process maximum; `sysconf` can report an unlimited soft limit.
    #[cfg(target_vendor = "apple")]
    // SAFETY: `getdtablesize` reads a limit.
    let size = libc::c_long::from(unsafe { libc::getdtablesize() });
    #[cfg(not(target_vendor = "apple"))]
    // SAFETY: `sysconf` reads a limit.
    let size = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    match libc::c_int::try_from(size) {
        Ok(size) if size > FIRST_NOT_INHERITED => size,
        _ => UNREPORTED_TABLE,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// A descriptor opened without close-on-exec, as C++ opens one.
    struct Planted(libc::c_int);

    impl Planted {
        fn open() -> Self {
            // SAFETY: `open` on a NUL-terminated path; no `O_CLOEXEC`.
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= FIRST_NOT_INHERITED, "a descriptor above stdio");
            Self(fd)
        }
    }

    impl Drop for Planted {
        fn drop(&mut self) {
            // SAFETY: closes the descriptor this value opened.
            unsafe { libc::close(self.0) };
        }
    }

    /// Whether a child spawned with `install` still holds `fd`. `/dev/fd/N`
    /// is the child's own table; a redirection (`<&N`) would not do, because
    /// dash takes only one-digit descriptor numbers there, and a test
    /// process can hold ten.
    fn child_holds(fd: libc::c_int, install: impl FnOnce(&mut std::process::Command)) -> bool {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("test -e /dev/fd/{fd}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        install(&mut cmd);
        crate::spawn_lock::status(&mut cmd)
            .expect("run the shell")
            .success()
    }

    #[test]
    fn a_planted_descriptor_reaches_a_child_without_it_and_not_with_it() {
        let planted = Planted::open();
        assert!(
            child_holds(planted.0, |_| {}),
            "the planted descriptor is inheritable: the control arm sees it"
        );
        let held = child_holds(planted.0, |cmd| {
            let stdio_only = StdioOnly::prepare();
            // SAFETY: as [`stdio_only`].
            unsafe {
                cmd.pre_exec(move || stdio_only.apply());
            }
        });
        assert!(!held, "the child inherits nothing beyond stdio");
    }

    #[test]
    fn a_failed_exec_is_still_reported_to_the_parent() {
        let stdio_only = StdioOnly::prepare();
        let mut cmd = std::process::Command::new("/nonexistent/shekyl-no-such-program");
        // SAFETY: as [`stdio_only`].
        unsafe {
            cmd.pre_exec(move || stdio_only.apply());
        }
        let error = crate::spawn_lock::spawn(&mut cmd).expect_err("no such program");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn the_table_size_covers_stdio_and_more() {
        assert!(table_size() > FIRST_NOT_INHERITED);
    }

    /// The walk a kernel without `close_range` takes keeps the planted
    /// descriptor from the child too.
    #[test]
    fn the_walk_alone_keeps_a_planted_descriptor_from_the_child() {
        let planted = Planted::open();
        let held = child_holds(planted.0, |cmd| {
            let stdio_only = StdioOnly::prepare();
            // SAFETY: as [`stdio_only`]; the walk is async-signal-safe.
            unsafe {
                cmd.pre_exec(move || stdio_only.walk());
            }
        });
        assert!(!held, "the walk marks every descriptor from 3 up");
    }
}
