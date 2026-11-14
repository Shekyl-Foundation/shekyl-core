// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A connected pair, one end for this process and one for a child, and the
//! window that hands the child its end.
//!
//! Unix: a `socketpair`, both ends close-on-exec as std makes them. The
//! child's end is made inheritable in the child only, after `fork`
//! ([`ChildKeeps`]), so no other spawn can inherit it, concurrent or not.
//!
//! Windows: a loopback TCP pair, accepted only from our own connect, both ends
//! not inheritable as std makes them. The parent's copy of the child's end is
//! marked inheritable around the spawn, under [`crate::spawn_lock`], and closed
//! before the lock is released ([`EndPair::spawn`]).
//!
//! **The parent's copy of the child's end is closed before the lock is
//! released.** While the parent holds it, the connection stays open whatever
//! the child does, and a read on the parent's end would never see the child's
//! death. On Windows the lock depends on the close too: a failed inherit-bit
//! clear must not leave the socket open and inheritable after the guard drops
//! (`TOR_SUPERVISOR.md` `TSR-F16`).

use std::io;

/// One end of the pair.
#[cfg(unix)]
pub type End = std::os::unix::net::UnixStream;
/// One end of the pair.
#[cfg(windows)]
pub type End = std::net::TcpStream;

/// The number a child is told its end has: a file descriptor on Unix, a
/// socket on Windows.
#[cfg(unix)]
pub type RawEnd = std::os::fd::RawFd;
/// The number a child is told its end has: a file descriptor on Unix, a
/// socket on Windows.
#[cfg(windows)]
pub type RawEnd = std::os::windows::io::RawSocket;

/// The highest standard stream. Std moves the child's stdin, stdout and stderr
/// onto 0, 1 and 2 before it runs `pre_exec`, so the child's end must be above
/// them.
#[cfg(unix)]
pub const LAST_STANDARD_STREAM: RawEnd = 2;

/// The connected pair before the spawn: this process's end, and the child's.
pub struct EndPair {
    ours: End,
    theirs: End,
}

impl EndPair {
    /// Make the connected pair.
    ///
    /// # Errors
    ///
    /// The pair could not be made, or the child's end landed on a standard
    /// stream's number: a process started with a standard stream closed hands
    /// those numbers out again, and the child's end there would be overwritten
    /// by the child's stdio.
    #[cfg(unix)]
    pub fn new() -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let (ours, theirs) = End::pair()?;
        if theirs.as_raw_fd() <= LAST_STANDARD_STREAM {
            return Err(io::Error::other(
                "the child's end landed on a standard stream's number",
            ));
        }
        Ok(Self { ours, theirs })
    }

    /// Make the connected pair. The listener is bound to loopback and accepts
    /// one connection; one that does not come from our own connect is
    /// refused, so another local process that races into the accept gets
    /// nothing and the launch fails instead.
    ///
    /// # Errors
    ///
    /// The listener, the connect or the accept failed, or the accepted peer
    /// was not our own connect.
    #[cfg(windows)]
    pub fn new() -> io::Result<Self> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let ours = End::connect(address)?;
        let (theirs, peer) = listener.accept()?;
        if Some(peer) != ours.local_addr().ok() {
            return Err(io::Error::other(
                "the pair's accepted peer was not our own connect",
            ));
        }
        Ok(Self { ours, theirs })
    }

    /// The number the child is given for its end.
    #[must_use]
    pub fn their_number(&self) -> RawEnd {
        raw_end(&self.theirs)
    }

    /// Run `spawn` with the child's end handed over, under
    /// [`crate::spawn_lock`], then close this process's copy of it before the
    /// lock is released. Returns what `spawn` returned and this process's end.
    ///
    /// `spawn` is given the child's number and does nothing but start the
    /// processes that are to inherit it: the lock is not reentrant, and a wait
    /// under it stalls every other spawn. On Unix the command must keep the
    /// end in the child ([`ChildKeeps`], [`keep_in_child`]); on Windows the
    /// end is inheritable for exactly the length of `spawn`.
    ///
    /// # Errors
    ///
    /// [`WindowError`]: the end could not be made inheritable, `spawn` failed,
    /// or this process's copy could not be closed cleanly after a spawn that
    /// succeeded (what it spawned is handed back, for the caller to stop).
    pub fn spawn<T, E>(
        self,
        spawn: impl FnOnce(RawEnd) -> Result<T, E>,
    ) -> Result<(T, End), WindowError<T, E>> {
        let Self { ours, theirs } = self;
        // Unix: the child's end reaches the children named in `spawn`, through
        // their `pre_exec`. Windows: the parent's copy is inheritable only
        // while `ParentEnd` is open inside this closure. The closure owns that
        // copy, so it is closed before `spawn_lock::with` drops the guard, on
        // every path.
        let outcome = crate::spawn_lock::with(|| {
            let window = match ParentEnd::open(theirs) {
                Ok(window) => window,
                Err(error) => return Err(WindowError::Open(error)),
            };
            let number = window.number();
            match spawn(number) {
                Ok(spawned) => match window.close() {
                    Ok(()) => Ok(spawned),
                    Err(error) => Err(WindowError::Close { spawned, error }),
                },
                Err(error) => Err(WindowError::Spawn {
                    error,
                    close: window.close().err(),
                }),
            }
        });
        outcome.map(|spawned| (spawned, ours))
    }
}

/// Why [`EndPair::spawn`] failed.
#[derive(Debug)]
pub enum WindowError<T, E> {
    /// The parent's copy could not be made inheritable (Windows); nothing was
    /// spawned, and the copy is closed.
    Open(io::Error),
    /// `spawn` failed. `close` is the inherit-bit clear's error when that
    /// failed too: the window failing open, which a caller reports in place
    /// of `error`.
    Spawn {
        /// The spawn's error.
        error: E,
        /// The clear's error, if any. The copy is closed either way.
        close: Option<io::Error>,
    },
    /// `spawn` succeeded and the inherit-bit clear did not (Windows). The copy
    /// is closed; what was spawned is handed back for the caller to stop,
    /// since a launch that fails closed must not leave it running.
    Close {
        /// What `spawn` returned.
        spawned: T,
        /// The clear's error.
        error: io::Error,
    },
}

/// The parent's copy of the child's end while the window is open.
///
/// On Windows the copy is inheritable from [`open`](Self::open) until it is
/// closed. Closing clears the inherit bit and then drops the socket. A failed
/// clear still drops the socket, so the bit cannot outlive the value. The value
/// is created and dropped inside [`crate::spawn_lock::with`], which is what
/// keeps the window private to that spawn.
struct ParentEnd {
    socket: Option<End>,
}

impl ParentEnd {
    fn open(socket: End) -> io::Result<Self> {
        if let Err(error) = set_inherit_bit(&socket, true) {
            drop(socket);
            return Err(error);
        }
        Ok(Self {
            socket: Some(socket),
        })
    }

    fn number(&self) -> RawEnd {
        raw_end(
            self.socket
                .as_ref()
                .expect("the parent's copy of the child's end is open"),
        )
    }

    /// Clear the inherit bit if this platform has one, then close. The clear's
    /// error is returned only after the socket is gone.
    fn close(mut self) -> io::Result<()> {
        self.close_socket()
    }

    fn close_socket(&mut self) -> io::Result<()> {
        let Some(socket) = self.socket.take() else {
            return Ok(());
        };
        let cleared = set_inherit_bit(&socket, false);
        drop(socket);
        cleared
    }
}

impl Drop for ParentEnd {
    fn drop(&mut self) {
        // A path that left early still closes inside the spawn lock: this value
        // is a local of the `spawn_lock::with` closure. Drop cannot report a
        // failed clear; [`ParentEnd::close`] is the path that does, and it too
        // closes before it returns the error.
        drop(self.close_socket());
    }
}

/// Set or clear the Windows inherit bit. Other targets have no such bit: the
/// child's end becomes inheritable only in the child, after `fork`.
#[cfg_attr(
    not(windows),
    allow(
        clippy::unnecessary_wraps,
        reason = "Windows can fail SetHandleInformation; other targets have no inherit bit"
    )
)]
pub(crate) fn set_inherit_bit(socket: &End, inherit: bool) -> io::Result<()> {
    #[cfg(windows)]
    return set_inheritable(socket, inherit);
    #[cfg(not(windows))]
    {
        let _ = (socket, inherit);
        Ok(())
    }
}

#[cfg(unix)]
fn raw_end(socket: &End) -> RawEnd {
    use std::os::fd::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(windows)]
fn raw_end(socket: &End) -> RawEnd {
    use std::os::windows::io::AsRawSocket;
    socket.as_raw_socket()
}

#[cfg(windows)]
fn set_inheritable(socket: &End, inherit: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    let flags = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
    // A socket from the base provider is a kernel handle. The value is
    // `usize`-wide on every Windows target; the cast restores it.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a SOCKET is pointer-sized on Windows"
    )]
    let handle = socket.as_raw_socket() as usize as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: `handle` is the socket `socket` holds open for the call's
    // duration.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Clear `FD_CLOEXEC` on `fd`.
///
/// Async-signal-safe: `fcntl` only, and [`std::io::Error::last_os_error`] reads
/// `errno` into an inline value. Called from `pre_exec`, in the child, between
/// `fork` and `exec`.
///
/// # Errors
///
/// The `fcntl` error.
#[cfg(unix)]
pub fn clear_cloexec(fd: RawEnd) -> io::Result<()> {
    // SAFETY: `fcntl` with `F_GETFD` / `F_SETFD` reads and writes only this
    // descriptor's flags. The caller is `pre_exec`, so no other thread exists
    // in the child and nothing else touches `fd`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What the child does between `fork` and `exec` to keep its end and nothing
/// else: mark every descriptor from 3 up close-on-exec
/// ([`crate::inherit::StdioOnly`]: a descriptor opened without the flag must
/// not reach the child), then clear the flag on the child's end alone. The
/// parent's copy keeps it, so no other spawn can inherit the end.
///
/// Made in the parent, before `fork`; [`apply`](Self::apply) runs in the child.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct ChildKeeps {
    stdio_only: crate::inherit::StdioOnly,
    end: RawEnd,
}

#[cfg(unix)]
impl ChildKeeps {
    /// Prepare the child's setup for `end`.
    #[must_use]
    pub fn prepare(end: RawEnd) -> Self {
        Self {
            stdio_only: crate::inherit::StdioOnly::prepare(),
            end,
        }
    }

    /// Run in the child, from `pre_exec`. Async-signal-safe.
    ///
    /// # Errors
    ///
    /// A descriptor could not be marked, or the end's flag not cleared. The
    /// spawn then fails with it.
    pub fn apply(&self) -> io::Result<()> {
        self.stdio_only.apply()?;
        clear_cloexec(self.end)
    }
}

/// Make `cmd`'s child keep `end` and nothing beyond its standard streams.
///
/// For a `std` command. A command of another library installs
/// [`ChildKeeps::apply`] in its own `pre_exec`. On Windows nothing is set on
/// the command: the end is inheritable for the length of the spawn
/// ([`EndPair::spawn`]).
#[cfg(unix)]
pub fn keep_in_child(cmd: &mut std::process::Command, end: RawEnd) {
    use std::os::unix::process::CommandExt;
    let keeps = ChildKeeps::prepare(end);
    // SAFETY: the closure runs in the child between `fork` and `exec`, and
    // [`ChildKeeps::apply`] is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || keeps.apply());
    }
}

/// Windows: nothing is set on the command (module docs).
#[cfg(windows)]
pub fn keep_in_child(_cmd: &mut std::process::Command, _end: RawEnd) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Set only in the child: the number of the end it was handed.
    const CHILD_END: &str = "SHEKYL_SPAWN_TEST_CHILD_END";

    /// The child's role: write "hello" on the end it inherited, read one
    /// byte, exit. Returns in the parent.
    fn run_child_if_requested() {
        let Some(number) = std::env::var_os(CHILD_END) else {
            return;
        };
        let number: RawEnd = number
            .to_str()
            .and_then(|n| n.parse().ok())
            .expect("an end number");
        #[cfg(unix)]
        // SAFETY: the parent handed this process the end at `number`, open and
        // owned by nothing else here.
        let mut end = unsafe { <End as std::os::fd::FromRawFd>::from_raw_fd(number) };
        #[cfg(windows)]
        // SAFETY: as on Unix: the inherited socket at `number`.
        let mut end =
            unsafe { <End as std::os::windows::io::FromRawSocket>::from_raw_socket(number) };
        end.write_all(b"hello").expect("write");
        let mut one = [0u8; 1];
        end.read_exact(&mut one).expect("read");
        std::process::exit(0);
    }

    /// This test binary again, as the child, told its end's number.
    fn child_command(test: &str, number: RawEnd) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("this binary"));
        cmd.args(["--exact", test, "--nocapture"])
            .env(CHILD_END, number.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        cmd
    }

    /// A child that inherits its end through the window can talk on it, and
    /// this process's end sees the child's death: once the child exits, a
    /// read on our end is at its end. Red edit: keep the parent's copy open
    /// past the window (skip `window.close()`) and the read never ends.
    #[test]
    fn the_child_holds_its_end_and_its_death_closes_the_connection() {
        const NAME: &str =
            "pair::tests::the_child_holds_its_end_and_its_death_closes_the_connection";
        run_child_if_requested();
        let pair = EndPair::new().expect("a pair");
        let (mut child, mut ours) = EndPair::spawn(pair, |number| -> io::Result<_> {
            let mut cmd = child_command(NAME, number);
            keep_in_child(&mut cmd, number);
            cmd.spawn()
        })
        .unwrap_or_else(|e| panic!("spawn: {e:?}"));
        let mut greeting = [0u8; 5];
        ours.read_exact(&mut greeting).expect("the child writes");
        assert_eq!(&greeting, b"hello");
        ours.write_all(b"x").expect("the child is reading");
        assert!(child.wait().expect("the child exits").success());
        // Bounded, so a parent copy left open fails here instead of hanging.
        ours.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("a read bound");
        let mut rest = Vec::new();
        ours.read_to_end(&mut rest)
            .expect("EOF once the child is gone");
        assert!(rest.is_empty());
    }

    /// A spawn that fails returns its own error, and the window still closes
    /// the parent's copy.
    #[test]
    fn a_failed_spawn_returns_its_error() {
        let pair = EndPair::new().expect("a pair");
        let failed = EndPair::spawn(pair, |_number| -> Result<(), &str> { Err("no program") });
        assert!(matches!(
            failed,
            Err(WindowError::Spawn {
                error: "no program",
                close: None
            })
        ));
    }
}
