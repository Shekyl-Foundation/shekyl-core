// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The operating-system account this process runs as, read from the
//! platform's own interface and never from the environment (IG-Q14).
//!
//! **The contract: who this account is, where its session keeps things, and
//! which account is at the other end of a local socket; nothing that dials,
//! listens or speaks a protocol.** It is a leaf with no network stack (libc
//! on Unix, `shekyl-win-sec` on Windows), so the daemon's process-hardening
//! crate and the client transport both read the account here without either
//! pulling in the other (`docs/design/RPC_CHANNEL.md` RT-15, §7.1).
//!
//! - [`effective_uid`] (Unix): this process's effective user id.
//! - [`session_dir`]: the account's per-user session directory, where a
//!   run-as-me daemon's owner's socket lives on Unix.
//! - [`account_root`]: the account's root for a rendezvous: the session
//!   directory on Unix, the local application data folder on Windows.
//! - [`peer_uid`] (Unix): the account of the process at the other end of a
//!   connected Unix socket (`SO_PEERCRED` on Linux, `getpeereid`
//!   elsewhere). On Windows the pipe's peer check is
//!   `shekyl_win_sec::open_verified`, which opens and checks in one call.

use std::path::PathBuf;

/// This process's effective user id.
#[cfg(unix)]
#[must_use]
#[allow(unsafe_code, reason = "geteuid has no safe wrapper in std")]
pub fn effective_uid() -> u32 {
    // SAFETY: no preconditions; returns the effective user id.
    unsafe { libc::geteuid() }
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
        let dir = PathBuf::from(format!("/run/user/{}", effective_uid()));
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

/// The account's root for a rendezvous: the session directory on Unix, the
/// local application data folder on Windows. `None` where there is none.
#[must_use]
pub fn account_root() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        session_dir()
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::known_folder::local_app_data()
    }
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`: the per-user, per-boot temporary
/// directory macOS keeps for the account, with no environment read.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "confstr has no safe wrapper")]
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

/// The account of the process at the other end of `socket`, a connected
/// Unix socket.
///
/// # Errors
///
/// The operating system's, when the peer's credentials cannot be read.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "SO_PEERCRED has no safe wrapper in std")]
pub fn peer_uid(socket: &impl std::os::fd::AsFd) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    // SAFETY: `ucred` is plain data; a zeroed value is a valid out-struct.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred's size fits socklen_t");
    // SAFETY: `cred` and `length` are locals of the sizes passed, and the
    // descriptor is `socket`'s, borrowed open for the call.
    let failed = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut length,
        )
    } != 0;
    if failed {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The account of the process at the other end of `socket`, a connected
/// Unix socket.
///
/// # Errors
///
/// The operating system's, when the peer's credentials cannot be read.
#[cfg(all(unix, not(target_os = "linux")))]
#[allow(unsafe_code, reason = "getpeereid has no safe wrapper in std")]
pub fn peer_uid(socket: &impl std::os::fd::AsFd) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are locals; the descriptor is `socket`'s,
    // borrowed open for the call.
    if unsafe { libc::getpeereid(socket.as_fd().as_raw_fd(), &raw mut uid, &raw mut gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The process at the other end of a pair this process made is this
    /// account.
    #[test]
    fn the_peer_of_this_process_s_own_pair_is_this_account() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        assert_eq!(
            peer_uid(&ours).expect("the peer's account"),
            effective_uid()
        );
        assert_eq!(
            peer_uid(&theirs).expect("the peer's account"),
            effective_uid()
        );
    }

    /// A descriptor that is not a socket has no peer: the call fails, it
    /// does not answer with an account.
    #[test]
    fn a_descriptor_that_is_not_a_socket_has_no_peer() {
        let file = tempfile::tempfile().expect("a file");
        assert!(peer_uid(&file).is_err());
    }

    /// On Linux the session directory is `/run/user/<euid>`, or none; it is
    /// never what `XDG_RUNTIME_DIR` says. The test sets that variable to a
    /// directory that exists and is not the session directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_session_directory_is_the_uids_and_not_the_environments() {
        let elsewhere = tempfile::tempdir().expect("a directory");
        // No other test in this crate reads the variable.
        std::env::set_var("XDG_RUNTIME_DIR", elsewhere.path());
        let expected = PathBuf::from(format!("/run/user/{}", effective_uid()));
        match session_dir() {
            Some(found) => assert_eq!(found, expected),
            None => assert!(!expected.is_dir(), "{} exists", expected.display()),
        }
    }

    /// On Unix the account's root is its session directory.
    #[test]
    fn the_unix_account_root_is_the_session_directory() {
        assert_eq!(account_root(), session_dir());
    }
}
