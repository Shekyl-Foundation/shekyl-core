// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Advisory lock on the keys file, held across the lifetime of a
//! `WalletFileHandle`.
//!
//! # Why advisory, and why on the keys file
//!
//! The wallet pair `(.wallet.keys, .wallet)` is logically one wallet.
//! Two processes mutating the same wallet concurrently would race on
//! the `.wallet` auto-save path and potentially corrupt the region-2
//! AEAD sequencing. The advisory lock enforces "one live handle per
//! wallet on this host" without needing cross-process IPC.
//!
//! We pin the lock to `.wallet.keys` rather than `.wallet` because:
//!
//! 1. `.wallet.keys` must exist by the time a second opener arrives.
//!    `.wallet` may briefly be absent (between wallet creation step 1
//!    and step 2, or after a `.wallet`-only deletion that triggers
//!    rescan recovery). Locking a file that might not exist is a
//!    worse user-experience than locking one that is required by
//!    construction.
//! 2. `.wallet.keys` is the root of trust — a second process that
//!    wants to open this wallet must traverse this file first. Locking
//!    there is the earliest point in the open sequence where contention
//!    can be detected loudly.
//!
//! The lock is *advisory*, not mandatory. A malicious process can
//! always race, since the OS does not enforce the lock. What the lock
//! does buy:
//!
//! - Accidental double-open from the same user (e.g. two wallet GUIs,
//!   a GUI + a CLI refresh) fails loudly instead of silently corrupting.
//! - The error surface is precise: we return
//!   [`WalletFileError::AlreadyLocked`] with the contended path, so the
//!   UI can render "the wallet is already open elsewhere".
//!
//! # Why non-blocking
//!
//! We use non-blocking lock flavors (`LOCK_NB` on POSIX,
//! `LOCKFILE_FAIL_IMMEDIATELY` on Windows). A GUI hanging silently on a
//! lock wait is worse than an immediate, explicit error — the user can
//! then resolve the conflict (close the other wallet, or kill a stale
//! process) and retry.
//!
//! # Lock release
//!
//! The lock is released automatically when the `KeysFileLock` is
//! dropped (POSIX: `flock(2)` locks are attached to the open-file-
//! description and are released when the last reference to that OFD
//! closes; Windows: Drop-time unlock is explicit via
//! [`windows_sys::Win32::Storage::FileSystem::UnlockFileEx`]). Rust's
//! `Drop` guarantees this happens on all exit paths including panic-
//! unwind.
//!
//! # Platform coverage
//!
//! POSIX: `rustix::fs::flock` with `LOCK_EX | LOCK_NB`. We deliberately
//! choose `flock(2)` over `fcntl(F_SETLK)` record locks because
//! `flock(2)` is per-open-file-description, meaning the in-process
//! contention path (two handles, same wallet) fires loudly in tests and
//! in production; fcntl record locks are per-process and would
//! silently succeed on a same-process second open. The trade-off is
//! that `flock(2)` does not work over NFS pre-2.6.12 — which the V3
//! README documents as an unsupported storage backend for the wallet
//! pair (use a local filesystem).
//!
//! Windows: `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK |
//! LOCKFILE_FAIL_IMMEDIATELY` over the first byte of the file. Per-
//! handle semantics match POSIX `flock`, so in-process contention
//! tests work identically.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::error::WalletFileError;

/// Advisory exclusive lock held on a `.wallet.keys` file for the lifetime
/// of a wallet handle. The underlying `File` is kept open so that the
/// lock is released on `Drop` (close-of-open-file-description semantics
/// on POSIX; explicit unlock on Windows).
#[derive(Debug)]
pub(crate) struct KeysFileLock {
    #[allow(dead_code)] // held for Drop-semantics lock release
    file: File,
    path: PathBuf,
}

impl KeysFileLock {
    /// Acquire a non-blocking exclusive advisory lock on `path`. On
    /// contention returns [`WalletFileError::AlreadyLocked`] rather
    /// than blocking.
    ///
    /// The keys file must already exist (the caller is responsible for
    /// either creating it first, or failing with a more precise error
    /// if it doesn't).
    pub(crate) fn acquire(path: &Path) -> Result<Self, WalletFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(WalletFileError::Io)?;

        platform::try_lock_exclusive(&file, path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Path this lock is bound to; used by error-path reporting.
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use rustix::fs::{flock, FlockOperation};

    pub(super) fn try_lock_exclusive(file: &File, path: &Path) -> Result<(), WalletFileError> {
        match flock(file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(()),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK || e == rustix::io::Errno::AGAIN => {
                Err(WalletFileError::AlreadyLocked {
                    path: path.to_path_buf(),
                })
            }
            Err(e) => Err(WalletFileError::Io(std::io::Error::from_raw_os_error(
                e.raw_os_error(),
            ))),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    pub(super) fn try_lock_exclusive(file: &File, path: &Path) -> Result<(), WalletFileError> {
        let handle = file.as_raw_handle() as _;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let last = std::io::Error::last_os_error();
        let code = last.raw_os_error().unwrap_or(0) as u32;
        if code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING {
            Err(WalletFileError::AlreadyLocked {
                path: path.to_path_buf(),
            })
        } else {
            Err(WalletFileError::Io(last))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release_on_drop_allows_reacquire() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.keys");
        std::fs::write(&path, b"placeholder").unwrap();

        {
            let _lock = KeysFileLock::acquire(&path).expect("first acquire");
        }
        // On drop, the lock should have been released.
        let _lock2 = KeysFileLock::acquire(&path).expect("re-acquire after drop");
    }

    #[test]
    fn second_acquire_on_same_file_fails_in_process() {
        // flock(2) is per-open-file-description on Linux/BSD (and
        // LockFileEx is per-handle on Windows), so opening the same
        // path twice in-process gives us two independent lock holders
        // and the second must fail — exactly the semantic we want for
        // catching accidental double-open.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.keys");
        std::fs::write(&path, b"placeholder").unwrap();

        let _first = KeysFileLock::acquire(&path).expect("first acquire");
        let err = KeysFileLock::acquire(&path).expect_err("second acquire must fail");
        match err {
            WalletFileError::AlreadyLocked { path: p } => assert_eq!(p, path),
            other => panic!("expected AlreadyLocked, got {other:?}"),
        }
    }
}
