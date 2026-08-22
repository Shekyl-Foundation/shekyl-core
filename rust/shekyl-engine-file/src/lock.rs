// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Exclusive lock on the keys file, held across the lifetime of a
//! `WalletFile`. Advisory on POSIX; on Windows it also denies access to
//! the locked byte (see *Platform semantics*).
//!
//! # Why a lock, and why on the keys file
//!
//! The wallet pair `(.wallet.keys, .wallet)` is logically one wallet.
//! Two processes mutating the same wallet concurrently would race on
//! the `.wallet` auto-save path and potentially corrupt the region-2
//! AEAD sequencing. The lock enforces "one live handle per wallet on
//! this host" without needing cross-process IPC.
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
//! # Platform semantics
//!
//! The lock is *advisory* on POSIX (`flock(2)`): the OS does not enforce
//! it, and a malicious process can always race. **On Windows it is
//! not.** `LockFileEx` is a mandatory byte-range lock: the byte it covers
//! cannot be read or written through any *other* handle — a second
//! handle in the same process included — until the locking handle
//! closes. `fd-lock` locks byte 0. That single fact is the contract the
//! API below is built on: **every read of the keys file while the lock
//! is held goes through the handle that holds it**
//! ([`KeysFileLock::acquire_and_read`]), and a caller that needs the keys
//! bytes while a wallet is open takes them from the open handle
//! (`WalletFile::sealed_keys_envelope`) rather than from the path. A unit
//! test below pins the platform fact; the incident that established it
//! (the first Windows `open`, failing with `ERROR_LOCK_VIOLATION`) is
//! recorded in `docs/design/WINDOWS_WALLET_PROBE_SHEET.md` §4.3 and the
//! CHANGELOG. What the lock buys on both platforms:
//!
//! - Accidental double-open from the same user (e.g. two wallet GUIs,
//!   a GUI + a CLI refresh) fails loudly instead of silently corrupting.
//! - The error surface is precise: we return
//!   [`WalletFileError::AlreadyLocked`] with the contended path, so the
//!   UI can render "the wallet is already open elsewhere".
//!
//! # Why non-blocking
//!
//! A GUI hanging silently on a lock wait is worse than an immediate,
//! explicit error — the user can then resolve the conflict (close the
//! other wallet, or kill a stale process) and retry.
//!
//! # Implementation: `fd-lock`
//!
//! We delegate the per-platform syscall to the [`fd_lock`] crate, which
//! wraps `flock(2)` on POSIX and `LockFileEx` on Windows behind a
//! `#![forbid(unsafe_code)]`-compatible safe API. This keeps
//! `shekyl-engine-file` itself `#![deny(unsafe_code)]` with zero
//! exceptions, per the workspace rule that only `shekyl-ffi` may relax
//! that lint (see `rust/25-rust-architecture.mdc`).
//!
//! The acquisition path:
//!
//! 1. Open the keys file read-write.
//! 2. Wrap it in [`fd_lock::RwLock`] and call `try_write()` for a
//!    non-blocking exclusive lock. Contention surfaces as
//!    [`std::io::ErrorKind::WouldBlock`], which we translate to
//!    [`WalletFileError::AlreadyLocked`].
//! 3. Leak the returned write-guard via [`std::mem::forget`] so the
//!    lock stays held until the owning [`KeysFileLock`] drops. Storing
//!    the guard directly inside the struct would require a self-
//!    referential borrow (guard borrows from the `RwLock` in the same
//!    struct); `mem::forget` is the safe Rust alternative.
//!
//! Lock release on `Drop` is guaranteed without an explicit
//! `UnlockFileEx`/`flock(LOCK_UN)` call: dropping the inner `File`
//! closes the underlying OS handle, and both POSIX (open-file-
//! description close releases `flock(2)`) and Windows (handle close
//! releases `LockFileEx`) treat handle-close as an authoritative lock-
//! release signal. `fd_lock`'s guard `Drop` would normally call the
//! explicit unlock, but since we `mem::forget` it, we rely on the
//! close-on-drop path instead. Rust's `Drop` semantics guarantee this
//! runs on all exit paths including panic-unwind.
//!
//! # Platform coverage
//!
//! `fd_lock` internally uses per-open-file-description `flock(2)` on
//! POSIX, meaning the in-process contention path (two handles, same
//! wallet) fires loudly in tests and in production. On Windows,
//! `LockFileEx` is per-handle with matching *contention* semantics — and
//! the stronger, mandatory *access* semantics described above, which is
//! why `acquire_and_read` exists and why a unit test below pins that a
//! path-based read while locked fails on Windows and succeeds on POSIX.
//! NFS pre-2.6.12 is unsupported as a wallet storage backend (documented
//! in the V3 README).

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use fd_lock::RwLock;

use crate::error::WalletFileError;

/// Exclusive lock held on a `.wallet.keys` file for the lifetime of a
/// wallet handle — advisory on POSIX, access-denying on Windows (module
/// doc, *Platform semantics*). The underlying `File` is kept open inside the
/// [`fd_lock::RwLock`] so that on `Drop` the handle closes and the OS
/// releases the lock.
pub(crate) struct KeysFileLock {
    // Order matters: `_lock` drops *after* `path`, which is irrelevant
    // for correctness but preserves the natural "release-as-late-as-
    // possible" semantic.
    _lock: RwLock<File>,
    path: PathBuf,
}

impl std::fmt::Debug for KeysFileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysFileLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl KeysFileLock {
    /// Acquire a non-blocking exclusive lock on `path`. On contention
    /// returns [`WalletFileError::AlreadyLocked`] rather than blocking.
    ///
    /// The keys file must already exist (the caller is responsible for
    /// either creating it first, or failing with a more precise error
    /// if it doesn't).
    pub(crate) fn acquire(path: &Path) -> Result<Self, WalletFileError> {
        Self::acquire_with(path, |_| Ok(())).map(|(lock, ())| lock)
    }

    /// Acquire the lock and read the whole file **through the locked
    /// handle**, returning both.
    ///
    /// One handle, not two. On Windows the lock is mandatory for the
    /// byte `fd-lock` covers (byte 0), so reading the path again through
    /// a fresh handle — `std::fs::read(path)` after [`Self::acquire`] —
    /// fails with `ERROR_LOCK_VIOLATION`, and every wallet `open` did
    /// until this existed. Reading through the handle that holds the
    /// lock is correct on both platforms, and it reads the file that was
    /// locked rather than whatever sits at the path a moment later.
    pub(crate) fn acquire_and_read(path: &Path) -> Result<(Self, Vec<u8>), WalletFileError> {
        Self::acquire_with(path, |file| {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
    }

    /// Open, lock, run `with_locked` against the locked handle, then keep
    /// the lock held for the lifetime of the returned value.
    fn acquire_with<R>(
        path: &Path,
        with_locked: impl FnOnce(&mut File) -> io::Result<R>,
    ) -> Result<(Self, R), WalletFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(WalletFileError::Io)?;

        let mut lock = RwLock::new(file);

        // Contention is decided HERE, on the lock attempt alone: only
        // `try_write`'s `WouldBlock` means "another handle holds the lock".
        // The callback's errors are I/O failures whatever their kind — a
        // `WouldBlock` from a read must not be reported as a second wallet
        // being open, because the remedies differ.
        //
        // The guard derefs to the locked `File`, the only handle that may
        // touch the locked byte on Windows, so whatever the caller needs to
        // read happens through it. On success the guard is `mem::forget`-ed:
        // that ends its borrow of `lock` without unlocking, and the lock
        // then stays held until the inner `File` closes on `KeysFileLock`
        // drop. On a callback failure the guard simply drops — unlocking —
        // and `lock` drops with it; nothing is returned that could hold it.
        let out = match lock.try_write() {
            Ok(mut guard) => match with_locked(&mut guard) {
                Ok(out) => {
                    std::mem::forget(guard);
                    out
                }
                Err(e) => return Err(WalletFileError::Io(e)),
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(WalletFileError::AlreadyLocked {
                    path: path.to_path_buf(),
                });
            }
            Err(e) => return Err(WalletFileError::Io(e)),
        };

        Ok((
            Self {
                _lock: lock,
                path: path.to_path_buf(),
            },
            out,
        ))
    }

    /// Path this lock is bound to; used by error-path reporting.
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
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
        // On drop, the lock should have been released (via close-on-drop
        // of the inner `File`).
        let _lock2 = KeysFileLock::acquire(&path).expect("re-acquire after drop");
    }

    /// The read goes through the locked handle and returns the file's
    /// bytes, and the lock is held afterwards (a second acquire fails).
    #[test]
    fn acquire_and_read_returns_contents_and_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.keys");
        std::fs::write(&path, b"keys-file-bytes").unwrap();

        let (_lock, bytes) = KeysFileLock::acquire_and_read(&path).expect("acquire + read");
        assert_eq!(bytes, b"keys-file-bytes");
        assert!(
            matches!(
                KeysFileLock::acquire(&path),
                Err(WalletFileError::AlreadyLocked { .. })
            ),
            "the lock must still be held after the read"
        );
    }

    /// The platform fact this module's API is built around, pinned rather
    /// than remembered: while the lock is held, a read of the same path
    /// through a **second** handle fails on Windows (`LockFileEx` is
    /// mandatory for the locked byte) and succeeds on POSIX (`flock` is
    /// advisory). The edit that turns the Windows arm red is `fd-lock`
    /// or std changing how the lock or the read is issued; the edit that
    /// turns the POSIX arm red is someone making the lock mandatory there.
    #[test]
    fn path_read_while_locked_is_platform_dependent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.keys");
        std::fs::write(&path, b"placeholder").unwrap();
        let _lock = KeysFileLock::acquire(&path).expect("acquire");
        let second_handle = std::fs::read(&path);
        #[cfg(windows)]
        assert!(
            second_handle.is_err(),
            "Windows: a path read while locked must fail — if it passes, the \
             mandatory-lock premise behind acquire_and_read no longer holds"
        );
        #[cfg(unix)]
        assert!(
            second_handle.is_ok(),
            "POSIX: flock is advisory; a path read while locked must succeed"
        );
    }

    /// Contention is decided by the lock attempt alone. A callback that
    /// happens to fail with `WouldBlock` — the kind `try_write` uses for
    /// contention — must surface as the I/O failure it is, never as
    /// `AlreadyLocked`: the two have different remedies ("close the other
    /// wallet" vs "the file could not be read").
    #[test]
    fn callback_would_block_is_not_reported_as_contention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.keys");
        std::fs::write(&path, b"placeholder").unwrap();

        let err = KeysFileLock::acquire_with(&path, |_file| {
            Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock))
        })
        .expect_err("the callback failed");
        assert!(
            matches!(err, WalletFileError::Io(ref e) if e.kind() == io::ErrorKind::WouldBlock),
            "a callback failure must be Io, not AlreadyLocked: {err:?}"
        );
        // And the failed attempt released the lock: the next acquire succeeds.
        let _relock = KeysFileLock::acquire(&path).expect("lock released after a failed callback");
    }

    #[test]
    fn second_acquire_on_same_file_fails_in_process() {
        // `fd_lock` uses per-OFD `flock(2)` on POSIX (and per-handle
        // `LockFileEx` on Windows), so opening the same path twice in-
        // process gives us two independent lock holders and the second
        // must fail — exactly the semantic we want for catching
        // accidental double-open.
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
