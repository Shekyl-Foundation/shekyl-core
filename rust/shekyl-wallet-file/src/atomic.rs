// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Atomic file-write helper: `tmp → fsync → rename → fsync(parent)`.
//!
//! The wallet envelope doesn't care about torn writes; the orchestrator
//! does. Every on-disk mutation of `.wallet.keys` or `.wallet` must
//! survive a crash such that the reader sees either the pre-write or
//! post-write bytes in full — never a half-written blob. This module
//! centralizes the pattern so the orchestrator has one, and only one,
//! code path that can create or replace a wallet artifact.
//!
//! # The six steps
//!
//! 1. **Create a sibling temp file** with a random suffix, opened
//!    `O_CREAT | O_EXCL | O_WRONLY`, mode `0o600`. "Sibling" (same
//!    parent directory) matters: POSIX `rename(2)` is only guaranteed
//!    atomic within a filesystem, and in practice within a mount. We
//!    use [`tempfile::Builder`] to get the exclusive-open guarantees
//!    and random suffix for free.
//! 2. **Write all bytes** into the temp file. A short write is treated
//!    as an error; we never leave a partial temp behind.
//! 3. **`fsync(fd)`** on the temp file to push the bytes to durable
//!    media *before* the rename. This is the step that earns "atomic
//!    durability": after it returns, a crash between rename and the
//!    parent fsync will still land the complete new contents under the
//!    target name on reboot (subject to the usual caveats about
//!    filesystem journaling modes).
//! 4. **`rename(tmp, target)`**. Atomic on POSIX within a filesystem.
//!    The tempfile handle is persisted (i.e. `NamedTempFile::persist`)
//!    so the drop guard doesn't try to unlink the just-renamed file.
//! 5. **`fsync(parent_dir)`**. Without this, the rename is not
//!    guaranteed durable across a crash on ext4/xfs/btrfs even though
//!    the file data is; the dirent entry pointing `target` at the new
//!    inode may still be buffered in the dcache.
//! 6. **Return**. On any failure between steps 1 and 4, the temp file is
//!    unlinked by `tempfile`'s drop guard; the target (if any) is left
//!    untouched.
//!
//! # Platform notes
//!
//! - On POSIX we `fsync(2)` both the file and the opened-by-rustix
//!   parent directory FD. On Windows there is no directory-fsync;
//!   [`std::fs::File::sync_all`] on the file is sufficient per Windows'
//!   durability model. The parent fsync is therefore a no-op on
//!   Windows (implemented as a `#[cfg]`-gated helper).
//! - `rename(2)` across mount points returns `EXDEV`, which we surface
//!   unchanged as an `io::Error`. Callers who want atomic installation
//!   across a mount boundary must copy-then-write within the target
//!   mount.
//!
//! # What this module does *not* do
//!
//! - It does **not** take the advisory lock. Locking is the caller's
//!   job — a save-state path locks the keys file once at open time and
//!   holds it across many auto-saves, so `atomic_write_file` has no
//!   business re-acquiring per-write.
//! - It does **not** enforce write-once. That is a handle-level
//!   invariant (see [`crate::error::WalletFileError::KeysFileWriteOnceViolation`])
//!   unrelated to whether the write itself is atomic.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::error::WalletFileError;

/// Write `bytes` to `target` using the six-step atomic dance described
/// in the module docs. Mode is `0o600` on Unix; inherit-default on
/// Windows. Returns `Ok(())` only after the durable rename has landed
/// and the parent directory has been fsynced (where applicable).
///
/// # Errors
///
/// - [`WalletFileError::Io`] for any filesystem failure before or
///   during the rename (create, write, fsync of the temp).
/// - [`WalletFileError::AtomicWriteRename`] specifically for failures
///   of the `rename(2)` step. The dedicated variant exists so callers
///   can distinguish "couldn't write the bytes" from "wrote the bytes
///   but couldn't swap them in" — the latter means the target is
///   untouched, which is sometimes recoverable.
pub(crate) fn atomic_write_file(target: &Path, bytes: &[u8]) -> Result<(), WalletFileError> {
    let parent = target.parent().ok_or_else(|| {
        WalletFileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "atomic_write_file: target {} has no parent directory",
                target.display()
            ),
        ))
    })?;
    // tempfile in the parent dir → same filesystem → rename(2) atomic.
    // Random suffix → two processes writing concurrently don't collide.
    let tmp = tempfile::Builder::new()
        .prefix(".")
        .suffix(".shekyl-tmp")
        .rand_bytes(12)
        .tempfile_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    {
        let file_ref = tmp.as_file();
        let mut w: &File = file_ref;
        w.write_all(bytes)?;
        w.flush()?;
        file_ref.sync_all()?;
    }

    // Persist into place; on any error, `tempfile` cleans up the temp.
    tmp.persist(target)
        .map_err(|e| WalletFileError::rename(target.to_path_buf(), e.error))?;

    fsync_parent_dir(parent)?;
    Ok(())
}

/// Platform-gated parent-directory fsync. POSIX: open the dir and
/// `fsync` the fd. Windows: no-op (per Windows' durability model, the
/// `sync_all` on the file suffices once the rename has completed).
#[cfg(unix)]
fn fsync_parent_dir(parent: &Path) -> Result<(), WalletFileError> {
    // `std::fs::File::open` on a directory is portable on all Unixes we
    // care about (Linux, macOS, FreeBSD).
    let dir = File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn fsync_parent_dir(_parent: &Path) -> Result<(), WalletFileError> {
    // Windows NTFS guarantees rename durability after the file's
    // sync_all; there is no directory-fsync equivalent.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn writes_to_fresh_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("foo.bin");
        atomic_write_file(&target, b"hello").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn overwrites_existing_target_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("foo.bin");
        fs::write(&target, b"old-contents").unwrap();
        atomic_write_file(&target, b"new-contents").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new-contents");
        // No stray temp files left in the directory.
        let leftover: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.file_name() != "foo.bin")
            .collect();
        assert!(
            leftover.is_empty(),
            "atomic_write_file left stray files: {leftover:?}"
        );
    }

    #[test]
    fn refuses_target_with_no_parent() {
        // `/` on Unix has a parent (itself); use a bare filename with
        // no components by probing the edge case through a stripped
        // path.
        let target = Path::new("");
        let err = atomic_write_file(target, b"x").unwrap_err();
        match err {
            WalletFileError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn multiple_writes_to_same_target_each_land_fully() {
        // Simulates the autosave loop. Every save must leave the target
        // holding exactly the latest bytes, never a prefix of an older
        // save and a suffix of a newer one.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("autosave.bin");
        for i in 0u8..32 {
            let payload = vec![i; 1024];
            atomic_write_file(&target, &payload).unwrap();
            let got = fs::read(&target).unwrap();
            assert_eq!(got, payload, "iteration {i}");
        }
    }
}
