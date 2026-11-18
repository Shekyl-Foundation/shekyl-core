// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Atomic file-write helper: `staged → fsync → rename → fsync(parent)`,
//! through the tree's one file replace.
//!
//! The wallet envelope doesn't care about torn writes; the orchestrator
//! does. Every on-disk mutation of `.wallet.keys` or `.wallet` must
//! survive a crash such that the reader sees either the pre-write or
//! post-write bytes in full — never a half-written blob. This module
//! centralizes the pattern so the orchestrator has one, and only one,
//! code path that can create or replace a wallet artifact.
//!
//! # The steps
//!
//! The file is replaced through [`StagedWrite`] from `shekyl-os-account`,
//! the one place the tree replaces a file (Rick, 2026-11-18). It is a
//! [`Replace`]: nothing names the staged file, so a failed commit removes
//! it and the next write of the same target removes one a crash left.
//!
//! 1. **Create the staged file** `<target name>.new` beside the target
//!    ([`staged_path`]), `O_CREAT | O_EXCL`, mode `0o600` on Unix and the
//!    directory's inherited ACL on Windows ([`Access::Private`]). A
//!    leftover from a crashed write is removed first. "Beside" (same
//!    parent directory) matters: POSIX `rename(2)` is only guaranteed
//!    atomic within a filesystem, and in practice within a mount.
//! 2. **Write all bytes** into it and **`fsync`** it, then sync its
//!    directory, *before* the rename. This is the step that earns
//!    "atomic durability": a crash between the rename and the parent
//!    fsync still lands the complete new contents under the target name on
//!    reboot (subject to the usual caveats about filesystem journaling
//!    modes).
//! 3. **The hook** ([`atomic_write_file_with`]) runs on the complete,
//!    synced staged file: password rotation locks it here.
//! 4. **Rename** the staged file over the target. On Unix this is
//!    `rename(2)`. On Windows it is `shekyl_win_sec::replace`: a rename
//!    through the staged file's handle with `FileRenameInfoEx`, replace-if-
//!    exists and POSIX semantics, so a target another handle holds open or
//!    under a byte-range lock (the keys file during password rotation) is
//!    superseded rather than refused; a reader that holds either file
//!    without delete sharing (a scanner) is waited for up to
//!    `REPLACE_WAIT`; FAT32 and exFAT take the classic rename, where
//!    replacing a held target fails.
//! 5. **`fsync(parent_dir)`**. Without this, the rename is not
//!    guaranteed durable across a crash on ext4/xfs/btrfs even though
//!    the file data is; the dirent entry pointing `target` at the new
//!    inode may still be buffered in the dcache. This step runs *after*
//!    the rename has committed, so its failure does not un-apply the
//!    write — it is reported as [`Durability::Unconfirmed`], not an error.
//!
//! On any failure before the rename lands, **the guarantee is that the
//! target is byte-unchanged**, returned as `Err`. Removing the staged file
//! is *best-effort* and deliberately not part of that guarantee: a failed
//! rename's own removal and a failed hook's removal can each fail, and a
//! `<name>.new` left behind is clutter, never a wallet artifact — no
//! reader opens a staged path, and the next write of that target removes
//! it — but a caller must not depend on its absence.
//!
//! Every write stages and renames: the target is never read first to skip
//! an unchanged write. A sealed file is an offline guessing target, and a
//! read of it for comparison would hold its bytes in an unwiped buffer on
//! every save; and [`Durability::Confirmed`] must mean this write's
//! directory sync succeeded, which a skipped write never ran.
//!
//! # Why not `persist`
//!
//! `NamedTempFile::persist` (and the tree-wide ban on it, `rust/clippy.toml`)
//! is `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` alone on Windows, which is
//! refused with `ERROR_ACCESS_DENIED` over a target under a byte-range lock:
//! password rotation replaces `.wallet.keys` while the wallet handle holds
//! `LockFileEx` on byte 0 of it, so through `persist` **every password
//! rotation on Windows failed**. The handle rename in step 4 supersedes the
//! locked target. A tempfile also stages with `FILE_ATTRIBUTE_TEMPORARY`,
//! which a rename carries onto the target; the staged file here is a plain
//! create and never carries it.
//!
//! # Platform notes
//!
//! - On POSIX the file and the parent directory are both `fsync`ed. On
//!   Windows there is no directory-fsync; [`std::fs::File::sync_all`] on
//!   the file is sufficient per Windows' durability model, and the parent
//!   sync is a no-op there.
//! - `rename(2)` across mount points returns `EXDEV`, which we surface
//!   unchanged as an `io::Error`. It cannot arise here: the staged file is
//!   beside the target.
//!
//! # What this module does *not* do
//!
//! - It does **not** take the keys-file lock. Locking is the caller's
//!   job — a save-state path locks the keys file once at open time and
//!   holds it across many auto-saves, so `atomic_write_file` has no
//!   business re-acquiring per-write. What it does offer is a hook
//!   *between* the fsync and the rename ([`atomic_write_file_with`]): a
//!   lock is held on an inode, and this module replaces inodes, so a
//!   caller that must stay locked across a replacement locks the staged
//!   file through that hook, before the path names it.
//! - It does **not** enforce write-once. That is a handle-level
//!   invariant (see [`crate::error::WalletFileError::KeysFileWriteOnceViolation`])
//!   unrelated to whether the write itself is atomic.

use std::io;
use std::path::Path;

use shekyl_os_account::private_file::{staged_path, Access, CommitError, Replace, StagedWrite};

use crate::error::WalletFileError;

/// Whether an [`atomic_write_file`] that **applied** its write also confirmed
/// the write's crash-durability.
///
/// The write's *data* is always fsynced before the rename, so `Unconfirmed`
/// means only that the post-rename parent-directory fsync — which hardens the
/// rename itself against an immediate crash — failed. The bytes are on disk
/// and the rename is visible; only a crash in the narrow window before the
/// filesystem journals the directory entry could revert the rename (the same
/// window any program that does not fsync the parent dir already lives with).
///
/// The dispatch mint branches on it: only [`Durability::Confirmed`] authorizes
/// a broadcast (`commit_dispatch`). It is deliberately not an error: the write
/// is applied, so surfacing it as `Err` would force every caller to unwind an
/// already-committed write. A caller that does not broadcast treats either
/// variant as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// The write is applied and the parent-directory fsync succeeded.
    Confirmed,
    /// The write is applied, but the post-rename parent-directory fsync
    /// failed — durability across an immediate crash is unconfirmed.
    Unconfirmed,
}

/// Write `bytes` to `target` through the steps in the module docs. Mode is
/// `0o600` on Unix; the directory's inherited ACL on Windows.
///
/// Returns [`Durability`] once the write is **applied** (the rename has
/// landed): `Confirmed` when the parent-directory fsync also succeeded,
/// `Unconfirmed` when it did not. A failure *before* the rename leaves the
/// target untouched and returns `Err`.
///
/// # Errors
///
/// - [`WalletFileError::Io`] for a filesystem failure while **producing**
///   the staged file: removing a leftover, create, write, or fsync.
/// - [`WalletFileError::AtomicWriteRename`] specifically for failures
///   of the rename step, including another program holding the staged
///   file or the target past the Windows replace's wait. The dedicated
///   variant exists so callers can distinguish "couldn't write the bytes"
///   from "wrote the bytes but couldn't swap them in" — the latter means
///   the target is untouched, which is sometimes recoverable.
///
/// Every error path leaves the target **byte-unchanged**; a post-rename
/// failure is reported as `Ok(Durability::Unconfirmed)`, never as `Err`.
/// Removal of the staged file is best-effort on every path (see the
/// module docs) and is not part of the contract.
pub(crate) fn atomic_write_file(
    target: &Path,
    bytes: &[u8],
) -> Result<Durability, WalletFileError> {
    atomic_write_file_with(target, bytes, |_| Ok(())).map(|((), durability)| durability)
}

/// [`atomic_write_file`] with a hook that runs after the staged file is
/// complete and fsynced and **before** it is renamed into place, receiving
/// the staged path. Whatever the hook returns is handed back beside the
/// [`Durability`]; if the rename then fails, it is dropped with the error
/// and the target is untouched.
///
/// The one caller is password rotation, which locks the staged file here
/// so the keys-file lock follows the inode the path is about to name.
///
/// # Errors
///
/// Exactly [`atomic_write_file`]'s, and the hook's own. A hook or rename
/// failure removes the staged file (best-effort) and leaves the target
/// untouched; a rename failure drops the hook's value with the error.
pub(crate) fn atomic_write_file_with<T>(
    target: &Path,
    bytes: &[u8],
    before_persist: impl FnOnce(&Path) -> Result<T, WalletFileError>,
) -> Result<(T, Durability), WalletFileError> {
    if target.parent().is_none() {
        return Err(WalletFileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "atomic_write_file: target {} has no parent directory",
                target.display()
            ),
        )));
    }
    let staged = StagedWrite::<Replace>::create(target, bytes, Access::Private)
        .map_err(|error| WalletFileError::Io(io::Error::from(error)))?;

    // The staged file is complete and durable; the caller may now attach
    // whatever must travel with it into place (the keys-file lock).
    let hooked = match before_persist(&staged_path(target)) {
        Ok(hooked) => hooked,
        Err(error) => {
            // Dropping a `StagedWrite` leaves its file; this write is not
            // going to commit, so the file is removed here, best-effort.
            remove_staged(target);
            return Err(error);
        }
    };

    // A `Replace` whose rename fails removes its own staged file. The hook's
    // value (for password rotation, a `KeysFileLock` holding a byte-0-locked
    // handle on that staged file) is still alive during that removal and is
    // dropped with the error: measured on Windows 11 23H2 / NTFS, an unlink
    // succeeds with that lock alive (std opens files with `FILE_SHARE_DELETE`,
    // and a `LockFileEx` byte range does not block deletion), and a removal
    // that fails is left to the next write of the target.
    match staged.commit() {
        Ok(()) => Ok((hooked, Durability::Confirmed)),
        // The rename has already committed the new file into place, and the
        // file data was fsynced before it. The parent-dir fsync only hardens
        // the rename against an immediate crash; if it fails the write is
        // still applied, so this is a completed write with unconfirmed
        // durability — not a failure a caller must unwind an already-applied
        // write around.
        Err(CommitError::Unsynced(..)) => Ok((hooked, Durability::Unconfirmed)),
        Err(CommitError::Io(_, error)) => {
            drop(hooked);
            Err(WalletFileError::rename(target.to_path_buf(), error))
        }
        Err(CommitError::HeldOpen(held)) => {
            drop(hooked);
            Err(WalletFileError::rename(
                target.to_path_buf(),
                io::Error::other(held),
            ))
        }
    }
}

/// Remove the staged file of a write that will not commit. Best-effort: a
/// stranded staged file is clutter rather than corruption — it is a
/// `<name>.new` sibling, never the wallet itself, and the next write of the
/// target removes it. Reported so it is not silent.
fn remove_staged(target: &Path) {
    let staged = staged_path(target);
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            staged = %staged.display(),
            error = %error,
            "could not remove the staged file after a failed write"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::KeysFileLock;
    use std::fs;
    use std::fs::File;
    use std::io::Write;

    /// Replacing a **locked** target is where `NamedTempFile::persist` and
    /// [`std::fs::rename`] diverge, and the module's *Why not `persist`*
    /// section (and the tree's ban on both, `rust/clippy.toml`) is written
    /// against this fact. It calls them on purpose, to pin the platform
    /// behaviour the one replace is chosen against. On Windows `persist` issues
    /// `MoveFileExW` alone and is refused with `ERROR_ACCESS_DENIED`; `rename`
    /// issues the same call and then retries through
    /// `SetFileInformationByHandle(FileRenameInfoEx)` with POSIX semantics,
    /// which supersedes the open target. On POSIX neither ever cared about an
    /// advisory `flock`.
    ///
    /// This is not decoration: password rotation replaces `.wallet.keys` while
    /// the wallet handle holds the lock on it, so the divergence is the
    /// difference between rotation working and **every rotation on Windows
    /// failing** — which is what it did until this module stopped using
    /// `persist`. This module now replaces through the handle rename
    /// directly ([`replaces_a_target_held_by_a_live_lock`]).
    ///
    /// The edit that turns the Windows `persist` arm red is `tempfile` gaining
    /// the fallback std already has, at which point the module doc's premise —
    /// not this crate's code — is what changed. The `rename` arm goes red if
    /// std loses it, and rotation would be broken again. The POSIX arms go red
    /// if a mandatory lock ever appears there.
    #[test]
    // CLIPPY: disallowed_methods — test support.
    #[allow(
        clippy::disallowed_methods,
        reason = "test support: pins how persist and std's rename behave over a locked target, the behaviour the one replace is chosen against"
    )]
    fn replacing_a_locked_target_is_platform_dependent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x.keys");
        fs::write(&target, b"OLD").unwrap();
        let _lock = KeysFileLock::acquire(&target).expect("acquire");

        // `persist`: `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` and nothing else.
        let via_persist = {
            let tmp = tempfile::Builder::new()
                .prefix(".")
                .suffix(".shekyl-tmp")
                .rand_bytes(12)
                .tempfile_in(dir.path())
                .unwrap();
            {
                let mut w: &File = tmp.as_file();
                w.write_all(b"NEW-persist").unwrap();
            }
            tmp.persist(&target).map(|_| ()).map_err(|e| e.error)
        };

        // `rename`: the same call, plus the `FileRenameInfoEx` retry.
        let via_rename = {
            let staged = dir.path().join(".rename.shekyl-tmp");
            fs::write(&staged, b"NEW-rename").unwrap();
            fs::rename(&staged, &target)
        };

        #[cfg(windows)]
        {
            /// `winerror.h`: the replace was refused outright — what a
            /// byte-range lock on the target produces for `MoveFileExW`.
            const ERROR_ACCESS_DENIED: i32 = 5;
            let err = via_persist.expect_err(
                "Windows: `persist` must be refused over a locked target — if it \
                 now succeeds, *Why not `persist`* in the module docs is stale",
            );
            assert_eq!(
                err.raw_os_error(),
                Some(ERROR_ACCESS_DENIED),
                "Windows: the refusal must be ACCESS_DENIED — a different code means \
                 a different mechanism is at work: {err}"
            );
            via_rename.expect(
                "Windows: `std::fs::rename` must supersede a locked target via \
                 FileRenameInfoEx — without it, password rotation cannot work",
            );
        }
        #[cfg(unix)]
        {
            via_persist.expect("POSIX: flock is advisory; persist replaces a locked target");
            via_rename.expect("POSIX: rename replaces a locked target");
        }

        assert_eq!(
            fs::read(&target).unwrap(),
            b"NEW-rename",
            "the rename must land its bytes, not merely return Ok"
        );
    }

    /// A `tempfile` staged file carries `FILE_ATTRIBUTE_TEMPORARY`, which asks
    /// the cache manager to avoid writing the data back while cache is
    /// available, and a rename carries it onto the target: a permanent wallet
    /// artifact left permanently marked temporary is false metadata, and a
    /// standing hint for any later writer that does not flush explicitly. The
    /// staged file here is a plain create and never carries it.
    ///
    /// The reason this needs a test rather than a comment is that the failure
    /// is **invisible in the bytes**: a staging step that went back to a
    /// temporary-file create changes no content and no test that compares
    /// content. Only the attribute moves, and only here.
    #[cfg(windows)]
    #[test]
    fn the_target_is_never_left_marked_temporary() {
        use std::os::windows::fs::MetadataExt;
        /// `winnt.h`.
        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x.keys");
        atomic_write_file(&target, b"hello").unwrap();

        let attrs = fs::metadata(&target).unwrap().file_attributes();
        assert_eq!(
            attrs & FILE_ATTRIBUTE_TEMPORARY,
            0,
            "`.wallet.keys` was left marked FILE_ATTRIBUTE_TEMPORARY (attrs=0x{attrs:08x}); \
             the staged file's attribute survived the rename, so a permanent wallet \
             artifact now carries a temporary-file caching hint for every later writer"
        );
    }

    /// The password-rotation shape end to end: replace a target that a **live**
    /// [`KeysFileLock`] holds, taking the lock on the staged file through the
    /// pre-persist hook so the lock follows the inode the path is about to
    /// name. This is the exact sequence `WalletFile::rotate_password` runs, and
    /// it returned `AtomicWriteRename { source: <os error 5> }` on Windows for
    /// every wallet until the `persist` swap above.
    #[test]
    fn replaces_a_target_held_by_a_live_lock() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x.keys");
        fs::write(&target, b"OLD").unwrap();

        let old_lock = KeysFileLock::acquire(&target).expect("acquire the target's lock");
        let (new_lock, _durability) = atomic_write_file_with(&target, b"NEW", |staged| {
            KeysFileLock::acquire_staged(staged, &target)
        })
        .expect("a target under a live keys-file lock must still be replaceable");

        // Both locks are released before the read: on Windows the lock is
        // mandatory, so a path read while `new_lock` is live would fail for a
        // reason that has nothing to do with what this test asserts.
        drop(old_lock);
        drop(new_lock);
        assert_eq!(fs::read(&target).unwrap(), b"NEW");

        // The staged file must not be left behind: on the success path the
        // rename consumed it.
        assert!(
            !staged_path(&target).exists(),
            "the staged file {} was left behind",
            staged_path(&target).display()
        );
    }

    /// A **failed** rename must still unlink the staged file.
    ///
    /// A [`Replace`]'s failed commit removes its own staged file, and without
    /// that every failed write strands a `<name>.new` beside the wallet until
    /// the next write. The success-path assertion in
    /// [`replaces_a_target_held_by_a_live_lock`] cannot see this: there the
    /// rename consumed the staged file, so losing the removal would leave
    /// that test green.
    ///
    /// A non-empty directory at the target is the portable way to make the
    /// rename fail after everything before it has succeeded — the staging, the
    /// write and the fsync all complete, and only the swap is refused. The
    /// edit that turns this red is staging the write as a `Journal`, whose
    /// failed commit keeps its file.
    ///
    /// **`AtomicWriteRename` means the rename on both platforms**: a failure
    /// while producing the staged file is [`WalletFileError::Io`], so matching
    /// `AtomicWriteRename` pins the failing step everywhere.
    ///
    /// The Unix arm additionally pins the errno (`EISDIR`/`ENOTDIR`). That is
    /// a refinement, not the load-bearing claim, and it stays Unix-only
    /// because the equivalent Windows code for this case has not been
    /// measured — an unmeasured constant in an assertion is how a check
    /// becomes decorative.
    #[test]
    fn a_failed_rename_still_removes_the_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x.keys");
        // A non-empty directory cannot be replaced by a file rename on either
        // platform.
        fs::create_dir(&target).unwrap();
        fs::write(target.join("occupied"), b"").unwrap();

        // The pre-persist hook is the only place the staged path is visible, and
        // capturing it is what makes this test name a file rather than scan for
        // a suffix. It also proves staging got as far as the hook: if the write
        // had failed earlier the hook would never run, `staged` would be `None`,
        // and a check for a stray would pass for the wrong reason.
        //
        // The hook also takes a real `KeysFileLock`, which is what password
        // rotation — the only production caller of this entry point — does, so
        // the test exercises the production shape rather than a stub that holds
        // no handle. Measured on Windows, an open byte-0-locked handle does
        // **not** block the unlink, so this guards the shape, not that hazard.
        let mut staged: Option<std::path::PathBuf> = None;
        let err = atomic_write_file_with(&target, b"NEW", |p| {
            staged = Some(p.to_path_buf());
            KeysFileLock::acquire_staged(p, &target)
        })
        .map(|(_lock, d)| d)
        .expect_err("renaming a file over a directory must fail");

        let staged = staged.expect(
            "the pre-persist hook never ran, so the failure was before staging and \
             this test is not exercising the cleanup at all",
        );
        assert_eq!(staged, staged_path(&target));
        let WalletFileError::AtomicWriteRename { ref source, .. } = err else {
            panic!(
                "the failure must be the rename step, not an earlier one — otherwise \
                 this test is not exercising the cleanup it exists for: {err:?}"
            );
        };
        #[cfg(unix)]
        {
            /// `errno.h`: the new path is a directory and the old one is not.
            const EISDIR: i32 = 21;
            /// The same conflict, reported the other way round by some kernels.
            const ENOTDIR: i32 = 20;
            assert!(
                matches!(source.raw_os_error(), Some(EISDIR | ENOTDIR)),
                "expected a directory-conflict errno from `rename`, got {source} — \
                 a different code means the write failed somewhere other than the \
                 swap"
            );
        }
        #[cfg(windows)]
        let _ = source;

        assert!(
            !staged.exists(),
            "a failed rename stranded its staged file: {}",
            staged.display()
        );
    }

    /// A hook that fails leaves the target untouched and removes the staged
    /// file: dropping a `StagedWrite` leaves its file, so this module removes
    /// it. Red edit: return the hook's error without `remove_staged`, and the
    /// staged file is left beside the target.
    #[test]
    fn a_failed_hook_removes_the_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x.keys");
        fs::write(&target, b"OLD").unwrap();
        let err = atomic_write_file_with(&target, b"NEW", |staged| -> Result<(), _> {
            assert!(staged.exists(), "the hook sees the complete staged file");
            Err(WalletFileError::Io(io::Error::other("the hook refused")))
        })
        .expect_err("the hook's failure is the write's");
        assert!(matches!(err, WalletFileError::Io(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"OLD");
        assert!(!staged_path(&target).exists());
    }

    #[test]
    fn writes_to_fresh_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("foo.bin");
        // A normal write on a healthy filesystem confirms durability.
        assert_eq!(
            atomic_write_file(&target, b"hello").unwrap(),
            Durability::Confirmed
        );
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
