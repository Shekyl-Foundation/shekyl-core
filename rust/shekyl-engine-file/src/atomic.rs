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
//!    The staged file is first `TempPath::keep`-ed so the drop guard
//!    doesn't try to unlink the just-renamed file — and, on Windows,
//!    because `keep` is what clears `FILE_ATTRIBUTE_TEMPORARY` (see
//!    *Why not `persist`* below).
//! 5. **`fsync(parent_dir)`**. Without this, the rename is not
//!    guaranteed durable across a crash on ext4/xfs/btrfs even though
//!    the file data is; the dirent entry pointing `target` at the new
//!    inode may still be buffered in the dcache. This step runs *after*
//!    the rename has committed, so its failure does not un-apply the
//!    write — it is reported as [`Durability::Unconfirmed`], not an error.
//! 6. **Return** [`Durability`]. A step-5 failure returns
//!    `Ok(Durability::Unconfirmed)` — applied, durability unconfirmed.
//!
//!    On any failure between steps 1 and 4, **the guarantee is that the
//!    target is byte-unchanged**, returned as `Err`. Removing the staged
//!    file is *best-effort* and deliberately not part of that guarantee:
//!    before the `keep` it is `tempfile`'s drop guard, which ignores unlink
//!    errors, and after the `keep` disarms that guard it is this module's
//!    own `remove_file`, which logs and continues. Either can leave a
//!    `.<random>.shekyl-tmp` sibling behind. That is clutter, never a
//!    wallet artifact — no caller reads a staged path — and it is
//!    reported rather than silent, but a caller must not depend on its
//!    absence. Saying "the staged file is removed" would promise something
//!    neither owner delivers.
//!
//! # Why not `persist`
//!
//! Step 4 is `TempPath::keep` + [`std::fs::rename`], not
//! `NamedTempFile::persist`. On Unix the two are equivalent. On Windows
//! they differ twice, and both differences are load-bearing:
//!
//! 1. **`persist` cannot replace a file under a byte-range lock.** It
//!    calls `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` and nothing else.
//!    `std::fs::rename` calls the same thing *and*, on
//!    `ERROR_ACCESS_DENIED` specifically, retries via
//!    `SetFileInformationByHandle(FileRenameInfoEx)` with
//!    `FILE_RENAME_FLAG_POSIX_SEMANTICS`, which supersedes the open
//!    target instead of deleting it. Password rotation replaces
//!    `.wallet.keys` while the wallet handle still holds `LockFileEx` on
//!    byte 0 of it, so `persist` returned `ERROR_ACCESS_DENIED` (os
//!    error 5) and **every password rotation on Windows failed**. The
//!    `FileRenameInfoEx` path needs NTFS: on exFAT or a share that does
//!    not support POSIX-semantics rename, rotation with a live lock
//!    still fails, and that is a known limitation rather than a
//!    regression.
//! 2. **`keep` is where `FILE_ATTRIBUTE_TEMPORARY` is cleared.**
//!    `Builder::tempfile_in` stages with that attribute, which asks the
//!    cache manager to avoid writing the data back to mass storage while
//!    cache is available — the usual case being a temp file that is
//!    deleted soon after its handle closes. `rename` does **not** clear
//!    it, so without the `keep` the attribute rides onto the target and a
//!    permanent wallet artifact is left permanently marked temporary.
//!
//!    **It does not undo step 3.** `sync_all` is `FlushFileBuffers` on
//!    Windows, which flushes unconditionally; a caching hint does not
//!    override an explicit flush, and this write's durability is not at
//!    risk either way. What the attribute misdescribes is the file's whole
//!    subsequent life: it is false metadata on an artifact that is not
//!    temporary, and it is a standing hint to the cache manager for any
//!    later writer that does not flush explicitly. `tempfile` refuses to
//!    persist a file still carrying it for the same reason, in `persist`'s
//!    own first step, and `keep` performs exactly that call
//!    (`SetFileAttributesW(FILE_ATTRIBUTE_NORMAL)`) — so keeping it is
//!    also what makes this path behaviour-preserving against the `persist`
//!    it replaced. Observed end state is byte-identical to `persist`'s
//!    (attrs `0x20`, the same as any ordinary write).
//!
//! Neither difference is observable on Unix, where `imp::keep` is a
//! no-op and `rename(2)` never cared about locks — which is why this
//! path survived to ship.
//!
//! # Platform notes
//!
//! - On POSIX we `fsync(2)` both the file and the parent directory FD
//!   (the latter opened via `std::fs::File::open` and synced with
//!   `sync_all`). On Windows there is no directory-fsync;
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

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

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
/// No caller branches on this today; it is **returned rather than swallowed**
/// so a durability-sensitive path — e.g. write-once keys-file creation — can
/// later choose to fail loud on `Unconfirmed` without re-litigating the
/// atomic-write contract. It is deliberately not an error: the write is
/// applied, so surfacing it as `Err` would force every caller to unwind an
/// already-committed write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Durability {
    /// The write is applied and the parent-directory fsync succeeded.
    Confirmed,
    /// The write is applied, but the post-rename parent-directory fsync
    /// failed — durability across an immediate crash is unconfirmed.
    Unconfirmed,
}

/// Write `bytes` to `target` using the six-step atomic dance described
/// in the module docs. Mode is `0o600` on Unix; inherit-default on
/// Windows.
///
/// Returns [`Durability`] once the write is **applied** (the `rename(2)` has
/// landed): `Confirmed` when the parent-directory fsync also succeeded,
/// `Unconfirmed` when it did not. A failure *before* the rename leaves the
/// target untouched and returns `Err`.
///
/// # Errors
///
/// - [`WalletFileError::Io`] for a filesystem failure while **producing**
///   the staged file: create, write, or fsync of the temp.
/// - [`WalletFileError::AtomicWriteFinalizeStaged`] for a failure to
///   finalize the staged file for the swap (the `FILE_ATTRIBUTE_TEMPORARY`
///   clear; Unix-unreachable). No `rename(2)` was attempted.
/// - [`WalletFileError::AtomicWriteRename`] specifically for failures
///   of the `rename(2)` step. The dedicated variants exist so callers
///   can distinguish "couldn't write the bytes" from "wrote the bytes
///   but couldn't swap them in" — the latter means the target is
///   untouched, which is sometimes recoverable.
///
/// Every error path leaves the target **byte-unchanged**; a post-rename
/// failure is reported as `Ok(Durability::Unconfirmed)`, never as `Err`.
/// Removal of the staged file is best-effort on every path (see the
/// module docs, step 6) and is not part of the contract.
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
/// Exactly [`atomic_write_file`]'s. A finalize or rename failure drops the
/// hook's value along with the error; the target is untouched in both cases.
pub(crate) fn atomic_write_file_with<T>(
    target: &Path,
    bytes: &[u8],
    before_persist: impl FnOnce(&Path) -> Result<T, WalletFileError>,
) -> Result<(T, Durability), WalletFileError> {
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

    // The staged file is complete and durable; the caller may now attach
    // whatever must travel with it into place (the keys-file lock). If this
    // fails, `tempfile` unlinks the staged file and the target is untouched.
    let staged = before_persist(tmp.path())?;

    // Persist into place. This is deliberately NOT `NamedTempFile::persist`,
    // and the difference is load-bearing on Windows — see the module docs,
    // *Why not `persist`*.
    //
    // `keep()` is the attribute clear (`SetFileAttributesW(FILE_ATTRIBUTE_NORMAL)`
    // on Windows, a no-op on Unix). It is guarded: a failure to clear returns
    // `Err`, and the `TempPath` rides inside that error, so its drop guard is
    // still armed and still *attempts* the unlink — best-effort, like every
    // other cleanup path here (the guard ignores unlink errors). The target is
    // untouched either way, which is the part that is guaranteed.
    let staged_path = tmp.into_temp_path();
    let kept = staged_path
        .keep()
        .map_err(|e| WalletFileError::finalize_staged(target.to_path_buf(), e.error))?;

    // `keep()` disarmed `tempfile`'s cleanup, so from here the staged file is
    // ours. `persist` used to carry the `NamedTempFile` inside its error and
    // clean up on drop; nothing does that now, and without this arm every
    // failed rotation would strand a `.<random>.shekyl-tmp` beside the wallet.
    if let Err(e) = std::fs::rename(&kept, target) {
        if let Err(cleanup) = std::fs::remove_file(&kept) {
            // Best-effort: the rename failure is the one the caller must see,
            // and a stranded staged file is clutter rather than corruption —
            // it is a sibling with a random `.shekyl-tmp` name, never the
            // wallet itself. Reported so it is not silent.
            tracing::warn!(
                staged = %kept.display(),
                error = %cleanup,
                "could not remove the staged file after a failed rename"
            );
        }
        return Err(WalletFileError::rename(target.to_path_buf(), e));
    }

    // The rename above has already committed the new file into place, and the
    // file data was fsynced before it. The parent-dir fsync only hardens the
    // rename against an immediate crash; if it fails the write is still
    // applied, so this is a completed write with unconfirmed durability — not
    // a failure a caller must unwind an already-applied write around. Report
    // it in the return value instead of as an error.
    match fsync_parent_dir(parent) {
        Ok(()) => Ok((staged, Durability::Confirmed)),
        Err(_) => Ok((staged, Durability::Unconfirmed)),
    }
}

/// Platform-gated parent-directory fsync. POSIX: open the dir and
/// `fsync` the fd. Windows: no-op (per Windows' durability model, the
/// `sync_all` on the file suffices once the rename has completed).
///
/// Returns the raw `io::Error` (not a `WalletFileError`) so the sole caller
/// classifies a failure as `Durability::Unconfirmed` rather than an error —
/// this runs *after* the rename has committed, so the write is already
/// applied.
#[cfg(unix)]
fn fsync_parent_dir(parent: &Path) -> io::Result<()> {
    // `std::fs::File::open` on a directory is portable on all Unixes we
    // care about (Linux, macOS, FreeBSD).
    let dir = File::open(parent)?;
    dir.sync_all()
}

#[cfg(not(unix))]
fn fsync_parent_dir(_parent: &Path) -> io::Result<()> {
    // Windows NTFS guarantees rename durability after the file's
    // sync_all; there is no directory-fsync equivalent, so the write is
    // always `Durability::Confirmed` there.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::KeysFileLock;
    use std::fs;

    /// Replacing a **locked** target is where `NamedTempFile::persist` and
    /// [`std::fs::rename`] diverge, and the module's *Why not `persist`*
    /// section is written against this fact. On Windows `persist` issues
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
    /// `persist`.
    ///
    /// The edit that turns the Windows `persist` arm red is `tempfile` gaining
    /// the fallback std already has, at which point the module doc's premise —
    /// not this crate's code — is what changed. The `rename` arm goes red if
    /// std loses it, and rotation would be broken again. The POSIX arms go red
    /// if a mandatory lock ever appears there.
    #[test]
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

    /// The staged file is created by `tempfile` with `FILE_ATTRIBUTE_TEMPORARY`,
    /// which asks the cache manager to avoid writing the data back while cache
    /// is available. `rename` does **not** clear it — `TempPath::keep` does —
    /// so without the `keep` a permanent wallet artifact is left permanently
    /// marked temporary: false metadata, and a standing hint for any later
    /// writer that does not flush explicitly. It does not undo this module's
    /// own `sync_all`, which flushes unconditionally.
    ///
    /// The reason this needs a test rather than a comment is that the failure
    /// is **invisible in the bytes**: a `keep` refactored away as a cleanup
    /// formality changes no content and no test that compares content. Only
    /// the attribute moves, and only here.
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
             the staged file's attribute survived the rename and the fsync guarantee is gone"
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

        // The staged file must not be left behind. `keep()` disarms
        // `tempfile`'s cleanup, so nothing but this module's own error arm
        // removes it — and on the success path the rename consumed it.
        let strays: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".shekyl-tmp"))
            .collect();
        assert!(strays.is_empty(), "staged files left behind: {strays:?}");
    }

    /// A **failed** rename must still unlink the staged file.
    ///
    /// This is the arm `keep()` created: it disarms `tempfile`'s drop guard, so
    /// on the failure path nothing but this module's explicit `remove_file`
    /// removes the staged file, and without it every failed write strands a
    /// `.<random>.shekyl-tmp` beside the wallet. The success-path assertion in
    /// [`replaces_a_target_held_by_a_live_lock`] cannot see this: there the
    /// rename consumed the staged file, so deleting the cleanup arm would leave
    /// that test green.
    ///
    /// A directory at the target is the portable way to make `rename` fail
    /// after everything before it has succeeded — the staging, the write and the
    /// fsync all complete, and only the swap is refused. The edit that turns
    /// this red is deleting the `remove_file` call; observed red before being
    /// trusted, with the stray file named in the failure message.
    ///
    /// **`AtomicWriteRename` means the rename on both platforms**, which is
    /// what makes this test sound rather than merely suggestive. An earlier
    /// form of this code mapped a `keep()` failure onto the same variant, and
    /// then this doc had to admit that the Windows arm proved less than the
    /// Unix one: a `keep()` failure leaves `tempfile`'s guard armed, so it does
    /// the cleanup and the test would pass with the `remove_file` arm never
    /// running. The fix was to the error model, not to the test — `keep()`
    /// failures are now [`WalletFileError::AtomicWriteFinalizeStaged`], so
    /// matching `AtomicWriteRename` pins the failing step everywhere and the
    /// asymmetry is gone rather than documented.
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
        // A directory cannot be replaced by a file rename on either platform.
        fs::create_dir(&target).unwrap();

        // The pre-persist hook is the only place the staged path is visible, and
        // capturing it is what makes this test name a file rather than scan for
        // a suffix. It also proves staging got as far as the hook: if the write
        // had failed earlier the hook would never run, `staged` would be `None`,
        // and a suffix scan would have reported "no strays" for the wrong
        // reason — the very fail-open shape this suite keeps finding.
        let mut staged: Option<std::path::PathBuf> = None;
        let err = atomic_write_file_with(&target, b"NEW", |p| {
            staged = Some(p.to_path_buf());
            Ok(())
        })
        .map(|((), d)| d)
        .expect_err("renaming a file over a directory must fail");

        let staged = staged.expect(
            "the pre-persist hook never ran, so the failure was before staging and \
             this test is not exercising the cleanup arm at all",
        );
        let WalletFileError::AtomicWriteRename { ref source, .. } = err else {
            panic!(
                "the failure must be the rename step, not an earlier one — otherwise \
                 this test is not exercising the cleanup arm it exists for: {err:?}"
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
                 swap, and `tempfile`'s guard would be doing the cleanup instead \
                 of the arm under test"
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
