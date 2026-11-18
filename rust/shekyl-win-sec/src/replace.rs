// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one Windows file replace for the whole tree (Rick, 2026-11-18):
//! renaming a staged file over a live one, through the staged file's
//! handle, with a wait for a reader that holds the staged file and a
//! fallback for a file system without POSIX rename semantics.
//! `shekyl-os-account`'s `replace` is its one caller on Windows.
//!
//! `std::fs::rename` on Windows is the same from 1.94.0 through 1.100.0,
//! beta (1.101) and main (`library/std/src/sys/fs/windows.rs`; beta and main
//! only factor it into `rename_inner` for the unstable `rename_noreplace`):
//! `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, and only on
//! `ERROR_ACCESS_DENIED` a retry through the handle. A sharing violation is
//! returned as it is. Here the handle is the rename, always:
//!
//! 1. [`open_source`] opens the staged file for `DELETE` and nothing else,
//!    sharing read, write and delete, without following a link. Another
//!    program that holds the staged file open without delete sharing (a
//!    scanner, an indexer) fails this open with `ERROR_SHARING_VIOLATION`
//!    ([`is_sharing_violation`]).
//! 2. [`Source::rename_over`] renames it over the destination with
//!    `FileRenameInfoEx`, `FILE_RENAME_FLAG_REPLACE_IF_EXISTS` and
//!    `FILE_RENAME_FLAG_POSIX_SEMANTICS`. A reader of the destination that
//!    shares delete keeps reading the old bytes; one that does not share
//!    delete fails the rename with `ERROR_SHARING_VIOLATION` (Windows 11
//!    23H2, build 22631, NTFS, 2026-11-18).
//! 3. FAT32 and exFAT refuse the `FileRenameInfoEx` class itself with
//!    `ERROR_INVALID_PARAMETER`, with or without the POSIX flag
//!    ([`is_ex_unsupported`]; measured on both, Windows 11 23H2, build
//!    22631, 2026-11-18). The same handle is then renamed once more through
//!    the classic `FileRenameInfo` class with `ReplaceIfExists`, which
//!    commits there. What such a file system loses is replacing a file a
//!    reader holds open: a reader of the destination, whatever it shares,
//!    fails the classic rename with `ERROR_ACCESS_DENIED`.
//!
//! **One deadline** (Rick, 2026-11-18): the removal of a leftover staged
//! file ([`remove`]), the source's open and the rename itself share the
//! caller's deadline, `REPLACE_WAIT` in all, not per step. Each waits only
//! on a reader that holds its file: a sharing violation, and on a file
//! system that took the classic rename, the access denial a held
//! destination gives there. The source's handle stays open across the
//! rename's retries. Past the deadline the failure names the file held
//! ([`Held`]).

#![cfg(windows)]

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileRenameInfo, FileRenameInfoEx, SetFileInformationByHandle, DELETE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_INFO_BY_HANDLE_CLASS, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
};

/// How long [`replace`] sleeps between two opens of a held staged file: a
/// reader that lets go is seen within 50 ms.
const POLL: Duration = Duration::from_millis(50);

/// Which file another program held past the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// The staged file (a leftover being removed, or the source's open).
    Staged,
    /// The live file the rename would replace.
    Live,
}

/// Why [`remove`] or [`replace`] failed.
#[derive(Debug)]
pub enum ReplaceError {
    /// Another program held this file open past the deadline.
    HeldOpen(Held),
    /// A step failed otherwise.
    Io(io::Error),
}

/// Run `step` until it succeeds, fails with something other than a held
/// file, or `deadline` passes; a held file is `held` past it.
fn waiting<T>(
    deadline: Instant,
    held: Held,
    mut step: impl FnMut() -> Result<T, (io::Error, bool)>,
) -> Result<T, ReplaceError> {
    loop {
        match step() {
            Ok(value) => return Ok(value),
            Err((_, true)) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err((_, true)) => return Err(ReplaceError::HeldOpen(held)),
            Err((error, false)) => return Err(ReplaceError::Io(error)),
        }
    }
}

/// Remove the leftover staged file at `staged`, if there is one, waiting
/// until `deadline` for a reader that holds it without delete sharing.
///
/// # Errors
///
/// [`ReplaceError::HeldOpen`] past the deadline; [`ReplaceError::Io`]
/// when the removal failed otherwise.
pub fn remove(staged: &Path, deadline: Instant) -> Result<(), ReplaceError> {
    waiting(deadline, Held::Staged, || {
        match std::fs::remove_file(staged) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                let held = is_sharing_violation(&error);
                Err((error, held))
            }
        }
    })
}

/// Rename `staged` over `live` through the handle, with POSIX semantics
/// where the file system has them, waiting until `deadline` for a reader
/// of either file. The handle stays open across the rename's retries.
///
/// # Errors
///
/// [`ReplaceError::HeldOpen`] naming the file held past the deadline;
/// [`ReplaceError::Io`] when the open or the rename failed otherwise.
pub fn replace(staged: &Path, live: &Path, deadline: Instant) -> Result<(), ReplaceError> {
    let source = waiting(deadline, Held::Staged, || {
        open_source(staged).map_err(|error| {
            let held = is_sharing_violation(&error);
            (error, held)
        })
    })?;
    waiting(deadline, Held::Live, || {
        source
            .attempt(live)
            .map_err(|failed| (failed.error, failed.held))
    })
}

/// A staged file, open for its rename.
#[derive(Debug)]
pub struct Source(File);

/// Open `source` for its rename: `DELETE` access alone, every sharing mode,
/// and a link opened as itself, never followed.
///
/// # Errors
///
/// The open failed. Another program holding the file without delete
/// sharing is [`is_sharing_violation`].
pub fn open_source(source: &Path) -> io::Result<Source> {
    std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source)
        .map(Source)
}

/// Whether `error` is another program holding a file open without the
/// sharing this open asked for (`ERROR_SHARING_VIOLATION`).
#[must_use]
pub fn is_sharing_violation(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_SHARING_VIOLATION).ok()
}

/// Whether `error` is a file system refusing the `FileRenameInfoEx` class
/// itself: `ERROR_INVALID_PARAMETER`, as FAT32 and exFAT do with or
/// without the POSIX flag (measured 2026-11-18).
#[must_use]
pub fn is_ex_unsupported(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok()
}

/// A failed rename, and whether a reader holding the destination failed it.
struct Failed {
    error: io::Error,
    held: bool,
}

/// The rename a call asks for: the class and the union's value.
#[derive(Clone, Copy)]
enum Rename {
    /// `FileRenameInfoEx` with these `Flags`.
    Ex(u32),
    /// The classic `FileRenameInfo` with `ReplaceIfExists`.
    Classic,
}

impl Source {
    /// Rename the file over `destination`, replacing it if it exists: with
    /// POSIX semantics, and once more through the classic class when the
    /// file system refuses `FileRenameInfoEx` ([`is_ex_unsupported`]).
    /// One attempt; [`replace`] is the waiting caller.
    ///
    /// # Errors
    ///
    /// `destination` is not a valid path, or the rename failed.
    pub fn rename_over(&self, destination: &Path) -> io::Result<()> {
        self.attempt(destination).map_err(|failed| failed.error)
    }

    /// One rename, and whether its failure is a reader holding the
    /// destination: a sharing violation, or on the classic class (a file
    /// system without POSIX renames) the access denial a held destination
    /// gives there.
    fn attempt(&self, destination: &Path) -> Result<(), Failed> {
        let posix =
            Rename::Ex(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS);
        match self.rename_with(destination, posix) {
            Ok(()) => Ok(()),
            Err(error) if is_ex_unsupported(&error) => self
                .rename_with(destination, Rename::Classic)
                .map_err(|error| Failed {
                    held: is_sharing_violation(&error)
                        || error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok(),
                    error,
                }),
            Err(error) => Err(Failed {
                held: is_sharing_violation(&error),
                error,
            }),
        }
    }

    fn rename_with(&self, destination: &Path, rename: Rename) -> io::Result<()> {
        // The rename takes a full path when no root directory handle is
        // given.
        let destination = std::path::absolute(destination)?;
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        let too_long = || io::Error::new(io::ErrorKind::InvalidInput, "the path is too long");
        let name_bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(too_long)?;
        let name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        // The structure, the name and its terminating NUL, in a buffer
        // aligned for the structure.
        let size = name_offset + name.len() * size_of::<u16>() + size_of::<u16>();
        let words = size.div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; words];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        let (class, flags): (FILE_INFO_BY_HANDLE_CLASS, u32) = match rename {
            Rename::Ex(flags) => (FileRenameInfoEx, flags),
            // The classic class reads the union as `ReplaceIfExists`, a
            // BOOLEAN in its first byte: 1 is TRUE.
            Rename::Classic => (FileRenameInfo, 1),
        };
        // SAFETY: `buffer` is at least `size` bytes, 8-byte aligned (the
        // structure's alignment), and zeroed. The writes stay inside it:
        // the header fields, then `name.len()` units at `FileName`, whose
        // offset plus the name and its NUL is `size`. Writing the union's
        // `Flags` sets its first byte, which the classic class reads as
        // `ReplaceIfExists`, on a little-endian target.
        unsafe {
            (*info).Anonymous.Flags = flags;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = name_bytes;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
        }
        let size = u32::try_from(size).map_err(|_| too_long())?;
        // SAFETY: the handle is open for `DELETE`; `info` is a valid
        // `FILE_RENAME_INFO` of `size` bytes, alive across the call.
        let renamed = unsafe {
            SetFileInformationByHandle(
                self.0.as_raw_handle(),
                class,
                info.cast::<core::ffi::c_void>(),
                size,
            )
        };
        if renamed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rename replaces the destination, the source's name is gone, and
    /// a reader that held the old destination open, sharing delete, still
    /// reads the old bytes. Red edit: drop `FILE_RENAME_FLAG_POSIX_SEMANTICS`,
    /// and the rename over a destination held open fails.
    #[test]
    fn the_rename_replaces_a_destination_a_reader_holds_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged = dir.path().join("record.new");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&live)
            .unwrap();
        open_source(&staged).unwrap().rename_over(&live).unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged.exists());
        let mut old = Vec::new();
        std::io::Read::read_to_end(&mut &reader, &mut old).unwrap();
        assert_eq!(old, b"old");
    }

    /// A reader of the staged file without delete sharing fails the open,
    /// and the failure is a sharing violation; released, the open succeeds.
    #[test]
    fn a_reader_without_delete_sharing_is_a_sharing_violation() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("record.new");
        std::fs::write(&staged, b"new").unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&staged)
            .unwrap();
        let held = open_source(&staged).unwrap_err();
        assert!(is_sharing_violation(&held), "{held}");
        drop(reader);
        open_source(&staged).unwrap();
    }
}
