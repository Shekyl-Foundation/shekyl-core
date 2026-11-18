// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Replacing a file by renaming another over it, through the handle
//! (`shekyl-os-account`'s `StagedWrite::commit`, the one caller; Rick,
//! 2026-11-18).
//!
//! `std::fs::rename` on the pinned toolchain (1.94.0,
//! `library/std/src/sys/fs/windows.rs`) calls `MoveFileExW` with
//! `MOVEFILE_REPLACE_EXISTING`, and only on `ERROR_ACCESS_DENIED` retries
//! through the handle. Here the handle is the rename, always:
//!
//! 1. [`open_source`] opens the staged file for `DELETE` and nothing else,
//!    sharing read, write and delete, without following a link. Another
//!    program that holds the file open without delete sharing (a scanner,
//!    an indexer) fails this open with `ERROR_SHARING_VIOLATION`
//!    ([`is_sharing_violation`]), and that is the only step a caller waits
//!    on.
//! 2. [`Source::rename_over`] renames it over the destination with
//!    `FileRenameInfoEx`, `FILE_RENAME_FLAG_REPLACE_IF_EXISTS` and
//!    `FILE_RENAME_FLAG_POSIX_SEMANTICS`: the destination's name moves to
//!    the new file even while a reader holds the old one open, and that
//!    reader keeps reading the old bytes.

#![cfg(windows)]

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    FileRenameInfoEx, SetFileInformationByHandle, DELETE, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
};

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

impl Source {
    /// Rename the file over `destination`, replacing it if it exists, with
    /// POSIX semantics.
    ///
    /// # Errors
    ///
    /// `destination` is not a valid path, or the rename failed.
    pub fn rename_over(self, destination: &Path) -> io::Result<()> {
        // The rename takes a full path when no root directory handle is
        // given.
        let destination = std::path::absolute(destination)?;
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        let name_bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path is too long"))?;
        let name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        // The structure, the name and its terminating NUL, in a buffer
        // aligned for the structure.
        let size = name_offset + name.len() * size_of::<u16>() + size_of::<u16>();
        let words = size.div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; words];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: `buffer` is at least `size` bytes, 8-byte aligned (the
        // structure's alignment), and zeroed. The writes stay inside it:
        // the header fields, then `name.len()` units at `FileName`, whose
        // offset plus the name and its NUL is `size`.
        unsafe {
            (*info).Anonymous.Flags =
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = name_bytes;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
        }
        let size = u32::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path is too long"))?;
        // SAFETY: the handle is open for `DELETE`; `info` is a valid
        // `FILE_RENAME_INFO` of `size` bytes, alive across the call.
        let renamed = unsafe {
            SetFileInformationByHandle(
                self.0.as_raw_handle(),
                FileRenameInfoEx,
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
    /// a reader that held the old destination open still reads the old
    /// bytes. Red edit: drop `FILE_RENAME_FLAG_POSIX_SEMANTICS`, and the
    /// rename over a destination held open fails.
    #[test]
    fn the_rename_replaces_a_destination_a_reader_holds_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged = dir.path().join("record.new");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        // A reader that shares read and write but not delete.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
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
