// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one Windows file replace for the whole tree (Rick, 2026-11-18):
//! renaming a staged file over a live one, through the staged file's
//! handle, with a wait for a reader that holds a file it needs and a
//! fallback for a file system without POSIX rename semantics.
//! `shekyl-os-account`'s `StagedWrite` and the Tor directory cache
//! (`shekyl-tor-control-client`) are its callers on Windows.
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
//! **The creating handle** (Rick, 2026-11-18). A replace that writes its
//! own staged file holds one handle from the create to the close
//! ([`create_staged`], [`Staged`]): created `CREATE_NEW` with write and
//! delete access, `FILE_FLAG_WRITE_THROUGH` and its access descriptor, it
//! writes and syncs the data, renames itself over the destination through
//! the steps above ([`Staged::commit`]), calls `FlushFileBuffers` after the
//! rename, and closes. No commit reopens a staged file it created, so a
//! reader of the staged file is never waited for: while the handle holds
//! `DELETE` access, another program that opens the staged file without
//! delete sharing fails its own open. Reopening with the source wait
//! ([`replace`]) stays only for resuming a journal a previous process left,
//! and [`remove`] for removing a leftover.
//!
//! **Durable, and how it is known** (Rick, 2026-11-18). `CreateFileW`'s
//! documentation, "Caching Behavior": "A write-through request via
//! `FILE_FLAG_WRITE_THROUGH` also causes NTFS to flush any metadata changes,
//! such as a time stamp update or a rename operation, that result from
//! processing the request."
//! (<https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew>)
//! The rename is a request on the write-through handle, so on NTFS it is
//! flushed with it. The `FlushFileBuffers` after the rename is a second
//! layer: Microsoft documents it for a file's data and metadata, not for a
//! rename, so it is not what the claim rests on. Windows documents no
//! user-mode flush of a directory, and `MoveFileExW`'s
//! `MOVEFILE_WRITE_THROUGH` documents a flush only for a move done as a copy
//! and a delete. [`Staged::commit`] therefore reports
//! [`Durability::Durable`] only when the volume's file system is NTFS
//! (`GetVolumeInformationByHandleW` on the handle), the POSIX rename was the
//! one that renamed, and the flush after it returned; FAT, exFAT, ReFS and
//! any other file system report [`Durability::Unconfirmed`], naming it.
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
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SHARING_VIOLATION, GENERIC_WRITE,
    INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfo, FileDispositionInfoEx, FileRenameInfo, FileRenameInfoEx,
    FlushFileBuffers, GetVolumeInformationByHandleW, SetFileInformationByHandle, CREATE_NEW,
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_INFO_BY_HANDLE_CLASS,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
};

use crate::sddl::OwnerOnlyDescriptor;
use crate::sid::current_user_sid;

/// How long [`replace`] sleeps between two opens of a held staged file: a
/// reader that lets go is seen within 50 ms.
const POLL: Duration = Duration::from_millis(50);

/// The one file system whose rename [`Staged::commit`] reports durable: the
/// name `GetVolumeInformationByHandleW` gives for it.
const NTFS: &str = "NTFS";

/// Which file another program held past the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// The staged file (a leftover being removed, or the source's open).
    Staged,
    /// The live file the rename would replace: a sharing violation.
    Live,
    /// The live file, on the classic rename (FAT32, exFAT): its access
    /// denial is a reader holding it or a file that is not writable, and
    /// the two cannot be told apart (Rick, 2026-11-18).
    LiveOrUnwritable,
}

/// Why [`remove`], [`replace`] or [`Staged::commit`] failed.
#[derive(Debug)]
pub enum ReplaceError {
    /// Another program held this file open past the deadline.
    HeldOpen(Held),
    /// A step failed otherwise.
    Io(io::Error),
}

/// Whether a rename that landed is known to survive a power loss.
#[derive(Debug)]
pub enum Durability {
    /// NTFS renamed it through the write-through handle on the POSIX path,
    /// and the flush after the rename returned (module docs).
    Durable,
    /// The rename landed; that it survives a power loss is not confirmed.
    Unconfirmed(Unconfirmed),
}

/// Why a rename that landed is not reported durable.
#[derive(Debug)]
pub enum Unconfirmed {
    /// The volume's file system is not NTFS: this is its name (`FAT32`,
    /// `exFAT`, `ReFS`, ...). Windows documents the write-through flush of a
    /// rename for NTFS alone.
    FileSystem(String),
    /// The volume is NTFS, but it refused the POSIX rename and the classic
    /// one renamed the file.
    ClassicRename,
    /// The flush after the rename failed.
    Flush(io::Error),
    /// The volume's file system could not be read.
    FileSystemUnread(io::Error),
}

/// Run `step` until it succeeds, fails with something other than a held
/// file, or `deadline` passes; past it, the last held failure's [`Held`].
fn waiting<T>(
    deadline: Instant,
    mut step: impl FnMut() -> Result<T, (io::Error, Option<Held>)>,
) -> Result<T, ReplaceError> {
    loop {
        match step() {
            Ok(value) => return Ok(value),
            Err((_, Some(_))) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err((_, Some(held))) => return Err(ReplaceError::HeldOpen(held)),
            Err((error, None)) => return Err(ReplaceError::Io(error)),
        }
    }
}

/// [`Held::Staged`] when `error` is a sharing violation.
fn staged_held(error: &io::Error) -> Option<Held> {
    is_sharing_violation(error).then_some(Held::Staged)
}

/// Remove the leftover staged file at `staged`, if there is one, waiting
/// until `deadline` for a reader that holds it without delete sharing.
///
/// # Errors
///
/// [`ReplaceError::HeldOpen`] past the deadline; [`ReplaceError::Io`]
/// when the removal failed otherwise.
pub fn remove(staged: &Path, deadline: Instant) -> Result<(), ReplaceError> {
    waiting(deadline, || match std::fs::remove_file(staged) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            let held = staged_held(&error);
            Err((error, held))
        }
    })
}

/// Rename `staged` over `live` through a handle reopened on it, with POSIX
/// semantics where the file system has them, waiting until `deadline` for a
/// reader of either file. The handle stays open across the rename's
/// retries.
///
/// Only for a staged file this process did not create: a journal a previous
/// process left. A staged file this process writes is renamed through its
/// creating handle ([`Staged::commit`]). The reopened handle is not
/// write-through, so nothing here reports the rename durable.
///
/// # Errors
///
/// [`ReplaceError::HeldOpen`] naming the file held past the deadline;
/// [`ReplaceError::Io`] when the open or the rename failed otherwise.
pub fn replace(staged: &Path, live: &Path, deadline: Instant) -> Result<(), ReplaceError> {
    let source = waiting(deadline, || {
        open_source(staged).map_err(|error| {
            let held = staged_held(&error);
            (error, held)
        })
    })?;
    waiting(deadline, || {
        attempt(&source.0, live).map_err(|failed| (failed.error, failed.held))
    })
    .map(drop)
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

/// The descriptor a staged file is created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedDescriptor {
    /// None of its own: the directory's inherited ACL.
    Inherited,
    /// Owner-only and unlabelled ([`OwnerOnlyDescriptor::private_file`]),
    /// as [`crate::create_owner_only_file`] creates a file: the Tor
    /// directory cache's files.
    PrivateFile,
    /// Owner-only with the no-read-up label
    /// ([`OwnerOnlyDescriptor::rendezvous_file`]): a key, a rendezvous
    /// record.
    RendezvousFile,
    /// A service's console file ([`OwnerOnlyDescriptor::console_file`]).
    ConsoleFile,
}

/// What the creating handle may do, and what another program may do while
/// it is open: write the data and flush it (`GENERIC_WRITE`), rename and
/// delete the file (`DELETE`), and read the volume's file system
/// (`FILE_READ_ATTRIBUTES`).
const STAGED_ACCESS: u32 = GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES;

/// Sharing of the creating handle. Delete sharing alone would not be enough:
/// the wallet's password rotation locks the staged file through a second
/// handle it opens for reading and writing before the rename
/// (`shekyl-engine-file`'s `atomic_write_file_with`), which needs write
/// sharing. A program that opens the file without sharing delete fails its
/// own open whatever this handle shares, because this handle holds
/// `DELETE` access.
const STAGED_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// A staged file, held from its create to its close by the one handle that
/// writes it, syncs it, renames it and flushes it (module docs).
#[derive(Debug)]
pub struct Staged(File);

/// What [`Staged::commit`] does with the staged file when the rename fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnFailure {
    /// Leave it: a journal a store transaction names.
    Keep,
    /// Delete it through the handle before closing: a staged file nothing
    /// names. Best effort; a deletion that fails leaves it to the next
    /// write of the destination.
    Remove,
}

/// Create the staged file `path`, `CREATE_NEW`, with `descriptor` set in the
/// creating call, write-through, held open for its whole life by the
/// returned handle.
///
/// # Errors
///
/// This account's SID or the descriptor could not be had (as
/// [`io::Error::other`]), or the create failed: an existing entry at `path`
/// is `ERROR_FILE_EXISTS`.
pub fn create_staged(path: &Path, descriptor: StagedDescriptor) -> io::Result<Staged> {
    let built = match descriptor {
        StagedDescriptor::Inherited => None,
        StagedDescriptor::PrivateFile => Some(
            current_user_sid()
                .map_err(io::Error::other)
                .and_then(|owner| {
                    OwnerOnlyDescriptor::private_file(&owner).map_err(io::Error::other)
                })?,
        ),
        StagedDescriptor::RendezvousFile => Some(
            current_user_sid()
                .map_err(io::Error::other)
                .and_then(|owner| {
                    OwnerOnlyDescriptor::rendezvous_file(&owner).map_err(io::Error::other)
                })?,
        ),
        StagedDescriptor::ConsoleFile => Some(
            current_user_sid()
                .map_err(io::Error::other)
                .and_then(|owner| {
                    OwnerOnlyDescriptor::console_file(&owner).map_err(io::Error::other)
                })?,
        ),
    };
    let attributes = built
        .as_ref()
        .map_or(std::ptr::null(), OwnerOnlyDescriptor::attributes_ptr);
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `attributes`
    // is null or points into `built`, which outlives the call; `CreateFileW`
    // reads both only during the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            STAGED_ACCESS,
            STAGED_SHARE,
            attributes,
            CREATE_NEW,
            FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh, valid, owned handle; `File` closes it exactly once.
    Ok(Staged(unsafe { File::from_raw_handle(handle) }))
}

impl Staged {
    /// The handle, to write the data through (`impl Write for &File`).
    #[must_use]
    pub fn file(&self) -> &File {
        &self.0
    }

    /// Flush the data written so far (`FlushFileBuffers`).
    ///
    /// # Errors
    ///
    /// The flush failed.
    pub fn sync(&self) -> io::Result<()> {
        flush(&self.0)
    }

    /// The name of the file system of the volume the staged file is on.
    ///
    /// # Errors
    ///
    /// `GetVolumeInformationByHandleW` failed.
    pub fn file_system(&self) -> io::Result<String> {
        file_system_of(&self.0)
    }

    /// Rename the staged file over `live` through this handle, waiting
    /// until `deadline` for a reader that holds `live` (never for one of the
    /// staged file: such a reader could not open it), then flush and close.
    ///
    /// Nothing after the rename lands is an error: what the flush and the
    /// volume's file system say is the [`Durability`].
    ///
    /// # Errors
    ///
    /// [`ReplaceError::HeldOpen`] naming the live file held past the
    /// deadline; [`ReplaceError::Io`] when the rename failed otherwise. The
    /// staged file is then kept or deleted as `on_failure` says.
    pub fn commit(
        self,
        live: &Path,
        deadline: Instant,
        on_failure: OnFailure,
    ) -> Result<Durability, ReplaceError> {
        let renamed = waiting(deadline, || {
            attempt(&self.0, live).map_err(|failed| (failed.error, failed.held))
        });
        let path = match renamed {
            Ok(path) => path,
            Err(error) => {
                if on_failure == OnFailure::Remove {
                    // Best effort: the next write of `live` removes a
                    // leftover the deletion missed.
                    drop(delete(&self.0));
                }
                return Err(error);
            }
        };
        // The second layer (module docs): not what the claim rests on.
        let flushed = flush(&self.0);
        let durability = match file_system_of(&self.0) {
            Err(error) => Durability::Unconfirmed(Unconfirmed::FileSystemUnread(error)),
            Ok(name) if name != NTFS => Durability::Unconfirmed(Unconfirmed::FileSystem(name)),
            Ok(_) if path == Renamed::Classic => {
                Durability::Unconfirmed(Unconfirmed::ClassicRename)
            }
            Ok(_) => match flushed {
                Ok(()) => Durability::Durable,
                Err(error) => Durability::Unconfirmed(Unconfirmed::Flush(error)),
            },
        };
        drop(self);
        Ok(durability)
    }

    /// Delete the staged file through this handle, and close it.
    ///
    /// # Errors
    ///
    /// The deletion failed.
    pub fn discard(self) -> io::Result<()> {
        delete(&self.0)
    }
}

/// `FlushFileBuffers` on the handle: the file's data and metadata.
fn flush(file: &File) -> io::Result<()> {
    // SAFETY: the handle is open for `GENERIC_WRITE`, which the call needs.
    let flushed = unsafe { FlushFileBuffers(file.as_raw_handle()) };
    if flushed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mark the file `file` is open on for deletion: with POSIX semantics,
/// which removes the name at once even while another handle that shares
/// delete is open; where the file system refuses that class, the classic
/// delete-on-close.
fn delete(file: &File) -> io::Result<()> {
    let posix = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    if set_info(file, FileDispositionInfoEx, &posix).is_ok() {
        return Ok(());
    }
    let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
    set_info(file, FileDispositionInfo, &classic)
}

/// `SetFileInformationByHandle` with `info` as the class's structure.
fn set_info<T>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS, info: &T) -> io::Result<()> {
    let size = u32::try_from(size_of::<T>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the structure is too large"))?;
    // SAFETY: `info` is a valid `T` of `size` bytes, borrowed across the
    // call; `class` is the class whose structure `T` is (each caller pairs
    // them); the handle is open for `DELETE`.
    let set = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            class,
            std::ptr::from_ref(info).cast::<core::ffi::c_void>(),
            size,
        )
    };
    if set == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The name of the file system of the volume `file` is on.
fn file_system_of(file: &File) -> io::Result<String> {
    let mut name = [0u16; MAX_PATH as usize + 1];
    let len = u32::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the buffer is too large"))?;
    // SAFETY: `name` is a writable buffer of `len` units, alive across the
    // call; every other out-parameter is null, which the function accepts
    // for what it is not asked for.
    let read = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            len,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..end]))
}

/// A failed rename, and whether a reader holding the destination failed it.
struct Failed {
    error: io::Error,
    held: Option<Held>,
}

/// The rename a call asks for: the class and the union's value.
#[derive(Clone, Copy)]
enum Rename {
    /// `FileRenameInfoEx` with these `Flags`.
    Ex(u32),
    /// The classic `FileRenameInfo` with `ReplaceIfExists`.
    Classic,
}

/// Which rename renamed the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Renamed {
    /// `FileRenameInfoEx` with POSIX semantics.
    Posix,
    /// The classic `FileRenameInfo`: the file system refused the other.
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
        attempt(&self.0, destination)
            .map(drop)
            .map_err(|failed| failed.error)
    }
}

/// One rename of the file `file` is open on, which rename renamed it, and
/// whether its failure is the destination held: a sharing violation on
/// every path; on the classic class (a file system without POSIX renames)
/// an access denial too, which may as well be a destination that is not
/// writable. On the POSIX path an access denial is the real error, at once
/// (Rick, 2026-11-18).
fn attempt(file: &File, destination: &Path) -> Result<Renamed, Failed> {
    let posix = Rename::Ex(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS);
    match rename_with(file, destination, posix) {
        Ok(()) => Ok(Renamed::Posix),
        Err(error) if is_ex_unsupported(&error) => rename_with(file, destination, Rename::Classic)
            .map(|()| Renamed::Classic)
            .map_err(|error| {
                let held = if is_sharing_violation(&error) {
                    Some(Held::Live)
                } else if error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() {
                    Some(Held::LiveOrUnwritable)
                } else {
                    None
                };
                Failed { error, held }
            }),
        Err(error) => Err(Failed {
            held: is_sharing_violation(&error).then_some(Held::Live),
            error,
        }),
    }
}

fn rename_with(file: &File, destination: &Path, rename: Rename) -> io::Result<()> {
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
            file.as_raw_handle(),
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
    /// Bytes written through a creating handle in `dir`, staged at
    /// `name.staging`, with nothing renamed yet.
    fn staged_in(dir: &Path, name: &str, bytes: &[u8]) -> (Staged, std::path::PathBuf) {
        let staged_path = dir.join(format!("{name}.staging"));
        let staged = create_staged(&staged_path, StagedDescriptor::Inherited).unwrap();
        std::io::Write::write_all(&mut staged.file(), bytes).unwrap();
        staged.sync().unwrap();
        (staged, staged_path)
    }

    /// The creating handle is write-through: its mode, read back from the
    /// handle (`NtQueryInformationFile`, `FileModeInformation`), carries
    /// `FILE_WRITE_THROUGH`. Red edit: drop `FILE_FLAG_WRITE_THROUGH` from
    /// `create_staged`, and the bit is clear.
    #[test]
    fn the_staged_handle_is_write_through() {
        use windows_sys::Wdk::Storage::FileSystem::{
            FileModeInformation, NtQueryInformationFile, FILE_MODE_INFORMATION, FILE_WRITE_THROUGH,
        };
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

        let dir = tempfile::tempdir().unwrap();
        let (staged, _) = staged_in(dir.path(), "record", b"new");
        let mut mode = FILE_MODE_INFORMATION::default();
        // SAFETY: an all-zero `IO_STATUS_BLOCK` is a valid out-parameter.
        let mut status: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open; `status` and `mode` are writable
        // locals of the sizes passed, alive across the call.
        let result = unsafe {
            NtQueryInformationFile(
                staged.file().as_raw_handle(),
                &raw mut status,
                (&raw mut mode).cast::<core::ffi::c_void>(),
                u32::try_from(size_of::<FILE_MODE_INFORMATION>()).unwrap(),
                FileModeInformation,
            )
        };
        assert!(result >= 0, "NtQueryInformationFile: NTSTATUS {result:#x}");
        assert_ne!(
            mode.Mode & FILE_WRITE_THROUGH,
            0,
            "the staged handle's mode {:#x} lacks FILE_WRITE_THROUGH",
            mode.Mode
        );
    }

    /// On NTFS the commit is durable: the bytes are under the live name,
    /// the staged name is gone. The test first asserts its own subject, a
    /// temporary directory on NTFS. Red edit: report `Durable` without the
    /// file system check, and the FAT and exFAT tests below fail; drop the
    /// flush, and nothing here can tell (it is the second layer).
    #[test]
    fn a_commit_on_ntfs_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let (staged, staged_path) = staged_in(dir.path(), "record", b"new");
        assert_eq!(
            staged.file_system().unwrap(),
            NTFS,
            "this test needs its temporary directory on NTFS"
        );
        let durability = staged
            .commit(
                &live,
                Instant::now() + Duration::from_secs(2),
                OnFailure::Remove,
            )
            .unwrap();
        assert!(matches!(durability, Durability::Durable), "{durability:?}");
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path.exists());
    }

    /// A commit in the directory `var` names on a volume formatted
    /// `expected` reports unconfirmed, naming that file system, and still
    /// lands the bytes. Refuses, never passes, when `var` is unset.
    fn a_commit_on_reports_unconfirmed(var: &str, expected: &[&str]) {
        let Some(dir) = std::env::var_os(var) else {
            panic!("{var} is unset: set it to a directory on the volume this test is about");
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let (staged, staged_path) = staged_in(dir.path(), "record", b"new");
        let durability = staged
            .commit(
                &live,
                Instant::now() + Duration::from_secs(2),
                OnFailure::Remove,
            )
            .unwrap();
        match &durability {
            Durability::Unconfirmed(Unconfirmed::FileSystem(name)) => assert!(
                expected.contains(&name.as_str()),
                "{var}'s volume is {name}, not one of {expected:?}"
            ),
            other => panic!("expected an unconfirmed file system, got {other:?}"),
        }
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path.exists());
    }

    /// FAT reports unconfirmed (Rick, 2026-11-18).
    #[test]
    #[ignore = "needs SHEKYL_TEST_FAT_DIR: a directory on a FAT32 volume (a scratch VHD)"]
    fn a_commit_on_fat_is_unconfirmed() {
        a_commit_on_reports_unconfirmed("SHEKYL_TEST_FAT_DIR", &["FAT32", "FAT"]);
    }

    /// exFAT reports unconfirmed (Rick, 2026-11-18).
    #[test]
    #[ignore = "needs SHEKYL_TEST_EXFAT_DIR: a directory on an exFAT volume (a scratch VHD)"]
    fn a_commit_on_exfat_is_unconfirmed() {
        a_commit_on_reports_unconfirmed("SHEKYL_TEST_EXFAT_DIR", &["exFAT"]);
    }

    /// A watcher that opens the staged file without delete sharing, between
    /// the create and the rename, fails its own open with a sharing
    /// violation, and the commit completes without waiting for it. Red
    /// edit: drop `DELETE` from the creating handle's access (renaming
    /// through a reopened handle instead), and the watcher's open succeeds
    /// and holds the rename until the deadline.
    #[test]
    fn a_watcher_without_delete_sharing_fails_its_own_open() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let (staged, staged_path) = staged_in(dir.path(), "record", b"new");
        let watcher = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&staged_path)
            .unwrap_err();
        assert!(is_sharing_violation(&watcher), "{watcher}");
        let began = Instant::now();
        let deadline = began + Duration::from_secs(5);
        staged.commit(&live, deadline, OnFailure::Remove).unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the commit waited {:?}",
            began.elapsed()
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
    }

    /// A failed rename keeps or deletes the staged file as asked, and the
    /// deletion goes through the handle: a watcher that shares delete and
    /// holds the staged file open does not keep its name. The destination,
    /// a directory with an entry, is one no rename replaces. Red edit: make
    /// the failure path ignore `OnFailure`, and one of the two assertions
    /// fails.
    #[test]
    fn a_failed_commit_keeps_or_removes_the_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("blocked");
        std::fs::create_dir(&live).unwrap();
        std::fs::write(live.join("entry"), b"x").unwrap();
        let deadline = || Instant::now() + Duration::from_secs(2);

        let (kept, kept_path) = staged_in(dir.path(), "kept", b"journal");
        assert!(kept.commit(&live, deadline(), OnFailure::Keep).is_err());
        assert_eq!(std::fs::read(&kept_path).unwrap(), b"journal");

        let (removed, removed_path) = staged_in(dir.path(), "removed", b"replace");
        let watcher = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&removed_path)
            .unwrap();
        assert!(removed
            .commit(&live, deadline(), OnFailure::Remove)
            .is_err());
        assert!(!removed_path.exists(), "the deletion left the staged name");
        drop(watcher);
    }
}
