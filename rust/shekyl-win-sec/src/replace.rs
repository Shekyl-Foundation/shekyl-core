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
//! 2. Through that handle the staged file is renamed over the destination with
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
//! 4. A destination whose read-only attribute is set fails either rename
//!    with `ERROR_ACCESS_DENIED` too. On that denial the destination's
//!    attribute is read: set, the failure is [`ReplaceError::ReadOnly`] at
//!    once, which no wait changes; clear, on the classic class it is a
//!    reader holding the destination ([`Held::Live`]), and on the POSIX
//!    path the denial itself (Rick, 2026-11-19).
//!
//! **The creating handle** (Rick, 2026-11-18). A replace that writes its
//! own staged file holds one handle from the create to the close
//! ([`create_staged`], [`Staged`]): created `CREATE_NEW` with write and
//! delete access, `FILE_FLAG_WRITE_THROUGH` and its access descriptor,
//! sharing read only (write sharing is an option for the wallet's password
//! rotation alone, [`StagedSharing`]; delete is never shared), it
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
//! [`Durability::Durable`] only when the volume is local, its file system
//! is NTFS (`GetVolumeInformationByHandleW` on the handle), the POSIX
//! rename was the one that renamed, and the flush after it returned; FAT,
//! exFAT, ReFS and any other file system report
//! [`Durability::Unconfirmed`], naming it.
//!
//! **A network drive is never durable** (Rick, 2026-11-19): a volume whose
//! device is `FILE_REMOTE_DEVICE` (`NtQueryVolumeInformationFile`,
//! `FileFsDeviceInformation`, on the handle) is
//! [`Unconfirmed::Remote`] whatever file system it reports. A server names
//! the file system of the disk it shares (a Samba share answers `NTFS`),
//! and the write-through sentence above is NTFS's, on this computer's disk.
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

use windows_sys::Wdk::Storage::FileSystem::{
    FileFsDeviceInformation, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SHARING_VIOLATION,
    GENERIC_WRITE, INVALID_HANDLE_VALUE, MAX_PATH,
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
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

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
    /// The live file the rename would replace: a sharing violation, or on
    /// the classic rename (FAT32, exFAT) an access denial while the file's
    /// read-only attribute is clear.
    Live,
}

/// Why [`remove`], [`replace`] or [`Staged::commit`] failed.
#[derive(Debug)]
pub enum ReplaceError {
    /// Another program held this file open past the deadline.
    HeldOpen(Held),
    /// The live file's read-only attribute is set, and the rename was
    /// refused for it (module docs, step 4).
    ReadOnly,
    /// A step failed otherwise.
    Io(io::Error),
}

/// What one failed step of a replace says: a file another program holds,
/// which the deadline waits for, or a failure no wait changes.
enum Fault {
    Held(Held),
    Final(ReplaceError),
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
    /// The volume is a network drive (`FILE_REMOTE_DEVICE`), which is
    /// never durable, whatever file system it reports: this is the name it
    /// reports.
    Remote(String),
    /// The volume's file system is not NTFS: this is its name (`FAT32`,
    /// `exFAT`, `ReFS`, ...). Windows documents the write-through flush of a
    /// rename for NTFS alone.
    FileSystem(String),
    /// The volume is local and NTFS, but it refused the POSIX rename and
    /// the classic one renamed the file.
    ClassicRename,
    /// The flush after the rename failed.
    Flush(io::Error),
    /// The volume could not be queried, for its device or its file system.
    VolumeUnread(io::Error),
}

/// Run `step` until it succeeds, fails with something other than a held
/// file, or `deadline` passes; past it, the last held failure's [`Held`].
fn waiting<T>(
    deadline: Instant,
    mut step: impl FnMut() -> Result<T, Fault>,
) -> Result<T, ReplaceError> {
    loop {
        match step() {
            Ok(value) => return Ok(value),
            Err(Fault::Held(_)) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err(Fault::Held(held)) => return Err(ReplaceError::HeldOpen(held)),
            Err(Fault::Final(error)) => return Err(error),
        }
    }
}

/// [`Held::Staged`] when `error` is a sharing violation; otherwise the
/// error itself.
fn staged_fault(error: io::Error) -> Fault {
    if is_sharing_violation(&error) {
        Fault::Held(Held::Staged)
    } else {
        Fault::Final(ReplaceError::Io(error))
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
    waiting(deadline, || match std::fs::remove_file(staged) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(staged_fault(error)),
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
/// [`ReplaceError::ReadOnly`] when `live`'s read-only attribute refused the
/// rename; [`ReplaceError::Io`] when the open or the rename failed
/// otherwise.
pub fn replace(staged: &Path, live: &Path, deadline: Instant) -> Result<(), ReplaceError> {
    let source = waiting(deadline, || open_source(staged).map_err(staged_fault))?;
    waiting(deadline, || attempt(&source.0, live)).map(drop)
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

/// What the creating handle shares with another program's open of the
/// staged file (Rick, 2026-11-18). Never delete: the handle holds `DELETE`
/// access to rename the file, and another program that could delete or
/// rename it would race the commit. A program that opens the file without
/// sharing delete fails its own open whatever this handle shares, because
/// this handle holds `DELETE` access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedSharing {
    /// `FILE_SHARE_READ`: a reader may open it, a writer may not. The
    /// default ([`create_staged`]).
    Read,
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE`: a writer may open it too. Only
    /// the wallet's password rotation, which locks the staged keys file
    /// through a second handle it opens for reading and writing before the
    /// rename (`shekyl-engine-file`'s `atomic_write_file_with`); read
    /// sharing alone refuses that open with `ERROR_SHARING_VIOLATION`.
    ReadWrite,
}

impl StagedSharing {
    /// The `dwShareMode` bits.
    fn share_mode(self) -> u32 {
        match self {
            Self::Read => FILE_SHARE_READ,
            Self::ReadWrite => FILE_SHARE_READ | FILE_SHARE_WRITE,
        }
    }
}

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
/// returned handle, sharing read only ([`StagedSharing::Read`]).
///
/// # Errors
///
/// This account's SID or the descriptor could not be had (as
/// [`io::Error::other`]), or the create failed: an existing entry at `path`
/// is `ERROR_FILE_EXISTS`.
pub fn create_staged(path: &Path, descriptor: StagedDescriptor) -> io::Result<Staged> {
    create_staged_with(path, descriptor, StagedSharing::Read)
}

/// [`create_staged`], the creating handle sharing as `sharing` says.
///
/// # Errors
///
/// Exactly [`create_staged`]'s.
pub fn create_staged_with(
    path: &Path,
    descriptor: StagedDescriptor,
    sharing: StagedSharing,
) -> io::Result<Staged> {
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
            sharing.share_mode(),
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

    /// Whether the volume the staged file is on is a network drive
    /// (`FILE_REMOTE_DEVICE`).
    ///
    /// # Errors
    ///
    /// `NtQueryVolumeInformationFile` failed.
    pub fn is_remote(&self) -> io::Result<bool> {
        is_remote(&self.0)
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
    /// deadline; [`ReplaceError::ReadOnly`] when its read-only attribute
    /// refused the rename; [`ReplaceError::Io`] when the rename failed
    /// otherwise. The staged file is then kept or deleted as `on_failure`
    /// says.
    pub fn commit(
        self,
        live: &Path,
        deadline: Instant,
        on_failure: OnFailure,
    ) -> Result<Durability, ReplaceError> {
        let renamed = waiting(deadline, || attempt(&self.0, live));
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
        // A network drive first: it may report NTFS (module docs).
        let volume = is_remote(&self.0).and_then(|remote| Ok((remote, file_system_of(&self.0)?)));
        let durability = match volume {
            Err(error) => Durability::Unconfirmed(Unconfirmed::VolumeUnread(error)),
            Ok((true, name)) => Durability::Unconfirmed(Unconfirmed::Remote(name)),
            Ok((false, name)) if name != NTFS => {
                Durability::Unconfirmed(Unconfirmed::FileSystem(name))
            }
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

/// Whether the volume `file` is on is a network drive: its device's
/// characteristics carry `FILE_REMOTE_DEVICE`.
fn is_remote(file: &File) -> io::Result<bool> {
    let mut status = IO_STATUS_BLOCK::default();
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let len = u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the structure is too large"))?;
    // SAFETY: `status` and `device` are valid, writable and alive across
    // the call; `len` is `device`'s size, and `FileFsDeviceInformation` is
    // the class whose structure it is. The handle is open; the class needs
    // no particular access.
    let queried = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &raw mut status,
            (&raw mut device).cast::<core::ffi::c_void>(),
            len,
            FileFsDeviceInformation,
        )
    };
    // An NTSTATUS below zero is an error.
    if queried < 0 {
        // SAFETY: a pure translation of a status value.
        let code = unsafe { RtlNtStatusToDosError(queried) };
        return Err(i32::try_from(code).map_or_else(
            |_| io::Error::other(format!("NTSTATUS {queried:#x}")),
            io::Error::from_raw_os_error,
        ));
    }
    Ok(device.Characteristics & FILE_REMOTE_DEVICE != 0)
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

/// One rename of the file `file` is open on, and which rename renamed it.
fn attempt(file: &File, destination: &Path) -> Result<Renamed, Fault> {
    let posix = Rename::Ex(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS);
    match rename_with(file, destination, posix) {
        Ok(()) => Ok(Renamed::Posix),
        Err(error) if is_ex_unsupported(&error) => rename_with(file, destination, Rename::Classic)
            .map(|()| Renamed::Classic)
            .map_err(|error| destination_fault(error, destination, Renamed::Classic)),
        Err(error) => Err(destination_fault(error, destination, Renamed::Posix)),
    }
}

/// What a failed rename over `destination` through `rename` says (module
/// docs, steps 2 to 4): a sharing violation is a reader holding it, on
/// every path. An access denial is its read-only attribute when that is
/// set; when it is clear, a reader holding it on the classic class, and
/// the denial itself on the POSIX path (Rick, 2026-11-18 and 2026-11-19).
/// An attribute that cannot be read leaves the denial as it is: it is
/// never taken for a reader.
fn destination_fault(error: io::Error, destination: &Path, rename: Renamed) -> Fault {
    if is_sharing_violation(&error) {
        return Fault::Held(Held::Live);
    }
    if error.raw_os_error() != i32::try_from(ERROR_ACCESS_DENIED).ok() {
        return Fault::Final(ReplaceError::Io(error));
    }
    match std::fs::symlink_metadata(destination).map(|meta| meta.permissions().readonly()) {
        Ok(true) => Fault::Final(ReplaceError::ReadOnly),
        Ok(false) if rename == Renamed::Classic => Fault::Held(Held::Live),
        Ok(false) | Err(_) => Fault::Final(ReplaceError::Io(error)),
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
        replace(&staged, &live, Instant::now()).unwrap();
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
        let dir = volume_dir(var);
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

    /// The directory `var` names, or a refusal when it is unset: the tests
    /// about a particular volume never pass without one.
    fn volume_dir(var: &str) -> tempfile::TempDir {
        let Some(dir) = std::env::var_os(var) else {
            panic!("{var} is unset: set it to a directory on the volume this test is about");
        };
        tempfile::tempdir_in(dir).unwrap()
    }

    /// A commit on a network drive reports [`Unconfirmed::Remote`], naming
    /// the file system the server reports, and still lands the bytes (Rick,
    /// 2026-11-19). It prints what it measured: that file system, and what
    /// the share answers the POSIX rename, which a second staged file asks
    /// for alone. Red edit: drop the device query from the commit, and a
    /// share reporting NTFS is `Durable`.
    #[test]
    #[ignore = "needs SHEKYL_TEST_SHARE_DIR: a directory on a mapped network share (Samba)"]
    fn a_commit_on_a_network_share_is_unconfirmed() {
        let dir = volume_dir("SHEKYL_TEST_SHARE_DIR");
        let probe_live = dir.path().join("probe");
        std::fs::write(&probe_live, b"old").unwrap();
        let (probe, _) = staged_in(dir.path(), "probe", b"new");
        let posix = rename_with(
            probe.file(),
            &probe_live,
            Rename::Ex(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS),
        );
        println!(
            "share: file system {:?}, remote {:?}, POSIX rename {:?}",
            probe.file_system(),
            probe.is_remote(),
            posix.as_ref().map_err(io::Error::raw_os_error)
        );
        drop(probe);

        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let (staged, staged_path) = staged_in(dir.path(), "record", b"new");
        assert!(
            staged.is_remote().unwrap(),
            "SHEKYL_TEST_SHARE_DIR is not on a network drive"
        );
        let durability = staged
            .commit(
                &live,
                Instant::now() + Duration::from_secs(2),
                OnFailure::Remove,
            )
            .unwrap();
        match &durability {
            Durability::Unconfirmed(Unconfirmed::Remote(name)) => {
                println!("share: unconfirmed as a network drive reporting {name}");
            }
            other => panic!("expected a network drive, got {other:?}"),
        }
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
        assert!(!staged_path.exists());
    }

    /// Set or clear `path`'s read-only attribute.
    #[allow(
        clippy::permissions_set_readonly_false,
        reason = "Windows: the read-only attribute alone, which a test sets and clears again so its directory can be removed"
    )]
    fn set_read_only(path: &Path, read_only: bool) {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(read_only);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    /// A commit over a destination whose read-only attribute is set, in
    /// `dir`, is refused as [`ReplaceError::ReadOnly`] at once, never waited
    /// for as a reader, and the destination keeps its bytes.
    fn a_read_only_destination_is_refused_at_once_in(dir: &Path) {
        let live = dir.join("record");
        std::fs::write(&live, b"old").unwrap();
        set_read_only(&live, true);
        let (staged, staged_path) = staged_in(dir, "record", b"new");
        let started = Instant::now();
        let refused = staged.commit(&live, started + Duration::from_secs(2), OnFailure::Remove);
        let waited = started.elapsed();
        set_read_only(&live, false);
        assert!(
            matches!(refused, Err(ReplaceError::ReadOnly)),
            "{refused:?}"
        );
        assert!(
            waited < Duration::from_secs(1),
            "the refusal waited {waited:?}"
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"old");
        assert!(!staged_path.exists());
    }

    /// On NTFS the POSIX rename refuses a read-only destination, and the
    /// refusal says so (Rick, 2026-11-19). Red edit: drop the attribute read
    /// from `destination_fault`, and the refusal is the bare access denial.
    #[test]
    fn a_read_only_destination_on_ntfs_is_refused_at_once() {
        let dir = tempfile::tempdir().unwrap();
        a_read_only_destination_is_refused_at_once_in(dir.path());
    }

    /// On FAT32 the classic rename refuses a read-only destination with the
    /// denial a held one gets, and the attribute tells them apart: read-only
    /// at once (Rick, 2026-11-19). Red edit: take every classic denial for a
    /// reader, and this waits the deadline out as `HeldOpen`.
    #[test]
    #[ignore = "needs SHEKYL_TEST_FAT_DIR: a directory on a FAT32 volume (a scratch VHD)"]
    fn a_read_only_destination_on_fat_is_refused_at_once() {
        let dir = volume_dir("SHEKYL_TEST_FAT_DIR");
        a_read_only_destination_is_refused_at_once_in(dir.path());
    }

    /// On FAT32 a reader that holds the destination, whatever it shares,
    /// denies the classic rename; with the read-only attribute clear that is
    /// the destination held, waited for until the deadline (Rick,
    /// 2026-11-18). Red edit: take every classic denial for a read-only
    /// file, and this is `ReadOnly` at once.
    #[test]
    #[ignore = "needs SHEKYL_TEST_FAT_DIR: a directory on a FAT32 volume (a scratch VHD)"]
    fn a_held_destination_on_fat_is_held_open() {
        let dir = volume_dir("SHEKYL_TEST_FAT_DIR");
        let live = dir.path().join("record");
        std::fs::write(&live, b"old").unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&live)
            .unwrap();
        let (staged, _) = staged_in(dir.path(), "record", b"new");
        let refused = staged.commit(
            &live,
            Instant::now() + Duration::from_millis(300),
            OnFailure::Remove,
        );
        drop(reader);
        assert!(
            matches!(refused, Err(ReplaceError::HeldOpen(Held::Live))),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"old");
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

    /// The creating handle's default sharing is read only: a second writer
    /// cannot open the staged file whatever it shares, and fails with a
    /// sharing violation, while a reader can. Red edit: share write in
    /// `StagedSharing::Read`, and the writer that shares everything opens it.
    #[test]
    fn a_second_writer_cannot_open_a_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let (staged, staged_path) = staged_in(dir.path(), "record", b"new");
        for share in [
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SHARE_READ,
            0,
        ] {
            let writer = std::fs::OpenOptions::new()
                .write(true)
                .share_mode(share)
                .open(&staged_path)
                .unwrap_err();
            assert!(is_sharing_violation(&writer), "share {share:#x}: {writer}");
        }
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&staged_path)
                .expect("a reader that shares everything opens the staged file"),
        );
        staged
            .commit(
                &live,
                Instant::now() + Duration::from_secs(2),
                OnFailure::Remove,
            )
            .unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"new");
    }

    /// With write sharing a writer that shares read, write and delete opens
    /// the staged file (the wallet's password rotation locks it so), and the
    /// creating handle still renames it with that writer's handle open. Red
    /// edit: drop `FILE_SHARE_WRITE` from `StagedSharing::ReadWrite`, and
    /// the open is a sharing violation.
    #[test]
    fn write_sharing_lets_a_writer_that_shares_everything_open_it() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("record");
        let staged_path = dir.path().join("record.staging");
        let staged = create_staged_with(
            &staged_path,
            StagedDescriptor::Inherited,
            StagedSharing::ReadWrite,
        )
        .unwrap();
        std::io::Write::write_all(&mut staged.file(), b"new").unwrap();
        staged.sync().unwrap();
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&staged_path)
            .expect("write sharing lets the writer open the staged file");
        staged
            .commit(
                &live,
                Instant::now() + Duration::from_secs(2),
                OnFailure::Remove,
            )
            .unwrap();
        drop(writer);
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
