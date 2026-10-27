// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An exclusive, non-blocking file lock on an open handle, for the daemon's
//! data-directory lock (DC-N1). The kernel releases it when the process
//! ends, however it ends.

#![cfg(windows)]

use std::fs::File;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// `Ok(true)` when the lock was taken, `Ok(false)` when another process
/// holds it.
///
/// # Errors
/// Any other failure of `LockFileEx`.
pub fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
    // SAFETY: `OVERLAPPED` is plain data the call reads for the offset.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a live handle; `overlapped` outlives the call,
    // which completes synchronously under `LOCKFILE_FAIL_IMMEDIATELY`.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle().cast(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &raw mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == i32::try_from(ERROR_LOCK_VIOLATION).expect("fits") => Ok(false),
        Some(code) if code == i32::try_from(ERROR_IO_PENDING).expect("fits") => Ok(false),
        _ => Err(err),
    }
}
