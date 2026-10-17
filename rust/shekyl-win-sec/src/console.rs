// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A write to standard error that takes no lock, for the daemon's panic
//! hook (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 1): the panicking thread may
//! hold the standard library's stderr lock, so the hook writes through the
//! handle directly.

#![cfg(windows)]

use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};

/// Writes `bytes` to standard error through its handle. Best effort: a
/// failure is ignored, because the caller is about to abort and has no one
/// to report it to.
pub fn write_stderr_raw(bytes: &[u8]) {
    // SAFETY: `GetStdHandle` reads no memory of ours; `WriteFile` reads
    // `bytes` for its length and writes the count into a local.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        if handle.is_null() {
            return;
        }
        let mut written = 0u32;
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        WriteFile(
            handle,
            bytes.as_ptr(),
            len,
            &raw mut written,
            std::ptr::null_mut(),
        );
    }
}
