// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Windows system directory, for a child process started with a cleared
//! environment. A Windows program started with no `SystemRoot` can abort
//! before its first line (the pinned `tor.exe` does, `TOR_BUNDLE_DISTRIBUTION.md`
//! TB-7 part 2), so a launcher that clears the environment sets exactly that
//! one variable, from the OS and never from this process's own environment.

use std::ffi::OsString;
use std::fmt;

/// Why the system directory could not be read.
#[derive(Debug)]
pub enum SystemDirectoryError {
    /// The call failed; the OS error code.
    Os(std::io::Error),
    /// The call answered a length that cannot hold a path.
    UnusableLength,
}

impl fmt::Display for SystemDirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os(e) => write!(f, "GetSystemWindowsDirectoryW failed: {e}"),
            Self::UnusableLength => {
                f.write_str("GetSystemWindowsDirectoryW answered an unusable length")
            }
        }
    }
}

impl std::error::Error for SystemDirectoryError {}

/// The system-wide Windows directory, from `GetSystemWindowsDirectoryW`: the
/// value `SystemRoot` carries, read from the OS. Not the per-session
/// directory `GetWindowsDirectoryW` would return under Terminal Services.
///
/// # Errors
/// The OS error, or an answered length that cannot hold a path.
pub fn system_windows_directory() -> Result<OsString, SystemDirectoryError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    // SAFETY: a null buffer with a size of zero writes nothing. The call
    // returns the size the buffer needs, terminating null included, or 0 on
    // failure. The OS error is read before any further call.
    let needed = unsafe { GetSystemWindowsDirectoryW(std::ptr::null_mut(), 0) };
    if needed == 0 {
        return Err(SystemDirectoryError::Os(std::io::Error::last_os_error()));
    }
    let len = usize::try_from(needed).map_err(|_| SystemDirectoryError::UnusableLength)?;
    let mut buf = vec![0u16; len];
    // SAFETY: `buf` holds `needed` u16s and the call writes at most that
    // many, including the terminating null. On success the return excludes
    // that null.
    let written = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), needed) };
    if written == 0 || written >= needed {
        return Err(SystemDirectoryError::UnusableLength);
    }
    let chars = usize::try_from(written).map_err(|_| SystemDirectoryError::UnusableLength)?;
    buf.truncate(chars);
    Ok(OsString::from_wide(&buf))
}
