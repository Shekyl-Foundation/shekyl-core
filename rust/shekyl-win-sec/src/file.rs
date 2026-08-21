// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner-only seed file (**WP-D8**, WP-B3).
//!
//! `shekyl-cli create --seed-out` writes the one-time seed backup to a file
//! that, on Unix, is opened `O_CREAT | O_EXCL` at `0600`. That mode is the
//! difference between a seed readable by one account and one readable by
//! every account on the box, so the Windows half sets the equivalent **at
//! creation**, through `SECURITY_ATTRIBUTES` on `CreateFileW`, rather than
//! creating and then tightening.
//!
//! The policy is `O:<user>G:<user>D:P(A;;FA;;;<user>)` — one ACE, protected
//! DACL, **the user SID**. WP-D6 forbade a user-SID grant on the *pipe*
//! because the pipe is session-bound (remote `IPC$` reach, terminal-session
//! separation); a seed file is persistent and must be readable at the next
//! logon, so the only account-scoped principal that survives a logon is the
//! one to grant. That is also exactly what `0600` means. No mandatory label:
//! the read-up question for files is not this slice's to answer, and a label
//! without a ruling would be a default wearing a decision's clothes.
//!
//! `CREATE_NEW` is the `O_EXCL` half: an existing entry at the path — a file,
//! a directory, a reparse point — fails the create rather than being
//! followed or truncated.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
};

use crate::sddl::{OwnerOnlyDescriptor, SddlError};
use crate::sid::{current_user_sid, SidError};

/// Why the file could not be created owner-only.
#[derive(Debug)]
pub enum FileCreateError {
    /// This process's user SID could not be read, so there is no owner to
    /// name. Refuse rather than fall back to the OS default descriptor —
    /// that default is the whole-account-readable state this exists to avoid.
    Sid(SidError),
    /// The descriptor could not be built.
    Descriptor(SddlError),
    /// `CreateFileW` failed; `ERROR_FILE_EXISTS` is the `CREATE_NEW` refusal.
    Create(io::Error),
}

impl fmt::Display for FileCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sid(e) => write!(f, "could not identify the owner for the file: {e}"),
            Self::Descriptor(e) => write!(f, "{e}"),
            Self::Create(e) => write!(f, "could not create the file owner-only: {e}"),
        }
    }
}

impl std::error::Error for FileCreateError {}

impl From<SidError> for FileCreateError {
    fn from(e: SidError) -> Self {
        Self::Sid(e)
    }
}

impl From<SddlError> for FileCreateError {
    fn from(e: SddlError) -> Self {
        Self::Descriptor(e)
    }
}

/// Create `path` for writing, owner-only from its first instant, refusing an
/// existing entry.
///
/// The returned [`File`] has write access only — the caller writes the seed,
/// flushes, and closes. `sync_all` works on it (`FlushFileBuffers` needs
/// `GENERIC_WRITE`, which this grants).
pub fn create_owner_only_file(path: &Path) -> Result<File, FileCreateError> {
    let owner = current_user_sid()?;
    let descriptor = OwnerOnlyDescriptor::private_file(&owner)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call;
    // `descriptor.attributes_ptr()` is valid for as long as `descriptor` is,
    // which is past the call; `CreateFileW` reads both only during the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_NONE,
            descriptor.attributes_ptr(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(FileCreateError::Create(io::Error::last_os_error()));
    }
    // SAFETY: a fresh, valid, owned handle; `File` closes it exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// The owner SID of an open file, read back off the handle (P-16).
///
/// Literal form via `ConvertSidToStringSidW`, never SDDL text, so it is not
/// exposed to the well-known-SID canonicalisation P-1's first run found.
#[cfg(feature = "test-utils")]
pub fn file_owner_for_testing(file: &File) -> Result<crate::SidString, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `file` owns a live handle; every out-param is a local. On
    // success `psd` is `LocalAlloc`-owned and freed by the guard; `owner`
    // points into it and is consumed before the guard drops.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut psd,
        )
    };
    if rc != 0 {
        return Err(format!("GetSecurityInfo failed (os error {rc})"));
    }
    let _guard = crate::sid::LocalFreeGuard(psd.cast());
    crate::sid::sid_to_string(owner).map_err(|e| e.to_string())
}

/// The owner + DACL of an open file as SDDL (P-16), for **structural**
/// assertions only — the owner in this string may be canonicalised.
#[cfg(feature = "test-utils")]
pub fn file_sddl_for_testing(file: &File) -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: as in `file_owner_for_testing`; only the descriptor is requested.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut psd,
        )
    };
    if rc != 0 {
        return Err(format!("GetSecurityInfo failed (os error {rc})"));
    }
    let _guard = crate::sid::LocalFreeGuard(psd.cast());
    // SAFETY: `psd` is a live descriptor owned by `_guard` for the call.
    unsafe { crate::sddl::sddl_of(psd, info) }.map_err(|e| e.to_string())
}
