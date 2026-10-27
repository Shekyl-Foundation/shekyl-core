// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The roots the daemon's defaults derive from on Windows (IG-13): the
//! per-account `LocalAppData`, never the roaming profile, and
//! `%ProgramData%` for the service run mode. Read through the known-folder
//! interface, never an environment variable.

#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath,
};

/// The calling account's local application data folder.
#[must_use]
pub fn local_app_data() -> Option<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

/// The machine-wide application data folder, `%ProgramData%`.
#[must_use]
pub fn program_data() -> Option<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

/// `KF_FLAG_DEFAULT`: the folder's current path, no creation, no alias.
const DEFAULT_FLAGS: u32 = 0;

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `id` is a live GUID; `wide` receives a `CoTaskMemAlloc`ed
    // NUL-terminated string on success, freed exactly once below.
    let hr =
        unsafe { SHGetKnownFolderPath(id, DEFAULT_FLAGS, std::ptr::null_mut(), &raw mut wide) };
    if hr < 0 || wide.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: the string is NUL-terminated.
    while unsafe { *wide.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` characters precede the NUL.
    let path = OsString::from_wide(unsafe { std::slice::from_raw_parts(wide, len) });
    // SAFETY: freed exactly once, after the copy.
    unsafe { CoTaskMemFree(wide.cast()) };
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}
