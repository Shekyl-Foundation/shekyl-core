// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Windows half of the serving store's disk-headroom probe (**WP-D9**).
//!
//! # Why this lives here rather than beside its caller
//!
//! Its one consumer is `shekyl-engine-core`, and locality would normally put
//! it there. `shekyl-engine-core` is `#![deny(unsafe_code)]`, and this needs
//! `unsafe` for a Win32 call.
//!
//! WP-D2 already decided how that resolves: **the dedicated `cfg(windows)`
//! crate carries the `unsafe`, rather than a crate-level `deny` being relaxed
//! or punctured at the call site.** The security primitives were the first two
//! cases; this is the third, and the rule does not change because the subject
//! is a disk rather than a descriptor.
//!
//! Moving it here also deleted a gate. While this lived in `shekyl-engine-core`
//! — a crate that cannot be cross-compiled from Linux, because its graph
//! reaches `ring` — the probe suite held a *copy* of it, and a CI gate existed
//! solely to prove the copy had not drifted. Here the real function is
//! compiled, clippy'd and tested directly for `x86_64-pc-windows-gnu`, so the
//! copy and its gate are gone rather than maintained
//! (`delete-the-duplicate-dont-synchronize-it`).

use std::path::Path;

/// Free space available *to this writer*, in bytes.
///
/// `GetDiskFreeSpaceExW`'s `lpFreeBytesAvailableToCaller` — the exact semantic
/// analog of `statvfs`'s `f_bavail`, which is what the Unix half reads. It
/// already accounts for per-user disk quotas, so it answers "how much can the
/// process filling this disk actually write" rather than "how much is
/// unallocated on the volume". `lpTotalNumberOfFreeBytes` would be the
/// `f_bfree` mistake: space that exists but this caller may not have.
///
/// The path goes through `OsStrExt::encode_wide` rather than a lossy
/// `to_string_lossy`, so a wallet directory containing unpaired surrogates
/// probes the directory the user actually named.
///
/// An error is returned rather than a guess: the caller's contract keeps
/// "the disk has room" and "I cannot tell" apart, and a fabricated figure
/// would collapse them.
pub fn free_bytes_available(path: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut available: u64 = 0;
    // SAFETY: `wide` is NUL-terminated and outlives the call; `available` is a
    // local. The two unused out-params are documented as optional and are
    // passed null because this probe deliberately wants only the
    // available-to-caller figure.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(available)
}
