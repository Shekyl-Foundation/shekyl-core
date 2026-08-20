// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The current process's user SID, as a string.
//!
//! WP-D1 derives the pipe name from this and WP-D4 compares the server's owner
//! against it. The string form is deliberate: it is what goes into both the
//! pipe name and the SDDL descriptor, so the *same* value keys both, and the
//! client's check collapses to one comparison with no separate expectation to
//! configure wrong.
//!
//! Kept literal rather than hashed. SID strings run ~45 characters against a
//! 256-character pipe-name limit, so hashing saves nothing — and it would
//! destroy the self-consistency property, because a hashed name could no
//! longer be compared against an owner SID read back off the handle.

use std::ffi::c_void;
use std::fmt;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A Windows security identifier in string form (`S-1-5-21-…`).
///
/// Compared by value, never parsed. Nothing in this crate interprets the
/// components; a SID is an opaque identity token here.
#[derive(Clone, PartialEq, Eq)]
pub struct SidString(String);

impl SidString {
    /// The string form, suitable for an SDDL clause or a pipe-name component.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap a SID string read back off an object's descriptor.
    ///
    /// `pub(crate)` on purpose: the only two ways to obtain a `SidString` are
    /// [`current_user_sid`] and a descriptor read inside this crate, so a
    /// caller cannot construct one from an arbitrary string and compare it
    /// against a peer's owner.
    pub(crate) fn from_raw(s: String) -> Self {
        Self(s)
    }
}

/// Redacted. A SID identifies a human account; it is not a secret, but it is
/// an identifier that should not leak into logs by accident (the same
/// discipline the persona-history types use).
impl fmt::Debug for SidString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SidString(<redacted>)")
    }
}

/// Why a SID could not be read. Deliberately coarse: every arm is a refusal,
/// and none of them is recoverable by the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum SidError {
    /// `OpenProcessToken` failed.
    OpenToken(u32),
    /// `GetTokenInformation` failed, at either the sizing or the read call.
    QueryToken(u32),
    /// `ConvertSidToStringSidW` failed.
    Stringify(u32),
}

impl fmt::Display for SidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenToken(e) => write!(f, "could not open the process token (os error {e})"),
            Self::QueryToken(e) => write!(f, "could not read the token's user SID (os error {e})"),
            Self::Stringify(e) => write!(f, "could not format the SID as a string (os error {e})"),
        }
    }
}

impl std::error::Error for SidError {}

/// Read the calling process's user SID.
///
/// Two-call sizing: the first `GetTokenInformation` asks how large the
/// `TOKEN_USER` buffer must be, the second fills it. The same discipline the
/// deleted envelope FFI used, for the same reason — a fixed-size guess here is
/// a buffer overrun waiting for an unusual account.
pub fn current_user_sid() -> Result<SidString, SidError> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close.
    // `token` is written only on success, and `TokenGuard` closes it on every
    // path out of this function.
    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(SidError::OpenToken(last_error()));
    }
    let token = TokenGuard(token);

    // Sizing call. It is EXPECTED to fail with ERROR_INSUFFICIENT_BUFFER; the
    // value we want is `needed`, so the return code is deliberately ignored
    // and only a zero `needed` is treated as failure.
    let mut needed: u32 = 0;
    // SAFETY: a null buffer with zero length is the documented sizing form.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is `needed` bytes, which is exactly what the sizing call
    // asked for, and it outlives the call.
    let read = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if read == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    // SAFETY: on success the buffer holds a `TOKEN_USER` whose `User.Sid`
    // points into that same allocation, which is still live here.
    let sid_ptr = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid_ptr` came from the token read above and is valid while
    // `buf` lives. On success the callee allocates `wide` with `LocalAlloc`.
    let converted = unsafe { ConvertSidToStringSidW(sid_ptr, &mut wide) };
    if converted == 0 {
        return Err(SidError::Stringify(last_error()));
    }
    let guard = LocalFreeGuard(wide);
    // SAFETY: `wide` is a NUL-terminated wide string owned by `guard`.
    let s = unsafe { wide_to_string(guard.0) };
    Ok(SidString(s))
}

/// Closes a token handle on every exit path.
struct TokenGuard(HANDLE);

impl Drop for TokenGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle from a successful `OpenProcessToken`
        // and is closed exactly once, here.
        unsafe { CloseHandle(self.0) };
    }
}

/// Frees a `LocalAlloc`-owned pointer. `LocalFree`, never `free` — the
/// allocator that produced it is the one that must reclaim it.
pub(crate) struct LocalFreeGuard(pub(crate) *mut u16);

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a Win32 call documented to allocate with
        // `LocalAlloc`, and is freed exactly once, here.
        unsafe { LocalFree(self.0.cast::<c_void>()) };
    }
}

/// # Safety
/// `p` must be a valid, NUL-terminated wide string.
pub(crate) unsafe fn wide_to_string(p: *const u16) -> String {
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// `GetLastError`, narrowed to a plain code. Callers only ever report it.
pub(crate) fn last_error() -> u32 {
    // SAFETY: no preconditions; reads a thread-local.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}
