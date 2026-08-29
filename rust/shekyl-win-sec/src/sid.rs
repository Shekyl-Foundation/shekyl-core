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
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
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
    /// The token carries no `SE_GROUP_LOGON_ID`-marked group of logon-SID
    /// (`S-1-5-5-…`) shape.
    ///
    /// Every *interactive* and *service* logon has one — but a **network
    /// logon does not**, and here that is not a corner case, it is the
    /// mechanism WP-D6 relies on. P-17 measured it (probe sheet §4.8): a
    /// genuine same-user caller arriving over `IPC$` impersonates onto a token
    /// that carries the user SID but **no** logon SID, so a logon-SID-only
    /// descriptor is unmatchable from the network *by construction* and the
    /// open is refused with `ERROR_ACCESS_DENIED`.
    ///
    /// So this is a **refusal, never a fallback** — and a future reader must
    /// not "recover" from it by granting the user SID instead. That same
    /// network token *does* carry the user SID, so a user-SID grant would admit
    /// exactly the caller WP-D6 refuses, silently undoing D6 (see `sddl.rs`)
    /// again. A descriptor built without the logon SID does not have the
    /// property WP-D6 claims, and issuing one anyway would be worse than not
    /// starting.
    NoLogonSid,
}

impl fmt::Display for SidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenToken(e) => write!(f, "could not open the process token (os error {e})"),
            Self::QueryToken(e) => write!(f, "could not read the token's user SID (os error {e})"),
            Self::Stringify(e) => write!(f, "could not format the SID as a string (os error {e})"),
            Self::NoLogonSid => f.write_str(
                "this process's token carries no logon SID, so a session-scoped \
                 pipe descriptor cannot be built",
            ),
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
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
    if opened == 0 {
        return Err(SidError::OpenToken(last_error()));
    }
    let token = TokenGuard(token);
    user_sid_of(token.0)
}

/// The user SID of an **arbitrary** token, by the same `TokenUser` read.
///
/// Split out of [`current_user_sid`] so the same reader can be pointed at an
/// impersonation token — P-17's two-machine server reads the *caller's* user
/// SID this way to assert same-user before believing a refusal, alongside the
/// logon SID from [`logon_sid_of`]. The caller owns `token` and keeps it open
/// across the call; nothing here closes it.
pub(crate) fn user_sid_of(token: HANDLE) -> Result<SidString, SidError> {
    // Sizing call. It is EXPECTED to fail with ERROR_INSUFFICIENT_BUFFER; the
    // value we want is `needed`, so the return code is deliberately ignored
    // and only a zero `needed` is treated as failure.
    let mut needed: u32 = 0;
    // SAFETY: a null buffer with zero length is the documented sizing form.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    // Allocated as `u64`, not `u8`, and that is a soundness requirement rather
    // than a style choice: `Vec<u8>`'s buffer is 1-byte aligned, `TOKEN_USER`
    // needs 8, and casting a `*const u8` to `*const TOKEN_USER` and
    // dereferencing it is undefined behaviour when the allocation is
    // under-aligned. Caught by clippy for the Windows target — the workspace
    // Linux run cannot see this code at all.
    let words = (needed as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` is at least `needed` bytes (rounded up to a whole number
    // of `u64`s), is 8-byte aligned by construction, and outlives the call.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut needed,
        )
    };
    if read == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    // SAFETY: on success the buffer holds a `TOKEN_USER` whose `User.Sid`
    // points into that same allocation, which is still live here. The cast is
    // sound because the allocation is `u64`-aligned (see above).
    let sid_ptr = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    sid_to_string(sid_ptr)
}

/// The prefix every logon SID carries: NT authority (5) then
/// `SECURITY_LOGON_IDS_RID` (5). What follows is the session LUID.
const LOGON_SID_PREFIX: &str = "S-1-5-5-";

/// Read the calling process's **logon SID** — the per-logon-session identity
/// (`S-1-5-5-X-Y`) that WP-D6 uses to separate terminal-services sessions.
///
/// It is a *group* in the token, marked with `SE_GROUP_LOGON_ID`, so this walks
/// `TokenGroups` and returns the first group carrying that attribute. Every
/// interactive and service logon has exactly one; a **network** logon has
/// **none** (P-17, §4.8), which is not a gap but WP-D6's `IPC$` boundary working
/// by construction — [`SidError::NoLogonSid`] is the signal of it, not an error
/// to route around.
///
/// This is what the pipe DACL grants. Granting the **user** SID instead would
/// not merely fail to narrow — it would *widen*: P-17 (§4.8) showed a network
/// caller carries the user SID but no logon SID, so a user-SID grant admits the
/// very `IPC$` caller the logon SID refuses. See `sddl.rs` for why that
/// distinction is the whole point of WP-D6.
pub fn current_logon_sid() -> Result<SidString, SidError> {
    // SAFETY: pseudo-handle needing no close; `token` written only on success
    // and closed by `TokenGuard` on every path out.
    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
    if opened == 0 {
        return Err(SidError::OpenToken(last_error()));
    }
    let token = TokenGuard(token);
    logon_sid_of(token.0)
}

/// The logon SID of an **arbitrary** token, by the same `TokenGroups` walk.
///
/// Split out of [`current_logon_sid`] so the same reader can be pointed at a
/// token that is not this process's — specifically an impersonation token, for
/// P-17. P-17's original method expected a caller arriving over `IPC$` to carry
/// a *different* logon SID; the run (§4.8) showed it carries **none at all** —
/// this returns [`SidError::NoLogonSid`] — and that absence is itself the
/// attribution: a token with no logon SID cannot match the logon-SID-only ACE,
/// so the refusal is the ACE's, not the transport's.
///
/// The caller owns `token` and must keep it open across the call. Nothing here
/// closes it.
pub(crate) fn logon_sid_of(token: HANDLE) -> Result<SidString, SidError> {
    let mut needed: u32 = 0;
    // SAFETY: the documented sizing form (null buffer, zero length).
    unsafe {
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    // `u64`-aligned for the same reason as `current_user_sid`: `TOKEN_GROUPS`
    // contains pointers, so a `Vec<u8>` allocation would be under-aligned and
    // the cast below would be UB.
    let words = (needed as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` is at least `needed` bytes and outlives the call.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut needed,
        )
    };
    if read == 0 {
        return Err(SidError::QueryToken(last_error()));
    }

    // SAFETY: on success the buffer holds a `TOKEN_GROUPS` whose `Groups` array
    // is `GroupCount` long and lives in the same allocation.
    let groups = buf.as_ptr().cast::<TOKEN_GROUPS>();
    let count = unsafe { (*groups).GroupCount } as usize;
    let first = unsafe { std::ptr::addr_of!((*groups).Groups) }
        .cast::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>();

    for i in 0..count {
        // SAFETY: `i < GroupCount`, and the array is that long by contract.
        let entry = unsafe { &*first.add(i) };
        // `SE_GROUP_LOGON_ID` is `0xC000_0000` — a marker of TWO bits, not one.
        // The test is equality, not "any bit set": `& … != 0` would accept a
        // group carrying either constituent bit on its own, and Microsoft's own
        // documented predicate is `(Attributes & SE_GROUP_LOGON_ID) ==
        // SE_GROUP_LOGON_ID`.
        //
        // The failure mode of the weaker test is not "no match" but a SILENT
        // WIDENING: it would select some other group this token belongs to —
        // `Users`, say — and WP-D6's DACL would then grant *that* group access
        // to the wallet pipe. The client-side owner check cannot notice,
        // because the owner is still us. (PR #516 review.)
        //
        // `cast_unsigned` rather than `as u32` because windows-sys declares the
        // constant as an `i32` with the top bit set; the reinterpretation is
        // bit-preserving and says so at the call site.
        const LOGON_ID_MARKER: u32 = SE_GROUP_LOGON_ID.cast_unsigned();
        if entry.Attributes & LOGON_ID_MARKER != LOGON_ID_MARKER {
            continue;
        }

        // Independent structural check on a value that decides the DACL.
        //
        // A logon SID is `S-1-5-5-<high>-<low>`: NT authority, the
        // `SECURITY_LOGON_IDS_RID` sub-authority, then the session's 64-bit
        // LUID. Verifying the shape means a wrong selection cannot quietly
        // become a wrong grant — which is the same class of defect the
        // allow-ACE union bug was, and this round has already paid for that
        // lesson once.
        let sid = sid_to_string(entry.Sid)?;
        if !sid.as_str().starts_with(LOGON_SID_PREFIX) {
            continue;
        }
        return Ok(sid);
    }
    Err(SidError::NoLogonSid)
}

/// Format a SID pointer as a string. Shared by both readers above and by the
/// P-16 file-owner readback.
pub(crate) fn sid_to_string(sid: *mut c_void) -> Result<SidString, SidError> {
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into a live token buffer owned by the caller.
    let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut wide) };
    if converted == 0 {
        return Err(SidError::Stringify(last_error()));
    }
    let guard = LocalFreeGuard(wide);
    // SAFETY: NUL-terminated wide string owned by `guard`.
    Ok(SidString(unsafe { wide_to_string(guard.0) }))
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
