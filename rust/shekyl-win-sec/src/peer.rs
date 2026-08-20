// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client-side peer check (**WP-D4**, **WP-D5**).
//!
//! Run on the pipe handle **before any secret crosses it**. Two comparisons,
//! both against the same handle, at one call site:
//!
//! 1. the pipe's **owner SID** equals the connecting user's SID;
//! 2. the pipe's **integrity level** is at least Medium.
//!
//! Without (2) the check verifies "same user" and silently accepts "same user,
//! sandboxed" — and per `WINDOWS_WALLET_SUPPORT.md` §6 the sandboxed case is
//! the *only* adversary this transport is defending against. A same-user
//! Medium-or-above process is out of scope because it already holds the wallet
//! file and the CLI's memory. So (2) is not defence-in-depth stacked on (1);
//! it is the half that addresses the in-scope threat.
//!
//! There is deliberately **no cross-user escape hatch** (WP-D5). The refusal
//! names both SIDs so an operator can see what happened, and says what to do —
//! rule 82: the error explains the security property rather than reading like
//! a bug to route around.

use std::ffi::c_void;
use std::fmt;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SYSTEM_MANDATORY_LABEL_ACE,
};

use crate::sid::{last_error, wide_to_string, LocalFreeGuard, SidString};

/// Windows mandatory integrity levels, coarse enough for the one comparison
/// this crate makes.
///
/// The numeric RIDs are the documented well-known values. Ordering is what
/// matters: `Low < Medium` is the whole check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    /// Untrusted (`0x0000`) — below AppContainer.
    Untrusted,
    /// Low (`0x1000`) — AppContainers, sandboxed renderers, downloaded files.
    Low,
    /// Medium (`0x2000`) — an ordinary user process. **The floor we accept.**
    Medium,
    /// High (`0x3000`) — elevated.
    High,
    /// System (`0x4000`) or above.
    System,
}

impl IntegrityLevel {
    fn from_rid(rid: u32) -> Self {
        match rid {
            0x0000..=0x0FFF => Self::Untrusted,
            0x1000..=0x1FFF => Self::Low,
            0x2000..=0x2FFF => Self::Medium,
            0x3000..=0x3FFF => Self::High,
            _ => Self::System,
        }
    }
}

/// Why a peer was refused. Every arm is a refusal — there is no "warn and
/// continue" path, because the next thing the caller does is send a passphrase.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerCheckError {
    /// `GetSecurityInfo` failed. Refuse: an unreadable descriptor is not a
    /// pass. This is the same fail-closed shape as the CI-gate lesson —
    /// "could not determine" must never read as "fine".
    Unreadable(u32),
    /// The pipe is owned by a different user (WP-D5 — no opt-in flag).
    OwnerMismatch {
        /// The SID we required: the connecting user's own.
        expected: SidString,
        /// The SID that actually owns the pipe.
        found: SidString,
    },
    /// The pipe is owned by the right user but at Low/Untrusted integrity —
    /// the sandboxed-escalation case of §6.
    IntegrityTooLow(IntegrityLevel),
}

impl fmt::Display for PeerCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(e) => write!(
                f,
                "refusing to use the wallet RPC pipe: its security descriptor \
                 could not be read (os error {e}), so who owns it is unknown"
            ),
            Self::OwnerMismatch { expected, found } => write!(
                f,
                "refusing to use the wallet RPC pipe: it is owned by {} but \
                 this process runs as {}. Shekyl does not connect across user \
                 accounts — run the wallet under your own account.",
                found.as_str(),
                expected.as_str()
            ),
            Self::IntegrityTooLow(level) => write!(
                f,
                "refusing to use the wallet RPC pipe: it was created by a \
                 {level:?}-integrity process. A sandboxed process running as \
                 you cannot read your wallet file, and must not receive your \
                 passphrase either."
            ),
        }
    }
}

impl std::error::Error for PeerCheckError {}

/// The verified outcome. Constructible only by [`PeerCheck::verify`], so a
/// caller cannot fabricate one — the same gate-the-unsound-surface-with-a-type
/// shape the engine uses for sealed evidence.
#[derive(Debug)]
pub struct PeerCheck {
    _private: (),
}

impl PeerCheck {
    /// Verify the pipe at `handle` against `expected_owner`.
    ///
    /// Call this **after connecting and before writing anything**. Returning
    /// `Ok` is the only thing that licenses sending a passphrase over the
    /// handle.
    /// # Safety
    ///
    /// `handle` must be a live handle to a named pipe this process opened.
    /// The call reads the object's security descriptor through it, so a
    /// dangling or foreign handle is undefined behaviour — and the caller is
    /// the only party that knows the handle is still valid, which is why this
    /// is `unsafe` rather than defensively checked.
    pub unsafe fn verify(
        handle: HANDLE,
        expected_owner: &SidString,
    ) -> Result<Self, PeerCheckError> {
        let mut owner_sid: *mut c_void = std::ptr::null_mut();
        let mut label_sid: *mut c_void = std::ptr::null_mut();
        let mut sacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        // One call reads both the owner and the mandatory label, so the two
        // comparisons cannot disagree about which object they describe.
        // SAFETY: `handle` is a live pipe handle owned by the caller; every
        // out-param is a local. On success `psd` is `LocalAlloc`-owned and is
        // freed by `guard` below; `owner_sid`/`label_sid` point INTO `psd` and
        // must not outlive it.
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                &raw mut owner_sid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut sacl,
                &raw mut psd,
            )
        };
        if rc != 0 {
            return Err(PeerCheckError::Unreadable(rc));
        }
        let _guard = SecurityDescriptorGuard(psd);

        // --- 1. owner ----------------------------------------------------
        let found = sid_to_string(owner_sid)?;
        if found != *expected_owner {
            return Err(PeerCheckError::OwnerMismatch {
                expected: expected_owner.clone(),
                found,
            });
        }

        // --- 2. integrity -------------------------------------------------
        // An object with NO label is treated by the OS as Medium, so an absent
        // SACL is a PASS, not a failure. Reading it as a failure here would
        // refuse every ordinary unlabelled pipe.
        let level = unsafe { label_from_sacl(sacl, &mut label_sid) };
        if level < IntegrityLevel::Medium {
            return Err(PeerCheckError::IntegrityTooLow(level));
        }

        Ok(Self { _private: () })
    }
}

/// Read the mandatory label out of a SACL, defaulting to Medium when absent.
///
/// # Safety
/// `sacl` must be null or point to a valid ACL that outlives the call.
unsafe fn label_from_sacl(
    sacl: *mut windows_sys::Win32::Security::ACL,
    label_sid: &mut *mut c_void,
) -> IntegrityLevel {
    if sacl.is_null() {
        return IntegrityLevel::Medium;
    }
    let ace_count = unsafe { (*sacl).AceCount };
    if ace_count == 0 {
        return IntegrityLevel::Medium;
    }
    // The mandatory label is the first (and, for a label SACL, only) ACE.
    let mut ace: *mut c_void = std::ptr::null_mut();
    let got = unsafe { windows_sys::Win32::Security::GetAce(sacl, 0, &raw mut ace) };
    if got == 0 || ace.is_null() {
        return IntegrityLevel::Medium;
    }
    let label = ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
    // `SidStart` is the first DWORD of an inline SID, not a pointer.
    let sid = unsafe { std::ptr::addr_of_mut!((*label).SidStart) }.cast::<c_void>();
    *label_sid = sid;

    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return IntegrityLevel::Medium;
    }
    let count = unsafe { *count_ptr };
    if count == 0 {
        return IntegrityLevel::Medium;
    }
    // The integrity RID is the LAST sub-authority.
    let rid_ptr = unsafe { GetSidSubAuthority(sid, u32::from(count) - 1) };
    if rid_ptr.is_null() {
        return IntegrityLevel::Medium;
    }
    IntegrityLevel::from_rid(unsafe { *rid_ptr })
}

fn sid_to_string(sid: *mut c_void) -> Result<SidString, PeerCheckError> {
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into a live security descriptor.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut wide) };
    if ok == 0 {
        return Err(PeerCheckError::Unreadable(last_error()));
    }
    let guard = LocalFreeGuard(wide);
    // SAFETY: `wide` is a NUL-terminated wide string owned by `guard`.
    Ok(SidString::from_raw(unsafe { wide_to_string(guard.0) }))
}

struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        // SAFETY: `GetSecurityInfo` documents `LocalAlloc` ownership of the
        // descriptor it writes; freed exactly once, here. The owner and label
        // SID pointers borrowed from it are not used after this point.
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}
