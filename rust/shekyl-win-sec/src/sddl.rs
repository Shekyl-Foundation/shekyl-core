// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner-only security descriptor, built from SDDL (**WP-D2**, **WP-D4**,
//! **WP-D6**).
//!
//! The policy this crate exists to express is one string:
//!
//! ```text
//! O:<sid>G:<sid>D:P(A;;GA;;;<sid>)(A;;GA;;;<logon-sid>)S:(ML;;NW;;;ME)
//! ```
//!
//! - `O:` / `G:` — owner and group are the creating user, so a peer reading
//!   the owner back off the handle sees the SID the pipe name was derived from
//!   (the WP-D1 self-consistency property).
//! - `D:P` — a **protected** DACL: `P` blocks inherited ACEs, so nothing in
//!   the object's ancestry can widen access behind our back.
//! - `(A;;GA;;;<sid>)` — generic-all for that user, and **no other ACE**. An
//!   absent ACE is a denial; there is deliberately no explicit `NETWORK` deny,
//!   because WP-D6 rules that the logon SID does that job better.
//! - `(A;;GA;;;<logon-sid>)` — WP-D6. The logon SID is per-logon-session, so
//!   it also separates terminal-services sessions, which an `S-1-5-2` deny
//!   does not.
//! - `S:(ML;;NW;;;ME)` — WP-D4's mandatory label. Asserted, not inherited.
//!
//! Building this as a string rather than assembling ACLs by hand is the whole
//! point: the failure mode of hand-assembly is a descriptor that is subtly
//! *wrong*, which no test on a Linux box would catch.

use std::ffi::c_void;
use std::fmt;

use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};

use crate::sid::{last_error, SidString};
use crate::MEDIUM_INTEGRITY_SACL;

/// Why a descriptor could not be built.
#[derive(Debug, PartialEq, Eq)]
pub enum SddlError {
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW` rejected the
    /// string or failed to allocate. The SDDL text is **not** included: it
    /// carries the user's SID, and an error string is the one place a value
    /// like that reliably ends up in a log.
    Convert(u32),
}

impl fmt::Display for SddlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Convert(e) => write!(
                f,
                "could not build the pipe security descriptor (os error {e})"
            ),
        }
    }
}

impl std::error::Error for SddlError {}

/// An owner-only descriptor, alive for as long as this value is.
///
/// Holds the `LocalAlloc`-owned descriptor the OS built for us and frees it on
/// drop. [`Self::attributes_ptr`] hands out a pointer for the duration of a
/// create call — it deliberately does not hand out ownership, because the
/// descriptor must outlive the `CreateNamedPipe` that consumes it and nothing
/// else should be able to extend or shorten that.
pub struct OwnerOnlyDescriptor {
    attributes: SECURITY_ATTRIBUTES,
}

impl OwnerOnlyDescriptor {
    /// Build the descriptor granting access to `owner` alone (plus the logon
    /// session, per WP-D6), labelled at Medium integrity.
    ///
    /// `logon_sid` is optional because it is read from the token's groups and
    /// a caller that could not find one should still get a working owner-only
    /// descriptor rather than no pipe at all — the logon SID narrows an
    /// already-narrow grant; it is not what carries the boundary.
    pub fn new(owner: &SidString, logon_sid: Option<&SidString>) -> Result<Self, SddlError> {
        let mut sddl = format!(
            "O:{owner}G:{owner}D:P(A;;GA;;;{owner})",
            owner = owner.as_str()
        );
        if let Some(logon) = logon_sid {
            sddl.push_str(&format!("(A;;GA;;;{})", logon.as_str()));
        }
        sddl.push_str(MEDIUM_INTEGRITY_SACL);

        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut psd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call. On success
        // the callee allocates `psd` with `LocalAlloc`, and `Drop` frees it
        // exactly once.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(SddlError::Convert(last_error()));
        }

        Ok(Self {
            attributes: SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .expect("SECURITY_ATTRIBUTES is a small fixed-size struct"),
                lpSecurityDescriptor: psd,
                // Never inheritable. A child process inheriting the pipe
                // handle would hold the server end without having satisfied
                // any of this, which is the one way a descriptor this narrow
                // still leaks.
                bInheritHandle: 0,
            },
        })
    }

    /// A pointer valid for as long as `self` is borrowed.
    ///
    /// The lifetime is the contract: `CreateNamedPipe` reads the descriptor
    /// during the call, so the descriptor must outlive it, and tying the
    /// pointer to `&self` is what makes that a compile-time property rather
    /// than a comment.
    pub fn attributes_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &raw const self.attributes
    }
}

impl OwnerOnlyDescriptor {
    /// Read the descriptor back as an SDDL string (**P-1**).
    ///
    /// This is the self-check the SDDL choice buys and hand-assembled ACLs
    /// cannot offer: the policy went in as a string, so it can come back out
    /// as one and be compared. Used by the probe suite to assert that the OS
    /// preserved what we wrote — which is a claim about the OS, not about our
    /// formatting, and therefore worth testing rather than assuming.
    pub fn to_sddl(&self) -> Result<String, SddlError> {
        let mut wide: *mut u16 = std::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: `lpSecurityDescriptor` is a live descriptor owned by `self`.
        // On success the callee allocates `wide` with `LocalAlloc`.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.attributes.lpSecurityDescriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                &raw mut wide,
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err(SddlError::Convert(last_error()));
        }
        let guard = crate::sid::LocalFreeGuard(wide);
        // SAFETY: `wide` is a NUL-terminated wide string owned by `guard`.
        Ok(unsafe { crate::sid::wide_to_string(guard.0) })
    }

    /// Whether the DACL is **protected** — inherited ACEs cannot widen it
    /// (**P-2**). `D:P` in the SDDL should produce this; the probe asserts the
    /// OS agrees.
    pub fn dacl_is_protected(&self) -> bool {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: live descriptor owned by `self`; both out-params are locals.
        let ok = unsafe {
            GetSecurityDescriptorControl(
                self.attributes.lpSecurityDescriptor,
                &raw mut control,
                &raw mut revision,
            )
        };
        ok != 0 && (control & SE_DACL_PROTECTED) != 0
    }
}

impl Drop for OwnerOnlyDescriptor {
    fn drop(&mut self) {
        // SAFETY: `lpSecurityDescriptor` came from a successful
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
        // documents `LocalAlloc` ownership, and is freed exactly once here.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.attributes.lpSecurityDescriptor);
        }
    }
}

// Not `Clone`: two owners would double-free. Not `Sync`/`Send` by default
// either — the descriptor is consumed by a create call on the thread that
// built it, and widening that is a decision, not a convenience.
