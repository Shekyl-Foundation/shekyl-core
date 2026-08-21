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
//! O:<user-sid>G:<user-sid>D:P(A;;GA;;;<logon-sid>)S:(ML;;NW;;;ME)
//! ```
//!
//! (A second, for the seed **file** — `O:<user>G:<user>D:P(A;;FA;;;<user>)`
//! — is [`OwnerOnlyDescriptor::private_file`]; `file.rs` explains why a file
//! grants the user SID where the pipe must not.)
//!
//! - `O:` / `G:` — owner and group are the **user** SID, so a peer reading the
//!   owner back off the handle sees the SID the pipe name was derived from
//!   (the WP-D1 self-consistency property). Owner is identity, not access.
//! - `D:P` — a **protected** DACL: `P` blocks inherited ACEs, so nothing in
//!   the object's ancestry can widen access behind our back.
//! - `(A;;GA;;;<logon-sid>)` — generic-all for the **logon session**, and
//!   **no other ACE**. An absent ACE is a denial.
//! - `S:(ML;;NW;;;ME)` — WP-D4's mandatory label. Asserted, not inherited.
//!
//! # Why the DACL grants the logon SID and NOT the user SID
//!
//! **Corrected 2026-08-20 (PR #516 review).** The first version granted *both*
//! — `(A;;GA;;;<user-sid>)(A;;GA;;;<logon-sid>)` — on the reasoning that the
//! logon SID "narrows" the grant. **It does not.** Windows combines allow ACEs
//! as a **union**, so the user-SID ACE alone authorises *any* token for that
//! user: another terminal-services session, a remote logon over `IPC$`, a
//! scheduled task. Adding a second allow-ACE cannot subtract from that. WP-D6
//! was therefore unenforced, and the descriptor was exactly as wide as if the
//! logon SID had never been mentioned.
//!
//! The fix is to grant the **logon SID alone**. It is present in the token of
//! every process in the current logon session and absent from every other, so
//! it is the ACE that actually carries the session boundary. The user SID stays
//! as owner/group, where it is an identity for the peer check to compare
//! against rather than a grant.
//!
//! This is also why [`OwnerOnlyDescriptor::new`] **requires** the logon SID
//! rather than taking an `Option`. There is no meaningful fallback: a
//! descriptor built without it would grant nothing (useless) or fall back to
//! the user SID (the bug above, reintroduced silently). Failing to build is the
//! honest outcome, and `SidError::NoLogonSid` says so.
//!
//! # Why SDDL rather than hand-assembled ACLs
//!
//! Every descriptor here is built by handing a **string** to
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`. Assembling ACLs by
//! hand means `InitializeAcl` / `AddAccessAllowedAce` / `SetSecurityDescriptorDacl`
//! with manual size arithmetic — a long unsafe sequence whose failure mode is a
//! descriptor that is *wrong* rather than one that fails to build. SDDL moves
//! that work into the OS, so our `unsafe` reduces to one call plus a
//! `LocalFree`, and the security policy becomes a reviewable string that a
//! probe can read back and compare (P-1).

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

// SAFETY: `SECURITY_ATTRIBUTES::lpSecurityDescriptor` is a `*mut c_void`, and
// raw pointers are `!Send` by an explicit negative impl in core
// (`impl<T> !Send for *mut T`, `core::marker`), so the auto-trait does NOT
// derive `Send` for this struct and `windows-sys` adds no impl of its own.
// The override is sound because the pointee is a `LocalAlloc` heap block this
// value owns exclusively and frees exactly once in `Drop`; `LocalAlloc`
// memory has no thread affinity and `LocalFree` may run on any thread.
// Needed so the pipe listener that holds one can live inside a spawned serve
// task — `pipe.rs` carries a compile-time `Send` assertion that goes red if
// this impl is removed.
unsafe impl Send for OwnerOnlyDescriptor {}

impl OwnerOnlyDescriptor {
    /// Build the descriptor: owned by `owner`, access granted to `logon_sid`
    /// alone, labelled at Medium integrity.
    ///
    /// `logon_sid` is **required**, not optional — see the module docs. A
    /// descriptor without it either grants nothing or silently widens to the
    /// whole user account, and neither is a thing to build by accident.
    pub fn new(owner: &SidString, logon_sid: &SidString) -> Result<Self, SddlError> {
        Self::build(owner, logon_sid, MEDIUM_INTEGRITY_SACL)
    }

    /// The seed-file descriptor (**WP-D8**): owned by `owner`, full file
    /// access for `owner` alone, protected DACL, **no label**.
    ///
    /// This is the one place in the crate that grants the *user* SID, and
    /// `file.rs` says why that is not the WP-D6 bug coming back: a file is
    /// persistent, so a logon-SID grant would make it unreadable at the next
    /// logon, and the user SID is exactly what `0600` means. Still one ACE —
    /// a second grant here would be the PR #516 shape, and P-16 counts.
    pub fn private_file(owner: &SidString) -> Result<Self, SddlError> {
        let sddl = format!("O:{o}G:{o}D:P(A;;FA;;;{o})", o = owner.as_str());
        Self::from_sddl(&sddl)
    }

    /// The one place the **pipe** policy string is assembled. Both pipe
    /// constructors route through it so the label is the *only* thing that
    /// can differ between them — a second `format!` would be a second policy
    /// to keep in sync. (The file policy has its own single `format!` in
    /// [`Self::private_file`]; two policies, one assembly point each.)
    fn build(owner: &SidString, logon_sid: &SidString, sacl: &str) -> Result<Self, SddlError> {
        // The user SID is owner and group (identity, for the peer check); the
        // logon SID is the ONLY grant (access, scoped to this session).
        let sddl = format!(
            "O:{owner}G:{owner}D:P(A;;GA;;;{logon}){sacl}",
            owner = owner.as_str(),
            logon = logon_sid.as_str(),
        );
        Self::from_sddl(&sddl)
    }

    /// Hand a finished SDDL string to the OS. Every constructor ends here, so
    /// there is exactly one `unsafe` conversion to review.
    fn from_sddl(sddl: &str) -> Result<Self, SddlError> {
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
    /// The same descriptor **without** the mandatory label, for probes only.
    ///
    /// P-7 asserts that an object carrying no label reads as Medium — the OS
    /// default, and the property that stops the peer check refusing every
    /// ordinary pipe. Testing it needs an object that actually *reaches* the
    /// integrity check, which means its owner must match ours.
    ///
    /// A pipe created with a **default** descriptor does not qualify, and the
    /// first run of P-7 is why we know: on an account that is a member of
    /// Administrators, Windows gives a default-owner object the owner
    /// `S-1-5-32-544` (`BUILTIN\Administrators`) rather than the user, so the
    /// probe failed on `OwnerMismatch` long before any label was read.
    ///
    /// That is a fact about the platform worth keeping visible: **any pipe we
    /// create without an explicit owner would be refused by our own peer check
    /// on an administrator account.** Production never does — every descriptor
    /// comes from [`Self::new`], which sets `O:` explicitly — and P-1's
    /// readback confirms it.
    #[cfg(feature = "test-utils")]
    pub fn without_label_for_testing(
        owner: &SidString,
        logon_sid: &SidString,
    ) -> Result<Self, SddlError> {
        Self::build(owner, logon_sid, "")
    }

    /// Read the descriptor back as an SDDL string (**P-1**).
    ///
    /// This is the self-check the SDDL choice buys and hand-assembled ACLs
    /// cannot offer: the policy went in as a string, so it can come back out
    /// as one and be compared. Used by the probe suite to assert that the OS
    /// preserved what we wrote — which is a claim about the OS, not about our
    /// formatting, and therefore worth testing rather than assuming.
    pub fn to_sddl(&self) -> Result<String, SddlError> {
        // SAFETY: `lpSecurityDescriptor` is a live descriptor owned by `self`
        // for the duration of the call.
        unsafe {
            sddl_of(
                self.attributes.lpSecurityDescriptor,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
            )
        }
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

/// Render the selected parts of a live descriptor as SDDL.
///
/// Shared by [`OwnerOnlyDescriptor::to_sddl`] and the P-16 file readback, so
/// there is one conversion to review. The returned string is the OS's
/// **canonicalised** form — well-known SIDs come back as abbreviations (P-1's
/// first run) — so callers compare structure, not literal owners.
///
/// # Safety
/// `psd` must point to a valid security descriptor that outlives the call.
pub(crate) unsafe fn sddl_of(
    psd: *mut c_void,
    info: windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION,
) -> Result<String, SddlError> {
    let mut wide: *mut u16 = std::ptr::null_mut();
    let mut len: u32 = 0;
    // SAFETY: `psd` is valid per the contract above. On success the callee
    // allocates `wide` with `LocalAlloc`, freed by `guard`.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            info,
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

// Not `Clone`: two owners would double-free.
//
// Not `Send`/`Sync` either, and that is enforced by the compiler rather than by
// this comment: `SECURITY_ATTRIBUTES` holds a `*mut c_void`, raw pointers are
// `!Send + !Sync`, and the auto-derive therefore does not fire. Verified by
// compiling `assert_send::<T>()` against a struct holding one — it fails with
// E0277. Adding the impls would be a decision about thread-affinity, not a
// convenience, and nothing here needs it: the descriptor is consumed by a
// create call on the thread that built it.
