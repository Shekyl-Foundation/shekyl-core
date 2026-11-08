// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Who a file's or directory's security descriptor lets write or read it,
//! for the daemon configuration's allowlist (`DAEMON_CONFIG_CUTOVER.md`
//! §2.4): write is permitted only to SYSTEM, Administrators, TrustedInstaller and the
//! daemon's own account, and any other access-control entry that grants
//! it refuses, whatever it names.
//!
//! The walk reads the DACL's allow entries that apply to the object itself
//! (inherit-only entries bind children, not it) and the owner, who can
//! always rewrite the DACL. Deny entries are not subtracted: an allow for a
//! principal outside the list is a refusal even when a deny also names it,
//! because the check is an allowlist of principals, not a computation of
//! effective rights.

#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_INVALID_ACL, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use crate::sid::{current_user_sid, sid_to_string, SidString};

/// SYSTEM.
const SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// NT SERVICE\TrustedInstaller, the Windows servicing account that owns
/// the system tree: a default `C:\` grants it full control, and nothing
/// below it is the operator's to restrict. Its SID is fixed.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// One principal the descriptor grants the right to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grantee {
    /// SYSTEM, Administrators, or the calling account.
    Permitted,
    /// Anyone else, by SID.
    Other(String),
}

/// Why the descriptor could not be read.
#[derive(Debug)]
pub struct DaclError(u32);

impl std::fmt::Display for DaclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the security descriptor could not be read (os error {})",
            self.0
        )
    }
}

impl std::error::Error for DaclError {}

/// Any write right, on a file or a directory.
const WRITE_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// The write rights on a directory that let a principal replace or remove
/// an entry below it: add a file, delete a child, or take the descriptor.
/// Not `FILE_APPEND_DATA`, which on a directory is "add a subdirectory":
/// a default `C:\` grants BUILTIN\Users exactly that, and it changes no
/// child the daemon reads. Not the attribute and EA writes either, which
/// touch the directory's own metadata.
const DIRECTORY_WRITE_MASK: u32 =
    FILE_WRITE_DATA | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;

/// Any read right.
const READ_MASK: u32 = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL;

/// Who may write `path`: the owner, and every allow entry carrying a write
/// right.
///
/// # Errors
/// [`DaclError`] when the descriptor cannot be read.
pub fn write_grantees(path: &Path) -> Result<Vec<Grantee>, DaclError> {
    grantees(path, WRITE_MASK, true)
}

/// Who may replace or remove an entry of the directory `path`: the owner,
/// and every allow entry that can add a file, delete a child, or take the
/// descriptor. The rule for a directory above a file the daemon reads.
///
/// # Errors
/// [`DaclError`] when the descriptor cannot be read.
pub fn directory_write_grantees(path: &Path) -> Result<Vec<Grantee>, DaclError> {
    grantees(path, DIRECTORY_WRITE_MASK, true)
}

/// Who may read `path`: every allow entry carrying a read right.
///
/// # Errors
/// [`DaclError`] when the descriptor cannot be read.
pub fn read_grantees(path: &Path) -> Result<Vec<Grantee>, DaclError> {
    grantees(path, READ_MASK, false)
}

/// Whether a SID is one of the platform's own principals: SYSTEM,
/// Administrators or TrustedInstaller.
#[must_use]
pub fn is_platform_principal(sid: &SidString) -> bool {
    matches!(sid.as_str(), SYSTEM | ADMINISTRATORS | TRUSTED_INSTALLER)
}

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: `GetNamedSecurityInfoW` allocates the descriptor with
        // `LocalAlloc`; it is freed exactly once, here.
        unsafe { LocalFree(self.0.cast::<c_void>()) };
    }
}

fn grantees(path: &Path, mask: u32, include_owner: bool) -> Result<Vec<Grantee>, DaclError> {
    let me = current_user_sid().ok();
    let classify = |sid: *mut c_void| -> Option<Grantee> {
        let s = sid_to_string(sid).ok()?;
        let permitted = is_platform_principal(&s) || me.as_ref() == Some(&s);
        Some(if permitted {
            Grantee::Permitted
        } else {
            Grantee::Other(s.as_str().to_owned())
        })
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call; every
    // out-parameter is a local; `owner` and `dacl` point into the descriptor
    // `psd`, which the guard frees after they are consumed.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut psd,
        )
    };
    if rc != 0 {
        return Err(DaclError(rc));
    }
    let _guard = Descriptor(psd);
    let mut out = Vec::new();
    if include_owner && !owner.is_null() {
        out.extend(classify(owner));
    }
    if dacl.is_null() {
        // A null DACL grants everyone everything.
        out.push(Grantee::Other(
            "Everyone (no access-control list)".to_owned(),
        ));
        return Ok(out);
    }
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: `dacl` is a live ACL inside `psd`; `info` is a local of the
    // size passed.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).expect("fits"),
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(DaclError(crate::sid::last_error()));
    }
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACE count the ACL reported. `GetAce`
        // writes `ace` on success; the null check below refuses a success
        // that did not, so every later read is of a live ACE.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(DaclError(crate::sid::last_error()));
        }
        // `GetAce` writes `ace` when it returns success. A pointer analysis
        // does not model that write, and a null ACE is not readable.
        if ace.is_null() {
            return Err(DaclError(ERROR_INVALID_ACL));
        }
        // SAFETY: every ACE begins with an `ACE_HEADER`.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
        {
            continue;
        }
        // SAFETY: the type says this ACE is an `ACCESS_ALLOWED_ACE`, whose
        // `SidStart` is the first dword of the SID that follows it in the ACL.
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // Read through the raw pointer, as the header is: an ACE is
        // dword-aligned by contract, and the read does not depend on it.
        let ace_mask = unsafe { std::ptr::addr_of!((*allowed).Mask).read_unaligned() };
        if ace_mask & mask == 0 {
            continue;
        }
        let sid = unsafe { (&raw const (*allowed).SidStart).cast_mut().cast::<c_void>() };
        out.extend(classify(sid));
    }
    Ok(out)
}
