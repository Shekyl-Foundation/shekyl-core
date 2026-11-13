// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The run-as-user rendezvous on Windows (`docs/design/RPC_CHANNEL.md` §7.1;
//! Rick, 2026-11-12).
//!
//! A daemon run as its user records its pipe's name in a rendezvous file,
//! `%LOCALAPPDATA%\Shekyl\rendezvous\shekyl-<name>`. Three objects, each made
//! with its owner, its protected owner-only DACL and its mandatory label in
//! the creating call, never tightened afterwards:
//!
//! - **the data home** `%LOCALAPPDATA%\Shekyl`, when the daemon creates it:
//!   owner-only, inherited by what is made inside, with an inheritable
//!   no-read-up label ([`ensure_data_home`]);
//! - **the rendezvous directory** inside it, which holds rendezvous files
//!   and nothing else: created, or where it exists checked for its owner,
//!   its protections and its label's policy bits, never adopted
//!   ([`ensure_rendezvous_dir`]);
//! - **each rendezvous file**, `CREATE_NEW`, with the no-read-up label in its
//!   own descriptor ([`create_rendezvous_file`]).
//!
//! The check reads the label's **policy bits** and asserts no-read-up. "A
//! mandatory label is present" passes on an object whose label lost the
//! read-up policy to inheritance or to `icacls`, which RT-P8 measured
//! doing exactly that, so that check could not fail.

use std::ffi::c_void;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ALREADY_EXISTS, ERROR_INVALID_ACL, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    SYSTEM_MANDATORY_LABEL_ACE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
};
use windows_sys::Win32::System::SystemServices::{
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
};

use crate::dacl::{read_grantees, write_grantees, Grantee};
use crate::sddl::{OwnerOnlyDescriptor, SddlError};
use crate::sid::{current_user_sid, last_error, sid_to_string, SidError};

/// Why a rendezvous object could not be made or does not pass its check.
#[derive(Debug)]
pub enum RendezvousError {
    /// This process's user SID could not be read, so there is no owner.
    Sid(SidError),
    /// The descriptor could not be built.
    Descriptor(SddlError),
    /// The create call failed.
    Create(io::Error),
    /// The object's descriptor could not be read (os error).
    Read(u32),
    /// The object exists and fails a condition, in the operator's words.
    Refused(String),
}

impl fmt::Display for RendezvousError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sid(e) => write!(f, "could not identify this account: {e}"),
            Self::Descriptor(e) => write!(f, "{e}"),
            Self::Create(e) => write!(f, "could not be created owner-only: {e}"),
            Self::Read(e) => write!(
                f,
                "its security descriptor could not be read (os error {e})"
            ),
            Self::Refused(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for RendezvousError {}

impl From<SidError> for RendezvousError {
    fn from(e: SidError) -> Self {
        Self::Sid(e)
    }
}

impl From<SddlError> for RendezvousError {
    fn from(e: SddlError) -> Self {
        Self::Descriptor(e)
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Create `path` as a directory under `descriptor`. `Ok(false)` when it
/// already exists, which the caller decides about; nothing is adopted here.
fn create_dir(path: &Path, descriptor: &OwnerOnlyDescriptor) -> Result<bool, RendezvousError> {
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated and outlives the call;
    // `descriptor.attributes_ptr()` is valid while `descriptor` is borrowed,
    // which is past the call; `CreateDirectoryW` reads both only during it.
    let ok = unsafe { CreateDirectoryW(w.as_ptr(), descriptor.attributes_ptr()) };
    if ok != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == i32::try_from(ERROR_ALREADY_EXISTS).ok() {
        return Ok(false);
    }
    Err(RendezvousError::Create(error))
}

/// The daemon's data home `root`, `%LOCALAPPDATA%\Shekyl`: created
/// owner-only with an inheritable no-read-up label when it does not exist.
/// An existing data home is the operator's and is left as it is.
///
/// # Errors
/// The owner or the descriptor could not be had, or the create failed.
pub fn ensure_data_home(root: &Path) -> Result<(), RendezvousError> {
    let owner = current_user_sid()?;
    let descriptor = OwnerOnlyDescriptor::data_home(&owner)?;
    create_dir(root, &descriptor).map(drop)
}

/// The rendezvous directory `dir`: created with its owner, its protections
/// and its no-read-up label in the creating call, or, where it exists,
/// checked for all three ([`check_owner_only_labelled`]).
///
/// # Errors
/// The create failed, or an existing directory fails its check.
pub fn ensure_rendezvous_dir(dir: &Path) -> Result<(), RendezvousError> {
    let owner = current_user_sid()?;
    let descriptor = OwnerOnlyDescriptor::rendezvous_dir(&owner)?;
    if create_dir(dir, &descriptor)? {
        return Ok(());
    }
    check_owner_only_labelled(dir)
}

/// Create the rendezvous file `path` for writing, `CREATE_NEW`, with its
/// owner, its protected owner-only DACL and its no-read-up label in the
/// creating call.
///
/// # Errors
/// The owner or the descriptor could not be had, or the create failed
/// (an existing entry is `ERROR_FILE_EXISTS`).
pub fn create_rendezvous_file(path: &Path) -> Result<File, RendezvousError> {
    let owner = current_user_sid()?;
    let descriptor = OwnerOnlyDescriptor::rendezvous_file(&owner)?;
    let w = wide(path);
    // SAFETY: as for `create_dir`; `CreateFileW` reads both pointers only
    // during the call.
    let handle = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_NONE,
            descriptor.attributes_ptr(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(RendezvousError::Create(io::Error::last_os_error()));
    }
    // SAFETY: a fresh, valid, owned handle; `File` closes it exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// The object at `path` is this account's alone and refuses a reader below
/// its integrity: owned by this account, a protected DACL that grants no
/// other principal a read or a write, and a mandatory label whose policy
/// includes no-read-up.
///
/// # Errors
/// [`RendezvousError::Refused`] naming the condition that failed, or the
/// descriptor could not be read.
pub fn check_owner_only_labelled(path: &Path) -> Result<(), RendezvousError> {
    let me = current_user_sid()?;
    let read = SecurityRead::of(path)?;
    let owner = read.owner()?;
    if owner != me {
        return Err(RendezvousError::Refused(format!(
            "it is owned by {}, not this account",
            owner.as_str()
        )));
    }
    if !read.dacl_protected() {
        return Err(RendezvousError::Refused(
            "its access list inherits from its parent".to_owned(),
        ));
    }
    let foreign = |grantees: Vec<Grantee>| {
        grantees.into_iter().find_map(|g| match g {
            Grantee::Other(sid) => Some(sid),
            Grantee::Permitted => None,
        })
    };
    let reads = read_grantees(path).map_err(|e| RendezvousError::Refused(e.to_string()))?;
    let writes = write_grantees(path).map_err(|e| RendezvousError::Refused(e.to_string()))?;
    if let Some(sid) = foreign(reads).or_else(|| foreign(writes)) {
        return Err(RendezvousError::Refused(format!(
            "its access list admits {sid}"
        )));
    }
    match read.label_policy()? {
        Some(policy) if policy & SYSTEM_MANDATORY_LABEL_NO_READ_UP != 0 => Ok(()),
        Some(_) => Err(RendezvousError::Refused(
            "its mandatory label does not refuse a reader below its integrity (no NR)".to_owned(),
        )),
        None => Err(RendezvousError::Refused(
            "it carries no mandatory label".to_owned(),
        )),
    }
}

/// The policy bits of the mandatory label on `path`, or `None` when it
/// carries none. The rendezvous objects assert
/// `SYSTEM_MANDATORY_LABEL_NO_READ_UP` among them.
///
/// # Errors
/// The descriptor could not be read.
pub fn label_policy(path: &Path) -> Result<Option<u32>, RendezvousError> {
    SecurityRead::of(path)?.label_policy()
}

/// One read of a path's owner, DACL control and label, freed on drop.
struct SecurityRead {
    psd: PSECURITY_DESCRIPTOR,
    owner: *mut c_void,
    sacl: *mut ACL,
}

impl Drop for SecurityRead {
    fn drop(&mut self) {
        // SAFETY: `GetNamedSecurityInfoW` allocated the descriptor with
        // `LocalAlloc`; it is freed exactly once, here. `owner` and `sacl`
        // point into it and are not read after this.
        unsafe { LocalFree(self.psd.cast::<c_void>()) };
    }
}

impl SecurityRead {
    fn of(path: &Path) -> Result<Self, RendezvousError> {
        let w = wide(path);
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut sacl: *mut ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated and outlives the call; every
        // out-parameter is a local. The label is read through the SACL
        // pointer, which `LABEL_SECURITY_INFORMATION` fills with the
        // mandatory label alone and needs no privilege beyond READ_CONTROL.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut sacl,
                &raw mut psd,
            )
        };
        if rc != 0 {
            return Err(RendezvousError::Read(rc));
        }
        Ok(Self { psd, owner, sacl })
    }

    fn owner(&self) -> Result<crate::SidString, RendezvousError> {
        if self.owner.is_null() {
            return Err(RendezvousError::Refused("it names no owner".to_owned()));
        }
        sid_to_string(self.owner).map_err(RendezvousError::Sid)
    }

    fn dacl_protected(&self) -> bool {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `psd` is a live descriptor owned by `self`; both
        // out-parameters are locals.
        let ok =
            unsafe { GetSecurityDescriptorControl(self.psd, &raw mut control, &raw mut revision) };
        ok != 0 && (control & SE_DACL_PROTECTED) != 0
    }

    fn label_policy(&self) -> Result<Option<u32>, RendezvousError> {
        if self.sacl.is_null() {
            return Ok(None);
        }
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `sacl` is a live ACL inside `psd`; `info` is a local of
        // the size passed.
        let ok = unsafe {
            GetAclInformation(
                self.sacl,
                (&raw mut info).cast::<c_void>(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).expect("fits"),
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(RendezvousError::Read(last_error()));
        }
        for index in 0..info.AceCount {
            let mut out = std::mem::MaybeUninit::<*mut c_void>::uninit();
            // SAFETY: `index` is below the count the ACL reported; `out` is
            // read only after the call reports success.
            if unsafe { GetAce(self.sacl, index, out.as_mut_ptr()) } == 0 {
                return Err(RendezvousError::Read(last_error()));
            }
            // SAFETY: `GetAce` succeeded, so it wrote `out`.
            let written = unsafe { out.assume_init() };
            let Some(ace) = std::ptr::NonNull::new(written.cast::<u8>()) else {
                return Err(RendezvousError::Read(ERROR_INVALID_ACL));
            };
            // SAFETY: `GetAce` returned a live ACE inside the SACL, readable
            // for its `AceSize` bytes, beginning with an `ACE_HEADER`.
            if let Some(policy) = unsafe { label_mask(ace) }? {
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }
}

/// The policy of the ACE at `ace` when it is a mandatory label, `None` when
/// it is another type. The `Mask` read is bounded by the ACE's own size: an
/// ACE that says it is a label and is too short to hold its mask is refused,
/// so the read never leaves it (CodeQL rust/access-invalid-pointer, alert
/// 200).
///
/// # Safety
///
/// `ace` is readable for its `AceSize` bytes.
///
/// # Errors
///
/// [`RendezvousError::Read`] with `ERROR_INVALID_ACL` for a label ACE shorter
/// than its mask.
unsafe fn label_mask(ace: std::ptr::NonNull<u8>) -> Result<Option<u32>, RendezvousError> {
    let ace = ace.as_ptr().cast_const();
    // SAFETY: the caller guarantees a readable header.
    let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
    if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
        return Ok(None);
    }
    let mask_at = std::mem::offset_of!(SYSTEM_MANDATORY_LABEL_ACE, Mask);
    if usize::from(header.AceSize) < mask_at + std::mem::size_of::<u32>() {
        return Err(RendezvousError::Read(ERROR_INVALID_ACL));
    }
    // SAFETY: the ACE holds at least `mask_at + 4` bytes, checked above.
    Ok(Some(unsafe {
        ace.add(mask_at).cast::<u32>().read_unaligned()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A label ACE is read for its mask; one whose size is too short to hold
    /// the mask is refused rather than read past; another type is skipped.
    /// Red edit: drop the size check and the short ACE's mask is read from
    /// past its end.
    #[test]
    fn a_label_ace_too_short_for_its_mask_is_refused() {
        let mask_at = std::mem::offset_of!(SYSTEM_MANDATORY_LABEL_ACE, Mask);
        let mut buffer = [0u8; 32];
        buffer[0] = u8::try_from(SYSTEM_MANDATORY_LABEL_ACE_TYPE).unwrap();
        buffer[2..4].copy_from_slice(&u16::try_from(mask_at + 4).unwrap().to_le_bytes());
        buffer[mask_at..mask_at + 4].copy_from_slice(&3u32.to_le_bytes());
        // SAFETY: the buffer is 32 readable bytes, more than any size here.
        assert_eq!(
            unsafe { label_mask(std::ptr::NonNull::from(&buffer).cast()) }.unwrap(),
            Some(3)
        );
        buffer[2..4].copy_from_slice(&u16::try_from(mask_at).unwrap().to_le_bytes());
        // SAFETY: as above.
        assert!(matches!(
            unsafe { label_mask(std::ptr::NonNull::from(&buffer).cast()) },
            Err(RendezvousError::Read(ERROR_INVALID_ACL))
        ));
        buffer[0] = 0;
        // SAFETY: as above.
        assert_eq!(
            unsafe { label_mask(std::ptr::NonNull::from(&buffer).cast()) }.unwrap(),
            None
        );
    }

    /// The three objects come out of their creating calls owner-only, with
    /// the no-read-up policy bit, and the directory check accepts what it
    /// made; a second ensure checks rather than adopts. Windows only: the
    /// estate's Windows hosts run it (RT-P8's Windows check).
    #[test]
    fn the_rendezvous_objects_are_owner_only_and_refuse_read_up() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("Shekyl");
        ensure_data_home(&root).unwrap();
        let home_label = label_policy(&root)
            .unwrap()
            .expect("the data home is labelled");
        assert_ne!(home_label & SYSTEM_MANDATORY_LABEL_NO_READ_UP, 0);

        let dir = root.join("rendezvous");
        ensure_rendezvous_dir(&dir).unwrap();
        check_owner_only_labelled(&dir).unwrap();
        ensure_rendezvous_dir(&dir).expect("an existing directory that passes is kept");

        let file = dir.join("shekyl-0123456789abcdef01234567");
        drop(create_rendezvous_file(&file).unwrap());
        check_owner_only_labelled(&file).unwrap();
        assert!(
            create_rendezvous_file(&file).is_err(),
            "CREATE_NEW refuses an existing entry"
        );
    }

    /// RT-P8's Windows check, re-run on the subdirectory (Rick,
    /// 2026-11-12): make the three objects under the directory named by
    /// `SHEKYL_RENDEZVOUS_PROBE_DIR` and leave them, so a low-integrity
    /// process can then be pointed at them. The test prints each path and
    /// its label's policy bits. Run by hand on a Windows host:
    /// `cargo test -p shekyl-win-sec rendezvous_probe -- --ignored --nocapture`.
    #[test]
    #[ignore = "RT-P8 probe: leaves its objects for a low-integrity reader"]
    fn rendezvous_probe_leaves_its_objects() {
        let base = std::path::PathBuf::from(
            std::env::var_os("SHEKYL_RENDEZVOUS_PROBE_DIR")
                .expect("SHEKYL_RENDEZVOUS_PROBE_DIR names an empty directory to fill"),
        );
        let root = base.join("Shekyl");
        let dir = root.join("rendezvous");
        let file = dir.join("shekyl-0123456789abcdef01234567");
        ensure_data_home(&root).unwrap();
        ensure_rendezvous_dir(&dir).unwrap();
        let mut handle = create_rendezvous_file(&file).unwrap();
        std::io::Write::write_all(&mut handle, b"probe\n").unwrap();
        drop(handle);
        for path in [&root, &dir, &file] {
            println!(
                "{}: label policy {:?}",
                path.display(),
                label_policy(path).unwrap()
            );
        }
        check_owner_only_labelled(&dir).unwrap();
        check_owner_only_labelled(&file).unwrap();
    }

    /// A directory made with the default descriptor is not adopted: it
    /// inherits its access list and carries no read-up label. Red edit:
    /// return Ok from the check, and this directory passes.
    #[test]
    fn an_existing_directory_without_the_label_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("rendezvous");
        std::fs::create_dir(&dir).unwrap();
        let refused = ensure_rendezvous_dir(&dir).unwrap_err();
        assert!(matches!(refused, RendezvousError::Refused(_)), "{refused}");
    }
}
