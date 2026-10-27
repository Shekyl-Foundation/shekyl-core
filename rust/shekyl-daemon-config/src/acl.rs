// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What an access-control list adds to a file's mode bits.
//!
//! [`probe`] reads the list on the opened handle. [`AclProbe::ModeOnly`] means
//! the mode rules are the whole policy. [`AclProbe::Named`] means a principal
//! those bits do not name can be granted access. [`AclProbe::Unreadable`]
//! means the list could not be read, which the caller refuses.
//!
//! A named entry is refused without consulting its permission bits. Once one
//! exists, the group-class bits of the mode are the mask, not the owning
//! group's permission, and a later mode change grants whatever the entry
//! stores.
//!
//! Each platform reports that fact in its own words:
//!
//! - Linux and Android: the POSIX access list in `system.posix_acl_access`.
//!   A named user or named group is [`AclProbe::Named`]. An NFSv4 list in
//!   `system.nfs4_acl` is [`AclProbe::Named`] as well; this probe does not
//!   compare it with the mode.
//! - macOS: one extended ACL entry is [`AclProbe::Named`]. The privacy label
//!   `com.apple.macl` is not a unix read grant, and this probe does not read it.
//! - FreeBSD: a POSIX.1e or NFSv4 list the system does not call trivial is
//!   [`AclProbe::Named`]. A list that only restates the mode passes, which is
//!   what a default ZFS file is.

use std::fs::File;

/// What the file's access-control list adds to the mode bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AclProbe {
    /// No list, or a list that only restates the mode bits.
    ModeOnly,
    /// A principal the mode bits do not name.
    Named,
    /// The list could not be read.
    Unreadable,
}

/// The list on `file`, or [`AclProbe::Unreadable`] when it cannot be read.
#[must_use]
pub(crate) fn probe(file: &File) -> AclProbe {
    platform::probe(file)
}

/// True when the operating system reports that this file has no list of the
/// kind just requested.
///
/// `INVAL` is absence, not a broken probe: FreeBSD UFS returns it for
/// `ACL_TYPE_NFS4` on a mount that has no NFSv4 lists, and macOS returns
/// `NOENT` when a file has no extended list. Any other error, including one
/// this crate does not recognize, is not absence.
///
/// Compared with `==`. On these targets `NOTSUP` and `OPNOTSUPP` are one
/// value, and an or-pattern of both is unreachable.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn os_reports_no_list() -> bool {
    let Some(err) = rustix::io::Errno::from_io_error(&std::io::Error::last_os_error()) else {
        return false;
    };
    err == rustix::io::Errno::NOENT
        || err == rustix::io::Errno::NOTSUP
        || err == rustix::io::Errno::OPNOTSUPP
        || err == rustix::io::Errno::INVAL
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::fs::File;

    use rustix::io::Errno;

    use super::AclProbe;

    /// `POSIX_ACL_XATTR_VERSION` in the Linux access-list attribute.
    const XATTR_VERSION: u32 = 2;
    const ENTRY_LEN: usize = 8;
    /// First buffer for [`attribute`]. A short list fits; a longer one grows.
    const INITIAL_BYTES: usize = 256;
    /// Larger than any list this check will trust. A longer attribute refuses.
    const MAX_BYTES: usize = 65_536;

    /// POSIX.1e `e_tag` values. A named user or named group is the extended list.
    mod tag {
        pub(super) const USER_OBJ: u16 = 0x0001;
        pub(super) const USER: u16 = 0x0002;
        pub(super) const GROUP_OBJ: u16 = 0x0004;
        pub(super) const GROUP: u16 = 0x0008;
        pub(super) const MASK: u16 = 0x0010;
        pub(super) const OTHER: u16 = 0x0020;
    }

    const POSIX_ACCESS: &str = "system.posix_acl_access";
    const NFS4: &str = "system.nfs4_acl";

    pub(super) fn probe(file: &File) -> AclProbe {
        match attribute(file, POSIX_ACCESS) {
            Err(outcome) => return outcome,
            Ok(Some(bytes)) => match posix_access_list(&bytes) {
                AclProbe::ModeOnly => {}
                outcome => return outcome,
            },
            Ok(None) => {}
        }
        match attribute(file, NFS4) {
            Err(outcome) => outcome,
            Ok(Some(bytes)) if !bytes.is_empty() => AclProbe::Named,
            Ok(_) => AclProbe::ModeOnly,
        }
    }

    /// `Ok(None)` is a file with no such attribute. `Err` is already a refusal.
    fn attribute(file: &File, name: &str) -> Result<Option<Vec<u8>>, AclProbe> {
        let mut buf = vec![0u8; INITIAL_BYTES];
        loop {
            match rustix::fs::fgetxattr(file, name, buf.as_mut_slice()) {
                Ok(len) if len <= buf.len() => {
                    buf.truncate(len);
                    return Ok(Some(buf));
                }
                Err(Errno::RANGE) => {
                    let next = buf.len().saturating_mul(2);
                    if next > MAX_BYTES || next <= buf.len() {
                        return Err(AclProbe::Unreadable);
                    }
                    buf.resize(next, 0);
                }
                // `NOTSUP` and `OPNOTSUPP` are one value on Linux, so the
                // pattern names the one that exists. A length past the
                // buffer, and every other error, cannot be read.
                Err(Errno::NODATA | Errno::NOTSUP) => return Ok(None),
                _ => return Err(AclProbe::Unreadable),
            }
        }
    }

    /// The POSIX access list in its on-disk attribute.
    ///
    /// A named user ([`tag::USER`]) or named group ([`tag::GROUP`]) is
    /// [`AclProbe::Named`]. Any other shape that is not the base entries is
    /// [`AclProbe::Unreadable`].
    pub(super) fn posix_access_list(bytes: &[u8]) -> AclProbe {
        // The version word is the header. A short buffer, a different
        // version, or a body that is not a whole number of entries cannot
        // be read. An empty body is not a list.
        let Some(body) = bytes.strip_prefix(&XATTR_VERSION.to_le_bytes()) else {
            return AclProbe::Unreadable;
        };
        if body.is_empty() || body.len() % ENTRY_LEN != 0 {
            return AclProbe::Unreadable;
        }
        let mut named = false;
        for entry in body.chunks_exact(ENTRY_LEN) {
            let raw = u16::from_le_bytes([entry[0], entry[1]]);
            match raw {
                tag::USER | tag::GROUP => named = true,
                tag::USER_OBJ | tag::GROUP_OBJ | tag::MASK | tag::OTHER => {}
                _ => return AclProbe::Unreadable,
            }
        }
        if named {
            AclProbe::Named
        } else {
            AclProbe::ModeOnly
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs::File;

        use rustix::io::Errno;

        use super::{posix_access_list, probe, tag, AclProbe, POSIX_ACCESS};

        const UNDEFINED_ID: u32 = 0xffff_ffff;
        /// `ACL_READ` and `ACL_WRITE` from `<sys/acl.h>`.
        const ACL_READ: u16 = 0x0004;
        const ACL_WRITE: u16 = 0x0002;
        /// A user that is not the file's owner. The usual unprivileged id.
        const NAMED_USER: u32 = 65_534;
        /// A group the mode bits do not already name as the owning group.
        const NAMED_GROUP: u32 = 50;
        /// Not a POSIX.1e `e_tag`.
        const NOT_A_TAG: u16 = 0x007f;
        /// Not [`super::XATTR_VERSION`].
        const NOT_THE_VERSION: u8 = 9;

        fn entry(tag: u16, perm: u16, id: u32) -> [u8; super::ENTRY_LEN] {
            let mut bytes = [0u8; super::ENTRY_LEN];
            bytes[..2].copy_from_slice(&tag.to_le_bytes());
            bytes[2..4].copy_from_slice(&perm.to_le_bytes());
            bytes[4..].copy_from_slice(&id.to_le_bytes());
            bytes
        }

        fn list(entries: &[[u8; super::ENTRY_LEN]]) -> Vec<u8> {
            let mut bytes = super::XATTR_VERSION.to_le_bytes().to_vec();
            for entry in entries {
                bytes.extend_from_slice(entry);
            }
            bytes
        }

        #[test]
        fn a_base_list_restates_the_mode_and_a_named_user_does_not() {
            let base = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::GROUP_OBJ, ACL_READ, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            assert_eq!(posix_access_list(&base), AclProbe::ModeOnly);
            // A mask restates the group class. It names nobody else.
            let masked = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::GROUP_OBJ, ACL_READ, UNDEFINED_ID),
                entry(tag::MASK, ACL_READ, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            assert_eq!(posix_access_list(&masked), AclProbe::ModeOnly);
            let named = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::USER, ACL_READ, NAMED_USER),
                entry(tag::GROUP_OBJ, ACL_READ, UNDEFINED_ID),
                entry(tag::MASK, ACL_READ, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            assert_eq!(posix_access_list(&named), AclProbe::Named);
            // The stored permission is not consulted: a later mode change
            // grants whatever the entry keeps, so zero still refuses.
            let stored = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::USER, 0, NAMED_USER),
                entry(tag::GROUP_OBJ, 0, UNDEFINED_ID),
                entry(tag::MASK, 0, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            assert_eq!(posix_access_list(&stored), AclProbe::Named);
        }

        #[test]
        fn a_named_group_is_the_same_refusal() {
            let bytes = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::GROUP_OBJ, 0, UNDEFINED_ID),
                entry(tag::GROUP, ACL_READ, NAMED_GROUP),
                entry(tag::MASK, ACL_READ, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            assert_eq!(posix_access_list(&bytes), AclProbe::Named);
        }

        #[test]
        fn a_short_or_unknown_list_cannot_be_read() {
            assert_eq!(posix_access_list(&[]), AclProbe::Unreadable);
            assert_eq!(posix_access_list(&[2, 0, 0]), AclProbe::Unreadable);
            let mut bad_version = list(&[entry(tag::USER_OBJ, ACL_READ, UNDEFINED_ID)]);
            bad_version[0] = NOT_THE_VERSION;
            assert_eq!(posix_access_list(&bad_version), AclProbe::Unreadable);
            let unknown = list(&[entry(NOT_A_TAG, ACL_READ, UNDEFINED_ID)]);
            assert_eq!(posix_access_list(&unknown), AclProbe::Unreadable);
            assert_eq!(
                posix_access_list(&super::XATTR_VERSION.to_le_bytes()),
                AclProbe::Unreadable
            );
        }

        /// The kernel's own attribute, on a real file: a named user refuses,
        /// and a file with no list does not.
        #[test]
        fn the_opened_handle_reports_a_named_user() {
            let dir = tempfile::tempdir().unwrap();
            let plain = dir.path().join("plain.toml");
            std::fs::write(&plain, b"").unwrap();
            let plain_file = File::open(&plain).unwrap();
            assert_eq!(probe(&plain_file), AclProbe::ModeOnly);

            let path = dir.path().join("listed.toml");
            let listed = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            let bytes = list(&[
                entry(tag::USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                entry(tag::USER, ACL_READ, NAMED_USER),
                entry(tag::GROUP_OBJ, ACL_READ, UNDEFINED_ID),
                entry(tag::MASK, ACL_READ, UNDEFINED_ID),
                entry(tag::OTHER, 0, UNDEFINED_ID),
            ]);
            match rustix::fs::fsetxattr(
                &listed,
                POSIX_ACCESS,
                &bytes,
                rustix::fs::XattrFlags::empty(),
            ) {
                Ok(()) => {}
                Err(Errno::NOTSUP) => {
                    eprintln!("not run: this filesystem stores no posix access list");
                    return;
                }
                Err(err) => panic!("the access list could not be stored: {err}"),
            }
            assert_eq!(probe(&listed), AclProbe::Named);
        }
    }
}

/// Darwin's list calls. rustix has no ACL API, so this module is the one
/// place the crate's `unsafe_code` deny is lifted.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(unsafe_code)]
mod platform {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    use super::AclProbe;

    /// `ACL_TYPE_EXTENDED` from `<sys/acl.h>`.
    const ACL_TYPE_EXTENDED: i32 = 0x0000_0004;
    /// `ACL_FIRST_ENTRY`.
    const ACL_FIRST_ENTRY: i32 = 0;

    mod sys {
        use std::os::raw::{c_int, c_void};

        pub(super) type Acl = *mut c_void;

        unsafe extern "C" {
            pub(super) fn acl_get_fd_np(fd: c_int, type_: c_int) -> Acl;
            pub(super) fn acl_get_entry(
                acl: Acl,
                entry_id: c_int,
                entry: *mut *mut c_void,
            ) -> c_int;
            pub(super) fn acl_free(obj: *mut c_void) -> c_int;
        }
    }

    struct Acl(sys::Acl);

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: `self.0` was returned by `acl_get_fd_np` and is freed
            // once, here. The entry pointer taken from it is not used after
            // this runs.
            unsafe {
                sys::acl_free(self.0);
            }
        }
    }

    pub(super) fn probe(file: &File) -> AclProbe {
        // SAFETY: `fd` is a live descriptor of `file`. A null return is an
        // error and leaves nothing to free; a list is freed by `Acl`'s drop.
        let acl = unsafe { sys::acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            return if super::os_reports_no_list() {
                AclProbe::ModeOnly
            } else {
                AclProbe::Unreadable
            };
        }
        let acl = Acl(acl);
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl.0` is a live list, and `entry` is a local out-parameter.
        // Zero means one entry exists. The pointer is not dereferenced.
        let found = unsafe { sys::acl_get_entry(acl.0, ACL_FIRST_ENTRY, &raw mut entry) };
        if found == 0 {
            AclProbe::Named
        } else if no_extended_entry() {
            // Apple returns `INVAL` when the list exists and has no entry.
            AclProbe::ModeOnly
        } else {
            AclProbe::Unreadable
        }
    }

    /// `acl_get_entry` reports an empty list as `INVAL`.
    fn no_extended_entry() -> bool {
        rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
            == Some(rustix::io::Errno::INVAL)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_file_without_an_extended_list_is_the_mode() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("plain.toml");
            std::fs::write(&path, b"").unwrap();
            let file = File::open(&path).unwrap();
            assert_eq!(probe(&file), AclProbe::ModeOnly);
        }
    }
}

/// FreeBSD's list calls. rustix has no ACL API, so this module is the one
/// place the crate's `unsafe_code` deny is lifted. `acl_is_trivial_np` is
/// the system's own word for "this list restates the mode": a default ZFS
/// file is that, and refusing every NFSv4 list would refuse it.
#[cfg(target_os = "freebsd")]
#[allow(unsafe_code)]
mod platform {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    use super::AclProbe;

    /// `ACL_TYPE_ACCESS` and `ACL_TYPE_NFS4` from `<sys/acl.h>`.
    const ACL_TYPE_ACCESS: i32 = 0x0000_0002;
    const ACL_TYPE_NFS4: i32 = 0x0000_0004;
    /// `acl_is_trivial_np` writes zero when the list names someone the mode
    /// does not.
    const NOT_TRIVIAL: i32 = 0;

    mod sys {
        use std::os::raw::{c_int, c_void};

        pub(super) type Acl = *mut c_void;

        unsafe extern "C" {
            pub(super) fn acl_get_fd_np(fd: c_int, type_: c_int) -> Acl;
            pub(super) fn acl_is_trivial_np(acl: Acl, trivial: *mut c_int) -> c_int;
            pub(super) fn acl_free(obj: *mut c_void) -> c_int;
        }
    }

    struct Acl(sys::Acl);

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: `self.0` was returned by `acl_get_fd_np` and is freed
            // once, here.
            unsafe {
                sys::acl_free(self.0);
            }
        }
    }

    pub(super) fn probe(file: &File) -> AclProbe {
        for type_ in [ACL_TYPE_ACCESS, ACL_TYPE_NFS4] {
            match one(file, type_) {
                AclProbe::ModeOnly => {}
                outcome => return outcome,
            }
        }
        AclProbe::ModeOnly
    }

    fn one(file: &File, type_: i32) -> AclProbe {
        // SAFETY: `fd` is a live descriptor of `file`. A null return is an
        // error and leaves nothing to free.
        let acl = unsafe { sys::acl_get_fd_np(file.as_raw_fd(), type_) };
        if acl.is_null() {
            return if super::os_reports_no_list() {
                AclProbe::ModeOnly
            } else {
                AclProbe::Unreadable
            };
        }
        let acl = Acl(acl);
        // Zero is the call's "not trivial". Left so a success that does not
        // write the out-parameter refuses.
        let mut trivial = NOT_TRIVIAL;
        // SAFETY: `acl.0` is a live list and `trivial` is a local out-parameter.
        let rc = unsafe { sys::acl_is_trivial_np(acl.0, &raw mut trivial) };
        if rc != 0 {
            AclProbe::Unreadable
        } else if trivial == NOT_TRIVIAL {
            AclProbe::Named
        } else {
            AclProbe::ModeOnly
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_file_without_an_extended_list_is_the_mode() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("plain.toml");
            std::fs::write(&path, b"").unwrap();
            let file = File::open(&path).unwrap();
            assert_eq!(probe(&file), AclProbe::ModeOnly);
        }
    }
}

/// An operating system this crate can build for and has no list probe.
/// Refusing is the whole policy: the mode bits are not known to be complete.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
)))]
mod platform {
    use std::fs::File;

    use super::AclProbe;

    pub(super) fn probe(_file: &File) -> AclProbe {
        AclProbe::Unreadable
    }
}
