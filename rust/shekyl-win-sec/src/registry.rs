// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's rendezvous record on Windows: a value under
//! `HKLM\SOFTWARE\Shekyl\Rendezvous` (Rick, 2026-11-18), always in the
//! 64-bit view (`KEY_WOW64_64KEY`).
//!
//! A world-readable file can be held open by any local account without
//! delete sharing, and then nothing can replace or remove it: a local
//! account could block the service's publish. A registry value is written
//! whole and removed whatever readers hold the key, so the record moved
//! there. The key is the installer's, never the daemon's: the daemon checks
//! it ([`RendezvousKey::check`]) and refuses one that is missing or exposed.
//!
//! [`RendezvousKey::check`]'s rule: the owner is Administrators or SYSTEM;
//! every account may read (an allow entry for Everyone, Authenticated Users
//! or BUILTIN\Users carrying a read right, and no entry denying a read right
//! to anyone); and nobody may write but this account (the service's) and the
//! platform's own principals.

#![cfg(windows)]

use std::io;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, WIN32_ERROR,
};
use windows_sys::Win32::Security::Authorization::SE_REGISTRY_WOW64_64KEY;
use windows_sys::Win32::Storage::FileSystem::{DELETE, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_BINARY, RRF_RT_REG_BINARY,
};

use crate::dacl::{is_platform_principal, read_descriptor, ADMINISTRATORS, SYSTEM};
use crate::sid::current_user_sid;

/// The key under `HKEY_LOCAL_MACHINE` that holds a service's rendezvous
/// records, one value per network and instance.
pub const RENDEZVOUS_KEY: &str = r"SOFTWARE\Shekyl\Rendezvous";

/// Everyone.
const EVERYONE: &str = "S-1-1-0";
/// NT AUTHORITY\Authenticated Users.
const AUTHENTICATED_USERS: &str = "S-1-5-11";
/// BUILTIN\Users.
const USERS: &str = "S-1-5-32-545";

/// Any right that changes the key: a value, a subkey, the descriptor, the
/// key itself.
const KEY_WRITE_MASK: u32 = KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_CREATE_LINK
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// How many times [`RendezvousKey::read`] asks for the value when a
/// publish keeps growing it between the size and the read: a publish is
/// rare (a service's start), so a few reads always see one settle.
const READ_ATTEMPTS: usize = 4;

/// A right that reads a value.
const KEY_READ_MASK: u32 = KEY_QUERY_VALUE | GENERIC_READ | GENERIC_ALL;

/// Why the key cannot hold the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyFault {
    /// The key does not exist.
    Missing,
    /// Its owner is neither Administrators nor SYSTEM.
    Owner(String),
    /// No entry lets every account read it.
    NotReadableByAll,
    /// Accounts other than this one and the platform's may write it.
    Writable(Vec<String>),
    /// Its descriptor could not be read (the OS error).
    Unreadable(u32),
}

impl std::fmt::Display for KeyFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("it does not exist"),
            Self::Owner(owner) => {
                write!(f, "it is owned by {owner}, not by Administrators or SYSTEM")
            }
            Self::NotReadableByAll => f.write_str("not every account may read it"),
            Self::Writable(who) => write!(f, "{} may write it", who.join(", ")),
            Self::Unreadable(code) => write!(
                f,
                "its security descriptor could not be read (os error {code})"
            ),
        }
    }
}

impl std::error::Error for KeyFault {}

/// A key under `HKEY_LOCAL_MACHINE`, in the 64-bit view.
#[derive(Clone, Debug)]
pub struct RendezvousKey {
    subkey: String,
}

impl RendezvousKey {
    /// The key `subkey` under `HKEY_LOCAL_MACHINE`: [`RENDEZVOUS_KEY`], or a
    /// test's own.
    #[must_use]
    pub fn new(subkey: &str) -> Self {
        Self {
            subkey: subkey.to_owned(),
        }
    }

    /// The key's name, for a refusal.
    #[must_use]
    pub fn name(&self) -> String {
        format!(r"HKEY_LOCAL_MACHINE\{}", self.subkey)
    }

    /// Whether the key may hold the record: it exists, its owner is
    /// Administrators or SYSTEM, every account may read it, and nobody but
    /// this account and the platform's own principals may write it.
    ///
    /// # Errors
    ///
    /// [`KeyFault`], naming the condition that failed.
    pub fn check(&self) -> Result<(), KeyFault> {
        let name: Vec<u16> = format!(r"MACHINE\{}", self.subkey)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let view = read_descriptor(&name, SE_REGISTRY_WOW64_64KEY).map_err(|e| {
            if e.code() == ERROR_FILE_NOT_FOUND {
                KeyFault::Missing
            } else {
                KeyFault::Unreadable(e.code())
            }
        })?;
        match &view.owner {
            Some(owner) if matches!(owner.as_str(), ADMINISTRATORS | SYSTEM) => {}
            Some(owner) => return Err(KeyFault::Owner(owner.as_str().to_owned())),
            None => return Err(KeyFault::Owner("nobody".to_owned())),
        }
        let Some(allowed) = view.allowed else {
            return Err(KeyFault::Writable(vec![
                "Everyone (no access-control list)".to_owned(),
            ]));
        };
        let me = current_user_sid().ok();
        let writers: Vec<String> = allowed
            .iter()
            .filter(|(sid, mask)| {
                mask & KEY_WRITE_MASK != 0
                    && !is_platform_principal(sid)
                    && me.as_ref() != Some(sid)
            })
            .map(|(sid, _)| sid.as_str().to_owned())
            .collect();
        if !writers.is_empty() {
            return Err(KeyFault::Writable(writers));
        }
        // A deny of a read right to anyone means some account cannot read
        // the record, whatever the allow entries say: a client of that
        // account would fail its discovery with an access denial.
        let read_denied = view
            .denied
            .iter()
            .any(|(_, mask)| mask & KEY_READ_MASK != 0);
        let readable_by_all = !read_denied
            && allowed.iter().any(|(sid, mask)| {
                mask & KEY_READ_MASK != 0
                    && matches!(sid.as_str(), EVERYONE | AUTHENTICATED_USERS | USERS)
            });
        if !readable_by_all {
            return Err(KeyFault::NotReadableByAll);
        }
        Ok(())
    }

    /// Write `bytes` as the value `name`, whole.
    ///
    /// # Errors
    ///
    /// The key could not be opened for writing, or the value not set.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let key = self.open(KEY_SET_VALUE)?;
        let name = wide(name);
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the record is too long"))?;
        // SAFETY: `key` is open for `KEY_SET_VALUE`; `name` is
        // NUL-terminated; `bytes` is `len` bytes, alive across the call.
        let rc =
            unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_BINARY, bytes.as_ptr(), len) };
        status(rc)
    }

    /// The value `name`, or `None` when the key or the value is absent.
    ///
    /// # Errors
    ///
    /// The key could not be opened or the value read.
    pub fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let key = match self.open(KEY_QUERY_VALUE) {
            Ok(key) => key,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let name = wide(name);
        // A publish may grow the value between the size the read asks for
        // and the read itself, which then answers `ERROR_MORE_DATA` with the
        // new size: read again at that size, a bounded number of times, so
        // a concurrent publish is never a discovery failure.
        let mut len: u32 = 0;
        for _ in 0..READ_ATTEMPTS {
            let mut bytes = vec![0u8; len as usize];
            let buffer = if bytes.is_empty() {
                std::ptr::null_mut()
            } else {
                bytes.as_mut_ptr().cast()
            };
            // SAFETY: `buffer` is null (a size query) or `bytes`, which
            // holds `len` bytes; `len` receives the size or what was
            // written.
            let rc = unsafe {
                RegGetValueW(
                    key.0,
                    std::ptr::null(),
                    name.as_ptr(),
                    RRF_RT_REG_BINARY,
                    std::ptr::null_mut(),
                    buffer,
                    &raw mut len,
                )
            };
            match rc {
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_MORE_DATA => continue,
                // A size query on a value: `len` now holds its size.
                0 if bytes.is_empty() && len > 0 => continue,
                0 => {
                    bytes.truncate(len as usize);
                    return Ok(Some(bytes));
                }
                other => return status(other).map(|()| None),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "the record kept changing while it was read",
        ))
    }

    /// Remove the value `name`; absent is done.
    ///
    /// # Errors
    ///
    /// The key could not be opened or the value not removed.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        let key = match self.open(KEY_SET_VALUE) {
            Ok(key) => key,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = wide(name);
        // SAFETY: `key` is open for `KEY_SET_VALUE`; `name` is NUL-terminated.
        let rc = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        status(rc)
    }

    fn open(&self, access: u32) -> io::Result<Key> {
        let subkey = wide(&self.subkey);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `subkey` is NUL-terminated; `key` receives the handle,
        // which `Key` closes.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                access | KEY_WOW64_64KEY,
                &raw mut key,
            )
        };
        status(rc)?;
        Ok(Key(key))
    }
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: an open handle `RegOpenKeyExW` returned, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn status(rc: WIN32_ERROR) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ))
    }
}

/// A scratch key under `HKLM\SOFTWARE\Shekyl`, created with a test's
/// descriptor and deleted on drop: what the installer's key is, for a test
/// on any account's machine. Creating under HKLM needs an elevated session
/// (CI's Windows runner is one); without it the creation panics with the
/// reason, so a test refuses rather than skips.
#[cfg(any(test, feature = "test-utils"))]
pub struct ScratchKey(RendezvousKey);

#[cfg(any(test, feature = "test-utils"))]
impl ScratchKey {
    /// Create `SOFTWARE\Shekyl\Test-<test>-<pid>` with the descriptor `sddl`.
    ///
    /// # Panics
    ///
    /// The descriptor does not parse, or the key cannot be created (an
    /// unelevated session).
    #[must_use]
    pub fn new(test: &str, sddl: &str) -> Self {
        use windows_sys::Win32::System::Registry::{
            RegCreateKeyExW, KEY_READ, REG_OPTION_NON_VOLATILE,
        };
        let subkey = format!(r"SOFTWARE\Shekyl\Test-{test}-{}", std::process::id());
        let descriptor =
            crate::sddl::OwnerOnlyDescriptor::from_sddl(sddl).expect("the test's descriptor");
        let wide_subkey = wide(&subkey);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `wide_subkey` is NUL-terminated; the descriptor lives
        // across the call; `key` receives a handle closed below.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide_subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WOW64_64KEY,
                descriptor.attributes_ptr(),
                &raw mut key,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            rc, 0,
            "creating HKLM\\{subkey} failed (os error {rc}): this test writes under \
             HKEY_LOCAL_MACHINE; run it from an elevated session (CI's runner is one)"
        );
        drop(Key(key));
        Self(RendezvousKey::new(&subkey))
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &RendezvousKey {
        &self.0
    }

    /// Its name relative to `HKEY_LOCAL_MACHINE`.
    #[must_use]
    pub fn subkey(&self) -> &str {
        &self.0.subkey
    }

    /// The installer's descriptor, for a test: owned by Administrators,
    /// full control for Administrators, SYSTEM and this account (the
    /// service's, in a real install), read for BUILTIN\Users, then `extra`.
    ///
    /// # Panics
    ///
    /// This account's SID cannot be read.
    #[must_use]
    pub fn installer_sddl(extra: &str) -> String {
        let me = current_user_sid().expect("this account");
        format!(
            "O:BAG:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;{me})(A;CI;KR;;;BU){extra}",
            me = me.as_str()
        )
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Drop for ScratchKey {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Registry::RegDeleteKeyExW;
        let subkey = wide(&self.0.subkey);
        // SAFETY: `subkey` is NUL-terminated.
        unsafe { RegDeleteKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), KEY_WOW64_64KEY, 0) };
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Registry::KEY_READ;

    use super::*;

    fn installer_sddl(extra: &str) -> String {
        ScratchKey::installer_sddl(extra)
    }
    /// A key as the installer makes it passes; one another account may
    /// write is refused, naming that account; one owned by this account
    /// is refused for its owner; a missing key is `Missing`. Red edit:
    /// drop the writers check, and a key BUILTIN\Users may write passes.
    #[test]
    fn the_key_is_checked_for_its_owner_its_readers_and_its_writers() {
        let good = ScratchKey::new("good", &installer_sddl(""));
        assert_eq!(good.key().check(), Ok(()));

        let writable = ScratchKey::new("writable", &installer_sddl("(A;CI;KW;;;BU)"));
        assert_eq!(
            writable.key().check(),
            Err(KeyFault::Writable(vec![USERS.to_owned()]))
        );

        let me = current_user_sid().expect("this account");
        let owned = ScratchKey::new(
            "owned",
            &installer_sddl("").replacen("O:BA", &format!("O:{}", me.as_str()), 1),
        );
        assert_eq!(
            owned.key().check(),
            Err(KeyFault::Owner(me.as_str().to_owned()))
        );

        let unread = ScratchKey::new("unread", &installer_sddl("").replace("(A;CI;KR;;;BU)", ""));
        assert_eq!(unread.key().check(), Err(KeyFault::NotReadableByAll));

        // A deny of read to any account (here BUILTIN\Guests), beside the
        // installer's grants, is not readable by all: a client of that
        // account would fail its discovery (Copilot, #1439).
        let denied = ScratchKey::new("denied", &installer_sddl("(D;CI;KR;;;BG)"));
        assert_eq!(denied.key().check(), Err(KeyFault::NotReadableByAll));

        let missing = RendezvousKey::new(r"SOFTWARE\Shekyl\Test-missing-never-created");
        assert_eq!(missing.check(), Err(KeyFault::Missing));
    }

    /// A reader holding the key open does not stop a publish whose bytes
    /// changed, nor the removal. Red edit: none; this is the property that
    /// decided a registry value over a file (Rick, 2026-11-18).
    #[test]
    fn a_reader_holding_the_key_does_not_stop_a_publish_or_a_removal() {
        let scratch = ScratchKey::new("held", &installer_sddl(""));
        let key = scratch.key();
        key.write("record", b"first").unwrap();
        let held = key.open(KEY_READ).expect("a reader's handle");
        key.write("record", b"second").unwrap();
        assert_eq!(key.read("record").unwrap().as_deref(), Some(&b"second"[..]));
        key.remove("record").unwrap();
        assert_eq!(key.read("record").unwrap(), None);
        drop(held);
        key.remove("record")
            .expect("removing an absent value is done");
    }
}
