// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three reads behind [`members_besides_me`]: `getgrgid_r`,
//! `getpwuid_r`, and the account walk.
//!
//! rustix wraps none of them. This module is the one place after `acl`
//! where the crate's `unsafe_code` deny is lifted. Each call carries its
//! own SAFETY comment. What a call means is [`step`], which does
//! not enter this module's unsafe code.
//!
//! `getpwent` walks one process-wide cursor, so two walks at once would
//! interleave. The walk holds `WALK` from `setpwent` to `endpwent`: it is
//! callable from any number of threads and they take turns. Nothing else in
//! the tree moves that cursor (`getpwuid_r` and `getpwuid`, the other
//! password reads, look one entry up and leave it alone), and at start the
//! check runs from `load`, before the daemon's logging, runtime or any
//! thread of its own exists (`shekyl-daemon`'s `run`); the lock is what
//! makes that order a convenience rather than a condition. The cursor is
//! closed when the walk's guard drops, including when the walk panics.
//!
//! The two readers share one module name. Each target compiles exactly one
//! of them. A target this does not name does not build.

use std::ffi::CStr;

use super::{Account, AccountName};

/// First buffer for a reentrant lookup. A short entry fits; `ERANGE` grows it.
const LOOKUP_BUFFER_START: usize = 16 * 1024;
/// Largest buffer a lookup may use. A still-short buffer refuses.
const LOOKUP_BUFFER_MAX: usize = 1024 * 1024;

/// The next buffer size after `len`, doubling up to [`LOOKUP_BUFFER_MAX`].
///
/// `None` when `len` is already at the ceiling, so a caller who retries
/// stops instead of asking the library again at the same size.
fn next_buffer_len(len: usize) -> Option<usize> {
    let next = len.saturating_mul(2).min(LOOKUP_BUFFER_MAX);
    (next > len).then_some(next)
}

/// One attempt to fill a caller-owned buffer.
enum BufferRead<T> {
    /// The call finished. The value was copied out of the buffer.
    Done(T),
    /// The buffer was too small.
    Range,
    /// The call failed with this `errno` value.
    Failed(i32),
}

/// Runs `read` on a buffer that doubles from [`LOOKUP_BUFFER_START`]
/// while the call reports `ERANGE`, and stops at [`LOOKUP_BUFFER_MAX`].
fn with_buffer<T>(mut read: impl FnMut(&mut [u8]) -> BufferRead<T>) -> Result<T, i32> {
    let mut buffer = vec![0u8; LOOKUP_BUFFER_START];
    loop {
        match read(&mut buffer) {
            BufferRead::Done(value) => return Ok(value),
            BufferRead::Range => match next_buffer_len(buffer.len()) {
                Some(next) => buffer.resize(next, 0),
                None => return Err(libc::ERANGE),
            },
            BufferRead::Failed(rc) => return Err(rc),
        }
    }
}

/// The name at a C string the system handed back.
///
/// # Safety
/// `ptr` is null, or it points at a NUL-terminated string that is live
/// for the call. Null and empty are both "no name".
unsafe fn read_name(ptr: *const libc::c_char) -> Option<AccountName> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    AccountName::new(bytes)
}

/// The operating system's text for `rc`, as a refusal embeds it.
fn os_error(rc: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(rc)
}

/// The account `uid` names, by `getpwuid_r`.
pub(super) fn account(uid: u32) -> Result<Account, String> {
    match with_buffer(|buffer| {
        // SAFETY: `passwd` is plain data; a zeroed value is a valid
        // out-struct for `getpwuid_r` to fill.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry`, `buffer` and `found` are live locals of the
        // sizes passed; the strings are written into `buffer`, which
        // outlives every read of `entry` below.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut entry,
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE {
            return BufferRead::Range;
        }
        if rc != 0 {
            return BufferRead::Failed(rc);
        }
        if found.is_null() {
            return BufferRead::Done(Err(format!(
                "the daemon's account, uid {uid}, is not known to the system"
            )));
        }
        // SAFETY: `pw_name` is null or a NUL-terminated string inside
        // `buffer`, which is live.
        let Some(name) = (unsafe { read_name(entry.pw_name) }) else {
            return BufferRead::Done(Err(format!("the daemon's account, uid {uid}, has no name")));
        };
        if entry.pw_uid != uid {
            return BufferRead::Done(Err(format!(
                "the daemon's account, uid {uid}, was reported as uid {}",
                entry.pw_uid
            )));
        }
        BufferRead::Done(Ok(Account {
            name,
            uid: entry.pw_uid,
            gid: entry.pw_gid,
        }))
    }) {
        Ok(account) => account,
        Err(rc) => Err(format!(
            "the daemon's account, uid {uid}, could not be read: {}",
            os_error(rc)
        )),
    }
}

/// The member list of group `gid`, by `getgrgid_r`.
pub(super) fn listed(gid: u32) -> Result<Vec<AccountName>, String> {
    match with_buffer(|buffer| {
        // SAFETY: `group` is plain data; a zeroed value is a valid
        // out-struct for `getgrgid_r` to fill.
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::group = std::ptr::null_mut();
        // SAFETY: as for `getpwuid_r` above; the member list and its
        // strings are written into `buffer`.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &raw mut entry,
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE {
            return BufferRead::Range;
        }
        if rc != 0 {
            return BufferRead::Failed(rc);
        }
        if found.is_null() {
            return BufferRead::Done(Err(format!(
                "the daemon's group, gid {gid}, is not known to the system"
            )));
        }
        if entry.gr_gid != gid {
            return BufferRead::Done(Err(format!(
                "the daemon's group, gid {gid}, was reported as gid {}",
                entry.gr_gid
            )));
        }
        let mut names = Vec::new();
        let mut member = entry.gr_mem;
        if !member.is_null() {
            // SAFETY: `gr_mem` is a NULL-terminated array of pointers
            // to NUL-terminated strings, all inside `buffer`.
            unsafe {
                while !(*member).is_null() {
                    let Some(name) = read_name(*member) else {
                        return BufferRead::Done(Err(format!(
                            "the daemon's group, gid {gid}, lists an account with no name"
                        )));
                    };
                    names.push(name);
                    member = member.add(1);
                }
            }
        }
        BufferRead::Done(Ok(names))
    }) {
        Ok(names) => names,
        Err(rc) => Err(format!(
            "the daemon's group, gid {gid}, could not be read: {}",
            os_error(rc)
        )),
    }
}

/// The one cursor `getpwent` walks, held for the whole walk.
static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Closes the `getpwent` cursor, including when the walk returns early
/// or panics. Constructed immediately after `setpwent`.
struct WalkCursor;

impl Drop for WalkCursor {
    fn drop(&mut self) {
        // SAFETY: `endpwent` takes nothing and touches only the library's
        // cursor, which the caller holds under [`WALK`].
        unsafe { libc::endpwent() }
    }
}

/// glibc and FreeBSD.
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "freebsd"))]
#[path = "reader/reentrant.rs"]
mod reader;

/// musl and macOS.
#[cfg(any(all(target_os = "linux", target_env = "musl"), target_os = "macos"))]
#[path = "reader/errno.rs"]
mod reader;

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    all(target_os = "linux", target_env = "musl"),
    target_os = "freebsd",
    target_os = "macos"
)))]
compile_error!(
    "group: name this target's account walk, getpwent_r and its end-of-list convention, \
     or getpwent with errno, read at its libc's source"
);

/// The first account besides `me` whose primary group is `gid`, by the
/// account walk under [`WALK`]. Each call is judged by [`super::step`].
/// `Ok(None)` is a finished list with no such account.
pub(super) fn first_other_primary(gid: u32, me: &Account) -> Result<Option<Account>, String> {
    // A poisoned lock is a walk that panicked mid-way. The cursor is
    // rewound by `setpwent` and closed by `_cursor` either way.
    let _walk = WALK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: `setpwent` takes nothing and touches only the library's
    // cursor, which `_walk` makes ours until it drops.
    unsafe { libc::setpwent() };
    let _cursor = WalkCursor;
    let mut reader = reader::Reader::new();
    loop {
        match reader.read()? {
            Some(account) if account.gid == gid && account.uid != me.uid => {
                return Ok(Some(account));
            }
            Some(_) => {}
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{next_buffer_len, read_name, LOOKUP_BUFFER_MAX, LOOKUP_BUFFER_START};
    use crate::group::AccountName;

    #[test]
    fn a_name_is_the_bytes_up_to_the_nul_and_empty_is_refused() {
        let read = unsafe { read_name(c"shekyl".as_ptr()) }.expect("a name");
        assert_eq!(read, AccountName::new(b"shekyl").unwrap());
        assert!(unsafe { read_name(c"".as_ptr()) }.is_none());
        assert!(unsafe { read_name(std::ptr::null()) }.is_none());
        assert!(AccountName::new(b"").is_none());
    }

    /// Doubling stops at the ceiling. The edit that goes red is a length
    /// past [`LOOKUP_BUFFER_MAX`], or another step once the ceiling is reached:
    /// either one lets a short buffer ask the library again at the same size.
    #[test]
    fn the_lookup_buffer_doubles_until_its_ceiling() {
        assert_eq!(
            next_buffer_len(LOOKUP_BUFFER_START),
            Some(LOOKUP_BUFFER_START * 2)
        );
        assert_eq!(
            next_buffer_len(LOOKUP_BUFFER_MAX / 2),
            Some(LOOKUP_BUFFER_MAX)
        );
        assert_eq!(
            next_buffer_len(LOOKUP_BUFFER_MAX / 2 + 1),
            Some(LOOKUP_BUFFER_MAX)
        );
        assert_eq!(next_buffer_len(LOOKUP_BUFFER_MAX), None);
    }
}
