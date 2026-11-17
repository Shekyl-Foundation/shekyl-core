// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The account walk's next entry by `getpwent` (musl, macOS and iOS). The
//! libc crate declares no `getpwent_r` for these targets, and musl defines
//! none.
//! The entry is the library's own storage, read before the next call and
//! never kept. The call tells its end from an error by `errno` alone.

use super::super::step::{step_errno, Entry, ErrnoReading};
use super::read_name;

pub(in crate::group) struct Reader;

impl Reader {
    pub(in crate::group) fn new() -> Self {
        Self
    }

    // CLIPPY: unused_self — `getpwent` keeps its cursor in the library, so
    // this reader has no fields. `&mut self` is the same signature as the
    // reentrant reader, whose buffer the call advances.
    #[allow(clippy::unused_self)]
    pub(in crate::group) fn read(&mut self) -> Result<Option<super::super::Account>, String> {
        clear_errno();
        // SAFETY: the cursor is the walk's, under [`super::WALK`]; the
        // returned entry is the library's own storage, read before the next
        // call and never kept.
        let found = unsafe { libc::getpwent() };
        let reading = if found.is_null() {
            ErrnoReading::Empty {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            }
        } else {
            // SAFETY: `found` is non-null. `pw_name` is null or a
            // NUL-terminated string, both live until the next call.
            // `pw_uid` and `pw_gid` are plain fields of that record.
            ErrnoReading::Record(unsafe {
                Entry {
                    name: read_name((*found).pw_name),
                    uid: (*found).pw_uid,
                    gid: (*found).pw_gid,
                }
            })
        };
        step_errno(reading).answer()
    }
}

/// Clears the thread's errno, so a NULL from `getpwent` can be told apart
/// from an error: `getpwent` is specified to leave errno alone at the end
/// of the list, so a stale value would read as a failed walk. The accessor
/// is each libc's own, named here as the libc crate declares it (read at
/// its source, 0.2.184, the version this crate locks).
fn clear_errno() {
    // SAFETY: each accessor returns the address of this thread's errno,
    // which is ours to write.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = 0;
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            *libc::__error() = 0;
        }
    }
}

/// The targets [`clear_errno`] knows how to clear. A target added to the
/// errno reader in `sys` without an accessor arm stops the build here.
#[cfg(not(any(
    all(target_os = "linux", target_env = "musl"),
    target_os = "macos",
    target_os = "ios"
)))]
compile_error!("group: name this target's errno accessor as the libc crate declares it");
