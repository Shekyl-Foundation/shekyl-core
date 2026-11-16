// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The account walk's next entry by `getpwent_r` (glibc, FreeBSD, DragonFly,
//! NetBSD), into a buffer the walk keeps.
//!
//! glibc re-reads an entry that did not fit, so it starts small and grows.
//! The BSDs move past it, so they start at the largest buffer. A `Grow` on
//! those targets meets the ceiling and refuses without another `getpwent_r`
//! call, which is what keeps a retry from skipping an account.

use super::super::step::{
    step_reentrant, Entry, ReentrantConvention, ReentrantReading, ReentrantStep,
};
use super::{next_buffer_len, read_name, LOOKUP_BUFFER_MAX};

/// The convention and the first buffer, one value so the two cannot drift.
struct Policy {
    convention: ReentrantConvention,
    start: usize,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const POLICY: Policy = Policy {
    convention: ReentrantConvention::Glibc,
    start: super::LOOKUP_BUFFER_START,
};

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
const POLICY: Policy = Policy {
    convention: ReentrantConvention::Bsd,
    // The ceiling. A short buffer is not retried: the library has already
    // moved past the entry.
    start: LOOKUP_BUFFER_MAX,
};

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd"
)))]
compile_error!("group: name this target's getpwent_r convention and starting buffer");

pub(in crate::group) struct Reader {
    buffer: Vec<u8>,
}

impl Reader {
    pub(in crate::group) fn new() -> Self {
        Self {
            buffer: vec![0u8; POLICY.start],
        }
    }

    /// One account, or the end of the list. glibc's short buffer is retried
    /// here; the search never sees it.
    pub(in crate::group) fn read(&mut self) -> Result<Option<super::super::Account>, String> {
        loop {
            match self.classify() {
                ReentrantStep::Grow => self.grow()?,
                ReentrantStep::Settled(step) => return step.answer(),
            }
        }
    }

    /// One `getpwent_r`. The record is decoded only when the return code is
    /// `0` and the result pointer is set.
    fn classify(&mut self) -> ReentrantStep {
        // SAFETY: `passwd` is plain data; a zeroed value is a valid
        // out-struct for `getpwent_r` to fill.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry`, `buffer` and `found` are live and of the sizes
        // passed; the strings are written into `buffer`, which outlives
        // every read of `entry` below. The cursor is the walk's, under
        // [`super::WALK`].
        let code = unsafe {
            libc::getpwent_r(
                &raw mut entry,
                self.buffer.as_mut_ptr().cast::<libc::c_char>(),
                self.buffer.len(),
                &raw mut found,
            )
        };
        let reading = if code != 0 {
            if found.is_null() {
                ReentrantReading::Absent { code }
            } else {
                ReentrantReading::Unread { code }
            }
        } else if found.is_null() {
            ReentrantReading::Absent { code: 0 }
        } else {
            // SAFETY: return code 0 and a non-null result. `pw_name` is null
            // or a NUL-terminated string inside `buffer`, which is live.
            ReentrantReading::Record(Entry {
                name: unsafe { read_name(entry.pw_name) },
                uid: entry.pw_uid,
                gid: entry.pw_gid,
            })
        };
        step_reentrant(POLICY.convention, reading)
    }

    /// The buffer doubled, up to [`LOOKUP_BUFFER_MAX`]. At the ceiling the
    /// entry is too large, and the walk does not call `getpwent_r` again.
    fn grow(&mut self) -> Result<(), String> {
        let Some(next) = next_buffer_len(self.buffer.len()) else {
            return Err(format!(
                "the system's account list holds an entry larger than {LOOKUP_BUFFER_MAX} bytes"
            ));
        };
        self.buffer.resize(next, 0);
        Ok(())
    }
}
