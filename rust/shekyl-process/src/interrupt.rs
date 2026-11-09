// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether `SIGINT` is ignored.
//!
//! [`sigint_is_ignored`] reads the disposition with `sigaction` and a null
//! new action. `SIG_IGN` is the inherited request a caller must not
//! overwrite: a handler installed later replaces it. The read fails closed
//! (`false`), so the caller takes `SIGINT`.

/// `true` when `SIGINT`'s disposition is `SIG_IGN` at the time of the call.
/// A failed read is `false`.
#[must_use]
pub fn sigint_is_ignored() -> bool {
    // SAFETY: `sigaction` with a null new action only reads the current
    // disposition into `current`, a local of the type it writes; a zeroed
    // `sigaction` is a valid value of that plain C struct.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `SIGINT` is a valid signal number.
    let read = unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), &raw mut current) };
    read == 0 && current.sa_sigaction == libc::SIG_IGN
}
