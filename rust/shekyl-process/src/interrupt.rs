// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether the program that started this process asked it to ignore an
//! interrupt (Rick, 2026-11-08: the daemon honours that on every platform).
//!
//! A parent that starts a program in the background asks for this so that an
//! interrupt typed at its terminal leaves the program alone: a shell's
//! background job, `nohup`, `start /b`. The request is inherited, and a
//! handler installed later would override it, so it is read at start, before
//! the daemon installs any.
//!
//! - **Unix:** the disposition of `SIGINT` at start, read with `sigaction`
//!   and a null new action. `SIG_IGN` is the request.
//! - **Windows:** the request is the inherited "ignore Ctrl-C" attribute that
//!   `SetConsoleCtrlHandler(NULL, TRUE)` sets. No documented call reads it
//!   back, so it is not read; the daemon's start names the stops that work
//!   whatever it holds.

/// `true` when `SIGINT` is ignored at the time of the call: the program that
/// started this process asked for it, if nothing in this process has set a
/// disposition yet. A failed read is `false`: the daemon then owns `SIGINT`,
/// as it would with no request.
#[cfg(unix)]
#[must_use]
pub fn interrupt_ignored_at_start() -> bool {
    // SAFETY: `sigaction` with a null new action only reads the current
    // disposition into `current`, a local of the type it writes; a zeroed
    // `sigaction` is a valid value of that plain C struct.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `SIGINT` is a valid signal number.
    let read = unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), &raw mut current) };
    read == 0 && current.sa_sigaction == libc::SIG_IGN
}
