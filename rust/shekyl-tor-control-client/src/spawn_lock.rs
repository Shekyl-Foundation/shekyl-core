// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The spawn lock for a process that launches a managed tor (`TOR_SUPERVISOR.md` §4.7).
//!
//! On Windows the managed tor inherits its control socket. The launch marks the
//! parent's copy of tor's end inheritable, spawns, and closes that copy, under this
//! lock. `CreateProcess` hands every inheritable handle in the process to whatever
//! child it starts, and std passes `bInheritHandles = TRUE` on every spawn, so a
//! second spawn on another thread while that copy was still open and inheritable
//! would inherit tor's end too. A leaked copy hides tor's death from the control
//! connection for as long as the other child lives (`TSR-F16`).
//!
//! Closing the parent's copy is what ends the window. Clearing the inherit bit and
//! returning while the socket is still open does not: a failed clear leaves the bit
//! set. The socket is closed before this lock is released, whether or not the clear
//! succeeded.
//!
//! Only a process that itself launches a managed tor takes the lock. A process that
//! never calls the launch has no control socket to leak. On Unix the launch does not
//! need the lock either: tor's end is made inheritable in the child only, after
//! `fork`. It is taken there so a spawn site reads the same on every platform.
//!
//! **What does not remove the lock.** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names the
//! handles one `CreateProcess` may inherit. It does not stop a different
//! `CreateProcess` in this process — still passing `bInheritHandles = TRUE`, still
//! omitting a list — from inheriting a handle that is inheritable at that moment.
//! std exposes the list only through the unstable
//! `windows_process_extensions_raw_attribute` (rust-lang/rust#114854). Stabilising it
//! does not retire this lock.
//!
//! **Residual.** The C++ `tools::spawn` (DC-F12's subject) does not take this lock.
//! It stays outside until that lane is gone.

use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, PoisonError};

static SPAWN: Mutex<()> = Mutex::new(());

/// Run `spawn` with the spawn lock held, and release it when `spawn` returns.
///
/// **Put the spawn call in `spawn` and nothing else**: never a wait for the child.
/// The lock is process-wide, and a managed launch takes it on an async worker, so a
/// holder that waits for a child to finish stalls every other spawn and that worker.
/// [`spawn`], [`output`] and [`status`] keep to this for a `std` command; a `tokio`
/// command, or a spawn that must do something else under the lock (the launch marks
/// tor's end inheritable around its spawn), passes a closure here.
///
/// The closure form is what `scripts/ci/check_spawn_sites_take_the_lock.py` reads: a
/// process start is under the lock when it sits inside a `spawn_lock::` call. A guard
/// held in a variable cannot be checked that way, so there is none.
///
/// Not reentrant: `spawn` must not call into this module again. A panic while it was
/// held does not poison it for later spawns: the lock guards no data, only the window.
pub fn with<T>(spawn: impl FnOnce() -> T) -> T {
    let _spawning = SPAWN.lock().unwrap_or_else(PoisonError::into_inner);
    spawn()
}

/// `cmd.spawn()` under the lock.
///
/// # Errors
///
/// The spawn's own error.
pub fn spawn(cmd: &mut Command) -> std::io::Result<Child> {
    with(|| cmd.spawn())
}

/// What `cmd.output()` does, with only the spawn under the lock: stdin is closed,
/// stdout and stderr are captured, and the wait happens after the lock is released.
///
/// # Errors
///
/// The spawn's or the wait's error.
pub fn output(cmd: &mut Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn(cmd)?.wait_with_output()
}

/// What `cmd.status()` does, with only the spawn under the lock.
///
/// # Errors
///
/// The spawn's or the wait's error.
pub fn status(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    spawn(cmd)?.wait()
}
