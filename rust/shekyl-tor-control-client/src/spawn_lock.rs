// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process-wide lock every Rust process spawn takes (`TOR_SUPERVISOR.md` §4.7).
//!
//! On Windows the managed tor inherits its control socket: the launch marks tor's end
//! inheritable, spawns, and clears the mark. `CreateProcess` hands every inheritable
//! handle in the process to whatever child it starts, and std passes
//! `bInheritHandles = TRUE` on every spawn, so a second spawn on another thread inside
//! that window would inherit tor's end too. A leaked copy hides tor's death from the
//! control connection for as long as the other child lives (`TSR-F16`). The launch
//! holds this lock across mark, spawn and clear, and every other Rust spawn site in a
//! process that can launch a managed tor holds it around its own spawn.
//!
//! On Unix the launch does not need it: tor's end is made inheritable in the child
//! only, after `fork`, so no concurrent spawn can see it. The lock is taken there as
//! well, so a spawn site reads the same on every platform.
//!
//! **Residuals.** The C++ `tools::spawn` (DC-F12's subject) does not take this lock;
//! it is outside it until that lane replaces it. The strict form is
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, which names the only handles a child receives;
//! std exposes it only through the unstable `windows_process_extensions_raw_attribute`
//! (rust-lang/rust#114854). Reopen when that is stable.

use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

static SPAWN: Mutex<()> = Mutex::new(());

/// Hold the spawn lock until the guard drops.
///
/// **Hold it across the spawn call and nothing else**: never across a wait for the
/// child. It is process-wide, and a managed launch takes it on an async worker, so a
/// holder that waits for a child to finish stalls every other spawn and that worker.
/// [`spawn`], [`output`] and [`status`] keep to this for a `std` command; a `tokio`
/// command takes the guard around its own `spawn()`.
///
/// A panic while it was held does not poison it for later spawns: the lock guards no
/// data, only the window.
pub fn hold() -> MutexGuard<'static, ()> {
    SPAWN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `cmd.spawn()` under the lock.
///
/// # Errors
///
/// The spawn's own error.
pub fn spawn(cmd: &mut Command) -> std::io::Result<Child> {
    let _spawning = hold();
    cmd.spawn()
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
