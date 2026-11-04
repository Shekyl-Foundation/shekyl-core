// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DC-Q21's acceptance on Unix (`docs/design/DAEMON_CONFIG_CUTOVER.md`
//! §2.2 step 1, DC-F34): after `harden_process`, a real fault ends the
//! process by its signal and writes no core, and a stack overflow prints
//! the runtime's message and aborts. Each test re-executes this binary in
//! a mode that calls `harden_process` first and then faults, and judges the
//! child's wait status from outside; a process cannot report its own
//! death.
//!
//! A binary of its own: the parent must not be hardened, so the child
//! inherits the runner's core limit (raised to its hard bound before the
//! exec) and the core it does not write is the hardening's doing. The
//! in-process reads of the limit and the flags are `harden.rs`'s tests.
//!
//! `SHEKYL_HARDEN_CHILD` is this harness's re-exec marker, read by the
//! test binary alone (the shape `shekyl-timing-engine`'s abort test uses);
//! no shipped binary reads it (IG-13).

#![cfg(unix)]

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Output};

use shekyl_ffi::harden::harden_process;

const CHILD_MARKER: &str = "SHEKYL_HARDEN_CHILD";

fn child_mode() -> Option<String> {
    std::env::var(CHILD_MARKER).ok()
}

/// Re-executes this test binary on `test` alone, in `mode`, with `cwd` as
/// its working directory and its soft core limit raised to the hard bound.
fn run_child(mode: &str, test: &str, cwd: &Path) -> Output {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MARKER, mode)
        .current_dir(cwd);
    // SAFETY: the closure runs between `fork` and `exec` and calls only
    // `getrlimit`/`setrlimit`, which are async-signal-safe, on a live
    // local.
    unsafe {
        command.pre_exec(|| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = limit.rlim_max;
            if libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Under the spawn lock: this binary links the managed-Tor launch, so
    // every process it starts takes the lock (TOR_SUPERVISOR.md §4.7).
    shekyl_tor_control_client::spawn_lock::output(&mut command).expect("spawn the child")
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read the child's working directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// (a) A write through a null pointer after hardening ends the child by
/// `SIGSEGV`, and no core file appears in its working directory. Red if
/// the child exits with a status: the write did not fault, or the fault
/// was caught.
#[test]
fn a_fault_after_hardening_ends_by_sigsegv_and_writes_no_core() {
    const NAME: &str = "a_fault_after_hardening_ends_by_sigsegv_and_writes_no_core";
    if child_mode().as_deref() == Some("fault") {
        harden_process().expect("hardening applies to an ordinary process");
        let null: *mut u8 = std::hint::black_box(std::ptr::null_mut());
        // SAFETY: none; the write is the fault under test. `black_box`
        // keeps the compiler from reasoning about the pointer's value, so
        // the store is emitted and the page is what refuses it.
        unsafe { null.write_volatile(1) };
        unreachable!("the write through a null pointer did not fault");
    }
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let out = run_child("fault", NAME, dir.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        None,
        "the child exited with a status instead of a signal; stderr:\n{stderr}"
    );
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGSEGV),
        "the child ended by another signal; stderr:\n{stderr}"
    );
    let left = names_in(dir.path());
    assert!(
        left.is_empty(),
        "a file appeared in the working directory: {left:?}"
    );
}

/// Every frame holds a buffer the optimiser cannot drop, and the addition
/// after the call keeps it from becoming a loop.
#[allow(unconditional_recursion)]
fn recurse(depth: u64) -> u64 {
    let frame = [depth; 64];
    std::hint::black_box(&frame);
    recurse(std::hint::black_box(depth + 1)) + frame[0]
}

/// (b) Unbounded recursion on a spawned thread after hardening prints the
/// runtime's overflow message on standard error and ends the child by
/// `SIGABRT`. Red if the message is absent or the child ends another way.
///
/// **FreeBSD is pinned to the runtime's defect, DC-F35.** There the fault
/// lands in the lowest page of the range libthr reports as the stack (the
/// kernel's `MAP_STACK` guard, `security.bsd.stack_guard_page`, moves up
/// one page when libthr protects its own guard below it), and std's
/// `current_guard()` for FreeBSD looks only below that range, so its
/// handler treats the overflow as an ordinary fault: the child ends by
/// `SIGSEGV` with no message. That arm asserts the defect so that it is
/// read every run; the day std's handler recognises the page, the arm goes
/// red, and the fix is to delete it and the DC-F35 row's caveat.
#[test]
fn a_stack_overflow_after_hardening_prints_the_runtimes_message_and_aborts() {
    const NAME: &str = "a_stack_overflow_after_hardening_prints_the_runtimes_message_and_aborts";
    if child_mode().as_deref() == Some("overflow") {
        harden_process().expect("hardening applies to an ordinary process");
        let depth = std::thread::Builder::new()
            .name("overflowing".to_owned())
            .spawn(|| recurse(0))
            .expect("spawn the overflowing thread")
            .join();
        unreachable!("the recursion returned: {depth:?}");
    }
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let out = run_child("overflow", NAME, dir.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let message = stderr.contains("has overflowed its stack");
    if cfg!(target_os = "freebsd") {
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGSEGV),
            "DC-F35: on FreeBSD the runtime misses a spawned thread's guard page and the \
             overflow ends by SIGSEGV; the child ended otherwise (status {:?}); stderr:\n{stderr}",
            out.status
        );
        assert!(
            !message,
            "DC-F35 has lifted: the runtime printed its overflow message on FreeBSD. \
             Delete this arm and the DC-F35 caveat. stderr:\n{stderr}"
        );
        return;
    }
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGABRT),
        "the child did not abort (status {:?}); stderr:\n{stderr}",
        out.status
    );
    assert!(
        message,
        "the runtime's overflow message is absent from stderr:\n{stderr}"
    );
}
