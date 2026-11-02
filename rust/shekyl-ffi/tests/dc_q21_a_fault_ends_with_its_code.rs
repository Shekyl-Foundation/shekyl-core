// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DC-Q21's acceptance on Windows (`docs/design/DAEMON_CONFIG_CUTOVER.md`
//! §2.2 step 1, DC-F38): after `harden_process`, a real fault ends the
//! process through the top-level filter with the exception's code as its
//! exit status, a stack overflow prints the runtime's message and ends the
//! same way, and a panic under the daemon's hook ends with `0xC0000409`;
//! none of them leaves a crash dump. Each test re-executes this binary in
//! a mode that calls `harden_process` first and then fails, and judges
//! the child's exit status from outside; a process cannot report its own
//! death. The Unix pair is `dc_q21_a_fault_ends_by_signal.rs`.
//!
//! The dump check reads `%LOCALAPPDATA%\CrashDumps`, where a `LocalDumps`
//! policy with no `DumpFolder` writes `<exe>.<pid>.dmp`. On a machine with
//! no such policy the folder is absent or untouched and the assertion is
//! trivially true; on one with the policy (Rick's, where the 2026-11-02
//! run saw the dumps) it is the check that can fail: remove the filter
//! from `harden_process` and the fault case writes a dump. A run on such a
//! machine evicts the operator's older dumps when the folder is at its
//! `DumpCount`; the PR body's procedure says to point the policy's
//! `DumpFolder` at a scratch folder first.
//!
//! `SHEKYL_HARDEN_CHILD` is this harness's re-exec marker, read by the
//! test binary alone; no shipped binary reads it (IG-13).

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use shekyl_ffi::platform::harden_process;
use windows_sys::Win32::Foundation::{
    STATUS_ACCESS_VIOLATION, STATUS_STACK_BUFFER_OVERRUN, STATUS_STACK_OVERFLOW,
};

const CHILD_MARKER: &str = "SHEKYL_HARDEN_CHILD";

fn child_mode() -> Option<String> {
    std::env::var(CHILD_MARKER).ok()
}

/// The child's pid and its output.
struct Ended {
    pid: u32,
    out: Output,
}

/// Re-executes this test binary on `test` alone, in `mode`, with `cwd` as
/// its working directory.
fn run_child(mode: &str, test: &str, cwd: &Path) -> Ended {
    let child = Command::new(std::env::current_exe().expect("this test binary"))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MARKER, mode)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let pid = child.id();
    let out = child.wait_with_output().expect("wait for the child");
    Ended { pid, out }
}

/// Where a `LocalDumps` policy with no `DumpFolder` writes, from the
/// known-folder interface (IG-13), or `None` when the account has none.
fn default_dump_folder() -> Option<PathBuf> {
    shekyl_win_sec::known_folder::local_app_data().map(|p| p.join("CrashDumps"))
}

/// The dump files in `folder` that name this test binary and `pid`.
fn dumps_of(pid: u32) -> Vec<String> {
    let Some(folder) = default_dump_folder() else {
        return Vec::new();
    };
    let exe = std::env::current_exe().expect("this test binary");
    let name = exe
        .file_name()
        .expect("the test binary has a name")
        .to_string_lossy()
        .into_owned();
    let wanted = format!("{name}.{pid}.dmp");
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.eq_ignore_ascii_case(&wanted))
        .collect()
}

fn assert_ended_with(ended: &Ended, code: i32, what: &str) -> String {
    let stderr = String::from_utf8_lossy(&ended.out.stderr).into_owned();
    assert_eq!(
        ended.out.status.code(),
        Some(code),
        "{what}: the child ended with {:?}, not {code:#x}; stderr:\n{stderr}",
        ended.out.status
    );
    let dumps = dumps_of(ended.pid);
    assert!(
        dumps.is_empty(),
        "{what}: a crash dump of the child appeared in the default LocalDumps folder: {dumps:?}"
    );
    stderr
}

/// (a) A write through a null pointer after hardening ends the child with
/// `STATUS_ACCESS_VIOLATION` as its exit status and writes no dump. Red
/// if the child exits otherwise: the write did not fault, the fault was
/// caught, or the filter is gone and the system ended the process (same
/// code, but then a `LocalDumps` policy writes the dump this asserts
/// against).
#[test]
fn a_fault_after_hardening_ends_with_its_code_and_writes_no_dump() {
    const NAME: &str = "a_fault_after_hardening_ends_with_its_code_and_writes_no_dump";
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
    let ended = run_child("fault", NAME, dir.path());
    assert_ended_with(&ended, STATUS_ACCESS_VIOLATION, "fault");
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
/// runtime's overflow message (its vectored handler runs first and
/// continues the search) and ends the child through the filter with
/// `STATUS_STACK_OVERFLOW`.
#[test]
fn a_stack_overflow_after_hardening_prints_the_runtimes_message_and_ends_with_its_code() {
    const NAME: &str =
        "a_stack_overflow_after_hardening_prints_the_runtimes_message_and_ends_with_its_code";
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
    let ended = run_child("overflow", NAME, dir.path());
    let stderr = assert_ended_with(&ended, STATUS_STACK_OVERFLOW, "overflow");
    assert!(
        stderr.contains("has overflowed its stack"),
        "the runtime's overflow message is absent from stderr:\n{stderr}"
    );
}

/// (c) A panic under the daemon's hook, after hardening, writes the
/// hook's line and ends the child with `STATUS_STACK_BUFFER_OVERRUN`, the
/// code `abort` reports, without reaching `abort` (whose `__fastfail`
/// would pass no filter and let a `LocalDumps` policy write a dump).
#[test]
fn a_panic_under_the_hook_after_hardening_ends_with_aborts_code_and_writes_no_dump() {
    const NAME: &str =
        "a_panic_under_the_hook_after_hardening_ends_with_aborts_code_and_writes_no_dump";
    if child_mode().as_deref() == Some("panic") {
        harden_process().expect("hardening applies to an ordinary process");
        shekyl_ffi::panic_hook::install();
        panic!("the panic under test");
    }
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let ended = run_child("panic", NAME, dir.path());
    let stderr = assert_ended_with(&ended, STATUS_STACK_BUFFER_OVERRUN, "panic");
    assert!(
        stderr.contains("shekyld: panic in thread") && stderr.contains("the panic under test"),
        "the hook's line is absent from stderr:\n{stderr}"
    );
}
