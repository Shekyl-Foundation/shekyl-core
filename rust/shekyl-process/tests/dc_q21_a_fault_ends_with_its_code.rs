// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DC-Q21's acceptance on Windows (`docs/design/DAEMON_CONFIG_CUTOVER.md`
//! §2.2 step 1, DC-F38, DC-F44): after `harden_process`, a real fault ends
//! the process with the exception's code as its exit status, a stack
//! overflow prints the runtime's message and ends the same way, and a
//! panic under the daemon's hook ends with `0xC0000409`; none of them
//! leaves a crash dump. Each test re-executes this binary in a mode that
//! fails after hardening and judges the child's exit status from outside;
//! a process cannot report its own death. The Unix pair is
//! `dc_q21_a_fault_ends_by_signal.rs`.
//!
//! **The dump check has a subject.** The first Windows run of this file
//! read `%LOCALAPPDATA%\CrashDumps`, which is empty on a machine with no
//! `LocalDumps` policy, so the "no dump" assertion held whatever
//! `harden_process` did; and the test's parent handed every child an error
//! mode with `SEM_NOGPFAULTERRORBOX` already set, which alone keeps Windows
//! Error Reporting out, so it held for that reason too (DC-F44, Rick's
//! second run). Now: every child clears the error mode it inherited before
//! it does anything else, so the state under test is this process's; the
//! test sets a per-application `LocalDumps` policy for its own binary
//! pointing at a scratch folder (`HKLM\SOFTWARE\Microsoft\Windows\Windows
//! Error Reporting\LocalDumps\<this binary>`, 64-bit view) and removes it
//! when the last test is done; and before any hardened child runs, a
//! **control** child faults *without* hardening and must write a dump to
//! that folder. A control that writes nothing fails the run: the machine's
//! WER is not reacting, and a green "no dump" from it would be the empty
//! check this paragraph exists to refuse (rule 47). Writing under `HKLM`
//! needs an elevated session; CI's runner has one, and the refusal names
//! it.
//!
//! **What turns this red.** `harden_process` closes WER's fault path twice
//! over: the top-level filter ends the process before WER is consulted,
//! and `SEM_NOGPFAULTERRORBOX` keeps WER from the fault on its own (both
//! measured in Rick's controls, DC-F44). Removing *one* line stays green;
//! removing both writes a dump in the fault and overflow cases, and the
//! test is red. It pins the property, not the mechanism count; the doc on
//! `harden_process` says why both lines stay.
//!
//! `SHEKYL_HARDEN_CHILD` is this harness's re-exec marker, read by the
//! test binary alone; no shipped binary reads it (IG-13).

#![cfg(windows)]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use shekyl_process::harden::harden_process;
use windows_sys::Win32::Foundation::{
    STATUS_ACCESS_VIOLATION, STATUS_STACK_BUFFER_OVERRUN, STATUS_STACK_OVERFLOW,
};

const CHILD_MARKER: &str = "SHEKYL_HARDEN_CHILD";

/// The control's test name: its child half faults with no hardening.
const CONTROL: &str = "a_fault_without_hardening_writes_a_dump_to_the_scratch_policy";

fn child_mode() -> Option<String> {
    std::env::var(CHILD_MARKER).ok()
}

/// The first thing every child does: drop the error mode its parent handed
/// it, so what the test measures is what the child itself sets. A parent
/// whose own mode carries `SEM_NOGPFAULTERRORBOX` (a CI agent, a shell
/// that hardened itself) would otherwise keep WER out of every child and
/// make the dump check pass for nothing (DC-F44).
fn clear_inherited_error_mode() {
    use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SetErrorMode};
    // SAFETY: both take and return a flags word and touch no memory of ours.
    let inherited = unsafe {
        let was = GetErrorMode();
        SetErrorMode(0);
        was
    };
    eprintln!("child: inherited error mode {inherited:#x}, cleared to 0");
}

/// The child's pid and its output.
struct Ended {
    pid: u32,
    out: Output,
}

/// Re-executes this test binary on `test` alone, in `mode`, with `cwd` as
/// its working directory.
fn run_child(mode: &str, test: &str, cwd: &Path) -> Ended {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MARKER, mode)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Under the spawn lock: this binary links the managed-Tor launch, so
    // every process it starts takes the lock (TOR_SUPERVISOR.md §4.7).
    let child = shekyl_spawn::spawn_lock::spawn(&mut command).expect("spawn the child");
    let pid = child.id();
    let out = child.wait_with_output().expect("wait for the child");
    Ended { pid, out }
}

/// This binary's file name, the key a per-application `LocalDumps` policy
/// is matched on.
fn exe_name() -> String {
    std::env::current_exe()
        .expect("this test binary")
        .file_name()
        .expect("the test binary has a name")
        .to_string_lossy()
        .into_owned()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const LOCAL_DUMPS: &str = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";

/// A per-application `LocalDumps` policy for this binary, pointing at a
/// scratch folder, in force while any test holds it; the last holder's
/// drop deletes the key. Setting it runs the control child once and
/// requires its dump, so a holder knows WER reacts on this machine.
struct ScratchPolicy {
    folder: tempfile::TempDir,
    subkey: Vec<u16>,
}

impl ScratchPolicy {
    fn set() -> Self {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS};
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
            KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
        };
        let folder = tempfile::tempdir().expect("a scratch folder for the dumps");
        let subkey = wide(&format!("{LOCAL_DUMPS}\\{}", exe_name()));
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local or a NUL-terminated
        // buffer this function owns; the sizes passed are the buffers'.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &raw mut key,
                std::ptr::null_mut(),
            )
        };
        assert!(
            rc != ERROR_ACCESS_DENIED,
            "this test sets a per-application LocalDumps policy for its own binary under \
             HKLM\\{LOCAL_DUMPS} and needs the right to write there: run it from an elevated \
             session (CI's runner is one)"
        );
        assert_eq!(
            rc, ERROR_SUCCESS,
            "RegCreateKeyExW on the scratch policy key"
        );
        let path = wide(&folder.path().to_string_lossy());
        let count: u32 = 16;
        let mini: u32 = 1;
        // SAFETY: `key` is the open key from above; each value's pointer
        // and byte length name one live buffer.
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            let path_bytes = (path.len() * 2) as u32;
            let set = |name: &str, kind: u32, data: *const u8, len: u32| {
                let n = wide(name);
                assert_eq!(
                    RegSetValueExW(key, n.as_ptr(), 0, kind, data, len),
                    ERROR_SUCCESS,
                    "RegSetValueExW {name}"
                );
            };
            set("DumpFolder", REG_SZ, path.as_ptr().cast(), path_bytes);
            set("DumpCount", REG_DWORD, (&raw const count).cast(), 4);
            set("DumpType", REG_DWORD, (&raw const mini).cast(), 4);
            RegCloseKey(key);
        }
        let policy = Self { folder, subkey };
        policy.prove_wer_reacts();
        policy
    }

    /// The subject assertion: a child that clears its error mode and faults
    /// with no hardening ends with the exception's code *and leaves a dump*
    /// in the scratch folder. WER writes the dump before the faulting
    /// process is released, so the wait is for the file system alone.
    fn prove_wer_reacts(&self) {
        let dir = tempfile::tempdir().expect("a working directory for the control");
        let ended = run_child("control", CONTROL, dir.path());
        let stderr = String::from_utf8_lossy(&ended.out.stderr).into_owned();
        assert_eq!(
            ended.out.status.code(),
            Some(STATUS_ACCESS_VIOLATION),
            "control: the unhardened child ended with {:?}, not {STATUS_ACCESS_VIOLATION:#x}; \
             stderr:\n{stderr}",
            ended.out.status
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let dumps = self.dumps_of(ended.pid);
            if !dumps.is_empty() {
                eprintln!("control: WER wrote {dumps:?} to the scratch folder");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "control: the unhardened child faulted and Windows Error Reporting wrote no dump \
                 to the scratch LocalDumps folder {}; the machine's WER is not reacting, so a \
                 'no dump' result from the hardened children would be an empty check; stderr:\n\
                 {stderr}",
                self.folder.path().display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The dump files in the scratch folder that name this binary and `pid`
    /// (`<exe>.<pid>.dmp` is the name a `LocalDumps` policy writes).
    fn dumps_of(&self, pid: u32) -> Vec<String> {
        let wanted = format!("{}.{pid}.dmp", exe_name());
        let Ok(entries) = std::fs::read_dir(self.folder.path()) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.eq_ignore_ascii_case(&wanted))
            .collect()
    }
}

impl Drop for ScratchPolicy {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_LOCAL_MACHINE};
        // SAFETY: the subkey is the NUL-terminated buffer `set` built.
        let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, self.subkey.as_ptr()) };
        if rc != 0 {
            eprintln!(
                "the scratch LocalDumps key HKLM\\{LOCAL_DUMPS}\\{} was not deleted (error {rc}); \
                 remove it by hand",
                exe_name()
            );
        }
    }
}

/// One policy shared by the tests that run concurrently in this binary;
/// created by the first to ask, deleted by the last to finish. A refusal
/// in `set` (no right to write `HKLM`, WER not reacting) panics with the
/// lock held and poisons it; the slot is still a sound `Weak`, so the
/// lock is recovered and every later test retries `set` and fails with
/// the same reason, instead of a `PoisonError` that names none (Rick's
/// third Windows run, 2026-11-02).
fn policy() -> Arc<ScratchPolicy> {
    static SHARED: Mutex<Weak<ScratchPolicy>> = Mutex::new(Weak::new());
    let mut slot = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(live) = slot.upgrade() {
        return live;
    }
    let fresh = Arc::new(ScratchPolicy::set());
    *slot = Arc::downgrade(&fresh);
    fresh
}

fn assert_ended_with(policy: &ScratchPolicy, ended: &Ended, code: i32, what: &str) -> String {
    let stderr = String::from_utf8_lossy(&ended.out.stderr).into_owned();
    assert_eq!(
        ended.out.status.code(),
        Some(code),
        "{what}: the child ended with {:?}, not {code:#x}; stderr:\n{stderr}",
        ended.out.status
    );
    assert!(
        stderr.contains("inherited error mode"),
        "{what}: the child did not report clearing its error mode; stderr:\n{stderr}"
    );
    // WER would have written the dump before the child was released; a
    // short wait covers the file system alone.
    std::thread::sleep(Duration::from_millis(500));
    let dumps = policy.dumps_of(ended.pid);
    assert!(
        dumps.is_empty(),
        "{what}: a crash dump of the hardened child appeared in the scratch LocalDumps folder: \
         {dumps:?}"
    );
    stderr
}

/// The control (DC-F44): a child that clears its error mode and faults
/// *without* hardening writes a dump to the scratch policy's folder. Its
/// parent half only asks for the policy, whose creation runs this child
/// and requires the dump; every other test shares that proof.
#[test]
fn a_fault_without_hardening_writes_a_dump_to_the_scratch_policy() {
    if child_mode().as_deref() == Some("control") {
        clear_inherited_error_mode();
        let null: *mut u8 = std::hint::black_box(std::ptr::null_mut());
        // SAFETY: none; the write is the fault under test.
        unsafe { null.write_volatile(1) };
        unreachable!("the write through a null pointer did not fault");
    }
    let _policy = policy();
}

/// (a) A write through a null pointer after hardening ends the child with
/// `STATUS_ACCESS_VIOLATION` as its exit status and writes no dump to the
/// scratch policy's folder. Red if the child exits otherwise, or if both
/// of `harden_process`'s Windows lines are gone and WER wrote the dump the
/// control shows it can.
#[test]
fn a_fault_after_hardening_ends_with_its_code_and_writes_no_dump() {
    const NAME: &str = "a_fault_after_hardening_ends_with_its_code_and_writes_no_dump";
    if child_mode().as_deref() == Some("fault") {
        clear_inherited_error_mode();
        harden_process().expect("hardening applies to an ordinary process");
        let null: *mut u8 = std::hint::black_box(std::ptr::null_mut());
        // SAFETY: none; the write is the fault under test. `black_box`
        // keeps the compiler from reasoning about the pointer's value, so
        // the store is emitted and the page is what refuses it.
        unsafe { null.write_volatile(1) };
        unreachable!("the write through a null pointer did not fault");
    }
    let policy = policy();
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let ended = run_child("fault", NAME, dir.path());
    assert_ended_with(&policy, &ended, STATUS_ACCESS_VIOLATION, "fault");
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
/// continues the search) and ends the child with `STATUS_STACK_OVERFLOW`,
/// no dump.
#[test]
fn a_stack_overflow_after_hardening_prints_the_runtimes_message_and_ends_with_its_code() {
    const NAME: &str =
        "a_stack_overflow_after_hardening_prints_the_runtimes_message_and_ends_with_its_code";
    if child_mode().as_deref() == Some("overflow") {
        clear_inherited_error_mode();
        harden_process().expect("hardening applies to an ordinary process");
        let depth = std::thread::Builder::new()
            .name("overflowing".to_owned())
            .spawn(|| recurse(0))
            .expect("spawn the overflowing thread")
            .join();
        unreachable!("the recursion returned: {depth:?}");
    }
    let policy = policy();
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let ended = run_child("overflow", NAME, dir.path());
    let stderr = assert_ended_with(&policy, &ended, STATUS_STACK_OVERFLOW, "overflow");
    assert!(
        stderr.contains("has overflowed its stack"),
        "the runtime's overflow message is absent from stderr:\n{stderr}"
    );
}

/// (c) A panic under the daemon's hook, after hardening, writes the
/// hook's line and ends the child with `STATUS_STACK_BUFFER_OVERRUN`, the
/// code `abort` reports, through `TerminateProcess` rather than `abort`'s
/// `__fastfail`; no dump.
#[test]
fn a_panic_under_the_hook_after_hardening_ends_with_aborts_code_and_writes_no_dump() {
    const NAME: &str =
        "a_panic_under_the_hook_after_hardening_ends_with_aborts_code_and_writes_no_dump";
    if child_mode().as_deref() == Some("panic") {
        clear_inherited_error_mode();
        harden_process().expect("hardening applies to an ordinary process");
        shekyl_process::panic_hook::install();
        panic!("the panic under test");
    }
    let policy = policy();
    let dir = tempfile::tempdir().expect("a working directory for the child");
    let ended = run_child("panic", NAME, dir.path());
    let stderr = assert_ended_with(&policy, &ended, STATUS_STACK_BUFFER_OVERRUN, "panic");
    assert!(
        stderr.contains("shekyld: panic in thread") && stderr.contains("the panic under test"),
        "the hook's line is absent from stderr:\n{stderr}"
    );
}
