// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Process hardening, the first statement of `shekyl_daemon::main`
//! (`DAEMON_CONFIG_CUTOVER.md` §2.2, DC-Q21).
//!
//! Before an argument is read, a file opened, or a key derived, this
//! process declares that a fatal signal ends it without writing its memory
//! to disk, and that a same-account process cannot attach to it.
//!
//! # What holds
//!
//! - **Every Unix.** `RLIMIT_CORE`, soft and hard, is zero. This process
//!   cannot raise the hard limit afterwards.
//! - **Linux, also.** `PR_SET_DUMPABLE` is zero: `/proc/self` is root-owned,
//!   and a process that is not root cannot `ptrace` this one. The daemon
//!   reads nothing under `/proc/self` that this takes away.
//! - **FreeBSD, also.** `procctl(PROC_TRACE_CTL, PROC_TRACE_CTL_DISABLE)`
//!   refuses `ptrace` and `procfs`/`kvm` memory reads from any process,
//!   root included, writes no core whatever the limit, and cannot be turned
//!   back on by this process.
//! - **macOS.** The Unix core limit only. There is no dumpable flag.
//! - **Windows.** [`end_at_fault`], installed with
//!   `SetUnhandledExceptionFilter`, ends the process with `TerminateProcess`
//!   and the exception's code (`0xC0000005` for an access violation,
//!   `0xC00000FD` for a stack overflow). Windows Error Reporting's fault
//!   path runs after the top-level filter. `SetErrorMode` sets
//!   `SEM_NOGPFAULTERRORBOX`, `SEM_FAILCRITICALERRORS`, and
//!   `SEM_NOOPENFILEERRORBOX`: a fault does not block a headless service on
//!   a dialog, and a missing volume or file is an error the code sees. The
//!   panic hook ends the process the same way, with `0xC0000409`
//!   ([`crate::panic_hook`]).
//!
//! # What does not hold
//!
//! Rust's `SIGSEGV`/`SIGBUS` handler stays. A guard-page fault prints "has
//! overflowed its stack" and aborts. Any other fault restores the default
//! disposition and returns, so the faulting instruction re-executes and the
//! signal ends the process. A `SIGSEGV` sent with `kill(2)` re-executes
//! nothing and is absorbed once; that is not a crash (DC-F34). On FreeBSD
//! the runtime misses a spawned thread's guard page, so an overflow there
//! ends by `SIGSEGV` without the message (DC-F35).
//!
//! The Windows error mode is process-wide, and any library can reset it.
//! That the flag also keeps Windows Error Reporting from writing a dump is
//! observed, and it holds only while the flag is this process's. The filter
//! is the line the dump property rests on. Fail-fast paths this process
//! does not route stay outside the filter: an allocation failure's abort,
//! heap corruption the OS heap detects, a `/GS` check in C++, and
//! `__fastfail`, which passes no filter. The installer's
//! `ExcludedApplications` value is the backstop against a report leaving
//! the machine. An administrator's `LocalDumps` policy can capture a dump
//! of an excluded name.
//!
//! # The checks
//!
//! This module reads the core limit back as zero on both bounds, the Linux
//! dumpable flag back clear, and FreeBSD tracing back disabled. A real
//! fault is judged from outside the process:
//! `tests/dc_q21_a_fault_ends_by_signal.rs` on Unix, and
//! `tests/dc_q21_a_fault_ends_with_its_code.rs` on Windows. That Windows
//! file's unhardened control child is the proof its dump check has a
//! subject.
//!
//! # Errors
//!
//! [`HardenError`] names the step and the operating system's error. Lowering
//! a limit to zero and clearing the dumpable flag are permitted to every
//! process, so a failure is a broken platform and the caller refuses to
//! start.

/// Why [`harden_process`] could not apply a step: the step's name and the
/// operating system's error.
#[derive(Debug)]
pub struct HardenError {
    /// The step that failed, as a reader would name it (`RLIMIT_CORE`,
    /// `PR_SET_DUMPABLE`, `PROC_TRACE_CTL`).
    pub step: &'static str,
    /// The operating system's error.
    pub source: std::io::Error,
}

impl std::fmt::Display for HardenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.step, self.source)
    }
}

impl std::error::Error for HardenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Applies the contract above. A daemon that cannot apply it does not start.
///
/// # Errors
///
/// The step that failed, with the operating system's error.
pub fn harden_process() -> Result<(), HardenError> {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit(2)` reads the `rlimit` struct behind a valid
        // pointer to a live local; it writes no memory of ours.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) } != 0 {
            return Err(HardenError {
                step: "RLIMIT_CORE",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(2)` with `PR_SET_DUMPABLE` takes one integer
        // argument; the trailing zeros are the unused arguments the
        // interface documents as ignored for this option.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(HardenError {
                step: "PR_SET_DUMPABLE",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        let mut disable: libc::c_int = libc::PROC_TRACE_CTL_DISABLE;
        // SAFETY: `procctl(2)` with `PROC_TRACE_CTL` reads one `int` behind
        // a valid pointer to a live local; `P_PID` with id 0 names the
        // calling process.
        if unsafe {
            libc::procctl(
                libc::P_PID,
                0,
                libc::PROC_TRACE_CTL,
                (&raw mut disable).cast::<libc::c_void>(),
            )
        } != 0
        {
            return Err(HardenError {
                step: "PROC_TRACE_CTL",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SetUnhandledExceptionFilter, SEM_FAILCRITICALERRORS,
            SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
        };
        // SAFETY: `SetErrorMode` takes a flags word and returns the
        // previous one; `SetUnhandledExceptionFilter` takes a function
        // pointer of the documented ABI and returns the previous one.
        // Neither touches memory of ours or can fail.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            SetUnhandledExceptionFilter(Some(end_at_fault));
        }
    }
    Ok(())
}

/// The top-level exception filter [`harden_process`] installs on Windows:
/// the process ends here, with the exception's code as its exit status,
/// before Windows Error Reporting is consulted. It returns only if
/// `TerminateProcess` refused, which it does not for the calling process;
/// `EXCEPTION_EXECUTE_HANDLER` then lets the system end the process the
/// ordinary way rather than loop.
#[cfg(windows)]
unsafe extern "system" fn end_at_fault(
    info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    use windows_sys::Win32::Foundation::STATUS_ACCESS_VIOLATION;
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_EXECUTE_HANDLER;
    // SAFETY: the system calls this with a live `EXCEPTION_POINTERS` whose
    // record is live for the call; the reads are of those two structs
    // only, guarded against a null either way.
    let code = unsafe {
        if info.is_null() || (*info).ExceptionRecord.is_null() {
            STATUS_ACCESS_VIOLATION
        } else {
            (*(*info).ExceptionRecord).ExceptionCode
        }
    };
    end_process(code);
    EXCEPTION_EXECUTE_HANDLER
}

/// Ends this process at once with `code` as its exit status, through
/// `TerminateProcess`: an ordinary termination the fault-reporting path
/// never sees. The exit status is an `NTSTATUS`, distinct from the
/// configuration refusal's 2 and the runtime failure's 1 (IG-11).
#[cfg(windows)]
pub fn end_process(code: windows_sys::Win32::Foundation::NTSTATUS) {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle and reads
    // nothing; `TerminateProcess` on it ends this process and does not
    // return on success. An `NTSTATUS` reinterpreted as the unsigned exit
    // code is how Windows itself reports a fault's code.
    unsafe {
        #[allow(clippy::cast_sign_loss)]
        TerminateProcess(GetCurrentProcess(), code as u32);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// After hardening, the core limit reads back as zero on both bounds:
    /// the process can write no core and cannot raise the limit again.
    #[test]
    fn hardening_zeroes_the_core_limit_on_both_bounds() {
        harden_process().expect("hardening applies to an ordinary process");
        let mut read = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `getrlimit(2)` writes the struct behind a valid pointer
        // to a live local.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut read) };
        assert_eq!(rc, 0);
        assert_eq!((read.rlim_cur, read.rlim_max), (0, 0));
    }

    /// On Linux the dumpable flag reads back clear as well.
    #[cfg(target_os = "linux")]
    #[test]
    fn hardening_clears_the_dumpable_flag() {
        harden_process().expect("hardening applies to an ordinary process");
        // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointer arguments and
        // returns the flag.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }

    /// On FreeBSD tracing reads back as disabled: `PROC_TRACE_STATUS`
    /// writes -1 for a process that refused it.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn hardening_disables_tracing() {
        harden_process().expect("hardening applies to an ordinary process");
        let mut status: libc::c_int = 0;
        // SAFETY: `procctl(2)` with `PROC_TRACE_STATUS` writes one `int`
        // behind a valid pointer to a live local.
        let rc = unsafe {
            libc::procctl(
                libc::P_PID,
                0,
                libc::PROC_TRACE_STATUS,
                (&raw mut status).cast::<libc::c_void>(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(status, -1);
    }
}
