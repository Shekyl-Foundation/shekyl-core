// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Lower the calling thread's CPU priority (`SH-3`,
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.8).
//!
//! One entry point, [`lower_current_thread`], called by every thread of
//! the serving runtime as it starts. The scheduling class stays normal on
//! every platform: a thread the scheduler may starve outright is a persona
//! that fails challenge reads it should pass, so none of the mappings is
//! an idle or background class.
//!
//! - **Linux and Android:** `setpriority(PRIO_PROCESS, 0, 19)`. The nice
//!   value is a per-thread attribute on Linux and `who = 0` is the calling
//!   thread. `SCHED_OTHER` throughout; never `SCHED_IDLE`.
//! - **macOS, iOS:** `pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0)`.
//!   Utility, not Background: the background class also lowers I/O
//!   priority and is what the system throttles.
//! - **Windows:** `SetThreadPriority(GetCurrentThread(),
//!   THREAD_PRIORITY_LOWEST)`. Not `THREAD_MODE_BACKGROUND_BEGIN`, which also
//!   lowers I/O and memory priority.
//! - **Other unix (the BSDs):** `setpriority(PRIO_PROCESS, 0, …)` there
//!   is the *process*, and the only per-thread alternative is the idle
//!   class. Neither is the ruling, so the call reports
//!   [`NotLowered::Unsupported`] and the caller's failure path applies:
//!   serving continues at normal priority, counted and warned about.
//!
//! This crate holds the three `unsafe` calls so that `shekyl-runtime` can
//! keep `deny(unsafe_code)`. Nothing here needs privilege.

use std::fmt;
use std::io;

/// The Linux nice value the serving runtime's threads run at.
///
/// The lowest nice under normal scheduling. `BA-T5` session 2 measured
/// serving at this value beside a syncing daemon: the daemon kept 90 to
/// 97 % of its no-serve sync rate and serving still delivered 5 to 8
/// responses per second. The ledger row `serving_priority_nice` carries
/// it.
pub const SERVING_NICE: i32 = 19;

/// Why the calling thread's priority was not lowered.
///
/// Never fatal to the caller: a thread that keeps normal priority still
/// serves. The host counts it and warns once (§9.8 item 3).
#[derive(Debug)]
pub enum NotLowered {
    /// The platform call was made and refused; the OS error is carried.
    Refused(io::Error),
    /// This platform has no per-thread mapping under normal scheduling.
    Unsupported,
}

impl fmt::Display for NotLowered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(e) => write!(
                f,
                "the platform refused to lower this thread's priority: {e}"
            ),
            Self::Unsupported => {
                f.write_str("this platform has no per-thread priority under normal scheduling")
            }
        }
    }
}

impl std::error::Error for NotLowered {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(e) => Some(e),
            Self::Unsupported => None,
        }
    }
}

/// Lower the calling thread's CPU priority, keeping its scheduling class.
///
/// Idempotent: a second call on the same thread sets the same value.
///
/// # Errors
///
/// [`NotLowered`] — the thread keeps the priority it had.
pub fn lower_current_thread() -> Result<(), NotLowered> {
    platform::lower()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{NotLowered, SERVING_NICE};

    pub(super) fn lower() -> Result<(), NotLowered> {
        // SAFETY: `setpriority` takes three integers and touches no memory
        // of ours. `who = 0` names the calling thread on Linux.
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, SERVING_NICE) };
        if rc == -1 {
            return Err(NotLowered::Refused(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(target_vendor = "apple")]
mod platform {
    use super::NotLowered;

    pub(super) fn lower() -> Result<(), NotLowered> {
        // SAFETY: the call takes a class and a relative priority by value
        // and acts on the calling thread only. It returns 0 or an errno.
        let rc =
            unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
        if rc != 0 {
            return Err(NotLowered::Refused(std::io::Error::from_raw_os_error(rc)));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::NotLowered;
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_LOWEST,
    };

    pub(super) fn lower() -> Result<(), NotLowered> {
        // SAFETY: `GetCurrentThread` returns a pseudo-handle that is never
        // closed, and `SetThreadPriority` takes it by value.
        let ok = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST) };
        if ok == 0 {
            return Err(NotLowered::Refused(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
mod platform {
    use super::NotLowered;

    pub(super) fn lower() -> Result<(), NotLowered> {
        Err(NotLowered::Unsupported)
    }
}

/// The calling thread's nice value, as the kernel reports it.
///
/// Linux and Android only: the read-back the tests and the serving host's
/// own check use. `getpriority` returns −1 for a nice of −1 as well as on
/// failure, so errno is cleared before the call and consulted after it.
///
/// # Errors
///
/// The OS error if the kernel refused the read.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn current_thread_nice() -> io::Result<i32> {
    // SAFETY: `__errno_location` returns this thread's errno slot, which
    // is valid for the thread's life; `getpriority` takes two integers.
    unsafe {
        *libc::__errno_location() = 0;
    }
    let value = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    if value == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(0) {
            return Err(err);
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn lowering_sets_the_calling_thread_and_only_it() {
        let before = current_thread_nice().expect("read nice");
        let (tx, rx) = std::sync::mpsc::channel();
        let lowered = std::thread::spawn(move || {
            lower_current_thread().expect("lower");
            tx.send(current_thread_nice().expect("read nice"))
                .expect("report");
            // A second call is the same value, not an error.
            lower_current_thread().expect("lower again");
            current_thread_nice().expect("read nice")
        });
        assert_eq!(rx.recv().expect("one reading"), SERVING_NICE);
        assert_eq!(lowered.join().expect("thread"), SERVING_NICE);
        assert_eq!(
            current_thread_nice().expect("read nice"),
            before,
            "the calling thread's own nice must not move"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_proc_stat_nice_field_agrees_with_getpriority() {
        std::thread::spawn(|| {
            lower_current_thread().expect("lower");
            // /proc/thread-self/stat: field 19 (1-based) is the nice value.
            // The comm field is parenthesised and may hold spaces, so split
            // after the last ')'.
            let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("stat");
            let after_comm = &stat[stat.rfind(')').expect("comm") + 2..];
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            // `after_comm` starts at field 3 (state), so nice is index 16.
            let nice: i32 = fields[16].parse().expect("nice field");
            assert_eq!(nice, SERVING_NICE);
            assert_eq!(current_thread_nice().expect("read nice"), nice);
        })
        .join()
        .expect("thread");
    }

    #[test]
    fn the_error_names_its_cause() {
        let refused = NotLowered::Refused(io::Error::from_raw_os_error(1));
        assert!(refused.to_string().starts_with("the platform refused"));
        assert!(std::error::Error::source(&refused).is_some());
        assert!(std::error::Error::source(&NotLowered::Unsupported).is_none());
    }
}
