// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The C ABI between the Rust `main()` and the C++ remnant
//! (`DAEMON_CONFIG_CUTOVER.md` §2.1, §2.9).
//!
//! Nothing crosses in either direction but what is here. C++ `main()`
//! hands [`shekyl_daemon_main`] a [`ShekylDaemonEntry`] — its version
//! strings and two function pointers, `run` and `stop` — and the process
//! `argc`/`argv`. Rust resolves that vector through
//! [`ArgumentVector`](shekyl_ffi::argument_vector::ArgumentVector) and fills
//! a [`ShekylDaemonSnapshot`], the read-only structure holding exactly the
//! values whose reader is still C++, and calls `run` with it. The C++
//! defines no symbol Rust imports, so every Rust test can drive the entry
//! with a fake pair. This file is the daemon's entry ABI and a
//! signature-gate surface; the `#[allow(unsafe_code)]` below are this
//! file's exceptions to the crate's rule, each on the one item the lint
//! names. `run::unsafe_c_str` is the crate's other one.
//!
//! **The snapshot** ([`ShekylDaemonSnapshot`], its field count and the
//! test binaries' parse export) is `shekyl-ffi`'s `daemon_snapshot_ffi`, in
//! the ordinary FFI library, so a binary that only constructs core from a
//! snapshot does not link the daemon image (§2.9).
//!
//! **One stop path.** [`shekyl_daemon_request_stop`] is how the remnant
//! asks for a stop — the console's `exit` and the RPC's `stop_daemon` —
//! so every trigger reaches the one owner in [`crate::signals`] and the
//! stop runs in §2.2 step 9's order. The remnant never stops itself.

use std::ffi::{c_char, c_int};

use shekyl_ffi::argument_vector::ArgumentVector;
use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;

/// The remnant's `run`: constructs core, the protocol handler, the node
/// server and the RPC from the snapshot, runs until stopped, and returns
/// the exit status. `noexcept`: every C++ exception is caught inside it.
pub type RunFn = extern "C" fn(*const ShekylDaemonSnapshot) -> c_int;

/// The remnant's `stop`: requests the stop `run` is waiting for and
/// returns at once. `noexcept`.
pub type StopFn = extern "C" fn();

/// What C++ hands the Rust entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylDaemonEntry {
    /// `SHEKYL_RELEASE_NAME`, NUL-terminated.
    pub release_name: *const c_char,
    /// `SHEKYL_VERSION_FULL`, NUL-terminated.
    pub version_full: *const c_char,
    /// `SHEKYL_PROTOCOL_VERSION`.
    pub protocol_version: u32,
    /// The remnant's `run`.
    pub run: Option<RunFn>,
    /// The remnant's `stop`.
    pub stop: Option<StopFn>,
}

/// The daemon's one C entry: C++ `main()` builds an entry and calls this
/// with its `argc` and `argv`, and Rust owns the process from here.
/// Returns the exit status.
///
/// The argument vector is [`ArgumentVector::from_process_entry`]. A vector
/// that cannot be read returns 1 and does not start.
///
/// # Safety
///
/// `entry` is null or points at a [`ShekylDaemonEntry`] that outlives the
/// call, with NUL-terminated static strings. `argc` and `argv` meet
/// [`ArgumentVector::from_process_entry`]'s contract. On Windows those
/// pointers are not read.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_main(
    entry: *const ShekylDaemonEntry,
    argc: c_int,
    argv: *const *const c_char,
) -> i32 {
    if entry.is_null() {
        return crate::run::EXIT_FAILED;
    }
    // SAFETY: the caller's contract above.
    let entry = unsafe { &*entry };
    // SAFETY: [`ArgumentVector::from_process_entry`]'s contract.
    let Some(arguments) = (unsafe { ArgumentVector::from_process_entry(argc, argv) }) else {
        return crate::run::EXIT_FAILED;
    };
    crate::main(entry, arguments.as_slice())
}

/// Asks for a stop, from the remnant: the console's `exit` and the RPC's
/// `stop_daemon`. Returns at once; the stop runs in step 9's order from the
/// one owner. A request before the owner waits is kept for it; a second
/// request is a no-op.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_request_stop() {
    crate::signals::request_stop();
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    fn entry(release: &CString, version: &CString) -> ShekylDaemonEntry {
        ShekylDaemonEntry {
            release_name: release.as_ptr(),
            version_full: version.as_ptr(),
            protocol_version: 3,
            run: None,
            stop: None,
        }
    }

    /// `--version` in the pointer array exits 0, and an unknown name exits 2.
    /// This bites against the entry reading `std::env::args_os`: that vector
    /// is this test process's own arguments, which are neither of those.
    /// It does not link a C `main` and does not start a daemon.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn the_pointers_main_passes_are_the_command_line() {
        let release = CString::new("test").unwrap();
        let version = CString::new("0").unwrap();
        let entry = entry(&release, &version);
        let program = CString::new("shekyld").unwrap();
        let flag = CString::new("--version").unwrap();
        let version_argv = [program.as_ptr(), flag.as_ptr()];
        let status = unsafe { shekyl_daemon_main(&raw const entry, 2, version_argv.as_ptr()) };
        assert_eq!(status, 0);

        let bogus = CString::new("--zzzz-bogus").unwrap();
        let bogus_argv = [program.as_ptr(), bogus.as_ptr()];
        let refused = unsafe { shekyl_daemon_main(&raw const entry, 2, bogus_argv.as_ptr()) };
        assert_eq!(refused, crate::run::EXIT_REFUSED);
    }

    /// The hole sits between `--network` and its value. A prefix would be
    /// a missing-value refusal (status 2) and would not start. A hole is
    /// status 1. An empty count is the same failure.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn a_null_slot_does_not_start() {
        let release = CString::new("test").unwrap();
        let version = CString::new("0").unwrap();
        let entry = entry(&release, &version);
        let program = CString::new("shekyld").unwrap();
        let network = CString::new("--network").unwrap();
        let name = CString::new("testnet").unwrap();
        let hole = [
            program.as_ptr(),
            network.as_ptr(),
            std::ptr::null(),
            name.as_ptr(),
        ];
        let status = unsafe { shekyl_daemon_main(&raw const entry, 4, hole.as_ptr()) };
        assert_eq!(status, crate::run::EXIT_FAILED);

        let empty = unsafe { shekyl_daemon_main(&raw const entry, 0, std::ptr::null()) };
        assert_eq!(empty, crate::run::EXIT_FAILED);
    }
}
