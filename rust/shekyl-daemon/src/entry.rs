// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The C ABI between the Rust `main()` and the C++ remnant
//! (`DAEMON_CONFIG_CUTOVER.md` §2.1, §2.9).
//!
//! Nothing crosses in either direction but what is here. C++ `main()`
//! hands [`shekyl_daemon_main`] a [`ShekylDaemonEntry`]: its version
//! strings and two function pointers, `run` and `stop`. Rust fills a
//! [`ShekylDaemonSnapshot`], the read-only structure holding exactly the
//! values whose reader is still C++, and calls `run` with it. The C++
//! defines no symbol Rust imports, so every Rust test can drive the entry
//! with a fake pair. This file is the daemon's entry ABI and a
//! signature-gate surface; the `#[allow(unsafe_code)]` below are its only
//! exceptions to the crate's rule, each on the one item the lint names.
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

/// The daemon's one C entry: C++ `main()` builds an entry and calls this,
/// and Rust owns the process from here. Returns the exit status.
///
/// # Safety
///
/// `entry` must be null or point to a `ShekylDaemonEntry` that outlives
/// the call and whose strings are NUL-terminated and static.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_main(entry: *const ShekylDaemonEntry) -> i32 {
    if entry.is_null() {
        return crate::run::EXIT_FAILED;
    }
    // SAFETY: the caller's contract above.
    let entry = unsafe { &*entry };
    crate::main(entry)
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
