// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The C++ remnant's two functions, as the Rust binary hands them to the
//! sequence (`DAEMON_CONFIG_CUTOVER.md` §2.1, §2.9, DC-Q19).
//!
//! `shekyld` is a Rust binary. Its `main` imports `shekyl_remnant_run` and
//! `shekyl_remnant_stop` from the remnant's archive and passes them here
//! as a [`Remnant`]: a plain Rust struct of two function pointers, never a
//! C layout, because nothing on the C++ side ever sees it. Rust fills a
//! [`ShekylDaemonSnapshot`], the read-only structure holding exactly the
//! values whose reader is still C++, and calls `run` with it. Every test
//! in this crate drives the sequence with a fake pair; none links C++.
//!
//! **The snapshot** ([`ShekylDaemonSnapshot`], its field count and the
//! test binaries' parse export) is `shekyl-ffi`'s `daemon_snapshot_ffi`,
//! so a binary that only constructs core from a snapshot (the importer,
//! core_tests) carries nothing of the daemon (§2.9).
//!
//! **One stop path.** The remnant asks for a stop through
//! [`crate::stop::shekyl_daemon_request_stop`]; it never stops itself.

use std::ffi::c_int;

use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;

/// The remnant's `run`: constructs core, the protocol handler, the node
/// server and the RPC from the snapshot, runs until stopped, and returns
/// the exit status. `noexcept`: every C++ exception is caught inside it.
pub type RunFn = extern "C" fn(*const ShekylDaemonSnapshot) -> c_int;

/// The remnant's `stop`: requests the stop `run` is waiting for and
/// returns at once. `noexcept`.
pub type StopFn = extern "C" fn();

/// The remnant, as the binary hands it to the sequence. Two function
/// pointers, both present: a binary that has no remnant does not build.
#[derive(Clone, Copy, Debug)]
pub struct Remnant {
    /// The remnant's `run`.
    pub run: RunFn,
    /// The remnant's `stop`.
    pub stop: StopFn,
}
