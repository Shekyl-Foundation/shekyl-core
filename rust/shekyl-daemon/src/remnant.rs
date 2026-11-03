// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The C++ remnant, as the Rust binary hands it to the sequence
//! (`DAEMON_CONFIG_CUTOVER.md` §2.1, §2.9, DC-Q19, DC-F43).
//!
//! `shekyld` is a Rust binary. Its `main` holds the one `extern "C"` block
//! for every C++ function Rust calls — `shekyl_remnant_run`,
//! `shekyl_remnant_stop`, the shell's relay entry and the RPC's core
//! reads — and passes them here as a [`Remnant`]: a plain Rust struct of
//! function pointers, never a C layout, because nothing on the C++ side
//! ever sees it. No library crate declares a C++ import. Rust fills a
//! [`ShekylDaemonSnapshot`], the read-only structure holding exactly the
//! values whose reader is still C++, and calls `run` with it; the sequence
//! hands `relay_local` to the node and installs `core` for the RPC before
//! `run` is reached. The peer lists and the session counts are not part of
//! this remnant: they are Rust, and [`crate::p2p_reads`] installs them.
//! Every test in this crate drives the sequence with a fake remnant
//! ([`Remnant::absent_core`]); none links C++, and none installs those
//! reads, so a test reads a process with no lists and no hub.
//!
//! **The snapshot** ([`ShekylDaemonSnapshot`], its field count and the
//! test binaries' parse export) is `shekyl-ffi`'s `daemon_snapshot_ffi`,
//! so a binary that only constructs core from a snapshot (the importer,
//! core_tests) carries nothing of the daemon (§2.9).
//!
//! **One stop path.** The remnant asks for a stop through
//! [`crate::stop::shekyl_daemon_request_stop`]; it never stops itself.

use std::ffi::c_int;
use std::sync::Arc;

use shekyl_daemon_rpc::seam::{CoreSeam, ABSENT};
use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;

/// The remnant's `run`: constructs core, the protocol handler, the node
/// server and the RPC from the snapshot, runs until stopped, and returns
/// the exit status. `noexcept`: every C++ exception is caught inside it.
/// `unsafe`: it dereferences the pointer, so the caller owes it a complete
/// snapshot that outlives the call ([`SnapshotData::call`] is that caller,
/// and the only one).
///
/// [`SnapshotData::call`]: shekyl_ffi::daemon_snapshot_ffi::SnapshotData::call
pub type RunFn = unsafe extern "C" fn(*const ShekylDaemonSnapshot) -> c_int;

/// The remnant's `stop`: requests the stop `run` is waiting for and
/// returns at once. `noexcept`.
pub type StopFn = extern "C" fn();

/// The shell's relay entry, `shekyl_shell_relay_local`: hands a committed
/// transaction's bytes to `levin_notify`; non-zero when the relay took
/// them, `0` when no notifier is bound (before `core::init` returns, or
/// offline). RD deletes it with `levin_notify`.
pub type RelayLocalFn = unsafe extern "C" fn(blob: *const u8, len: usize) -> i32;

/// The remnant, as the binary hands it to the sequence. Every pointer
/// present: a binary that has no remnant does not build.
#[derive(Clone, Copy, Debug)]
pub struct Remnant {
    /// The remnant's `run`.
    pub run: RunFn,
    /// The remnant's `stop`.
    pub stop: StopFn,
    /// The shell's relay entry, for the node.
    pub relay_local: RelayLocalFn,
    /// The RPC's reads of the C++ core. The peer lists and the sessions
    /// are [`crate::p2p_reads`], not this seam.
    pub core: CoreSeam,
}

impl Remnant {
    /// A remnant over a `run` and a `stop` with no core behind them: no
    /// relay route (every transaction shows at the origin) and the
    /// [`ABSENT`] seam. The shape of every test's remnant.
    #[must_use]
    pub fn absent_core(run: RunFn, stop: StopFn) -> Self {
        Self {
            run,
            stop,
            relay_local: no_relay,
            core: ABSENT,
        }
    }

    /// The node's view of [`Self::relay_local`].
    #[must_use]
    pub fn relay_local(&self) -> shekyl_node::RelayLocal {
        let relay = self.relay_local;
        Arc::new(move |blob: &[u8]| {
            // SAFETY: `blob` is a live slice for the call; the shell reads
            // `len` bytes from it and keeps nothing.
            #[allow(unsafe_code)]
            let took = unsafe { relay(blob.as_ptr(), blob.len()) };
            took != 0
        })
    }
}

/// A [`RelayLocalFn`] with no route.
extern "C" fn no_relay(_blob: *const u8, _len: usize) -> i32 {
    0
}
