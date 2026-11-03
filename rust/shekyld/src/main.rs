// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyld`'s `main` (`DAEMON_CONFIG_CUTOVER.md` §2.2, DC-Q19, DC-F43).
//!
//! Rust's process entry runs this. It hands `shekyl-daemon`'s sequence the
//! C++ remnant and the argument vector the runtime resolved
//! (`std::env::args_os`: the bytes on Unix, `GetCommandLineW` on Windows),
//! and exits with the status the sequence returns. Nothing else happens
//! here: the hardening of the process is the sequence's first act, the
//! panic hook its second.
//!
//! The `extern "C"` block below is the whole of what Rust takes from C++
//! by name, and the only such block in any crate the daemon is built from:
//! the libraries (`shekyl-daemon`, `shekyl-node`, `shekyl-daemon-rpc`)
//! declare no C++ import and take these as function pointers in the
//! [`Remnant`], so their tests link no C++ and stub nothing (DC-F39's
//! link stubs are gone with their cause). `scripts/ci/check_cpp_import_signatures.py`
//! holds the block to the C declarations and holds every other crate to
//! having no such block. The symbols reach this link only through CMake
//! (`corrosion_import_crate` in `cmake/BuildRust.cmake`); see `build.rs`.
//!
//! The peer lists and the session counts are Rust. `shekyl-daemon` installs
//! them as ordinary functions ([`shekyl_daemon::p2p_reads`]); they are not
//! imported, and they are not members of this seam.

use std::ffi::{c_char, c_int, c_void};

use shekyl_daemon::Remnant;
use shekyl_daemon_rpc::ffi::{ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi};
use shekyl_daemon_rpc::seam::CoreSeam;
use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;

// Every C++ function Rust calls, all `noexcept`.
//
// The remnant's two: `run` dereferences the snapshot it is given, so it is
// `unsafe`; its one caller, `SnapshotData::call`, owes it a complete
// snapshot that outlives the call and says so there. `stop` takes nothing
// and reads nothing, so it is `safe`. They are defined in
// `src/daemon/daemon.cpp`, declared in `src/daemon/daemon.h`.
//
// The shell's relay entry, `src/cryptonote_core/cryptonote_core.cpp`,
// declared in `src/shekyl/shekyl_ffi.h`: the node's `relay_local`.
//
// The RPC's core reads, `src/rpc/core_rpc_ffi.cpp` and
// `src/rpc/rpc_facts_ffi.cpp`, declared beside them: the seam's C++ half.
// Their contracts are on the `CoreSeam` fields that carry them.
unsafe extern "C" {
    unsafe fn shekyl_remnant_run(snapshot: *const ShekylDaemonSnapshot) -> c_int;
    safe fn shekyl_remnant_stop();

    unsafe fn shekyl_shell_relay_local(blob: *const u8, len: usize) -> i32;

    unsafe fn core_rpc_ffi_create(rpc_server_ptr: *mut c_void) -> *mut CoreRpcHandle;
    unsafe fn core_rpc_ffi_destroy(h: *mut CoreRpcHandle);
    unsafe fn core_rpc_ffi_stem_tallies(h: *mut CoreRpcHandle) -> *mut c_char;
    unsafe fn core_rpc_ffi_free_string(s: *mut c_char);
    unsafe fn shekyl_rpc_net_stats(h: *mut CoreRpcHandle, out: *mut NetStatsFactsFfi) -> i32;
    unsafe fn shekyl_rpc_connections(
        h: *mut CoreRpcHandle,
        out_now: *mut u64,
        out: *mut *const ConnectionFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut c_void,
    ) -> i32;
    unsafe fn shekyl_rpc_connections_free(owner: *mut c_void);
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let remnant = Remnant {
        run: shekyl_remnant_run,
        stop: shekyl_remnant_stop,
        relay_local: shekyl_shell_relay_local,
        core: CoreSeam {
            create: core_rpc_ffi_create,
            destroy: core_rpc_ffi_destroy,
            stem_tallies: core_rpc_ffi_stem_tallies,
            free_string: core_rpc_ffi_free_string,
            net_stats: shekyl_rpc_net_stats,
            connections: shekyl_rpc_connections,
            connections_free: shekyl_rpc_connections_free,
        },
    };
    std::process::exit(shekyl_daemon::main(remnant, &args));
}
