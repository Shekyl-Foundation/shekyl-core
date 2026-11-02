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
//! Four of the seam's entries are Rust, exported by `shekyl-ffi` for the
//! C++ side and reached by `shekyl-daemon-rpc` the same way as the C++
//! ones, because that crate cannot depend on `shekyl-ffi` (the layering
//! note in `shekyl-ffi/Cargo.toml`). They are taken from the crate here,
//! not imported by name: a Rust symbol is never declared `extern`.

use std::ffi::{c_char, c_int, c_void};

use shekyl_daemon::Remnant;
use shekyl_daemon_rpc::ffi::{
    ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi, PeerFactsFfi, SeamSessionCountsFfi,
};
use shekyl_daemon_rpc::seam::CoreSeam;
use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;
use shekyl_ffi::rpc_peerlist_ffi::{
    shekyl_rpc_peer_list, shekyl_rpc_peer_list_free, shekyl_rpc_peerlist_sizes, ShekylRpcPeerFacts,
};
use shekyl_ffi::seam_board_ffi::{shekyl_seam_session_counts, ShekylSeamSessionCounts};

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

// The two Rust entries whose pointee type is spelled twice — once in
// `shekyl-ffi` for the C header, once in `shekyl-daemon-rpc` for the
// reader — are one layout. The cast below is sound only while this holds.
const _: () = assert!(size_of::<PeerFactsFfi>() == size_of::<ShekylRpcPeerFacts>());
const _: () = assert!(align_of::<PeerFactsFfi>() == align_of::<ShekylRpcPeerFacts>());
const _: () = assert!(size_of::<SeamSessionCountsFfi>() == size_of::<ShekylSeamSessionCounts>());
const _: () = assert!(align_of::<SeamSessionCountsFfi>() == align_of::<ShekylSeamSessionCounts>());

/// `shekyl_rpc_peer_list`, with the reader's spelling of the facts.
///
/// # Safety
///
/// As `shekyl_rpc_peer_list`'s.
unsafe extern "C" fn peer_list(
    public_only: u8,
    out: *mut *const PeerFactsFfi,
    out_len: *mut usize,
    out_owner: *mut *mut c_void,
) -> i32 {
    // SAFETY: the caller's contract is the callee's; the pointee types are
    // one layout, asserted above.
    unsafe { shekyl_rpc_peer_list(public_only, out.cast(), out_len, out_owner) }
}

/// `shekyl_seam_session_counts`, with the reader's spelling of the counts.
///
/// # Safety
///
/// As `shekyl_seam_session_counts`'s.
unsafe extern "C" fn session_counts(out: *mut SeamSessionCountsFfi) -> i32 {
    // SAFETY: as above.
    unsafe { shekyl_seam_session_counts(out.cast()) }
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
            peer_list,
            peer_list_free: shekyl_rpc_peer_list_free,
            peerlist_sizes: shekyl_rpc_peerlist_sizes,
            session_counts,
        },
    };
    std::process::exit(shekyl_daemon::main(remnant, &args));
}
