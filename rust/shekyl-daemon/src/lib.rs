// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's Rust `main()` (`docs/design/DAEMON_CONFIG_CUTOVER.md` §2.2,
//! DC-Q13, DC-Q19).
//!
//! `shekyld` (`rust/shekyld`) is the binary: its `main` is Rust's, and it
//! calls [`main`] with the C++ remnant's two functions ([`remnant`]) and the
//! process's argument vector. Everything here is safe Rust: the remnant is
//! reached through function pointers the binary handed over, the one
//! export it calls back is [`stop`], and the platform probes come from
//! `shekyl-ffi`.

#![deny(unsafe_code)]

pub mod help;
pub mod network;
pub mod options;
pub mod remnant;
pub mod run;
pub mod signals;
pub mod stop;
pub mod tor;
pub mod verify;

pub use remnant::{Remnant, RunFn, StopFn};
pub use run::{Host, EXIT_FAILED, EXIT_REFUSED};

/// The daemon binary supplies this from C++. This crate's tests link the
/// node, which calls it, and link no C++.
#[cfg(test)]
#[allow(unsafe_code)]
#[no_mangle]
extern "C" fn shekyl_shell_relay_local(_blob: *const u8, _len: usize) -> i32 {
    0
}

/// The entry with the real platform: the account's roots from the
/// operating system, the network id's one derivation, and `args`, the
/// argument vector Rust's process entry resolved (IG-Q2). Returns the exit
/// status; the binary exits with it.
///
/// The first statement is the process hardening (DC-Q21): no core, no
/// same-account tracer, before an argument is read. A process that cannot
/// apply it does not go on to hold anything worth protecting; it says so
/// on standard error and exits [`EXIT_FAILED`].
#[must_use]
pub fn main(remnant: Remnant, args: &[std::ffi::OsString]) -> i32 {
    if let Err(e) = shekyl_ffi::platform::harden_process() {
        eprintln!("shekyld: process hardening {e}; not starting");
        return EXIT_FAILED;
    }
    shekyl_ffi::panic_hook::install();
    run::main(remnant, args, &host())
}

/// This machine's platform facts and the network id derivation.
pub(crate) fn host() -> Host {
    Host {
        platform: shekyl_ffi::platform::current(),
        network_id_of: shekyl_ffi::network_id_ffi::network_id_of,
    }
}

/// Link-time stubs for the crate's **unit** tests only (DC-F39).
///
/// The lib test binary links no C++ archive, and `run::main` reaches
/// `shekyl_daemon_rpc::core::CoreRpc`, whose methods call the C++ `rpc`
/// library's exports. GNU ld and lld drop those references with the
/// unreferenced sections, so the Linux, macOS and FreeBSD test links never
/// asked for them; MSVC's `link.exe` resolves every symbol of every object
/// it pulls before it discards anything, and failed on exactly these seven
/// (`LNK2019`, Rick's Windows test of #1254). Each stub is the "no core
/// here" answer the twin module in `shekyl-daemon-rpc` gives: a null handle
/// or the NULL error code. Only symbols that link asked for are stubbed, so
/// a new C++ import shows up as a link error on MSVC rather than as a
/// silently stubbed production path; the MSVC CI job runs this crate's
/// tests so that error is seen.
#[cfg(test)]
#[allow(unsafe_code)]
mod unit_test_link_stubs {
    use shekyl_daemon_rpc::ffi::{
        ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi, SHEKYL_RPC_FACTS_ERR_NULL,
    };
    use std::ffi::c_void;
    use std::os::raw::c_char;

    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_create(_p: *mut c_void) -> *mut CoreRpcHandle {
        std::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_destroy(_h: *mut CoreRpcHandle) {}
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_stem_tallies(_h: *mut CoreRpcHandle) -> *mut c_char {
        std::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_free_string(_s: *mut c_char) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_net_stats(
        _h: *mut CoreRpcHandle,
        _out: *mut NetStatsFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections(
        _h: *mut CoreRpcHandle,
        _out_now: *mut u64,
        _out: *mut *const ConnectionFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections_free(_owner: *mut c_void) {}
}
