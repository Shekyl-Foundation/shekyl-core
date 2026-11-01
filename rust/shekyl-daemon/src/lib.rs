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
