// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's Rust `main()` (`docs/design/DAEMON_CONFIG_CUTOVER.md` §2.2,
//! DC-Q13, DC-Q19; `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2).
//!
//! `shekyld` (`rust/shekyld`) is the binary: its `main` is Rust's, and it
//! calls [`main`] with the process's argument vector. Everything here is
//! safe Rust: the node and its network are `shekyl-node`'s, the process
//! probes and hardening are `shekyl-process`'s, and nothing reaches an
//! FFI.

#![deny(unsafe_code)]

pub mod help;
pub mod levers;
pub mod network;
pub mod notify;
pub mod options;
pub mod run;
pub mod signals;
pub mod tor;
pub mod verify;

pub use run::{EXIT_FAILED, EXIT_REFUSED};

/// The entry with the real platform: the account's roots from the
/// operating system, and `args`, the argument vector Rust's process entry
/// resolved (IG-Q2). Returns the exit status; the binary exits with it.
///
/// The first statement is the process hardening (DC-Q21): no core, no
/// same-account tracer, before an argument is read. A process that cannot
/// apply it does not go on to hold anything worth protecting; it says so
/// on standard error and exits [`EXIT_FAILED`].
#[must_use]
pub fn main(args: &[std::ffi::OsString]) -> i32 {
    if let Err(e) = shekyl_process::harden::harden_process() {
        run::tell(
            &mut std::io::stderr(),
            &format!("shekyld: process hardening {e}; not starting"),
        );
        return EXIT_FAILED;
    }
    shekyl_process::panic_hook::install();
    run::main(args, &shekyl_process::platform::current())
}
