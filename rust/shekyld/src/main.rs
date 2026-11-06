// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyld`'s `main` (`DAEMON_CONFIG_CUTOVER.md` §2.2, DC-Q19).
//!
//! Rust's process entry runs this. It hands `shekyl-daemon`'s sequence the
//! argument vector the runtime resolved (`std::env::args_os`: the bytes on
//! Unix, `GetCommandLineW` on Windows) and exits with the status the
//! sequence returns. Nothing else happens here: the hardening of the
//! process is the sequence's first act, the panic hook its second.
//!
//! The binary is Rust from this line down (`P2P_3_REMNANT_CUTOVER_BRIEF.md`
//! §1): no crate it is built from declares a C++ import, and `cargo build
//! -p shekyld` is the whole build.

#![deny(unsafe_code)]

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    std::process::exit(shekyl_daemon::main(&args));
}
