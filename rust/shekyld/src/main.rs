// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyld`'s `main` (`DAEMON_CONFIG_CUTOVER.md` §2.2, DC-Q19).
//!
//! Rust's process entry runs this. It hands `shekyl-daemon`'s sequence the
//! C++ remnant's two functions and the argument vector the runtime
//! resolved (`std::env::args_os`: the bytes on Unix, `GetCommandLineW` on
//! Windows), and exits with the status the sequence returns. Nothing else
//! happens here: the hardening of the process is the sequence's first act,
//! the panic hook its second.
//!
//! The two imports are the whole of what this binary takes from C++ by
//! name. They are defined in `src/daemon/daemon.cpp`, declared in
//! `src/daemon/daemon.h`, and reach this link only through CMake
//! (`corrosion_import_crate` in `cmake/BuildRust.cmake`); see `build.rs`.

use std::ffi::c_int;

use shekyl_daemon::Remnant;
use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;

// The remnant's two functions. `safe`: each is `noexcept` and catches every
// exception; `run` checks its pointer and the snapshot's field count before
// reading, and `stop` reads nothing. Neither has a precondition a caller
// could violate.
unsafe extern "C" {
    safe fn shekyl_remnant_run(snapshot: *const ShekylDaemonSnapshot) -> c_int;
    safe fn shekyl_remnant_stop();
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let remnant = Remnant {
        run: shekyl_remnant_run,
        stop: shekyl_remnant_stop,
    };
    std::process::exit(shekyl_daemon::main(remnant, &args));
}
