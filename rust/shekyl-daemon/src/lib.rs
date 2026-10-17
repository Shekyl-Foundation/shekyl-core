// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's Rust `main()` (`docs/design/DAEMON_CONFIG_CUTOVER.md` §2.2,
//! DC-Q13).
//!
//! `shekyl-daemon-image` exports the one C symbol, `shekyl_daemon_main`,
//! which calls [`run::main`] with the entry C++ built. Everything here is
//! safe Rust: the C ABI types are plain data ([`entry`]), the remnant is
//! reached through function pointers it handed over, and the platform
//! probes come from `shekyl-ffi`.

#![deny(unsafe_code)]

pub mod entry;
pub mod help;
pub mod network;
pub mod options;
pub mod run;
pub mod signals;
pub mod tor;

pub use entry::{
    ShekylClientEndpoint, ShekylDaemonEntry, ShekylDaemonSnapshot, ShekylMineAddress,
    ShekylStringList, SNAPSHOT_FIELDS,
};
pub use run::{Host, EXIT_FAILED, EXIT_REFUSED};

/// The entry with the real platform: the account's roots from the
/// operating system, the network id's one derivation, and the arguments
/// as the operating system gave them (IG-Q2).
#[must_use]
pub fn main(entry: &ShekylDaemonEntry) -> i32 {
    shekyl_ffi::panic_hook::install();
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    run::main(entry, &args, &host())
}

/// This machine's platform facts and the network id derivation.
pub(crate) fn host() -> Host {
    Host {
        platform: shekyl_daemon_config::Platform {
            home: shekyl_ffi::platform::account_home(),
            program_data: shekyl_ffi::platform::program_data(),
        },
        network_id_of: shekyl_ffi::network_id_ffi::network_id_of,
    }
}
