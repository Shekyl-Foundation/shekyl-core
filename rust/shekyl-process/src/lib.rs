// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's process (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 1): what
//! `shekyl_daemon::main` does before it reads an argument, and the facts
//! it takes from the operating system rather than the environment.
//!
//! - [`harden`]: no core, and a same-account process cannot attach
//!   (DC-Q21). The first statement of the daemon's entry.
//! - [`panic_hook`]: a panic is never silent under `panic = "abort"`.
//! - [`platform`]: the account's home and the machine's roots from the
//!   account interface, never `HOME`, `XDG_*` or `%APPDATA%` (IG-13).
//!
//! On Unix, `interrupt` reads whether `SIGINT` is ignored, before a handler
//! is installed. Windows has no documented read of the inherited
//! ignore-Ctrl-C attribute, so that module is Unix-only; the daemon records
//! the attribute as unreadable and does not pretend to have observed it.
//!
//! The `unsafe` here is the operating-system calls these modules make; the
//! daemon that calls them is safe Rust.

pub mod harden;
#[cfg(unix)]
pub mod interrupt;
pub mod panic_hook;
pub mod platform;
