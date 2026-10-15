// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's configuration (`docs/design/DAEMON_CONFIG_CUTOVER.md` §2.1).
//!
//! This crate builds `shekyld`'s option table from `shekyl-options`
//! ([`TABLE`]) and owns what the shared crate does not: precedence between
//! the command line and the per-network file, the file's location and its
//! permission checks, the resolved paths, the data-directory lock and the
//! network marker, the effective-configuration line, and the typed sections
//! each Rust owner takes at construction.

#![deny(unsafe_code)]

pub mod table;

pub use table::{LEVELS, NETWORKS, TABLE};
