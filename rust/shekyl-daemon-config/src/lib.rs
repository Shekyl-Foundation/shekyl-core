// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's configuration (`docs/design/DAEMON_CONFIG_CUTOVER.md` §2.1).
//!
//! This crate builds `shekyld`'s option table from `shekyl-options`
//! ([`TABLE`]) and owns what the shared crate does not: precedence between
//! the command line and the per-network file ([`resolve`](mod@resolve)), the file's
//! location ([`paths`]) and its permission checks ([`file`](mod@file)), the
//! data-directory lock ([`lock`]) and the network marker ([`marker`]), and
//! the typed sections each Rust owner takes at construction. Platform facts
//! come in as values ([`Platform`]); nothing here reads the environment.

#![deny(unsafe_code)]

#[cfg(unix)]
mod acl;
pub mod announce;
pub mod docs;
pub mod exit;
pub mod file;
pub mod load;
pub mod lock;
pub mod marker;
pub mod network;
pub mod paths;
pub mod platform;
pub mod resolve;
pub mod sections;
pub mod table;

pub use load::{load, Loaded};
pub use lock::Lock;
pub use marker::{MarkerOutcome, NetworkId};
pub use network::Network;
pub use platform::{Platform, RunMode};
pub use resolve::{choosers, resolve, Resolved};
pub use sections::{apply_logging, build, link_limits, Clearnet, DaemonConfig, Tor};
pub use table::{runtime_owner, RuntimeOwner, LEVELS, NETWORKS, TABLE};
