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

pub mod account;
#[cfg(unix)]
mod acl;
pub mod announce;
#[cfg(unix)]
mod directory;
pub mod docs;
pub mod exit;
pub mod file;
#[cfg(unix)]
mod group;
pub mod load;
pub mod lock;
pub mod marker;
pub mod network;
pub mod owner_socket;
pub mod paths;
pub mod platform;
mod probe;
pub mod replace;
pub mod resolve;
pub mod sections;
pub mod table;

pub use load::{
    after_file, load, load_default_file_unread, load_table, AfterFile, ConfigFileFate, Loaded,
    TableLoaded,
};
pub use lock::Lock;
pub use marker::{MarkerOutcome, MarkerRead, NetworkId};
pub use network::Network;
pub use owner_socket::OwnerSocketPlan;
pub use platform::{Platform, RunMode};
pub use resolve::Resolved;
pub use sections::{
    apply_logging, link_limits, log_location_creatable, log_location_writable, logging,
    logging_to_named_file, Clearnet, DaemonConfig, Logging, Tor,
};
pub use table::{runtime_owner, RuntimeOwner, BYTES, LEVEL, LEVELS, LOG_CATEGORY, NETWORKS, TABLE};
