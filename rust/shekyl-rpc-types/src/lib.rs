// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's wire contract (`RPC_WIRE.md`): the single Rust
//! definition of every method's request and reply, consumed by
//! `shekyl-daemon-rpc` (the server) and every client (RK-D1).
//!
//! - [`wire`] holds every method's types under its `INPUT_GRAMMAR.md`
//!   Part C name, and [`wire::TABLE`], the one method table (RW-Q7): a
//!   method's name, request, reply and grant, from one list.
//! - [`method`] is what a method is ([`method::RpcMethod`]) and who may call
//!   it ([`method::Policy`]).
//! - [`schema`] reads the table's names and shapes; the grammar's walk gate
//!   reads its rendering, `docs/generated/rpc_wire_schema.tsv`.
//! - [`kinds`] holds the wire's value kinds, one type each (RW-Q4).
//! - [`errors`] is the error registry: a failure's class and its typed
//!   diagnostic (RW-Q3).
//! - [`version`] is `CORE_RPC_VERSION` and its history, and [`identity`]
//!   the one lenient reader of the version read (RK-D25).

#![deny(unsafe_code)]

pub mod consensus_digest;
pub mod endpoint;
pub mod errors;
pub mod hash;
pub mod hex128;
pub mod identity;
pub mod kinds;
pub mod method;
pub mod nullable;
pub mod options;
pub mod schema;
pub mod version;
pub mod wire;

pub use consensus_digest::{Network, CONSENSUS_CONSTANTS_DIGEST, CONSENSUS_CONSTANTS_DIGEST_HASH};
pub use hash::{HashHex, HashHexError};
pub use hex128::{HexU128, HexU128Error};
pub use identity::{
    daemon_rpc_version, genesis_hash_for, IdentityAxis, IdentityExpectation, IdentityMismatch,
    IdentityRefusal, VersionUnreadable,
};
pub use nullable::Nullable;
pub use version::{
    core_rpc_version_string, CORE_RPC_VERSION, CORE_RPC_VERSION_MAJOR, CORE_RPC_VERSION_MINOR,
};
