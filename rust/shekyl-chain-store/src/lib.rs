// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon chain store (`shekyl-chain-store`, DRS-R-19).
//!
//! This crate is the named home for the daemon's consensus store. DRS-E1
//! will grow the redb engine here. Freeze layers land as sibling modules:
//!
//! - **DRS-P0d** — [`digest_v0`]: the layout-independent logical-state
//!   digest that DRS-0 / DRS-C use as a regression oracle against
//!   production LMDB
//!   ([`docs/design/DAEMON_REDB_STORE.md`](../../docs/design/DAEMON_REDB_STORE.md)
//!   §7.1, DRS-D11, Tier-A **A2**). Transform-shaped (rule 18): defined
//!   by the function over the three v0 families, not by a stored value.
//! - **DRS-0 slice B** — [`schema`] / [`lmdb_order`]: one redb
//!   `TableDefinition` per censused LMDB table, with the key types that
//!   reproduce LMDB order. Table types encode ordering; domain identity
//!   (`BlockHash` vs `TxHash` vs key image) converts at the engine API.

#![deny(unsafe_code)]

pub mod digest_v0;
pub mod lmdb_order;
pub mod schema;
