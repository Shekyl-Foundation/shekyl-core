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
//! - **DRS-0 slice A** — [`accumulator`]: the incremental replacements
//!   for that full-domain scan, the five-token class vocabulary, and
//!   the per-table write contracts the Rust port must honour.
//!
//! Later slices (schema map, codecs) add modules next to these. They
//! must bijection-pin table names against
//! [`accumulator::TABLE_CLASSES`].

#![deny(unsafe_code)]

pub mod accumulator;
pub mod digest_v0;
