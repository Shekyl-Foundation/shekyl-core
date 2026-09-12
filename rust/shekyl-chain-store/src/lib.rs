// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon chain store (`shekyl-chain-store`, DRS-R-19).
//!
//! This crate is the named home for the daemon's consensus store. DRS-E1
//! will grow the redb engine here. **DRS-P0d** lands first: the
//! layout-independent logical-state digest v0 that DRS-0 / DRS-C use as
//! a regression oracle against production LMDB
//! ([`docs/design/DAEMON_REDB_STORE.md`](../../docs/design/DAEMON_REDB_STORE.md)
//! §7.1, DRS-D11, Tier-A **A2**).
//!
//! The digest is transform-shaped (rule 18): it is defined by the
//! function over the three v0 families, not by a stored value. Callers
//! recompute it from LMDB reads.

#![deny(unsafe_code)]

pub mod digest_v0;
pub mod lmdb_order;
pub mod schema;
