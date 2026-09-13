// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The LMDB key orderings, carried into redb.
//!
//! Table types in [`crate::schema`] encode **ordering**, not domain identity.
//! A block hash, a tx hash, and a key image are distinct types at the engine
//! API (`shekyl-types`); at the store they share one 32-byte layout and,
//! where LMDB used `compare_hash32`, one order. [`Hash32`] is that layout.
//! [`LmdbHashKey`] is the same bytes with that order. Convert at the API
//! edge (`from_bytes` / `to_bytes`); do not impl `redb::Key` on the domain
//! types — their `Ord` is byte-lexicographic, which is the order this
//! module exists to reject.
//!
//! INTEGERKEY tables stay `u64` here for the same reason: numeric order is
//! the store invariant. When a typed engine API wraps a column
//! (`BlockHeight`, `GlobalOutputIndex`, …), reuse `shekyl-curve-tree`'s
//! `redb_delegated_key` pattern: on-disk bytes and order stay the inner
//! `u64`; only `TypeName` differs. Do not use that pattern for
//! [`LmdbHashKey`] — its order is not the inner `[u8; 32]` order.

mod hash;
mod u64_prefix;

pub use hash::{Hash32, LmdbHashKey};
pub use u64_prefix::U64PrefixBytes;
