// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One drawable `(P, s)` pair.
//!
//! The public urn that scheduled these pairs (`challenge_assignment`) is
//! deleted. The secret draw replaces it (`ARCHIVAL_SERVE_CREDIT_SPEC.md`).
//! The pair type stays: [`crate`] consumers and `DrawableSet` sort by it.

/// One drawable `(P, s)` pair — the unit of a draw.
///
/// Order is persona canonical-id bytes, then `shard_id` numeric. That is
/// the derived `Ord`, not the little-endian wire encoding of `shard_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrawablePair {
    /// Persona canonical id (32 bytes; the major key).
    pub p_id: [u8; 32],
    /// Shard id (the minor key).
    pub shard_id: u64,
}
