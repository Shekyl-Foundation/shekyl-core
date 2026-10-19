// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One drawable `(P, s)` pair.
//!
//! The public urn that scheduled these pairs (`challenge_assignment`) is
//! deleted. The secret draw replaces it (`ARCHIVAL_SERVE_CREDIT_SPEC.md`).
//! The pair type stays: [`crate::DrawableEpoch`] holds `D` as these, and
//! the drawable-epoch builder in `shekyl-chain-rules` emits them.

use shekyl_types::{PCanonicalId, ShardId};

/// One drawable `(P, s)` pair — the unit of a draw.
///
/// Order is persona canonical-id bytes, then shard id numerically (spec
/// §4.1). That is the derived `Ord` over the two typed fields — the id's
/// byte order and the shard's numeric order — and not the little-endian
/// wire encoding of the shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrawablePair {
    /// The persona (the major key).
    pub persona: PCanonicalId,
    /// The shard (the minor key).
    pub shard: ShardId,
}
