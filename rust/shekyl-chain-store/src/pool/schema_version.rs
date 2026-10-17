// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file's own layout version (`DRS_E1_SPOOL.md` `SPL-Q8`).
//!
//! The pool file is a second file with a layout of its own, and it is
//! discardable: a mismatch **recreates** it (`super::header`), where the
//! chain file's [`SCHEMA_VERSION`](crate::codec::SCHEMA_VERSION) refuses and
//! asks for a rebuild. So the two numbers are separate. A pool-only change
//! bumps this one and recreates only the pool file; the chain file, and
//! every node's synced chain, is untouched.
//!
//! This is the constant the schema-snapshot workflow pairs every
//! `rust/shekyl-chain-store/pool_schemas/*.snap` against. A `.snap` there
//! that moves without the declaration line below moving in the same PR
//! fails CI.

use shekyl_store_codec::{Canonical, CodecError};

/// The pool file layout this binary reads and writes.
///
/// **Bump when any byte the pool file stores changes**: the record's
/// codec, or a pool table added, removed or re-typed. History:
///
/// - `1` — the pool file leaves the chain store's number (`SPL-Q8` as
///   ruled; the 2026-09-24 as-built deviation that shared it, closed
///   2026-10-17). The layout is the one chain layout `27` sealed it at:
///   `pool_meta` (`txid → pool_record`: the receive hour, the public bit
///   and a standing), `pool_blob`, `pool_header`. A file sealed at any
///   other number, the chain's included, is recreated at open.
pub const POOL_SCHEMA_VERSION: PoolSchemaVersion = PoolSchemaVersion::new(1);

/// A pool file layout version, as stored in the header's
/// [`POOL_VERSION_KEY`](super::POOL_VERSION_KEY) cell.
///
/// Its own type, not the chain's
/// [`SchemaVersion`](crate::codec::SchemaVersion): the two files' numbers
/// answer a mismatch differently (recreate, refuse), and a type keeps
/// either from being checked against the other's constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolSchemaVersion(u64);

impl PoolSchemaVersion {
    /// Wrap a raw version number.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// The raw number, for diagnostics.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for PoolSchemaVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "pool schema v{}", self.0)
    }
}

impl Canonical for PoolSchemaVersion {
    const NAME: &'static str = "pool_schema_version";
    const FIXED_WIDTH: Option<usize> = <u64 as Canonical>::FIXED_WIDTH;

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_pool_version_is_pinned_and_encodes_as_u64_le() {
        // Moves with every pool layout bump, on purpose: the history list
        // above the constant is the record, and this line is what makes a
        // bump without a history entry visible in review.
        assert_eq!(POOL_SCHEMA_VERSION, PoolSchemaVersion::new(1));
        assert_eq!(POOL_SCHEMA_VERSION.encode(), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            PoolSchemaVersion::decode(&[1, 0, 0, 0, 0, 0, 0, 0]),
            Ok(POOL_SCHEMA_VERSION)
        );
    }
}
