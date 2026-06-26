// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output staking metadata.
//!
//! Brought native off the vendored `shekyl-oxide` in the un-vendor slice-2 dissolve.
//! Lives with its semantic owner (the staking crate, alongside [`crate::tiers`])
//! rather than in the scanner that consumes it.

use zeroize::Zeroize;

/// Metadata attached to a staked output (serialized as tag `0x04` on the wire).
///
/// `lock_until` is **not** stored on-chain; the effective lock expiry is computed
/// dynamically as `creation_height + tier_lock_blocks` wherever needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct StakingMeta {
    /// Tier index: `0` = short, `1` = medium, `2` = long.
    ///
    /// A typed `LockTier` enum (replacing this magic `u8`, related to
    /// [`crate::tiers::StakeTier`]) is a tracked follow-up — deferred from the
    /// un-vendor dissolve to keep that PR's diff to the genesis-relevant changes.
    pub lock_tier: u8,
}
