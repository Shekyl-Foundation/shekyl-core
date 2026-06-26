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

use crate::tiers::LockTier;

/// Metadata attached to a staked output (serialized as tag `0x04` on the wire).
///
/// `lock_until` is **not** stored on-chain; the effective lock expiry is computed
/// dynamically as `creation_height + tier_lock_blocks` wherever needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct StakingMeta {
    /// The lock-duration tier of this staked output (`Short`/`Medium`/`Long`).
    ///
    /// A typed [`LockTier`] rather than a bare `u8`: the wire edge validates the tier
    /// byte on deserialization, and the tier→parameters lookup ([`LockTier::params`])
    /// becomes infallible.
    pub lock_tier: LockTier,
}
