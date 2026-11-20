// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet's safety constants: one set, on every network.
//!
//! These are the consensus-adjacent defaults a wallet applies when it has
//! no user override in play. They are the "hardcoded" layer of the
//! three-layer preference model pinned in
//! [`docs/WALLET_PREFS.md`](../../../../docs/WALLET_PREFS.md) (§2.1, §3.1,
//! §3.3).
//!
//! Policy, restated briefly:
//!
//! - Hardcoded constants cannot be persisted and cannot be flipped by any
//!   GUI control. Source edits and a new release are the only ways to
//!   change them.
//! - A small subset of these values (the ones in [`WalletSafetyConstants`]
//!   that correspond to §3.3 of the audit doc) serve as the default the
//!   `SafetyOverrides` struct overlays on at wallet open. An override is
//!   ephemeral; it lives only for the current process.
//! - Fields that do not appear here are, by construction, not
//!   consensus-relevant. Cosmetic and operational preferences live in
//!   the plaintext-with-HMAC TOML layer owned by the `shekyl-engine-prefs`
//!   crate (added in commit 2k.3).
//!
//! Rule cross-references: `60-no-monero-legacy.mdc` — segregation forks
//! and pre-fork output sets are Monero-lineage concepts that do not apply
//! to a V3 fresh-start wallet and are deliberately absent from this
//! struct. `70-modular-consensus.mdc` — this module lives in
//! `shekyl-engine-state` rather than `shekyl-consensus` because
//! `shekyl-consensus` holds only the consensus lock windows; wallet safety
//! policy is a wallet-state concern.
//!
//! One set on every network (`NETWORK_IDENTITY.md` NI-R4; Rick,
//! 2026-11-03): no field differs by network, so nothing here takes one.
//! The reorg depth is the consensus lock window, referenced, not restated:
//! an output is not spendable until [`shekyl_consensus::DEFAULT_LOCK_WINDOW`]
//! blocks have passed, so a wallet treating a transfer as final sooner
//! would report finality the chain does not grant. An override may only
//! raise it ([`ReorgDepthOverride`]).

use shekyl_types::{BlockCount, BlockHeight};

/// The shallowest reorg depth a wallet uses: the consensus lock window.
pub const MIN_REORG_DEPTH: BlockCount =
    BlockCount::from_raw(shekyl_consensus::DEFAULT_LOCK_WINDOW as u64);

/// The wallet's safety defaults, the same on every network.
///
/// Every field is consensus-adjacent: tampering with any of these values
/// changes how the wallet interprets chain state or which outputs it is
/// willing to spend from. That is exactly why they are baked into the
/// binary and not persisted anywhere a non-root attacker could reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WalletSafetyConstants {
    /// Minimum number of confirmations before the wallet treats a
    /// transfer as final: [`MIN_REORG_DEPTH`]. See `docs/WALLET_PREFS.md`
    /// §3.3 — a session may raise it ([`ReorgDepthOverride`]) but it is
    /// never persisted.
    pub max_reorg_depth: BlockCount,

    /// Key-reuse mitigation v2 (defensive derivation that hardens the
    /// wallet against view-key-reuse linkability attacks). Invariant:
    /// always `true`. No CLI override exists; research use cases build
    /// a debug binary with the constant flipped at source level. See
    /// `docs/WALLET_PREFS.md` §3.1.
    pub key_reuse_mitigation2: bool,

    /// Default starting height when the wallet first scans a chain.
    /// Zero means "from wallet creation"; a non-zero value is a
    /// one-shot import hint supplied via
    /// `SafetyOverrides::skip_to_height` (§3.3). Once the scanner has
    /// produced a `SyncStateBlock` the stored `restore_from_height`
    /// takes over and this field becomes irrelevant.
    pub default_skip_to_height: BlockHeight,

    /// Default refresh cursor when reopening a wallet whose
    /// `SyncStateBlock` is absent (the lost-`.wallet` recovery path).
    /// Same structure as `default_skip_to_height`; the CLI override is
    /// `SafetyOverrides::refresh_from_block_height` (§3.3).
    pub default_refresh_from_block_height: BlockHeight,
}

impl WalletSafetyConstants {
    /// The defaults every wallet runs with unless a session override
    /// replaces one.
    pub const DEFAULTS: Self = Self {
        max_reorg_depth: MIN_REORG_DEPTH,
        key_reuse_mitigation2: true,
        default_skip_to_height: BlockHeight::ZERO,
        default_refresh_from_block_height: BlockHeight::ZERO,
    };
}

/// A session's reorg depth, raised above the default: never below
/// [`MIN_REORG_DEPTH`]. More caution is the user's to choose; less means
/// nothing the chain respects, so it is refused with its reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReorgDepthOverride(BlockCount);

impl ReorgDepthOverride {
    /// `depth`, if it is at least the lock window.
    ///
    /// # Errors
    ///
    /// [`ReorgDepthBelowLockWindow`] when `depth` is shallower than
    /// [`MIN_REORG_DEPTH`].
    pub const fn new(depth: BlockCount) -> Result<Self, ReorgDepthBelowLockWindow> {
        if depth.to_raw() < MIN_REORG_DEPTH.to_raw() {
            return Err(ReorgDepthBelowLockWindow {
                asked: depth,
                floor: MIN_REORG_DEPTH,
            });
        }
        Ok(Self(depth))
    }

    /// The depth.
    pub const fn depth(self) -> BlockCount {
        self.0
    }
}

/// A reorg-depth override below the lock window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "a reorg depth of {asked} blocks is below the chain's lock window of {floor}: an output \
     cannot be spent until {floor} blocks have passed, so a shallower depth would treat a \
     transfer as final before the chain does; use {floor} or more"
)]
pub struct ReorgDepthBelowLockWindow {
    /// The depth asked for.
    pub asked: BlockCount,
    /// The lock window it may not go below.
    pub floor: BlockCount,
}

const _: () = assert!(
    WalletSafetyConstants::DEFAULTS.key_reuse_mitigation2,
    "key_reuse_mitigation2 must be true",
);
const _: () = assert!(
    !MIN_REORG_DEPTH.is_zero(),
    "the reorg depth must be at least 1",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reorg_depth_is_the_consensus_lock_window() {
        assert_eq!(
            WalletSafetyConstants::DEFAULTS.max_reorg_depth.to_raw(),
            u64::try_from(shekyl_consensus::DEFAULT_LOCK_WINDOW).expect("fits"),
        );
    }

    #[test]
    fn an_override_may_raise_the_depth_and_not_lower_it() {
        let floor = MIN_REORG_DEPTH;
        assert_eq!(
            ReorgDepthOverride::new(floor).map(ReorgDepthOverride::depth),
            Ok(floor)
        );
        let deeper = BlockCount::from_raw(floor.to_raw() + 30);
        assert_eq!(
            ReorgDepthOverride::new(deeper).map(ReorgDepthOverride::depth),
            Ok(deeper)
        );
        for shallower in [0, floor.to_raw() - 1] {
            let asked = BlockCount::from_raw(shallower);
            let refused = ReorgDepthOverride::new(asked).expect_err("below the lock window");
            assert_eq!(refused, ReorgDepthBelowLockWindow { asked, floor });
            assert!(refused.to_string().contains("lock window"), "{refused}");
        }
    }

    #[test]
    fn import_hint_defaults_are_zero() {
        assert_eq!(
            WalletSafetyConstants::DEFAULTS.default_skip_to_height,
            BlockHeight::ZERO
        );
        assert_eq!(
            WalletSafetyConstants::DEFAULTS.default_refresh_from_block_height,
            BlockHeight::ZERO
        );
    }

    #[test]
    fn struct_is_copy_and_hashable() {
        // Regression guard: callers rely on Copy for cheap reads and on
        // Eq/Hash for use in test assertions and caches.
        fn assert_bounds<T: Copy + Eq + std::hash::Hash + std::fmt::Debug>() {}
        assert_bounds::<WalletSafetyConstants>();
        assert_bounds::<ReorgDepthOverride>();
    }
}
