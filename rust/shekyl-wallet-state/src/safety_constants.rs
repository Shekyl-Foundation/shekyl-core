// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Network-scoped wallet safety constants.
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
//! - A small subset of these values (the ones in [`NetworkSafetyConstants`]
//!   that correspond to §3.3 of the audit doc) serve as the default the
//!   `SafetyOverrides` struct overlays on at wallet open. An override is
//!   ephemeral; it lives only for the current process.
//! - Fields that do not appear here are, by construction, not
//!   consensus-relevant. Cosmetic and operational preferences live in
//!   the plaintext-with-HMAC TOML layer owned by the `shekyl-wallet-prefs`
//!   crate (added in commit 2k.3).
//!
//! Rule cross-references: `60-no-monero-legacy.mdc` — segregation forks
//! and pre-fork output sets are Monero-lineage concepts that do not apply
//! to a V3 fresh-start wallet and are deliberately absent from this
//! struct. `70-modular-consensus.mdc` — this module lives in
//! `shekyl-wallet-state` rather than `shekyl-consensus` because
//! `shekyl-consensus` is scoped to PoW proof validation; per-network
//! wallet safety policy is wallet-state concern.

use shekyl_address::Network;

/// Per-network wallet safety defaults.
///
/// Every field is consensus-adjacent: tampering with any of these values
/// changes how the wallet interprets chain state or which outputs it is
/// willing to spend from. That is exactly why they are baked into the
/// binary and not persisted anywhere a non-root attacker could reach.
///
/// The struct is `Copy` to make dispatch at call sites cheap; callers
/// typically do:
///
/// ```rust,ignore
/// let base = NetworkSafetyConstants::for_network(network);
/// let effective_reorg_depth = overrides
///     .max_reorg_depth
///     .unwrap_or(base.max_reorg_depth);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkSafetyConstants {
    /// Minimum number of confirmations before the wallet treats a
    /// transfer as final. Lower values accept a reorg that should be
    /// rejected; higher values merely delay UX. See
    /// `docs/WALLET_PREFS.md` §3.3 — this field accepts a CLI-ephemeral
    /// override (`--max-reorg-depth N`) but is never persisted.
    pub max_reorg_depth: u64,

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
    pub default_skip_to_height: u64,

    /// Default refresh cursor when reopening a wallet whose
    /// `SyncStateBlock` is absent (the lost-`.wallet` recovery path).
    /// Same structure as `default_skip_to_height`; the CLI override is
    /// `SafetyOverrides::refresh_from_block_height` (§3.3).
    pub default_refresh_from_block_height: u64,
}

impl NetworkSafetyConstants {
    /// Mainnet defaults.
    pub const fn mainnet() -> Self {
        Self {
            max_reorg_depth: 10,
            key_reuse_mitigation2: true,
            default_skip_to_height: 0,
            default_refresh_from_block_height: 0,
        }
    }

    /// Testnet defaults. A shallower reorg depth speeds up test
    /// workflows; finality there is an iteration concern, not a fund
    /// concern.
    pub const fn testnet() -> Self {
        Self {
            max_reorg_depth: 6,
            key_reuse_mitigation2: true,
            default_skip_to_height: 0,
            default_refresh_from_block_height: 0,
        }
    }

    /// Stagenet defaults. Stagenet mirrors mainnet parameters because
    /// its purpose is to exercise the mainnet parameter set against
    /// non-production value.
    pub const fn stagenet() -> Self {
        Self {
            max_reorg_depth: 10,
            key_reuse_mitigation2: true,
            default_skip_to_height: 0,
            default_refresh_from_block_height: 0,
        }
    }

    /// Dispatch the per-network defaults from a typed `Network`.
    ///
    /// This is the single entry point callers should use; adding a new
    /// network variant forces this `match` to be extended, which is
    /// the compile-time guarantee that no network silently runs with
    /// default-of-defaults.
    pub const fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Stagenet => Self::stagenet(),
        }
    }
}

// Compile-time invariants. These catch accidental regressions in the
// per-network constructors without needing the test harness to run.

const _: () = assert!(
    NetworkSafetyConstants::mainnet().key_reuse_mitigation2,
    "key_reuse_mitigation2 must be true on mainnet",
);
const _: () = assert!(
    NetworkSafetyConstants::testnet().key_reuse_mitigation2,
    "key_reuse_mitigation2 must be true on testnet",
);
const _: () = assert!(
    NetworkSafetyConstants::stagenet().key_reuse_mitigation2,
    "key_reuse_mitigation2 must be true on stagenet",
);
const _: () = assert!(
    NetworkSafetyConstants::mainnet().max_reorg_depth >= 1,
    "max_reorg_depth must be at least 1 on mainnet",
);
const _: () = assert!(
    NetworkSafetyConstants::testnet().max_reorg_depth >= 1,
    "max_reorg_depth must be at least 1 on testnet",
);
const _: () = assert!(
    NetworkSafetyConstants::stagenet().max_reorg_depth >= 1,
    "max_reorg_depth must be at least 1 on stagenet",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_network_dispatches_each_variant() {
        assert_eq!(
            NetworkSafetyConstants::for_network(Network::Mainnet),
            NetworkSafetyConstants::mainnet(),
        );
        assert_eq!(
            NetworkSafetyConstants::for_network(Network::Testnet),
            NetworkSafetyConstants::testnet(),
        );
        assert_eq!(
            NetworkSafetyConstants::for_network(Network::Stagenet),
            NetworkSafetyConstants::stagenet(),
        );
    }

    #[test]
    fn mainnet_and_stagenet_share_reorg_depth() {
        assert_eq!(
            NetworkSafetyConstants::mainnet().max_reorg_depth,
            NetworkSafetyConstants::stagenet().max_reorg_depth,
            "stagenet exists to exercise mainnet parameters",
        );
    }

    #[test]
    fn testnet_reorg_depth_is_not_mainnet() {
        assert_ne!(
            NetworkSafetyConstants::mainnet().max_reorg_depth,
            NetworkSafetyConstants::testnet().max_reorg_depth,
            "testnet should be tuned for fast iteration",
        );
    }

    #[test]
    fn import_hint_defaults_are_zero_on_every_network() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let k = NetworkSafetyConstants::for_network(net);
            assert_eq!(k.default_skip_to_height, 0);
            assert_eq!(k.default_refresh_from_block_height, 0);
        }
    }

    #[test]
    fn struct_is_copy_and_hashable() {
        // Regression guard: callers rely on Copy for cheap dispatch
        // and on Eq/Hash for use in test assertions and caches.
        fn assert_bounds<T: Copy + Eq + std::hash::Hash + std::fmt::Debug>() {}
        assert_bounds::<NetworkSafetyConstants>();
    }
}
