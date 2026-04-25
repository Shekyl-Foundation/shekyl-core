// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CLI-ephemeral safety overrides applied at wallet open.
//!
//! Implements the "CLI-ephemeral overrides" layer of the three-layer
//! preference model pinned in
//! [`docs/WALLET_PREFS.md`](../../../../docs/WALLET_PREFS.md) §2.3 and
//! §3.3. These values are request-scoped: they are not persisted
//! anywhere and die with the `WalletFile` that carries them.
//!
//! Layering policy:
//!
//! 1. Hardcoded constants
//!    ([`shekyl_wallet_state::NetworkSafetyConstants`]) supply the
//!    per-network defaults.
//! 2. `SafetyOverrides` (this struct) optionally overrides one or more
//!    of those fields for the current process. Only fields §3.3 of the
//!    audit doc lists as override-admissible are represented here;
//!    adding a new field requires amending the audit doc first.
//! 3. Call sites resolve the effective value at point of use via
//!    [`crate::WalletFile::effective_max_reorg_depth`] and
//!    friends, so there is no way to accidentally read the raw default
//!    and miss an override.
//!
//! The struct is intentionally **not** `Serialize`/`Deserialize`.
//! Overrides must not round-trip through any file, TOML body, or
//! wire-level message. A misguided future attempt to derive
//! `Serialize` will break this contract and should be loudly refused
//! in code review.

use shekyl_address::Network;
use shekyl_wallet_state::NetworkSafetyConstants;

/// Runtime-only safety overrides supplied at wallet open.
///
/// Every field is `Option<T>`: `None` means "honor the network default";
/// `Some(v)` means "use `v` for this session only, and log a `WARN`
/// line at open time naming the field, the value, and the default."
///
/// The struct is `Copy` so it can be stored on a [`WalletFile`]
/// without giving up the ability to call handle methods mutably.
///
/// [`WalletFile`]: crate::WalletFile
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SafetyOverrides {
    /// Override for [`NetworkSafetyConstants::max_reorg_depth`]. CLI
    /// flag: `--max-reorg-depth N`.
    pub max_reorg_depth: Option<u64>,

    /// Override for
    /// [`NetworkSafetyConstants::default_skip_to_height`]. CLI flag:
    /// `--skip-to-height N`.
    pub skip_to_height: Option<u64>,

    /// Override for
    /// [`NetworkSafetyConstants::default_refresh_from_block_height`].
    /// CLI flag: `--refresh-from-block-height N`.
    pub refresh_from_block_height: Option<u64>,
}

impl SafetyOverrides {
    /// Construct an empty override set. Every field is `None`. The GUI
    /// binary always passes this; the CLI binary passes this when no
    /// advanced flags were supplied.
    pub const fn none() -> Self {
        Self {
            max_reorg_depth: None,
            skip_to_height: None,
            refresh_from_block_height: None,
        }
    }

    /// True iff at least one field is overridden. Cheap predicate used
    /// by the open-time WARN logger to decide whether to emit a header
    /// line.
    pub const fn is_any_active(&self) -> bool {
        self.max_reorg_depth.is_some()
            || self.skip_to_height.is_some()
            || self.refresh_from_block_height.is_some()
    }

    /// Resolve the effective `max_reorg_depth` against the given
    /// network's hardcoded default.
    pub fn effective_max_reorg_depth(&self, network: Network) -> u64 {
        self.max_reorg_depth
            .unwrap_or_else(|| NetworkSafetyConstants::for_network(network).max_reorg_depth)
    }

    /// Resolve the effective `skip_to_height` against the given
    /// network's hardcoded default.
    pub fn effective_skip_to_height(&self, network: Network) -> u64 {
        self.skip_to_height
            .unwrap_or_else(|| NetworkSafetyConstants::for_network(network).default_skip_to_height)
    }

    /// Resolve the effective `refresh_from_block_height` against the
    /// given network's hardcoded default.
    pub fn effective_refresh_from_block_height(&self, network: Network) -> u64 {
        self.refresh_from_block_height.unwrap_or_else(|| {
            NetworkSafetyConstants::for_network(network).default_refresh_from_block_height
        })
    }

    /// Emit a `tracing::warn!` line per active override at the given
    /// network, plus one header line announcing that advanced
    /// overrides are in effect. No-op if [`Self::is_any_active`] is
    /// `false`, so the GUI path stays silent.
    ///
    /// Factored out of the open path so callers driving tests can
    /// exercise it without going through the full envelope dance.
    pub fn log_warn_if_active(&self, network: Network) {
        if !self.is_any_active() {
            return;
        }
        tracing::warn!(
            target: "shekyl_wallet_file",
            %network,
            "advanced safety override(s) active for this session; values are ephemeral and not persisted"
        );
        let defaults = NetworkSafetyConstants::for_network(network);
        if let Some(v) = self.max_reorg_depth {
            tracing::warn!(
                target: "shekyl_wallet_file",
                field = "max_reorg_depth",
                override_value = v,
                network_default = defaults.max_reorg_depth,
                "safety override"
            );
        }
        if let Some(v) = self.skip_to_height {
            tracing::warn!(
                target: "shekyl_wallet_file",
                field = "skip_to_height",
                override_value = v,
                network_default = defaults.default_skip_to_height,
                "safety override"
            );
        }
        if let Some(v) = self.refresh_from_block_height {
            tracing::warn!(
                target: "shekyl_wallet_file",
                field = "refresh_from_block_height",
                override_value = v,
                network_default = defaults.default_refresh_from_block_height,
                "safety override"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_none_are_empty() {
        let a = SafetyOverrides::default();
        let b = SafetyOverrides::none();
        assert_eq!(a, b);
        assert!(!a.is_any_active());
    }

    #[test]
    fn any_active_true_when_any_field_set() {
        let mut o = SafetyOverrides::none();
        assert!(!o.is_any_active());
        o.max_reorg_depth = Some(0);
        assert!(o.is_any_active());
        let o2 = SafetyOverrides {
            skip_to_height: Some(100),
            ..SafetyOverrides::none()
        };
        assert!(o2.is_any_active());
        let o3 = SafetyOverrides {
            refresh_from_block_height: Some(42),
            ..SafetyOverrides::none()
        };
        assert!(o3.is_any_active());
    }

    #[test]
    fn effective_none_returns_network_default() {
        let o = SafetyOverrides::none();
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let k = NetworkSafetyConstants::for_network(net);
            assert_eq!(o.effective_max_reorg_depth(net), k.max_reorg_depth);
            assert_eq!(o.effective_skip_to_height(net), k.default_skip_to_height);
            assert_eq!(
                o.effective_refresh_from_block_height(net),
                k.default_refresh_from_block_height,
            );
        }
    }

    #[test]
    fn effective_some_returns_override() {
        let o = SafetyOverrides {
            max_reorg_depth: Some(42),
            skip_to_height: Some(1_000_000),
            refresh_from_block_height: Some(999),
        };
        // Value returned is independent of network when override is
        // active — the caller has explicitly chosen to bypass the
        // per-network default.
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            assert_eq!(o.effective_max_reorg_depth(net), 42);
            assert_eq!(o.effective_skip_to_height(net), 1_000_000);
            assert_eq!(o.effective_refresh_from_block_height(net), 999);
        }
    }

    #[test]
    fn struct_is_copy_and_default() {
        fn assert_bounds<T: Copy + Default + Eq + std::hash::Hash + std::fmt::Debug>() {}
        assert_bounds::<SafetyOverrides>();
    }

    #[test]
    fn log_warn_if_active_is_noop_when_empty() {
        // Compiles and runs; with no subscriber the macros are
        // effectively no-ops. This test is structural — it asserts
        // the early-return path does not panic and does not try to
        // read defaults it shouldn't need.
        SafetyOverrides::none().log_warn_if_active(Network::Mainnet);
    }

    #[test]
    fn log_warn_if_active_emits_for_each_override() {
        // Emits tracing events; with no subscriber bound they are
        // dropped. The structural guarantee we care about is that
        // calling this method with an active override does not
        // panic and consults the correct default table (exercising
        // the NetworkSafetyConstants::for_network branch on each
        // network).
        let o = SafetyOverrides {
            max_reorg_depth: Some(0),
            skip_to_height: Some(u64::MAX),
            refresh_from_block_height: Some(1),
        };
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            o.log_warn_if_active(net);
        }
    }
}
