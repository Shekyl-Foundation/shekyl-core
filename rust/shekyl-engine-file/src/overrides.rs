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
//!    ([`shekyl_engine_state::WalletSafetyConstants`]) supply the
//!    defaults, the same on every network.
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
//!
//! ```compile_fail
//! // The reorg-depth override is a checked span: a bare count, which
//! // could be below the lock window, does not type-check.
//! let _ = shekyl_engine_file::SafetyOverrides {
//!     max_reorg_depth: Some(shekyl_types::BlockCount::from_raw(2)),
//!     skip_to_height: None,
//!     refresh_from_block_height: None,
//! };
//! ```

use shekyl_address::Network;
use shekyl_engine_state::{ReorgDepthOverride, WalletSafetyConstants};
use shekyl_types::{BlockCount, BlockHeight};

/// Runtime-only safety overrides supplied at wallet open.
///
/// Every field is `Option<T>`: `None` means "honor the default";
/// `Some(v)` means "use `v` for this session only, and log a `WARN`
/// line at open time naming the field, the value, and the default."
///
/// The struct is `Copy` so it can be stored on a [`WalletFile`]
/// without giving up the ability to call handle methods mutably.
///
/// [`WalletFile`]: crate::WalletFile
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SafetyOverrides {
    /// Override for [`WalletSafetyConstants::max_reorg_depth`]. CLI
    /// flag: `--max-reorg-depth N`. It can only raise the depth: a value
    /// below the lock window does not construct.
    pub max_reorg_depth: Option<ReorgDepthOverride>,

    /// Override for
    /// [`WalletSafetyConstants::default_skip_to_height`]. CLI flag:
    /// `--skip-to-height N`.
    pub skip_to_height: Option<u64>,

    /// Override for
    /// [`WalletSafetyConstants::default_refresh_from_block_height`].
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

    /// Resolve the effective `max_reorg_depth` against the default.
    pub fn effective_max_reorg_depth(&self) -> BlockCount {
        self.max_reorg_depth.map_or(
            WalletSafetyConstants::DEFAULTS.max_reorg_depth,
            ReorgDepthOverride::depth,
        )
    }

    /// Resolve the effective `skip_to_height` against the default.
    pub fn effective_skip_to_height(&self) -> BlockHeight {
        self.skip_to_height.map_or(
            WalletSafetyConstants::DEFAULTS.default_skip_to_height,
            BlockHeight::from_raw,
        )
    }

    /// Resolve the effective `refresh_from_block_height` against the
    /// default.
    pub fn effective_refresh_from_block_height(&self) -> BlockHeight {
        self.refresh_from_block_height.map_or(
            WalletSafetyConstants::DEFAULTS.default_refresh_from_block_height,
            BlockHeight::from_raw,
        )
    }

    /// Emit a `tracing::warn!` line per active override (the network
    /// names the session in the log), plus one header line announcing that advanced
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
            target: "shekyl_engine_file",
            %network,
            "advanced safety override(s) active for this session; values are ephemeral and not persisted"
        );
        let defaults = WalletSafetyConstants::DEFAULTS;
        if let Some(depth) = self.max_reorg_depth {
            tracing::warn!(
                target: "shekyl_engine_file",
                field = "max_reorg_depth",
                override_value = depth.depth().to_raw(),
                default = defaults.max_reorg_depth.to_raw(),
                "safety override"
            );
        }
        if let Some(v) = self.skip_to_height {
            tracing::warn!(
                target: "shekyl_engine_file",
                field = "skip_to_height",
                override_value = v,
                default = defaults.default_skip_to_height.to_raw(),
                "safety override"
            );
        }
        if let Some(v) = self.refresh_from_block_height {
            tracing::warn!(
                target: "shekyl_engine_file",
                field = "refresh_from_block_height",
                override_value = v,
                default = defaults.default_refresh_from_block_height.to_raw(),
                "safety override"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deeper() -> ReorgDepthOverride {
        ReorgDepthOverride::new(BlockCount::from_raw(42)).expect("above the lock window")
    }

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
        o.max_reorg_depth = Some(deeper());
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
    fn effective_none_returns_the_default() {
        let o = SafetyOverrides::none();
        let k = WalletSafetyConstants::DEFAULTS;
        assert_eq!(o.effective_max_reorg_depth(), k.max_reorg_depth);
        assert_eq!(o.effective_skip_to_height(), k.default_skip_to_height);
        assert_eq!(
            o.effective_refresh_from_block_height(),
            k.default_refresh_from_block_height,
        );
    }

    #[test]
    fn effective_some_returns_override() {
        let o = SafetyOverrides {
            max_reorg_depth: Some(deeper()),
            skip_to_height: Some(1_000_000),
            refresh_from_block_height: Some(999),
        };
        assert_eq!(o.effective_max_reorg_depth(), BlockCount::from_raw(42));
        assert_eq!(
            o.effective_skip_to_height(),
            BlockHeight::from_raw(1_000_000)
        );
        assert_eq!(
            o.effective_refresh_from_block_height(),
            BlockHeight::from_raw(999)
        );
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
        // the early-return path does not panic.
        SafetyOverrides::none().log_warn_if_active(Network::Mainnet);
    }

    #[test]
    fn log_warn_if_active_emits_for_each_override() {
        // Emits tracing events; with no subscriber bound they are
        // dropped. The structural guarantee is that an active override
        // of every field logs without panicking.
        let o = SafetyOverrides {
            max_reorg_depth: Some(deeper()),
            skip_to_height: Some(u64::MAX),
            refresh_from_block_height: Some(1),
        };
        o.log_warn_if_active(Network::Mainnet);
    }
}
