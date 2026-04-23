// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TOML schema for `prefs.toml`. Mirrors the Layer-2 categorization
//! pinned in [`docs/WALLET_PREFS.md §3.2`](../../docs/WALLET_PREFS.md).
//!
//! # Structural choices
//!
//! * Every struct and enum carries `#[serde(deny_unknown_fields)]`.
//!   New fields added in later releases are forward-incompatible by
//!   construction: an older binary reading a TOML with a new field
//!   rejects the file, treating it as tamper. This is the spec's
//!   "we want strict rejection so hand-edited malice is loud" policy
//!   (§6.3).
//!
//! * Every `Default` impl returns the per-network-agnostic safe
//!   defaults. These values are the same across mainnet, testnet, and
//!   stagenet; none of the Layer-2 fields are consensus-relevant so no
//!   per-network variation is needed.
//!
//! * Buckets are modeled as distinct nested structs under a top-level
//!   [`WalletPrefs`]. Users can omit whole sections (the `Default`
//!   impl on the parent fills them in); they cannot add sections that
//!   don't exist (the `deny_unknown_fields` catch-all catches it).
//!
//! * Default priority, refresh type, and export format are modeled as
//!   `enum`s so a typo in the TOML (`"Medium"` instead of `"medium"`)
//!   produces a clear parse error rather than a silent fallback.

use serde::{Deserialize, Serialize};

/// Fee priority used when the user does not pick one explicitly.
/// Listed in ascending fee order so `Default` picking `Medium` lands
/// in the centre — both safe and representative of normal usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum FeePriority {
    /// Lowest recommended fee. Slow confirmation.
    Low,
    /// Balanced fee. The default.
    #[default]
    Medium,
    /// Higher fee for expedited confirmation.
    High,
    /// Aggressive fee for same-block-as-possible confirmation.
    Rush,
}

/// Scanner strategy for refresh operations. Matches the legacy
/// `wallet2` `refresh_type` options 1:1 so existing documentation
/// screenshots are still readable, minus the consensus-sensitive
/// options (which Shekyl hardcodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RefreshType {
    /// Scan every transaction in every block.
    Full,
    /// Skip non-candidate outputs early using view-tag hints. The
    /// spec default.
    #[default]
    Optimized,
    /// Skip coinbase transactions. Saves scan time on non-mining
    /// wallets; costs coinbase visibility for mining wallets.
    NoCoinbase,
}

/// Mode used when the user hits File → Export. Purely a format
/// selector; has no consensus meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ExportFormat {
    /// Canonical binary export format.
    #[default]
    Binary,
    /// Human-readable JSON export.
    Json,
}

/// Background-mining prompt state. Determines whether the GUI asks
/// on startup whether to start background mining, remembers an
/// earlier decision, or is disabled outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BackgroundMiningSetup {
    /// Ask the user on each startup. The default for fresh wallets.
    #[default]
    Prompt,
    /// User opted in; start background mining on open.
    Enabled,
    /// User opted out; do not ask and do not start.
    Disabled,
}

/// Cosmetic prefs (Bucket 1 in `WALLET_PREFS.md §3.2`). Tampering
/// degrades UX but cannot threaten funds; the HMAC layer covers
/// detection, and defaults cover recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CosmeticPrefs {
    /// Display decimal point for amounts. 12 matches Shekyl V3's
    /// smallest-unit-per-atomic-shekyl value.
    #[serde(default = "default_decimal_point")]
    pub default_decimal_point: u8,

    /// Whether the lock screen shows the wallet file name.
    #[serde(default)]
    pub show_wallet_name_when_locked: bool,

    /// Prompt state for background mining.
    #[serde(default)]
    pub setup_background_mining: BackgroundMiningSetup,

    /// Fee priority used when not explicitly overridden per-send.
    #[serde(default)]
    pub default_priority: FeePriority,

    /// Warn the user if the mempool backlog exceeds
    /// [`CosmeticPrefs::confirm_backlog_threshold`] outstanding txs.
    #[serde(default = "default_true")]
    pub confirm_backlog: bool,

    /// Mempool-backlog threshold past which the UI warns on send.
    /// 4096 matches the legacy wallet2 value.
    #[serde(default = "default_confirm_backlog_threshold")]
    pub confirm_backlog_threshold: u32,

    /// Ask before overwriting an export file at the same path.
    #[serde(default = "default_true")]
    pub confirm_export_overwrite: bool,

    /// Show the summary-and-confirm screen before sending. Off makes
    /// transfers one-click and is an advanced-user preference.
    #[serde(default = "default_true")]
    pub always_confirm_transfers: bool,

    /// Default export format on File → Export.
    #[serde(default)]
    pub export_format: ExportFormat,
}

impl Default for CosmeticPrefs {
    fn default() -> Self {
        Self {
            default_decimal_point: default_decimal_point(),
            show_wallet_name_when_locked: false,
            setup_background_mining: BackgroundMiningSetup::default(),
            default_priority: FeePriority::default(),
            confirm_backlog: true,
            confirm_backlog_threshold: default_confirm_backlog_threshold(),
            confirm_export_overwrite: true,
            always_confirm_transfers: true,
            export_format: ExportFormat::default(),
        }
    }
}

fn default_decimal_point() -> u8 {
    12
}

fn default_confirm_backlog_threshold() -> u32 {
    4096
}

fn default_true() -> bool {
    true
}

/// Operational prefs (Bucket 2). Coin-selection floors, refresh
/// strategy, local audit toggles. Privacy-sensitive but never
/// consensus-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalPrefs {
    /// Scanner strategy.
    #[serde(default)]
    pub refresh_type: RefreshType,

    /// Start a refresh automatically on wallet open.
    #[serde(default = "default_true")]
    pub auto_refresh: bool,

    /// Automatically fall back to a lower fee priority when the
    /// mempool suggests the current one is wasteful.
    #[serde(default)]
    pub auto_low_priority: bool,

    /// Track how often each subaddress is used. Local forensic
    /// metadata; never emitted on chain.
    #[serde(default)]
    pub track_uses: bool,

    /// Persist extra tx metadata locally (notes, tags). Local audit
    /// trail; never emitted on chain.
    #[serde(default = "default_true")]
    pub store_tx_info: bool,

    /// Coin-selection minimum output count per input bucket.
    #[serde(default)]
    pub min_output_count: u64,

    /// Coin-selection minimum output value in atomic units.
    #[serde(default)]
    pub min_output_value: u64,

    /// Coin-selection upper cap: ignore outputs above this value.
    /// `None` (the default, or `ignore_outputs_above = 0` as a
    /// convenience spelling) disables the cap.
    ///
    /// Modeled as `Option<u64>` rather than a sentinel `u64::MAX`
    /// because TOML's integer type is `i64`; writing out a literal
    /// `u64::MAX` fails to serialize. An explicit `None` is both
    /// simpler to express in the schema and clearer to read on disk.
    #[serde(default)]
    pub ignore_outputs_above: Option<u64>,

    /// Coin-selection lower cap: ignore outputs below this value.
    #[serde(default)]
    pub ignore_outputs_below: u64,

    /// Combine multiple outputs to the same destination. Off by
    /// default because it is a privacy regression.
    #[serde(default)]
    pub merge_destinations: bool,

    /// Inactivity lock timeout in minutes. Zero disables. Enforced at
    /// the GUI/CLI layer; the wallet engine itself does not
    /// auto-lock.
    #[serde(default)]
    pub inactivity_lock_timeout: u32,
}

impl Default for OperationalPrefs {
    fn default() -> Self {
        Self {
            refresh_type: RefreshType::default(),
            auto_refresh: true,
            auto_low_priority: false,
            track_uses: false,
            store_tx_info: true,
            min_output_count: 0,
            min_output_value: 0,
            ignore_outputs_above: None,
            ignore_outputs_below: 0,
            merge_destinations: false,
            inactivity_lock_timeout: 0,
        }
    }
}

/// Device prefs (Bucket 4). HW-wallet routing hints; tampering
/// redirects to the wrong device and fails at signing time —
/// annoying but not funds-threatening.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePrefs {
    /// HW-wallet name hint.
    #[serde(default)]
    pub device_name: String,
    /// HW-wallet derivation path hint (e.g. `"m/44'/1001'/0'"`).
    #[serde(default)]
    pub device_derivation_path: String,
}

/// RPC prefs (Bucket 5). Client-ID and credit-target settings for
/// the pay-per-call daemon RPC.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcPrefs {
    /// Stable client identifier for RPC payments. Empty string means
    /// "generate a fresh one on first use".
    #[serde(default)]
    pub persistent_rpc_client_id: String,

    /// Auto-mine-for-credits threshold in atomic shekyl units. Zero
    /// disables. Non-zero enables bounded auto-mining up to the
    /// threshold.
    #[serde(default)]
    pub auto_mine_for_rpc_payment_threshold: u64,

    /// Target RPC credit balance.
    #[serde(default)]
    pub credits_target: u64,
}

/// Subaddress-lookahead prefs (Bucket 6). Visibility trade-off: too
/// small misses incoming transfers on heavy subaddress generators,
/// too large is a CPU tax. HW-wallet workflows often need to bump
/// these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubaddressLookahead {
    /// Account-index lookahead distance.
    #[serde(default = "default_lookahead_major")]
    pub major: u32,
    /// Per-account subaddress-index lookahead distance.
    #[serde(default = "default_lookahead_minor")]
    pub minor: u32,
}

impl Default for SubaddressLookahead {
    fn default() -> Self {
        Self {
            major: default_lookahead_major(),
            minor: default_lookahead_minor(),
        }
    }
}

fn default_lookahead_major() -> u32 {
    5
}

fn default_lookahead_minor() -> u32 {
    200
}

/// Top-level prefs document. Serialized as a TOML file with one
/// table per bucket.
///
/// The `#[serde(default)]` on every field means a minimal TOML file
/// (`[cosmetic]` with no fields, or even an empty document) round-
/// trips into [`Self::default`] without a parse error. `default =
/// "Default::default"` is explicit on the enum-typed fields so missing
/// values fall through to the [`Default`] impl on the enum itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPrefs {
    /// Version byte for the prefs schema. Currently fixed at `1`.
    /// A future breaking schema change bumps this and adds an
    /// explicit migration (or refuses to load the old version,
    /// depending on the kind of change).
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,

    /// BIP-39 wordlist for displaying the seed back to the user.
    /// Part of the cluster identity, set once at creation; kept on
    /// the prefs file because it's display-only, not cryptographic.
    #[serde(default = "default_seed_language")]
    pub seed_language: String,

    /// Bucket 1.
    #[serde(default)]
    pub cosmetic: CosmeticPrefs,
    /// Bucket 2.
    #[serde(default)]
    pub operational: OperationalPrefs,
    /// Bucket 4.
    #[serde(default)]
    pub device: DevicePrefs,
    /// Bucket 5.
    #[serde(default)]
    pub rpc: RpcPrefs,
    /// Bucket 6.
    #[serde(default)]
    pub subaddress_lookahead: SubaddressLookahead,
}

impl Default for WalletPrefs {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            seed_language: default_seed_language(),
            cosmetic: CosmeticPrefs::default(),
            operational: OperationalPrefs::default(),
            device: DevicePrefs::default(),
            rpc: RpcPrefs::default(),
            subaddress_lookahead: SubaddressLookahead::default(),
        }
    }
}

fn default_schema_version() -> u8 {
    1
}

fn default_seed_language() -> String {
    "english".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A default-constructed `WalletPrefs` must round-trip through
    /// TOML byte-for-byte. Keeps us honest about schema completeness
    /// (every field is serde-serializable) and about ordering (TOML
    /// output ordering is stable via serde's struct-field order).
    #[test]
    fn default_prefs_round_trips_via_toml() {
        let prefs = WalletPrefs::default();
        let encoded = toml::to_string(&prefs).expect("serialize");
        let decoded: WalletPrefs = toml::from_str(&encoded).expect("parse");
        assert_eq!(prefs, decoded);
    }

    /// An empty TOML document must parse as the default. This is the
    /// "first-open bootstrap" contract from `WALLET_PREFS.md §4.2`:
    /// if a user (or test) writes an empty `prefs.toml`, every field
    /// falls back to its documented default.
    #[test]
    fn empty_toml_parses_as_default() {
        let prefs: WalletPrefs = toml::from_str("").expect("parse");
        assert_eq!(prefs, WalletPrefs::default());
    }

    /// Adding a field the schema does not recognise must fail
    /// parsing. Any forward-compat leniency here would silently
    /// swallow typos and hand-edited malice.
    #[test]
    fn unknown_top_level_field_rejected() {
        let src = r#"
            schema_version = 1
            some_unknown_field = true
        "#;
        assert!(toml::from_str::<WalletPrefs>(src).is_err());
    }

    /// A typo inside a nested table must also fail.
    #[test]
    fn unknown_nested_field_rejected() {
        let src = r#"
            [cosmetic]
            defalt_priority = "high"
        "#;
        assert!(toml::from_str::<WalletPrefs>(src).is_err());
    }

    /// The Bucket-3 names are NOT rejected at this layer — the schema
    /// simply does not declare them, so they trip the generic
    /// `deny_unknown_fields` rejection. The I/O layer intercepts them
    /// earlier and returns a per-field diagnostic; here we pin the
    /// structural fallback so the two paths can't both silently
    /// succeed.
    #[test]
    fn bucket3_names_trigger_parse_error_at_schema_layer() {
        let src = r#"
            max_reorg_depth = 3
        "#;
        assert!(toml::from_str::<WalletPrefs>(src).is_err());
    }

    /// Enum typos produce clean parse errors.
    #[test]
    fn enum_typo_rejected() {
        let src = r#"
            [cosmetic]
            default_priority = "Medium"
        "#;
        assert!(toml::from_str::<WalletPrefs>(src).is_err());
    }

    /// Values on the happy path survive unchanged.
    #[test]
    fn populated_round_trip_preserves_values() {
        let mut prefs = WalletPrefs::default();
        prefs.cosmetic.default_decimal_point = 10;
        prefs.operational.refresh_type = RefreshType::Full;
        prefs.subaddress_lookahead.major = 50;
        prefs.rpc.credits_target = 1_000_000;

        let encoded = toml::to_string(&prefs).expect("serialize");
        let decoded: WalletPrefs = toml::from_str(&encoded).expect("parse");
        assert_eq!(prefs, decoded);
    }
}
