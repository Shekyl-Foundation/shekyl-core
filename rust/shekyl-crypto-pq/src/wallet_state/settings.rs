// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **settings block** of [`WalletState`](super::WalletState).
//!
//! User-facing knobs: scan policy, UX preferences, spending policy,
//! scan-safety margins, the subaddress lookahead window, hardware-device
//! identity hints, optional originating-address provenance, and the
//! background-sync configuration.
//!
//! Versioning: this block owns [`SETTINGS_BLOCK_VERSION`]. Any change to
//! the field set bumps it; binaries refuse mismatched versions.
//!
//! # Shekyl-native design notes
//!
//! This block is not a port of any single predecessor — it is a designed
//! set of knobs chosen for Shekyl V3. Several Monero-era settings were
//! deliberately dropped:
//!
//! * `export_format` (binary vs ASCII for signed tx / key images) — the
//!   Shekyl V3 export format is a single canonical form; there is no
//!   runtime choice.
//! * `segregate_pre_fork_outputs` / `segregation_height` — Shekyl V3 is
//!   genesis-fresh; there is no pre-fork chain to segregate from.
//! * `key_reuse_mitigation2` — FCMP++ eliminates rings, so there is no
//!   "10-block ring-member freeze" to mitigate.
//! * `confirm_backlog_threshold` — the Shekyl V3 fee module subsumes
//!   the backlog-aware threshold; no separate knob is needed here.
//! * `track_uses` — per-output reuse tracking existed exclusively to
//!   feed Monero's ring-selection heuristic. FCMP++ has no rings;
//!   nothing in the Shekyl V3 send path consumes a per-transfer uses list.
//! * `rpc_*` — RPC-pay client-id, credits-target, and auto-mine
//!   threshold were Monero's RPC-pay economics; Shekyl V3 does not
//!   inherit that model.
//!
//! The remaining scan-safety knob (`max_reorg_depth`) moved from a
//! struct named "consensus safety" to [`ScanSafetySettings`], which is
//! what it actually is — a scan-time safety margin against reorgs, not
//! a consensus parameter.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::primitives::{decode_hex32, encode_hex32, repr_u8_enum, WalletStateError};

/// Schema version of the settings block. V3.0 ships version `1`. Bumped
/// on any field addition / removal / renaming within this block.
pub const SETTINGS_BLOCK_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Defaults pinned at the wallet-state layer so this module is
// self-contained and unit-testable without reaching into config headers.
// ---------------------------------------------------------------------------

/// Default inactivity-lock timeout in seconds.
pub const DEFAULT_INACTIVITY_LOCK_TIMEOUT: u32 = 90;

/// Default subaddress lookahead (major axis).
pub const DEFAULT_SUBADDRESS_LOOKAHEAD_MAJOR: u32 = 50;

/// Default subaddress lookahead (minor axis).
pub const DEFAULT_SUBADDRESS_LOOKAHEAD_MINOR: u32 = 200;

/// Default maximum reorg depth (in blocks).
pub const DEFAULT_MAX_REORG_DEPTH: u64 = 100;

/// Upper bound for [`SpendingPrefs::ignore_outputs_above`] when the user
/// has not set a finite cap. Equivalent to "no cap".
pub const TOTAL_MONEY_SUPPLY: u64 = u64::MAX;

/// Default decimal-point count for display (12 atomic digits per SHK).
pub const DEFAULT_DISPLAY_DECIMAL_POINT: i32 = 12;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

repr_u8_enum! {
    /// Scan strategy.
    ///
    /// `Full` scans every transaction in every block. `OptimizeCoinbase`
    /// (the default) skips coinbase / miner transactions for wallets
    /// that know they will not match — a meaningful speedup given
    /// coinbase-tx prevalence. `NoCoinbase` hard-skips coinbase regardless.
    ///
    /// The wire format is an honest statement of which of the three
    /// behaviors the user selected — there is no sentinel "default"
    /// variant; the default is `OptimizeCoinbase` directly.
    pub enum ScanMode ("scan_mode") {
        Full             = 0,
        OptimizeCoinbase = 1,
        NoCoinbase       = 2,
    }
}

repr_u8_enum! {
    /// Prompt-state for the optional background-mining UX.
    ///
    /// `NotYetAsked` is the fresh-wallet default: the UI will ask the
    /// user once. `Enabled` / `Declined` record the user's answer so
    /// the UI does not ask again.
    pub enum BackgroundMiningSetup ("background_mining") {
        NotYetAsked = 0,
        Enabled     = 1,
        Declined    = 2,
    }
}

repr_u8_enum! {
    /// Background-sync wallet mode.
    ///
    /// `Off` is the default. `ReusePassword` derives the background-sync
    /// cache key from the wallet password. `CustomPassword` uses a
    /// caller-supplied 32-byte key (serialized as `custom_background_key`).
    pub enum BackgroundSyncType ("background_sync_type") {
        Off            = 0,
        ReusePassword  = 1,
        CustomPassword = 2,
    }
}

// ---------------------------------------------------------------------------
// Sub-structs
// ---------------------------------------------------------------------------

/// Scan / refresh settings.
///
/// * `auto_refresh` — periodically poll the daemon while the wallet is open.
/// * `scan_mode` — coinbase-inclusion policy (see [`ScanMode`]).
/// * `scan_from_height` — live, user-adjustable restore height. This is
///   the authoritative value for a loaded wallet; the immutable
///   `restore_height_hint` in region 1 of the keys file is only used on
///   wallet creation and on lost-state recovery.
/// * `resume_from_height` — user-requested "skip ahead to this height on
///   the next refresh" checkpoint. `0` disables.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSettings {
    #[serde(default = "default_auto_refresh")]
    pub auto_refresh: bool,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: ScanMode,
    #[serde(default)]
    pub scan_from_height: u64,
    #[serde(default)]
    pub resume_from_height: u64,
}

fn default_auto_refresh() -> bool {
    true
}
fn default_scan_mode() -> ScanMode {
    ScanMode::OptimizeCoinbase
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            auto_refresh: default_auto_refresh(),
            scan_mode: default_scan_mode(),
            scan_from_height: 0,
            resume_from_height: 0,
        }
    }
}

/// UX / display preferences.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxPrefs {
    #[serde(default = "default_true")]
    pub always_confirm_transfers: bool,
    #[serde(default = "default_decimal_point")]
    pub default_decimal_point: i32,
    #[serde(default)]
    pub show_wallet_name_when_locked: bool,
    #[serde(default = "default_inactivity_lock_timeout")]
    pub inactivity_lock_timeout: u32,
    #[serde(default = "default_background_mining")]
    pub background_mining: BackgroundMiningSetup,
}

fn default_true() -> bool {
    true
}
fn default_decimal_point() -> i32 {
    DEFAULT_DISPLAY_DECIMAL_POINT
}
fn default_inactivity_lock_timeout() -> u32 {
    DEFAULT_INACTIVITY_LOCK_TIMEOUT
}
fn default_background_mining() -> BackgroundMiningSetup {
    BackgroundMiningSetup::NotYetAsked
}

impl Default for UxPrefs {
    fn default() -> Self {
        Self {
            always_confirm_transfers: default_true(),
            default_decimal_point: default_decimal_point(),
            show_wallet_name_when_locked: false,
            inactivity_lock_timeout: default_inactivity_lock_timeout(),
            background_mining: default_background_mining(),
        }
    }
}

/// Spending / fee / output-selection preferences. See module docs for
/// fields that were deliberately dropped vs. the Monero-era equivalent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingPrefs {
    /// Default fee priority tier (`0` = unspecified / module default).
    #[serde(default)]
    pub default_priority: u32,
    #[serde(default = "default_true")]
    pub store_tx_info: bool,
    #[serde(default)]
    pub merge_destinations: bool,
    #[serde(default = "default_true")]
    pub confirm_backlog: bool,
    #[serde(default = "default_true")]
    pub confirm_export_overwrite: bool,
    #[serde(default = "default_true")]
    pub auto_low_priority: bool,
    #[serde(default)]
    pub min_output_count: u32,
    #[serde(default)]
    pub min_output_value: u64,
    #[serde(default = "default_true")]
    pub ignore_fractional_outputs: bool,
    #[serde(default = "default_money_supply")]
    pub ignore_outputs_above: u64,
    #[serde(default)]
    pub ignore_outputs_below: u64,
}

fn default_money_supply() -> u64 {
    TOTAL_MONEY_SUPPLY
}

impl Default for SpendingPrefs {
    fn default() -> Self {
        Self {
            default_priority: 0,
            store_tx_info: default_true(),
            merge_destinations: false,
            confirm_backlog: default_true(),
            confirm_export_overwrite: default_true(),
            auto_low_priority: default_true(),
            min_output_count: 0,
            min_output_value: 0,
            ignore_fractional_outputs: default_true(),
            ignore_outputs_above: default_money_supply(),
            ignore_outputs_below: 0,
        }
    }
}

/// Scan-safety toggles applied while refreshing from a daemon.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSafetySettings {
    /// Maximum number of blocks a reorg may span before the wallet asks
    /// the user to confirm. Older blocks than this are treated as final.
    #[serde(default = "default_max_reorg_depth")]
    pub max_reorg_depth: u64,
}

fn default_max_reorg_depth() -> u64 {
    DEFAULT_MAX_REORG_DEPTH
}

impl Default for ScanSafetySettings {
    fn default() -> Self {
        Self {
            max_reorg_depth: default_max_reorg_depth(),
        }
    }
}

/// Subaddress lookahead window. Pre-populates lookup tables so receiving
/// to a never-queried subaddress still matches on scan.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubaddressLookahead {
    #[serde(default = "default_lookahead_major")]
    pub major: u32,
    #[serde(default = "default_lookahead_minor")]
    pub minor: u32,
}

fn default_lookahead_major() -> u32 {
    DEFAULT_SUBADDRESS_LOOKAHEAD_MAJOR
}
fn default_lookahead_minor() -> u32 {
    DEFAULT_SUBADDRESS_LOOKAHEAD_MINOR
}

impl Default for SubaddressLookahead {
    fn default() -> Self {
        Self {
            major: default_lookahead_major(),
            minor: default_lookahead_minor(),
        }
    }
}

/// Non-secret hardware-device identity hints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DeviceSettings {
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub device_derivation_path: String,
}

/// Originating spend-address for watch-only wallets that remember their
/// parent (for display / provenance). `None` for wallets without
/// provenance.
///
/// `original_address` is stored as a Bech32m-encoded string (the canonical
/// display form). `original_view_secret_key` is wrapped in `Zeroizing`
/// and stored as a 64-char lowercase hex string on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginalKeys {
    pub original_address: String,
    #[serde(with = "original_view_sk_as_hex")]
    pub original_view_secret_key: Zeroizing<[u8; 32]>,
}

mod original_view_sk_as_hex {
    use super::{decode_hex32, encode_hex32};
    use serde::{de::Error as _, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_hex32(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        let arr = decode_hex32(&s, "original_view_secret_key")
            .map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(Zeroizing::new(arr))
    }
}

/// Background-sync configuration. `custom_background_key` is only
/// populated when `sync_type == BackgroundSyncType::CustomPassword`; the
/// key itself is wrapped in `Zeroizing` and wiped on drop.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackgroundSyncConfig {
    #[serde(default = "default_background_sync_type")]
    pub sync_type: BackgroundSyncType,
    #[serde(default, with = "bg_key_as_hex")]
    pub custom_background_key: Option<Zeroizing<[u8; 32]>>,
}

fn default_background_sync_type() -> BackgroundSyncType {
    BackgroundSyncType::Off
}

impl Default for BackgroundSyncConfig {
    fn default() -> Self {
        Self {
            sync_type: default_background_sync_type(),
            custom_background_key: None,
        }
    }
}

mod bg_key_as_hex {
    use super::{decode_hex32, encode_hex32};
    use serde::{de::Error as _, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(
        v: &Option<Zeroizing<[u8; 32]>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&encode_hex32(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, D::Error> {
        let opt = <Option<String> as serde::Deserialize>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let arr = decode_hex32(&s, "custom_background_key")
                    .map_err(|e| D::Error::custom(e.to_string()))?;
                Ok(Some(Zeroizing::new(arr)))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SettingsBlock
// ---------------------------------------------------------------------------

/// The settings block of a [`WalletState`](super::WalletState). See the
/// module docs for scope, versioning, and design rationale.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettingsBlock {
    /// Per-block schema version. Always [`SETTINGS_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,
    #[serde(default)]
    pub scan: ScanSettings,
    #[serde(default)]
    pub ux: UxPrefs,
    #[serde(default)]
    pub spending: SpendingPrefs,
    #[serde(default)]
    pub scan_safety: ScanSafetySettings,
    #[serde(default)]
    pub subaddress_lookahead: SubaddressLookahead,
    #[serde(default)]
    pub device: DeviceSettings,
    #[serde(default)]
    pub original_keys: Option<OriginalKeys>,
    #[serde(default)]
    pub background_sync: BackgroundSyncConfig,
}

impl Default for SettingsBlock {
    fn default() -> Self {
        Self {
            block_version: SETTINGS_BLOCK_VERSION,
            scan: ScanSettings::default(),
            ux: UxPrefs::default(),
            spending: SpendingPrefs::default(),
            scan_safety: ScanSafetySettings::default(),
            subaddress_lookahead: SubaddressLookahead::default(),
            device: DeviceSettings::default(),
            original_keys: None,
            background_sync: BackgroundSyncConfig::default(),
        }
    }
}

impl SettingsBlock {
    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != SETTINGS_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "settings",
                file: self.block_version,
                binary: SETTINGS_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_constants() {
        let s = SettingsBlock::default();
        assert_eq!(s.block_version, SETTINGS_BLOCK_VERSION);
        assert!(s.scan.auto_refresh);
        assert_eq!(s.scan.scan_mode, ScanMode::OptimizeCoinbase);
        assert_eq!(s.scan.scan_from_height, 0);
        assert_eq!(s.scan.resume_from_height, 0);
        assert!(s.ux.always_confirm_transfers);
        assert_eq!(s.ux.default_decimal_point, DEFAULT_DISPLAY_DECIMAL_POINT);
        assert_eq!(
            s.ux.inactivity_lock_timeout,
            DEFAULT_INACTIVITY_LOCK_TIMEOUT
        );
        assert_eq!(s.ux.background_mining, BackgroundMiningSetup::NotYetAsked);
        assert_eq!(s.scan_safety.max_reorg_depth, DEFAULT_MAX_REORG_DEPTH);
        assert_eq!(
            s.subaddress_lookahead.major,
            DEFAULT_SUBADDRESS_LOOKAHEAD_MAJOR
        );
        assert_eq!(
            s.subaddress_lookahead.minor,
            DEFAULT_SUBADDRESS_LOOKAHEAD_MINOR
        );
        assert_eq!(s.spending.ignore_outputs_above, TOTAL_MONEY_SUPPLY);
        assert_eq!(s.spending.ignore_outputs_below, 0);
        assert!(s.spending.ignore_fractional_outputs);
        assert!(s.spending.store_tx_info);
        assert!(s.spending.confirm_backlog);
        assert!(s.spending.confirm_export_overwrite);
        assert!(s.spending.auto_low_priority);
        assert_eq!(s.background_sync.sync_type, BackgroundSyncType::Off);
        assert!(s.background_sync.custom_background_key.is_none());
        assert!(s.original_keys.is_none());
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let s = SettingsBlock {
            block_version: 999,
            ..Default::default()
        };
        match s.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "settings");
                assert_eq!(file, 999);
                assert_eq!(binary, SETTINGS_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn scan_mode_discriminants_pinned() {
        assert_eq!(u8::from(ScanMode::Full), 0);
        assert_eq!(u8::from(ScanMode::OptimizeCoinbase), 1);
        assert_eq!(u8::from(ScanMode::NoCoinbase), 2);
    }

    #[test]
    fn background_mining_discriminants_pinned() {
        assert_eq!(u8::from(BackgroundMiningSetup::NotYetAsked), 0);
        assert_eq!(u8::from(BackgroundMiningSetup::Enabled), 1);
        assert_eq!(u8::from(BackgroundMiningSetup::Declined), 2);
    }

    #[test]
    fn background_sync_discriminants_pinned() {
        assert_eq!(u8::from(BackgroundSyncType::Off), 0);
        assert_eq!(u8::from(BackgroundSyncType::ReusePassword), 1);
        assert_eq!(u8::from(BackgroundSyncType::CustomPassword), 2);
    }

    #[test]
    fn custom_background_key_round_trips() {
        let s = SettingsBlock {
            background_sync: BackgroundSyncConfig {
                sync_type: BackgroundSyncType::CustomPassword,
                custom_background_key: Some(Zeroizing::new([0x42u8; 32])),
            },
            ..Default::default()
        };
        let json = serde_json::to_vec(&s).expect("serialize");
        let s2: SettingsBlock = serde_json::from_slice(&json).expect("deserialize");
        let k = s2
            .background_sync
            .custom_background_key
            .as_ref()
            .expect("present");
        assert_eq!(&k[..], &[0x42u8; 32]);
    }

    #[test]
    fn original_keys_round_trip() {
        let s = SettingsBlock {
            original_keys: Some(OriginalKeys {
                original_address: "shekyl1qexample".into(),
                original_view_secret_key: Zeroizing::new([0xCDu8; 32]),
            }),
            ..Default::default()
        };
        let json = serde_json::to_vec(&s).expect("serialize");
        let s2: SettingsBlock = serde_json::from_slice(&json).expect("deserialize");
        let ok2 = s2.original_keys.as_ref().expect("present");
        assert_eq!(ok2.original_address, "shekyl1qexample");
        assert_eq!(&ok2.original_view_secret_key[..], &[0xCDu8; 32]);
    }

    #[test]
    fn unknown_scan_mode_is_refused() {
        let json = br#"{
            "block_version": 1,
            "scan": { "auto_refresh": true, "scan_mode": 42,
                      "scan_from_height": 0, "resume_from_height": 0 }
        }"#;
        assert!(serde_json::from_slice::<SettingsBlock>(json).is_err());
    }
}
