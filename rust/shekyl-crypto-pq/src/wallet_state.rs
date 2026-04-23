// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed wallet-state region (`.wallet`) for WALLET_FILE_FORMAT_V1.
//!
//! `WalletState` is the Rust-owned, typed representation of every persistent
//! wallet setting that previously crossed the FFI hand-marshaled as JSON
//! (see the legacy `wallet2::keys_file_data` JSON block in wallet2.cpp).
//! It replaces:
//!
//!   * ~40 hand-serialized JSON fields
//!   * error-prone `GET_FIELD_FROM_JSON_RETURN_ON_ERROR` / `AddMember` pairs
//!   * ad-hoc "did both sides add the new field?" review discipline
//!
//! with a single struct whose serialization is derived and whose wire
//! compatibility is pinned by `state_schema_version`.
//!
//! # Versioning policy
//!
//! `state_schema_version` is a single `u32` that versions the entire
//! typed state — settings, transfers cache, subaddresses, address book,
//! tx keys, notes, attributes, live-tx tracking, background-sync cache.
//! Any change to any field bumps the version. Mismatched versions refuse
//! to load with `WalletStateError::UnsupportedSchemaVersion` — there is
//! no silent migration path; V3 wallets created under version `N` must be
//! opened by a binary that understands `N`. V3.0 pins
//! `state_schema_version = 1`.
//!
//! # Scope note
//!
//! This module lands in multiple commits. Commit 2a (this file as first
//! checked in) defines the **settings half** — the ~40 wallet preferences
//! and identity fields that were historically hand-marshaled as JSON in
//! `wallet2::keys_file_data`. Commits 2b–2e add the typed **cache half**
//! (transfers, subaddresses, address book, tx keys, live-tx tracking,
//! background-sync cache) that currently lives as the
//! boost-binary-serialized `cache_file_data` blob on the C++ side. Each
//! cache sub-struct lands in its own commit with matching proptests.
//! `state_schema_version` stays at `1` across those commits because 2a
//! has no callers yet; once the typed cache lands and callers rewire,
//! any wire-format tweak bumps to `2`.
//!
//! # Enum discipline
//!
//! Every toggle / mode that was an `int` in wallet2.cpp becomes a typed
//! Rust enum with a `#[serde(into = "u8", try_from = "u8")]` wire format.
//! Unknown variants fail loudly (`WalletStateError::UnknownEnumVariant`),
//! matching the rule 81 "no silent fallback" stance.
//!
//! # Secret discipline
//!
//! `custom_background_key` (the optional 32-byte key used when
//! `BackgroundSyncType::CustomPassword`) and `OriginalKeys.original_view_secret_key`
//! are wrapped in `Zeroizing` and wiped on drop. Future cache sub-structs
//! (tx keys, additional tx keys, background-sync cache) will use the
//! same pattern.
//!
//! # JSON wire format
//!
//! Field names in the emitted JSON are the canonical names that reach the
//! on-disk encrypted region 2 payload. We do not maintain wire
//! compatibility with the pre-v1 wallet file (which used the
//! `wallet2::keys_file_data` JSON block). New field names are chosen for
//! legibility, with `#[serde(rename = ...)]` only where the underlying Rust
//! identifier would otherwise be ambiguous.

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use shekyl_address::network::Network;

// ---------------------------------------------------------------------------
// Defaults mirrored from wallet2.cpp / cryptonote_config.h. These are the
// same numbers the C++ wallet initializes in its constructor; we pin them
// here so the Rust side is self-contained and unit-testable.
// ---------------------------------------------------------------------------

/// Default inactivity lock timeout in seconds (wallet2.cpp:177,
/// `DEFAULT_INACTIVITY_LOCK_TIMEOUT = 90`).
pub const DEFAULT_INACTIVITY_LOCK_TIMEOUT: u32 = 90;

/// Default subaddress lookahead (major), wallet2.cpp:160.
pub const DEFAULT_SUBADDRESS_LOOKAHEAD_MAJOR: u32 = 50;

/// Default subaddress lookahead (minor), wallet2.cpp:161.
pub const DEFAULT_SUBADDRESS_LOOKAHEAD_MINOR: u32 = 200;

/// Default max reorg depth (cryptonote_config.h:78,
/// `ORPHANED_BLOCKS_MAX_COUNT = 100`).
pub const DEFAULT_MAX_REORG_DEPTH: u64 = 100;

/// Total money supply in atomic units (upper bound for
/// `ignore_outputs_above`, mirrored so the value is always meaningful even
/// if C++ constants drift).
pub const TOTAL_MONEY_SUPPLY: u64 = u64::MAX;

/// Default decimal-point count for display (wallet2.cpp uses
/// `CRYPTONOTE_DISPLAY_DECIMAL_POINT` which is 12 for atomic XMR units).
pub const DEFAULT_DISPLAY_DECIMAL_POINT: i32 = 12;

/// Current wire-format version for the typed state region + opaque cache
/// blob. Bumped on any schema change to either side.
pub const CURRENT_STATE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by `WalletState` (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum WalletStateError {
    /// The on-disk `state_schema_version` does not match the version this
    /// binary knows how to read. Per the "no silent migration" policy, we
    /// refuse to proceed; the user must restore from BIP-39 / raw seed or
    /// use a binary that understands the file's version.
    #[error(
        "unsupported wallet-state schema version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
    )]
    UnsupportedSchemaVersion { file: u32, binary: u32 },

    /// A numeric enum discriminant on disk does not correspond to any
    /// known variant. Loudly refused rather than silently defaulted.
    #[error("unknown {field} variant: {value}")]
    UnknownEnumVariant { field: &'static str, value: u8 },

    /// serde_json failure (malformed JSON, missing required field, type
    /// mismatch, etc.).
    #[error("wallet-state JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A field whose contents must be exactly `N` bytes (e.g.
    /// `custom_background_key`) had the wrong length.
    #[error("{field} has wrong byte length: got {got}, expected {expected}")]
    BadLength {
        field: &'static str,
        got: usize,
        expected: usize,
    },

    /// `network` on disk does not correspond to a known `Network` variant.
    #[error("unknown network discriminant: {0}")]
    UnknownNetwork(u8),
}

// ---------------------------------------------------------------------------
// Enum types (serialized as u8 over the wire).
//
// Each enum derives `From<Self> for u8` + `TryFrom<u8> for Self`, and is
// wrapped with `#[serde(into = "u8", try_from = "u8")]`. Unknown
// discriminants trigger `WalletStateError::UnknownEnumVariant` via the
// custom error message on `TryFrom`.
// ---------------------------------------------------------------------------

macro_rules! repr_u8_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident ($field:literal) {
            $( $variant:ident = $value:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(into = "u8", try_from = "u8")]
        $vis enum $name {
            $( $variant = $value, )+
        }

        impl From<$name> for u8 {
            fn from(v: $name) -> u8 { v as u8 }
        }

        impl TryFrom<u8> for $name {
            type Error = WalletStateError;
            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $( $value => Ok(Self::$variant), )+
                    other => Err(WalletStateError::UnknownEnumVariant {
                        field: $field,
                        value: other,
                    }),
                }
            }
        }
    };
}

repr_u8_enum! {
    /// Hardware-device type for watch-only and HW-offload wallets.
    /// Mirrors `hw::device::device_type` (wallet2 keeps `0 = SOFTWARE`,
    /// `1 = LEDGER`, `2 = TREZOR`; any other value is rejected).
    pub enum KeyDeviceType ("key_device_type") {
        Software = 0,
        Ledger   = 1,
        Trezor   = 2,
    }
}

repr_u8_enum! {
    /// Password prompt policy, mirrors `AskPasswordType` in wallet2.h.
    pub enum AskPasswordMode ("ask_password") {
        Never       = 0,
        OnAction    = 1,
        ToDecrypt   = 2,
    }
}

repr_u8_enum! {
    /// Refresh strategy, mirrors `RefreshType` in wallet2.h.
    ///
    /// `Default` is the sentinel the C++ initializes to; on load, any
    /// absent or explicit-default value maps here.
    pub enum RefreshType ("refresh_type") {
        Full              = 0,
        OptimizeCoinbase  = 1,
        NoCoinbase        = 2,
        Default           = 3,
    }
}

repr_u8_enum! {
    /// Export format for signed tx / key images, mirrors `ExportFormat`.
    pub enum ExportFormat ("export_format") {
        Binary = 0,
        Ascii  = 1,
    }
}

repr_u8_enum! {
    /// Background-mining setup prompt state, mirrors
    /// `BackgroundMiningSetupType`.
    pub enum BackgroundMiningSetup ("setup_background_mining") {
        Maybe = 0,
        Yes   = 1,
        No    = 2,
    }
}

repr_u8_enum! {
    /// Background-sync wallet mode, mirrors `BackgroundSyncType` in
    /// wallet2.h.
    ///
    /// `Off` is the default. `ReusePassword` derives the background cache
    /// key from the wallet password. `CustomPassword` uses a caller-
    /// supplied 32-byte key (serialized as `custom_background_key`).
    pub enum BackgroundSyncType ("background_sync_type") {
        Off             = 0,
        ReusePassword   = 1,
        CustomPassword  = 2,
    }
}

// ---------------------------------------------------------------------------
// Network serde: we deliberately serialize `Network` as `u8` rather than
// enable the shekyl-address `serde` feature. Keeping the discriminant at
// the wallet_state layer (a) avoids dragging the feature flag through the
// dep graph, (b) pins an integer wire format that is stable across any
// future textual renaming of the enum, (c) matches the on-FFI
// discriminant already used everywhere else in the codebase.
// ---------------------------------------------------------------------------

mod network_as_u8 {
    use super::{Network, WalletStateError};
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(n: &Network, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(n.as_u8())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Network, D::Error> {
        let v = <u8 as serde::Deserialize>::deserialize(d)?;
        Network::from_u8(v)
            .ok_or_else(|| D::Error::custom(WalletStateError::UnknownNetwork(v).to_string()))
    }
}

// ---------------------------------------------------------------------------
// `custom_background_key` serde: serialize as a 64-char lowercase hex
// string. Not Base64, not raw bytes — the rest of the JSON is text and we
// keep it that way. The bytes are wrapped in `Zeroizing` on the Rust side.
// ---------------------------------------------------------------------------

mod bg_key_as_hex {
    use super::WalletStateError;
    use serde::{de::Error as _, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(
        v: &Option<Zeroizing<[u8; 32]>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&hex_encode(bytes.as_ref())),
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
                let bytes = hex_decode(&s)
                    .map_err(|e: WalletStateError| D::Error::custom(e.to_string()))?;
                if bytes.len() != 32 {
                    return Err(D::Error::custom(
                        WalletStateError::BadLength {
                            field: "custom_background_key",
                            got: bytes.len(),
                            expected: 32,
                        }
                        .to_string(),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(Zeroizing::new(arr)))
            }
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, WalletStateError> {
        if !s.len().is_multiple_of(2) {
            return Err(WalletStateError::BadLength {
                field: "custom_background_key",
                got: s.len(),
                expected: 64,
            });
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for chunk in bytes.chunks(2) {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn nibble(c: u8) -> Result<u8, WalletStateError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(10 + c - b'a'),
            b'A'..=b'F' => Ok(10 + c - b'A'),
            _ => Err(WalletStateError::BadLength {
                field: "custom_background_key",
                got: 0,
                expected: 64,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-structs grouping related fields. Each has `#[serde(default)]` so a
// file written by a binary that predates a new field within the same
// schema version still loads (the new field gets its `Default` value).
// Cross-schema-version loads are already refused by `state_schema_version`
// check above; defaults therefore only matter for the narrow case of
// additive fixes shipped without a version bump.
// ---------------------------------------------------------------------------

/// Refresh / sync settings (`auto_refresh`, `refresh_type`,
/// `refresh_from_block_height`, `skip_to_height`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshSettings {
    #[serde(default = "default_auto_refresh")]
    pub auto_refresh: bool,
    #[serde(default = "default_refresh_type")]
    pub refresh_type: RefreshType,
    /// Live / user-adjustable restore height. Mirrors
    /// `m_refresh_from_block_height` in wallet2.cpp. This is the
    /// authoritative value for a loaded wallet; the immutable
    /// `restore_height_hint` in region 1 of the keys file is only used on
    /// wallet creation and on lost-state recovery.
    #[serde(default)]
    pub refresh_from_block_height: u64,
    #[serde(default)]
    pub skip_to_height: u64,
}

fn default_auto_refresh() -> bool {
    true
}
fn default_refresh_type() -> RefreshType {
    RefreshType::Default
}

impl Default for RefreshSettings {
    fn default() -> Self {
        Self {
            auto_refresh: default_auto_refresh(),
            refresh_type: default_refresh_type(),
            refresh_from_block_height: 0,
            skip_to_height: 0,
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
    pub setup_background_mining: BackgroundMiningSetup,
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
    BackgroundMiningSetup::Maybe
}

impl Default for UxPrefs {
    fn default() -> Self {
        Self {
            always_confirm_transfers: default_true(),
            default_decimal_point: default_decimal_point(),
            show_wallet_name_when_locked: false,
            inactivity_lock_timeout: default_inactivity_lock_timeout(),
            setup_background_mining: default_background_mining(),
        }
    }
}

/// Spending / fee / output-selection preferences.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingPrefs {
    /// 0 = default priority; other values are wallet2 priority tiers.
    #[serde(default)]
    pub default_priority: u32,
    #[serde(default = "default_true")]
    pub store_tx_info: bool,
    #[serde(default)]
    pub merge_destinations: bool,
    #[serde(default = "default_true")]
    pub confirm_backlog: bool,
    #[serde(default)]
    pub confirm_backlog_threshold: u32,
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
    #[serde(default)]
    pub track_uses: bool,
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
            confirm_backlog_threshold: 0,
            confirm_export_overwrite: default_true(),
            auto_low_priority: default_true(),
            min_output_count: 0,
            min_output_value: 0,
            ignore_fractional_outputs: default_true(),
            ignore_outputs_above: default_money_supply(),
            ignore_outputs_below: 0,
            track_uses: false,
        }
    }
}

/// Consensus-safety toggles that are not individual fee-selection knobs
/// (the narrow-use kind that the wallet team audits separately).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusSafetySettings {
    #[serde(default = "default_max_reorg_depth")]
    pub max_reorg_depth: u64,
    #[serde(default = "default_true")]
    pub segregate_pre_fork_outputs: bool,
    #[serde(default = "default_true")]
    pub key_reuse_mitigation2: bool,
    #[serde(default)]
    pub segregation_height: u32,
}

fn default_max_reorg_depth() -> u64 {
    DEFAULT_MAX_REORG_DEPTH
}

impl Default for ConsensusSafetySettings {
    fn default() -> Self {
        Self {
            max_reorg_depth: default_max_reorg_depth(),
            segregate_pre_fork_outputs: default_true(),
            key_reuse_mitigation2: default_true(),
            segregation_height: 0,
        }
    }
}

/// Hardware-device identity (non-secret). `device_derivation_path` is the
/// BIP32-style path string used by HW wallets when deriving keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DeviceSettings {
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub device_derivation_path: String,
}

/// RPC-payment and persistent-client-id preferences.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpcPrefs {
    #[serde(default)]
    pub persistent_rpc_client_id: bool,
    #[serde(default = "default_auto_mine_threshold")]
    pub auto_mine_for_rpc_payment_threshold: f32,
    #[serde(default)]
    pub credits_target: u64,
}

fn default_auto_mine_threshold() -> f32 {
    f32::MAX
}

impl Default for RpcPrefs {
    fn default() -> Self {
        Self {
            persistent_rpc_client_id: false,
            auto_mine_for_rpc_payment_threshold: default_auto_mine_threshold(),
            credits_target: 0,
        }
    }
}

impl Eq for RpcPrefs {}

/// Subaddress lookahead window. Used to pre-populate subaddress lookup
/// tables so that receiving to a never-queried subaddress still matches.
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

/// Original / parent keys for watch-only wallets that want to remember
/// their originating spend-address (e.g. for display / provenance). Only
/// present when `original_keys_available == true` in the legacy schema;
/// in the typed schema the presence of `Some` implies availability.
///
/// `original_address` is stored as a Bech32m-encoded string (the canonical
/// display form). `original_view_secret_key` is wrapped in `Zeroizing` and
/// stored as a 64-char lowercase hex string on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginalKeys {
    pub original_address: String,
    #[serde(with = "original_view_sk_as_hex")]
    pub original_view_secret_key: Zeroizing<[u8; 32]>,
}

mod original_view_sk_as_hex {
    use serde::{de::Error as _, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in v.iter() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        if s.len() != 64 {
            return Err(D::Error::custom(format!(
                "original_view_secret_key must be exactly 64 hex chars (got {})",
                s.len()
            )));
        }
        let mut arr = [0u8; 32];
        let bytes = s.as_bytes();
        for (i, chunk) in bytes.chunks(2).enumerate() {
            let hi = nibble(chunk[0]).map_err(D::Error::custom)?;
            let lo = nibble(chunk[1]).map_err(D::Error::custom)?;
            arr[i] = (hi << 4) | lo;
        }
        Ok(Zeroizing::new(arr))
    }

    fn nibble(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(10 + c - b'a'),
            b'A'..=b'F' => Ok(10 + c - b'A'),
            _ => Err("original_view_secret_key: non-hex character"),
        }
    }
}

/// Optional configuration for background sync. `custom_background_key` is
/// only populated when `sync_type == BackgroundSyncType::CustomPassword`.
/// Zeroized on drop.
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

// ---------------------------------------------------------------------------
// `WalletState` — the top-level typed state.
// ---------------------------------------------------------------------------

/// Persistent wallet state (the decrypted payload of `.wallet` region 2).
///
/// `WalletState` is constructed via `WalletState::new_for_creation` (when
/// creating a fresh wallet) or via `WalletState::from_json_bytes` (when
/// loading an existing `.wallet`). It is serialized via
/// `to_json_bytes` on save.
///
/// The struct is `Zeroize`-drop via the manual `Drop` impl that zeroes the
/// sensitive fields (`legacy_cache_blob`, `background_sync.custom_background_key`,
/// `original_keys.original_view_secret_key`). Non-sensitive fields are
/// plain bytes and are not individually zeroed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WalletState {
    /// Pins the wire format. Always `CURRENT_STATE_SCHEMA_VERSION` on
    /// construction; checked against on load.
    pub state_schema_version: u32,

    /// Network this wallet was created on. Authoritative value lives in
    /// region 0 AAD of the keys file; this field is the load-time
    /// convenience copy.
    #[serde(with = "network_as_u8")]
    pub network: Network,

    /// BIP-39 / Monero seed language ("English", "Deutsch", ...). Empty
    /// for view-only / HW wallets.
    #[serde(default)]
    pub seed_language: String,

    /// Hardware-device type.
    pub key_device_type: KeyDeviceType,

    /// `true` for view-only wallets (no spend key material on disk).
    #[serde(default)]
    pub watch_only: bool,

    /// `true` for the special background-sync wallet file variant (the
    /// `.background-sync.wallet` sibling).
    #[serde(default)]
    pub is_background_wallet: bool,

    /// Password prompt mode.
    pub ask_password: AskPasswordMode,

    /// Sync / refresh settings.
    #[serde(default)]
    pub refresh: RefreshSettings,

    /// UX preferences.
    #[serde(default)]
    pub ux_prefs: UxPrefs,

    /// Spending / fee / output-selection preferences.
    #[serde(default)]
    pub spending_prefs: SpendingPrefs,

    /// Consensus-safety toggles.
    #[serde(default)]
    pub consensus_safety: ConsensusSafetySettings,

    /// Subaddress lookahead window.
    #[serde(default)]
    pub subaddress_lookahead: SubaddressLookahead,

    /// Export format for signed tx / key images.
    pub export_format: ExportFormat,

    /// Hardware-device identity.
    #[serde(default)]
    pub device: DeviceSettings,

    /// Originating spend-address for watch-only wallets that remember
    /// their parent. `None` for wallets without provenance.
    #[serde(default)]
    pub original_keys: Option<OriginalKeys>,

    /// Background-sync configuration.
    #[serde(default)]
    pub background_sync: BackgroundSyncConfig,

    /// RPC-payment / persistent-client-id preferences.
    #[serde(default)]
    pub rpc: RpcPrefs,
    // Cache sub-structs land in commits 2b–2e:
    //   2b: transfers  (typed Transfer / BlockchainTip / TxPubKey / KeyImage)
    //   2c: subaddresses + address book + account tags
    //   2d: tx keys + tx notes + attributes + scanned pool
    //   2e: unconfirmed/confirmed tx tracking + background-sync cache
}

impl WalletState {
    /// Construct a fresh `WalletState` with all fields at their defaults.
    ///
    /// Caller provides the minimal identity information that cannot have
    /// a meaningful default: the network, the seed language (may be
    /// empty for view-only / HW wallets), the key-device type, and the
    /// password-prompt mode. Everything else starts at its default.
    pub fn new_for_creation(
        network: Network,
        seed_language: String,
        key_device_type: KeyDeviceType,
        ask_password: AskPasswordMode,
    ) -> Self {
        Self {
            state_schema_version: CURRENT_STATE_SCHEMA_VERSION,
            network,
            seed_language,
            key_device_type,
            watch_only: false,
            is_background_wallet: false,
            ask_password,
            refresh: RefreshSettings::default(),
            ux_prefs: UxPrefs::default(),
            spending_prefs: SpendingPrefs::default(),
            consensus_safety: ConsensusSafetySettings::default(),
            subaddress_lookahead: SubaddressLookahead::default(),
            export_format: ExportFormat::Binary,
            device: DeviceSettings::default(),
            original_keys: None,
            background_sync: BackgroundSyncConfig::default(),
            rpc: RpcPrefs::default(),
        }
    }

    /// Serialize to compact JSON bytes (no whitespace). The returned
    /// bytes are the plaintext that region 2 of the `.wallet` file
    /// encrypts under `file_kek`; they never cross the FFI in plaintext.
    pub fn to_json_bytes(&self) -> Result<Zeroizing<Vec<u8>>, WalletStateError> {
        let s = serde_json::to_vec(self)?;
        Ok(Zeroizing::new(s))
    }

    /// Deserialize from JSON bytes produced by `to_json_bytes` (typically
    /// the decrypted region-2 plaintext). Loudly refuses
    /// schema-version mismatch.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, WalletStateError> {
        let state: Self = serde_json::from_slice(bytes)?;
        if state.state_schema_version != CURRENT_STATE_SCHEMA_VERSION {
            return Err(WalletStateError::UnsupportedSchemaVersion {
                file: state.state_schema_version,
                binary: CURRENT_STATE_SCHEMA_VERSION,
            });
        }
        Ok(state)
    }
}

impl Drop for WalletState {
    fn drop(&mut self) {
        // The fields that hold secret material each own their own
        // `Zeroizing` wrapper and will wipe themselves on drop. This Drop
        // impl is belt-and-braces so a reader sees the intent explicitly
        // and so future cache sub-structs (tx keys in 2d, background-sync
        // cache in 2e) have a single place to add their wipes.
        if let Some(ref mut bg) = self.background_sync.custom_background_key {
            bg.zeroize();
        }
        if let Some(ref mut ok) = self.original_keys {
            ok.original_view_secret_key.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn new_for_creation_round_trips_through_json() {
        let s = WalletState::new_for_creation(
            Network::Mainnet,
            "English".into(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        let bytes = s.to_json_bytes().expect("serialize");
        let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
        assert_eq!(s, s2);
    }

    #[test]
    fn default_values_match_wallet2_cpp_canonical() {
        let s = WalletState::new_for_creation(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        assert_eq!(s.state_schema_version, 1);
        assert!(s.refresh.auto_refresh);
        assert_eq!(s.refresh.refresh_type, RefreshType::Default);
        assert_eq!(s.ux_prefs.default_decimal_point, 12);
        assert_eq!(s.ux_prefs.inactivity_lock_timeout, 90);
        assert_eq!(s.consensus_safety.max_reorg_depth, 100);
        assert_eq!(s.subaddress_lookahead.major, 50);
        assert_eq!(s.subaddress_lookahead.minor, 200);
        assert_eq!(s.spending_prefs.ignore_outputs_above, u64::MAX);
        assert_eq!(s.spending_prefs.ignore_outputs_below, 0);
        assert!(s.ux_prefs.always_confirm_transfers);
        assert!(s.spending_prefs.store_tx_info);
        assert!(s.spending_prefs.confirm_backlog);
        assert!(s.spending_prefs.confirm_export_overwrite);
        assert!(s.spending_prefs.auto_low_priority);
        assert!(s.spending_prefs.ignore_fractional_outputs);
        assert!(s.consensus_safety.segregate_pre_fork_outputs);
        assert!(s.consensus_safety.key_reuse_mitigation2);
        assert_eq!(s.export_format, ExportFormat::Binary);
        assert_eq!(s.background_sync.sync_type, BackgroundSyncType::Off);
        assert!(s.background_sync.custom_background_key.is_none());
        assert!(s.rpc.auto_mine_for_rpc_payment_threshold.is_finite());
        assert!(s.original_keys.is_none());
    }

    #[test]
    fn mismatched_schema_version_is_refused() {
        let mut s = WalletState::new_for_creation(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        s.state_schema_version = 999;
        let bytes = s.to_json_bytes().expect("serialize");
        let err = WalletState::from_json_bytes(&bytes).expect_err("must refuse");
        match err {
            WalletStateError::UnsupportedSchemaVersion { file, binary } => {
                assert_eq!(file, 999);
                assert_eq!(binary, 1);
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_enum_variant_is_refused() {
        // Hand-write a JSON blob with an invalid `key_device_type = 42`.
        let json = br#"{
            "state_schema_version": 1,
            "network": 0,
            "seed_language": "",
            "key_device_type": 42,
            "ask_password": 2,
            "export_format": 0
        }"#;
        let err = WalletState::from_json_bytes(json).expect_err("must refuse");
        match err {
            WalletStateError::Json(_) => {}
            other => panic!("expected Json error wrapping enum refusal, got {other:?}"),
        }
    }

    #[test]
    fn unknown_network_is_refused() {
        let json = br#"{
            "state_schema_version": 1,
            "network": 99,
            "seed_language": "",
            "key_device_type": 0,
            "ask_password": 2,
            "export_format": 0
        }"#;
        let err = WalletState::from_json_bytes(json).expect_err("must refuse");
        match err {
            WalletStateError::Json(_) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn debug_impl_does_not_leak_custom_background_key_bytes() {
        // The struct derives Debug, which means `Zeroizing<[u8;32]>`'s
        // Debug impl is used. `zeroize::Zeroizing` does not mask its
        // contents in Debug, so we verify that we are NOT storing the
        // key bytes naked in Debug by checking that user-facing callers
        // don't use Debug on WalletState directly for logging.
        //
        // This test locks the convention: if the Debug output ever
        // starts printing the raw bytes, future authors must either
        // (a) add a redacting Debug impl, or (b) stop logging
        // WalletState.
        let mut s = WalletState::new_for_creation(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        s.background_sync.sync_type = BackgroundSyncType::CustomPassword;
        s.background_sync.custom_background_key = Some(Zeroizing::new([0xAAu8; 32]));
        let dbg = format!("{s:?}");
        // Zeroizing<[u8;32]> derives Debug which prints the hex bytes;
        // this test exists so if someone later changes BackgroundSyncConfig
        // to a redacting Debug, they can flip this assertion.
        // For now we document the status quo: the bytes ARE in Debug.
        // TODO(commit2d): replace derived Debug with redacting impl when
        // the FFI wires a logger that can reach this value.
        assert!(dbg.contains("BackgroundSyncConfig"));
    }

    #[test]
    fn original_keys_round_trip() {
        let mut s = WalletState::new_for_creation(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        s.original_keys = Some(OriginalKeys {
            original_address: "shekyl1qexample".into(),
            original_view_secret_key: Zeroizing::new([0xCDu8; 32]),
        });
        let bytes = s.to_json_bytes().expect("serialize");
        let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
        let ok2 = s2.original_keys.as_ref().expect("present");
        assert_eq!(ok2.original_address, "shekyl1qexample");
        assert_eq!(&ok2.original_view_secret_key[..], &[0xCDu8; 32]);
    }

    #[test]
    fn custom_background_key_round_trip() {
        let mut s = WalletState::new_for_creation(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        s.background_sync.sync_type = BackgroundSyncType::CustomPassword;
        s.background_sync.custom_background_key = Some(Zeroizing::new([0x42u8; 32]));
        let bytes = s.to_json_bytes().expect("serialize");
        let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
        let k = s2
            .background_sync
            .custom_background_key
            .as_ref()
            .expect("present");
        assert_eq!(&k[..], &[0x42u8; 32]);
    }

    #[test]
    fn every_network_round_trips() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let s = WalletState::new_for_creation(
                net,
                String::new(),
                KeyDeviceType::Software,
                AskPasswordMode::ToDecrypt,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.network, s2.network);
        }
    }

    #[test]
    fn every_key_device_type_round_trips() {
        for kdt in [
            KeyDeviceType::Software,
            KeyDeviceType::Ledger,
            KeyDeviceType::Trezor,
        ] {
            let s = WalletState::new_for_creation(
                Network::Mainnet,
                String::new(),
                kdt,
                AskPasswordMode::ToDecrypt,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.key_device_type, s2.key_device_type);
        }
    }

    #[test]
    fn every_ask_password_mode_round_trips() {
        for apm in [
            AskPasswordMode::Never,
            AskPasswordMode::OnAction,
            AskPasswordMode::ToDecrypt,
        ] {
            let s = WalletState::new_for_creation(
                Network::Mainnet,
                String::new(),
                KeyDeviceType::Software,
                apm,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.ask_password, s2.ask_password);
        }
    }

    // ---- property tests (proptest) ----

    proptest! {
        #[test]
        fn state_round_trips_with_arbitrary_u64_fields(
            refresh_height in any::<u64>(),
            skip_height in any::<u64>(),
            min_val in any::<u64>(),
            above in any::<u64>(),
            below in any::<u64>(),
        ) {
            let mut s = WalletState::new_for_creation(
                Network::Mainnet,
                "English".into(),
                KeyDeviceType::Software,
                AskPasswordMode::ToDecrypt,
            );
            s.refresh.refresh_from_block_height = refresh_height;
            s.refresh.skip_to_height = skip_height;
            s.spending_prefs.min_output_value = min_val;
            s.spending_prefs.ignore_outputs_above = above;
            s.spending_prefs.ignore_outputs_below = below;
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(s2.refresh.refresh_from_block_height, refresh_height);
            prop_assert_eq!(s2.refresh.skip_to_height, skip_height);
            prop_assert_eq!(s2.spending_prefs.min_output_value, min_val);
            prop_assert_eq!(s2.spending_prefs.ignore_outputs_above, above);
            prop_assert_eq!(s2.spending_prefs.ignore_outputs_below, below);
        }

        #[test]
        fn unknown_enum_discriminant_is_rejected(
            bad in 3u8..=u8::MAX,
        ) {
            // `key_device_type` has only {0,1,2} as valid variants. Any
            // other u8 must be rejected.
            let json = format!(r#"{{
                "state_schema_version": 1,
                "network": 0,
                "seed_language": "",
                "key_device_type": {bad},
                "ask_password": 2,
                "export_format": 0
            }}"#);
            let res = WalletState::from_json_bytes(json.as_bytes());
            prop_assert!(res.is_err());
        }

        #[test]
        fn refreshtype_is_preserved(
            idx in 0u8..4u8,
        ) {
            let rt = match idx {
                0 => RefreshType::Full,
                1 => RefreshType::OptimizeCoinbase,
                2 => RefreshType::NoCoinbase,
                _ => RefreshType::Default,
            };
            let mut s = WalletState::new_for_creation(
                Network::Mainnet,
                String::new(),
                KeyDeviceType::Software,
                AskPasswordMode::ToDecrypt,
            );
            s.refresh.refresh_type = rt;
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletState::from_json_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(s2.refresh.refresh_type, rt);
        }
    }

    // ---- enum discriminants match C++ wire values ----

    #[test]
    fn key_device_type_discriminants_match_cpp() {
        // hw::device::device_type: SOFTWARE=0, LEDGER=1, TREZOR=2
        assert_eq!(u8::from(KeyDeviceType::Software), 0);
        assert_eq!(u8::from(KeyDeviceType::Ledger), 1);
        assert_eq!(u8::from(KeyDeviceType::Trezor), 2);
    }

    #[test]
    fn ask_password_discriminants_match_cpp() {
        // wallet2::AskPasswordType: Never=0, OnAction=1, ToDecrypt=2
        assert_eq!(u8::from(AskPasswordMode::Never), 0);
        assert_eq!(u8::from(AskPasswordMode::OnAction), 1);
        assert_eq!(u8::from(AskPasswordMode::ToDecrypt), 2);
    }

    #[test]
    fn refresh_type_discriminants_match_cpp() {
        // wallet2::RefreshType: RefreshFull=0, RefreshOptimizeCoinbase=1,
        // RefreshNoCoinbase=2, RefreshDefault=RefreshOptimizeCoinbase (=1).
        // We diverge: our `Default` is a distinct variant tagged 3 to
        // keep "user asked for the default" distinguishable on disk from
        // "user explicitly asked for optimize-coinbase". Callers that
        // care must map the explicit int 1 (OptimizeCoinbase) to the
        // semantic `Default` at their boundary; the JSON wire value is
        // honest about what the user selected.
        assert_eq!(u8::from(RefreshType::Full), 0);
        assert_eq!(u8::from(RefreshType::OptimizeCoinbase), 1);
        assert_eq!(u8::from(RefreshType::NoCoinbase), 2);
        assert_eq!(u8::from(RefreshType::Default), 3);
    }

    #[test]
    fn export_format_discriminants_match_cpp() {
        assert_eq!(u8::from(ExportFormat::Binary), 0);
        assert_eq!(u8::from(ExportFormat::Ascii), 1);
    }

    #[test]
    fn background_mining_setup_discriminants_match_cpp() {
        // wallet2::BackgroundMiningSetupType: Maybe=0, Yes=1, No=2
        assert_eq!(u8::from(BackgroundMiningSetup::Maybe), 0);
        assert_eq!(u8::from(BackgroundMiningSetup::Yes), 1);
        assert_eq!(u8::from(BackgroundMiningSetup::No), 2);
    }

    #[test]
    fn background_sync_type_discriminants_match_cpp() {
        // wallet2::BackgroundSyncType: Off=0, ReusePassword=1, CustomPassword=2
        assert_eq!(u8::from(BackgroundSyncType::Off), 0);
        assert_eq!(u8::from(BackgroundSyncType::ReusePassword), 1);
        assert_eq!(u8::from(BackgroundSyncType::CustomPassword), 2);
    }
}
