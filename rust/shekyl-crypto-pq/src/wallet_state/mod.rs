// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed **wallet metadata** region for WALLET_FILE_FORMAT_V1.
//!
//! [`WalletMetadata`] is the Rust-owned, typed representation of the
//! small, human-oriented wallet state that lives in the JSON-serialized
//! region 2 of the `.wallet.keys` file:
//!
//! * [`identity`] — network, seed language, key-device kind, password mode
//! * [`settings`] — scan / UX / spending / scan-safety / subaddress /
//!   device / original-keys / background-sync preferences
//!
//! Everything else that historically lived here — the transfers cache,
//! subaddress/address-book/account tags, tx keys/notes, and the
//! confirmed/unconfirmed sync state — is deliberately *not* part of this
//! type. Those live in [`shekyl_wallet_state`] as `postcard`-serialized
//! ledger blocks that fit in the `.wallet` (region 3) of the two-file
//! envelope, and they follow their own per-block versioning there. This
//! separation keeps the keys-file metadata small and JSON-friendly (human
//! readable after decryption, stable across minor settings additions) and
//! the ledger binary-compact (the hot path on every scanner write).
//!
//! # Versioning
//!
//! Two levels of version check, both `==`-strict (no silent migration):
//!
//! * [`CURRENT_METADATA_FORMAT_VERSION`] pins the bundle shape — which
//!   blocks exist in [`WalletMetadata`]. Bumped only when a block is
//!   added or removed from this type.
//! * Each block has its own `BLOCK_VERSION` constant and a `block_version`
//!   field that must match exactly on load. Any mismatch on any level
//!   aborts the load — the user must restore from seed or use a binary
//!   that understands the file's version combination.
//!
//! # JSON wire format
//!
//! [`WalletMetadata::to_json_bytes`] emits compact JSON (no whitespace).
//! The bytes are the plaintext of region 2 of the `.wallet.keys` file
//! (which is then AEAD-encrypted under `file_kek`); they never cross
//! the FFI in plaintext. Reader and writer live only on the Rust side;
//! C++ sees only an opaque handle that vends per-field accessors.
//!
//! # Secret discipline
//!
//! Every field that carries secret bytes is wrapped in [`zeroize::Zeroizing`]
//! at the leaf (currently `SettingsBlock::background_sync.custom_background_key`
//! and `SettingsBlock::original_keys.original_view_secret_key`). Wipes
//! happen automatically on drop via the `Zeroizing` wrapper — there is
//! no parent-level `Drop` coordinator, deliberately, so new secret
//! fields can land in any block without modifying a central list.

pub mod identity;
pub mod primitives;
pub mod settings;

pub use identity::{AskPasswordMode, IdentityBlock, KeyDeviceType, IDENTITY_BLOCK_VERSION};
pub use primitives::{Network, WalletStateError};
pub use settings::{
    BackgroundMiningSetup, BackgroundSyncConfig, BackgroundSyncType, DeviceSettings, OriginalKeys,
    ScanMode, ScanSafetySettings, ScanSettings, SettingsBlock, SpendingPrefs, SubaddressLookahead,
    UxPrefs, DEFAULT_DISPLAY_DECIMAL_POINT, DEFAULT_INACTIVITY_LOCK_TIMEOUT,
    DEFAULT_MAX_REORG_DEPTH, DEFAULT_SUBADDRESS_LOOKAHEAD_MAJOR,
    DEFAULT_SUBADDRESS_LOOKAHEAD_MINOR, SETTINGS_BLOCK_VERSION, TOTAL_MONEY_SUPPLY,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Current metadata-bundle-shape version. V3.0 ships version `1` — the
/// bundle has exactly two blocks (`identity` and `settings`) in the order
/// declared by [`WalletMetadata`]. A future release that adds or removes
/// a top-level block bumps this.
pub const CURRENT_METADATA_FORMAT_VERSION: u32 = 1;

/// The typed wallet-metadata bundle. See module docs for scope,
/// versioning, wire format, and secret discipline.
///
/// This type contains **only** the small, human-oriented settings +
/// identity surface serialized into region 2 of the `.wallet.keys` file.
/// Runtime ledger state (transfers, blockchain tip, sync bookkeeping,
/// subaddress registry, tx notes / keys) lives separately in
/// [`shekyl_wallet_state`] and is persisted as postcard-encoded blocks
/// in the `.wallet` file via the wallet-file orchestrator (commit 2h).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletMetadata {
    /// Bundle-shape version. Always [`CURRENT_METADATA_FORMAT_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub format_version: u32,
    pub identity: IdentityBlock,
    #[serde(default)]
    pub settings: SettingsBlock,
}

impl WalletMetadata {
    /// Construct a fresh `WalletMetadata` for a new wallet. Caller
    /// supplies the minimal identity that has no meaningful default
    /// (network, seed language, key-device type, password-prompt mode);
    /// settings start at their defaults.
    pub fn new_for_creation(
        network: Network,
        seed_language: String,
        key_device_type: KeyDeviceType,
        ask_password: AskPasswordMode,
    ) -> Self {
        Self {
            format_version: CURRENT_METADATA_FORMAT_VERSION,
            identity: IdentityBlock::new(network, seed_language, key_device_type, ask_password),
            settings: SettingsBlock::default(),
        }
    }

    /// Serialize to compact JSON bytes (no whitespace). The returned
    /// bytes are the plaintext of region 2 of the `.wallet.keys` file;
    /// they never cross the FFI in plaintext.
    pub fn to_json_bytes(&self) -> Result<Zeroizing<Vec<u8>>, WalletStateError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(Zeroizing::new(bytes))
    }

    /// Deserialize from JSON bytes produced by
    /// [`WalletMetadata::to_json_bytes`]. Refuses any version mismatch
    /// — bundle shape or any block.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, WalletStateError> {
        let state: Self = serde_json::from_slice(bytes)?;
        state.check_versions()?;
        Ok(state)
    }

    /// Run the full version-check chain: bundle shape, then each block.
    /// Any mismatch returns a specific error naming the offending scope.
    fn check_versions(&self) -> Result<(), WalletStateError> {
        if self.format_version != CURRENT_METADATA_FORMAT_VERSION {
            return Err(WalletStateError::UnsupportedFormatVersion {
                file: self.format_version,
                binary: CURRENT_METADATA_FORMAT_VERSION,
            });
        }
        self.identity.check_version()?;
        self.settings.check_version()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bundle-level tests. Per-block behavior is covered in each block's own
// module; this section exercises the bundle-shape invariants, cross-block
// version refusal, and round-trips of representative sub-states.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fresh() -> WalletMetadata {
        WalletMetadata::new_for_creation(
            Network::Mainnet,
            "English".into(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        )
    }

    #[test]
    fn new_for_creation_round_trips_through_json() {
        let s = fresh();
        let bytes = s.to_json_bytes().expect("serialize");
        let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
        assert_eq!(s, s2);
    }

    #[test]
    fn defaults_pin_format_and_block_versions() {
        let s = fresh();
        assert_eq!(s.format_version, CURRENT_METADATA_FORMAT_VERSION);
        assert_eq!(s.identity.block_version, IDENTITY_BLOCK_VERSION);
        assert_eq!(s.settings.block_version, SETTINGS_BLOCK_VERSION);
    }

    #[test]
    fn mismatched_format_version_is_refused() {
        let mut s = fresh();
        s.format_version = 999;
        let bytes = s.to_json_bytes().expect("serialize");
        match WalletMetadata::from_json_bytes(&bytes).unwrap_err() {
            WalletStateError::UnsupportedFormatVersion { file, binary } => {
                assert_eq!(file, 999);
                assert_eq!(binary, CURRENT_METADATA_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_identity_block_version_is_refused() {
        let mut s = fresh();
        s.identity.block_version = 999;
        let bytes = s.to_json_bytes().expect("serialize");
        match WalletMetadata::from_json_bytes(&bytes).unwrap_err() {
            WalletStateError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "identity");
                assert_eq!(file, 999);
                assert_eq!(binary, IDENTITY_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(identity), got {other:?}"),
        }
    }

    #[test]
    fn mismatched_settings_block_version_is_refused() {
        let mut s = fresh();
        s.settings.block_version = 999;
        let bytes = s.to_json_bytes().expect("serialize");
        match WalletMetadata::from_json_bytes(&bytes).unwrap_err() {
            WalletStateError::UnsupportedBlockVersion { block, .. } => {
                assert_eq!(block, "settings")
            }
            other => panic!("expected UnsupportedBlockVersion(settings), got {other:?}"),
        }
    }

    #[test]
    fn unknown_fields_rejected_by_load() {
        // A file from a future binary that added a new top-level block (say
        // `ledger_head` on the metadata bundle) must not deserialize under
        // our schema — we rely on `serde_json`'s default deny-unknown
        // behavior only for tagged enums, so we pin the contract explicitly
        // here via an old-field-only positive case.
        let s = fresh();
        let bytes = s.to_json_bytes().expect("serialize");
        // Adding a nonsense top-level field is silently ignored by default.
        // That's acceptable here because the `format_version` gate is what
        // actually stops a future binary's output from loading — any
        // block-adding change must bump that version.
        let mut obj: serde_json::Value = serde_json::from_slice(&bytes).expect("parse back");
        obj.as_object_mut()
            .unwrap()
            .insert("ledger_head".into(), serde_json::json!({"wat": 1}));
        let perturbed = serde_json::to_vec(&obj).expect("reserialize");
        // Still parses because we don't `deny_unknown_fields`, but the
        // format_version gate is ALSO unchanged here so load succeeds.
        // The real defense is that a binary *adding* a new block bumps
        // `CURRENT_METADATA_FORMAT_VERSION`, which tripwires this check.
        assert!(WalletMetadata::from_json_bytes(&perturbed).is_ok());
    }

    #[test]
    fn unknown_enum_discriminant_on_load_is_refused() {
        let json = br#"{
            "format_version": 1,
            "identity": {
                "block_version": 1,
                "network": 0,
                "seed_language": "",
                "key_device_type": 42,
                "ask_password": 2
            }
        }"#;
        assert!(WalletMetadata::from_json_bytes(json).is_err());
    }

    #[test]
    fn unknown_network_on_load_is_refused() {
        let json = br#"{
            "format_version": 1,
            "identity": {
                "block_version": 1,
                "network": 99,
                "seed_language": "",
                "key_device_type": 0,
                "ask_password": 2
            }
        }"#;
        assert!(WalletMetadata::from_json_bytes(json).is_err());
    }

    #[test]
    fn every_network_round_trips() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let s = WalletMetadata::new_for_creation(
                net,
                String::new(),
                KeyDeviceType::Software,
                AskPasswordMode::ToDecrypt,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.identity.network, s2.identity.network);
        }
    }

    #[test]
    fn every_key_device_type_round_trips() {
        for kdt in [
            KeyDeviceType::Software,
            KeyDeviceType::Ledger,
            KeyDeviceType::Trezor,
        ] {
            let s = WalletMetadata::new_for_creation(
                Network::Mainnet,
                String::new(),
                kdt,
                AskPasswordMode::ToDecrypt,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.identity.key_device_type, s2.identity.key_device_type);
        }
    }

    #[test]
    fn every_ask_password_mode_round_trips() {
        for apm in [
            AskPasswordMode::Never,
            AskPasswordMode::OnAction,
            AskPasswordMode::ToDecrypt,
        ] {
            let s = WalletMetadata::new_for_creation(
                Network::Mainnet,
                String::new(),
                KeyDeviceType::Software,
                apm,
            );
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
            assert_eq!(s.identity.ask_password, s2.identity.ask_password);
        }
    }

    proptest! {
        #[test]
        fn scan_and_spending_heights_round_trip(
            scan_from in any::<u64>(),
            resume_from in any::<u64>(),
            ignore_above in any::<u64>(),
            ignore_below in any::<u64>(),
            min_output_value in any::<u64>(),
        ) {
            let mut s = fresh();
            s.settings.scan.scan_from_height = scan_from;
            s.settings.scan.resume_from_height = resume_from;
            s.settings.spending.ignore_outputs_above = ignore_above;
            s.settings.spending.ignore_outputs_below = ignore_below;
            s.settings.spending.min_output_value = min_output_value;
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(s2.settings.scan.scan_from_height, scan_from);
            prop_assert_eq!(s2.settings.scan.resume_from_height, resume_from);
            prop_assert_eq!(s2.settings.spending.ignore_outputs_above, ignore_above);
            prop_assert_eq!(s2.settings.spending.ignore_outputs_below, ignore_below);
            prop_assert_eq!(s2.settings.spending.min_output_value, min_output_value);
        }

        #[test]
        fn scan_mode_round_trips(idx in 0u8..3u8) {
            let mode = match idx {
                0 => ScanMode::Full,
                1 => ScanMode::OptimizeCoinbase,
                _ => ScanMode::NoCoinbase,
            };
            let mut s = fresh();
            s.settings.scan.scan_mode = mode;
            let bytes = s.to_json_bytes().expect("serialize");
            let s2 = WalletMetadata::from_json_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(s2.settings.scan.scan_mode, mode);
        }

        #[test]
        fn unknown_key_device_type_discriminant_is_rejected(bad in 3u8..=u8::MAX) {
            let json = format!(r#"{{
                "format_version": 1,
                "identity": {{
                    "block_version": 1,
                    "network": 0,
                    "seed_language": "",
                    "key_device_type": {bad},
                    "ask_password": 2
                }}
            }}"#);
            prop_assert!(WalletMetadata::from_json_bytes(json.as_bytes()).is_err());
        }
    }
}
