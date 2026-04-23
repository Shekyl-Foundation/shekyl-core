// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **identity block** of [`WalletState`](super::WalletState).
//!
//! Holds the fields that identify the wallet itself — which chain it was
//! created on, what kind of keystore backs it, how it interacts with
//! passwords, and whether it is a view-only or background-sync variant.
//! None of these values change during a wallet's lifetime for the
//! current feature set; the block is effectively an immutable identity
//! card that the orchestrator layer cross-checks against the authoritative
//! copies in the `.wallet.keys` region-0 AAD on every open.
//!
//! Versioning: this block owns [`IDENTITY_BLOCK_VERSION`]. Any change to
//! the field set or semantics bumps it, and any binary that does not
//! recognize the new version refuses to load.

use serde::{Deserialize, Serialize};

use super::primitives::{network_as_u8, repr_u8_enum, Network, WalletStateError};

/// Schema version of the identity block. V3.0 ships version `1`. Bumped
/// on any field addition / removal / renaming within this block.
pub const IDENTITY_BLOCK_VERSION: u32 = 1;

repr_u8_enum! {
    /// Where the wallet's long-term secrets live.
    ///
    /// `Software` — secrets live on-disk inside the encrypted `.wallet.keys`
    /// region. `Ledger` / `Trezor` — secrets live on the named hardware
    /// device and only non-secret hints (device identity, derivation path)
    /// live on disk. Future hardware backends take new discriminants;
    /// known-but-newer values from a future binary are refused by the
    /// `TryFrom<u8>` impl.
    pub enum KeyDeviceType ("key_device_type") {
        Software = 0,
        Ledger   = 1,
        Trezor   = 2,
    }
}

repr_u8_enum! {
    /// Password-prompt policy.
    ///
    /// `Never` — wallet is usable without a password prompt (either
    /// passwordless or cached-password mode).
    /// `OnAction` — prompt before any value-moving action (send,
    /// change-password, export).
    /// `ToDecrypt` — prompt whenever the wallet is unlocked from disk.
    /// Safest and the default for new wallets.
    pub enum AskPasswordMode ("ask_password") {
        Never     = 0,
        OnAction  = 1,
        ToDecrypt = 2,
    }
}

/// The identity block of a [`WalletState`](super::WalletState). See
/// module docs for scope and versioning.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityBlock {
    /// Per-block schema version. Always [`IDENTITY_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Network this wallet was created on. The authoritative value lives
    /// in region-0 AAD of the keys file; this field is the load-time
    /// convenience copy, verified against region 0 by the orchestrator
    /// before the state is exposed to callers.
    #[serde(with = "network_as_u8")]
    pub network: Network,

    /// BIP-39 / Shekyl seed-language identifier (e.g. `"English"`).
    /// Empty for view-only and hardware-device wallets that never held
    /// a mnemonic.
    #[serde(default)]
    pub seed_language: String,

    /// Where this wallet's long-term secrets live.
    pub key_device_type: KeyDeviceType,

    /// Password-prompt policy. See [`AskPasswordMode`].
    pub ask_password: AskPasswordMode,

    /// `true` for view-only wallets (the disk has no spend-key material).
    #[serde(default)]
    pub watch_only: bool,

    /// `true` for the companion background-sync wallet file variant
    /// (the `.background-sync.wallet` sibling of a primary wallet).
    #[serde(default)]
    pub is_background_wallet: bool,
}

impl IdentityBlock {
    /// Construct a fresh identity block at the current block version.
    pub fn new(
        network: Network,
        seed_language: String,
        key_device_type: KeyDeviceType,
        ask_password: AskPasswordMode,
    ) -> Self {
        Self {
            block_version: IDENTITY_BLOCK_VERSION,
            network,
            seed_language,
            key_device_type,
            ask_password,
            watch_only: false,
            is_background_wallet: false,
        }
    }

    /// Refuse a load whose block version this binary does not recognize.
    pub(crate) fn check_version(&self) -> Result<(), WalletStateError> {
        if self.block_version != IDENTITY_BLOCK_VERSION {
            return Err(WalletStateError::UnsupportedBlockVersion {
                block: "identity",
                file: self.block_version,
                binary: IDENTITY_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_current_block_version() {
        let id = IdentityBlock::new(
            Network::Mainnet,
            "English".into(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        assert_eq!(id.block_version, IDENTITY_BLOCK_VERSION);
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut id = IdentityBlock::new(
            Network::Mainnet,
            String::new(),
            KeyDeviceType::Software,
            AskPasswordMode::ToDecrypt,
        );
        id.block_version = 999;
        match id.check_version().unwrap_err() {
            WalletStateError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "identity");
                assert_eq!(file, 999);
                assert_eq!(binary, IDENTITY_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn key_device_type_discriminants_pinned() {
        assert_eq!(u8::from(KeyDeviceType::Software), 0);
        assert_eq!(u8::from(KeyDeviceType::Ledger), 1);
        assert_eq!(u8::from(KeyDeviceType::Trezor), 2);
    }

    #[test]
    fn ask_password_discriminants_pinned() {
        assert_eq!(u8::from(AskPasswordMode::Never), 0);
        assert_eq!(u8::from(AskPasswordMode::OnAction), 1);
        assert_eq!(u8::from(AskPasswordMode::ToDecrypt), 2);
    }
}
