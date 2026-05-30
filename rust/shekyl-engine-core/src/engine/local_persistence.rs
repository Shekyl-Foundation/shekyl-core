// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stage 1 [`PersistenceEngine`](super::traits::PersistenceEngine) implementor:
//! [`shekyl_engine_file::WalletFile`].

use shekyl_engine_file::WalletFile;
use shekyl_engine_prefs::{PrefsHmacKey, WalletPrefs};
use shekyl_engine_state::WalletLedger;

use super::error::PersistenceError;
use super::lifecycle::Credentials;
use super::sealing_keys::StateWrapKey;
use super::traits::PersistenceEngine;
use super::Capability;

impl PersistenceEngine for WalletFile {
    type Error = PersistenceError;

    fn base_path(&self) -> &std::path::Path {
        WalletFile::base_path(self)
    }

    fn network(&self) -> shekyl_address::Network {
        WalletFile::network(self)
    }

    fn capability(&self) -> Capability {
        WalletFile::capability(self)
    }

    fn save_state(
        &self,
        state_key: &StateWrapKey,
        ledger: &WalletLedger,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(
            self.save_state(state_key.as_bytes(), ledger)
                .map_err(PersistenceError::WalletFile),
        )
    }

    fn save_prefs(
        &self,
        prefs_key: &PrefsHmacKey,
        prefs: &WalletPrefs,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(
            shekyl_engine_prefs::save_prefs(self.state_path(), prefs_key, prefs)
                .map_err(PersistenceError::Prefs),
        )
    }

    /// Password-handling moment: rewraps the `file_kek` wrap layer in `.wallet.keys`.
    ///
    /// Region-1 ciphertext and `.wallet` region-2 bytes are unchanged on success
    /// (spec §4.2). Region-2 AEAD AAD is `magic \|\| version \|\| seed_block_tag`
    /// per [`docs/WALLET_FILE_FORMAT_V1.md`](../../../../docs/WALLET_FILE_FORMAT_V1.md)
    /// §2.2 — `seed_block_tag` is the region-1 Poly1305 tag (16 bytes at the tail of
    /// the keys file), not the wrap-header nonce/ciphertext. The in-memory
    /// `keys_file_bytes` cache is updated after a successful rewrap.
    fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: Option<shekyl_crypto_pq::wallet_envelope::KdfParams>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(
            self.rotate_password(old.password(), new.password(), new_kdf)
                .map_err(PersistenceError::WalletFile),
        )
    }
}
