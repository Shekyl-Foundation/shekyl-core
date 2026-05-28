// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stage 1 [`PersistenceEngine`](super::traits::PersistenceEngine) implementor:
//! [`shekyl_engine_file::WalletFile`].

use shekyl_engine_file::{WalletFile, WalletFileError};
use shekyl_engine_prefs::{PrefsHmacKey, WalletPrefs};
use shekyl_engine_state::WalletLedger;

use super::lifecycle::Credentials;
use super::sealing_keys::StateWrapKey;
use super::traits::PersistenceEngine;
use super::Capability;

impl PersistenceEngine for WalletFile {
    type Error = WalletFileError;

    fn base_path(&self) -> &std::path::Path {
        WalletFile::base_path(self)
    }

    fn network(&self) -> shekyl_address::Network {
        WalletFile::network(self)
    }

    fn capability(&self) -> Capability {
        WalletFile::capability(self)
    }

    async fn save_state(
        &self,
        state_key: &StateWrapKey,
        ledger: &WalletLedger,
    ) -> Result<(), Self::Error> {
        self.save_state_with_wrap_key_region_2(state_key.as_bytes(), ledger)
    }

    async fn save_prefs(
        &self,
        prefs_key: &PrefsHmacKey,
        prefs: &WalletPrefs,
    ) -> Result<(), Self::Error> {
        shekyl_engine_prefs::save_prefs(self.state_path(), prefs_key, prefs)?;
        Ok(())
    }

    async fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: shekyl_crypto_pq::wallet_envelope::KdfParams,
    ) -> Result<(), Self::Error> {
        self.rotate_password(old.password(), new.password(), Some(new_kdf))
    }
}

