// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Session sealing-key newtypes for [`PersistenceEngine`](super::traits::persistence::PersistenceEngine).
//!
//! [`StateWrapKey`] is the steady-state region-2 AEAD key (`wrap_key_region_2`
//! per [`docs/WALLET_FILE_FORMAT_V1.md`](../../../../docs/WALLET_FILE_FORMAT_V1.md)
//! §2.6 / HKDF amendment). [`shekyl_engine_prefs::PrefsHmacKey`] covers prefs
//! integrity. Password material stays on open / `rotate_password` only.

use std::fmt;

use shekyl_engine_prefs::hmac_key::FILE_KEK_BYTES;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Steady-state ledger seal key: HKDF-derived `wrap_key_region_2`.
///
/// Orchestrator holds `Zeroizing<StateWrapKey>` after open; trait methods take
/// `&StateWrapKey<'_>` (borrowed view). Not [`Clone`] — re-derive after
/// `rotate_password` when the wrap layer changes.
#[derive(ZeroizeOnDrop)]
pub struct StateWrapKey(Zeroizing<[u8; FILE_KEK_BYTES]>);

impl StateWrapKey {
    /// Construct from HKDF output (`derive_wrap_key_region_2`).
    pub fn from_region2_key(key: Zeroizing<[u8; FILE_KEK_BYTES]>) -> Self {
        Self(key)
    }

    /// Borrow the 32-byte AEAD key for region 2.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; FILE_KEK_BYTES] {
        &self.0
    }
}

impl fmt::Debug for StateWrapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateWrapKey(<redacted>)")
    }
}

impl fmt::Display for StateWrapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Derive session `wrap_key_region_2` from an opened [`WalletFile`](shekyl_engine_file::WalletFile).
pub(crate) fn state_wrap_key_from_wallet_file(
    file: &shekyl_engine_file::WalletFile,
) -> StateWrapKey {
    use shekyl_crypto_pq::wallet_envelope::derive_wrap_key_region_2;

    let file_kek = &file.opened_keys().file_kek;
    let addr = file.expected_classical_address();
    let wrap_key_region_2 = derive_wrap_key_region_2(file_kek, addr);
    StateWrapKey::from_region2_key(wrap_key_region_2)
}
