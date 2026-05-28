// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PersistenceEngine` trait surface.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.6 (PR 6 Phase 0a) and
//! [`docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md`] §5.9 (F5(b)), steady-state
//! persistence takes HKDF-derived sealing keys — not passwords. Stage 1
//! implementor: [`shekyl_engine_file::WalletFile`]; Stage 4:
//! `ActorRef<PersistenceActor>` with the same trait.
//!
//! # Backup warning (G4)
//!
//! Wallet files under the user's home directory may be copied by OS backup
//! tools (Time Machine, iCloud Drive, Dropbox). Encrypted blobs still leak to
//! third-party storage; offline password guessing remains a threat. Operators
//! should exclude wallet paths from cloud backup where the platform allows.
//!
//! # Durability and nonces
//!
//! On `Ok`, `.wallet` bytes are durable across power loss (`atomic_write_file`:
//! tmp → fsync → rename → fsync parent). Region-2 AEAD uses a fresh 24-byte
//! nonce from the OS CSPRNG on every save — never counter-derived
//! (`seal_state_file` in `shekyl-crypto-pq`).
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md

use std::path::Path;

use shekyl_address::Network;
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_prefs::{PrefsHmacKey, WalletPrefs};
use shekyl_engine_state::WalletLedger;

use crate::engine::error::PersistenceError;
use crate::engine::lifecycle::Credentials;
use crate::engine::sealing_keys::StateWrapKey;
use crate::engine::Capability;

/// On-disk wallet persistence: state flush, prefs flush, password rotation.
///
/// Hydration (`open` / `create`) stays on [`Engine`](super::super::Engine)
/// constructors per Q9.11 — not on this trait.
pub(crate) trait PersistenceEngine: Send + Sync + 'static {
    /// Save/rotate vocabulary — not [`OpenError`](super::super::OpenError).
    type Error: Into<PersistenceError>;

    fn base_path(&self) -> &Path;
    fn network(&self) -> Network;
    fn capability(&self) -> Capability;

    /// Seal and atomically write `.wallet` for `ledger`.
    ///
    /// `state_key` is `wrap_key_region_2` for this session. After a successful
    /// [`rotate_password`](Self::rotate_password), previously cached keys are
    /// **stale** — re-derive before the next save (Poly1305 MAC failure).
    async fn save_state(
        &self,
        state_key: &StateWrapKey,
        ledger: &WalletLedger,
    ) -> Result<(), Self::Error>;

    async fn save_prefs(
        &self,
        prefs_key: &PrefsHmacKey,
        prefs: &WalletPrefs,
    ) -> Result<(), Self::Error>;

    /// Password-handling moment: Argon2 rewrap of the keys file. Does not
    /// rewrite region-2 ciphertext on success (spec §4.2).
    async fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: KdfParams,
    ) -> Result<(), Self::Error>;
}
