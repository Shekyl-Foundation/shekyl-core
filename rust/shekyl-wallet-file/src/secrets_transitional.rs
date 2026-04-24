// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transitional secret-extraction API for the 2k → 2m-keys rewire window.
//!
//! **This module is scheduled for deletion in commit 2m-keys.** It exists
//! for one reason: the C++ `wallet2` shim still holds the Ed25519 spend
//! and view secret keys in its `m_account` field, and every wallet2 code
//! path that signs a transaction, derives a subaddress, or answers a
//! view-key RPC still reads those bytes directly. Until 2l / 2m-keys
//! relocate those read sites onto the Rust FFI, `load_keys_buf` needs
//! to populate `m_account` with the same scalars the legacy JSON keys
//! file used to produce.
//!
//! The policy pinned in
//! [`docs/wallet-state-promotion_ab273bfe.plan.md`](../../../../.cursor/plans/wallet-state-promotion_ab273bfe.plan.md)
//! (see "2k design pins" under the 2k commit entry) requires the
//! derivation to stay in **one place** (this module) so the
//! `shekyl-master-derive-v1-<network>-<format>` salt contract in
//! [`shekyl_crypto_pq::account`] stays a single source of truth, grep-
//! able in one commit when 2m-keys deletes it. The legacy FFI
//! primitives `shekyl_seed_derive_spend` / `shekyl_seed_derive_view`
//! (labelled "legacy, pending wallet-account-rewire" in
//! `src/shekyl/shekyl_ffi.h`) are **not** called from this path —
//! they predate the per-network salt policy.
//!
//! # Design (from the user's 2k review)
//!
//! - **Typed capability refusal, not zero bytes.** The FFI signature
//!   at the C boundary zero-fills the out-pointers on *any* failure
//!   (rule 40), but the specific "this is a VIEW_ONLY / HARDWARE_OFFLOAD
//!   wallet, spend secret is not on disk" case returns a distinct
//!   [`ExtractClassicalSecretsError`] variant. The C++ call site maps
//!   that to its existing capability-mode-branch, not to a generic
//!   failure with garbage output that a careless caller might forget
//!   to check.
//! - **Leak-on-success defense.** Returning [`ClassicalSecretKeys`]
//!   (scalars in [`Zeroizing`]) keeps the auto-wipe guarantee on the
//!   Rust side of the boundary; the FFI layer performs the
//!   Zeroizing-to-C-buffer copy with rule 40 on every exit edge.
//!
//! # Invariants
//!
//! The handle has already validated at `open` / `create` time that
//! `(network, seed_format)` is a permitted pair per
//! [`DerivationNetwork::permitted_seed_format`]; this module does not
//! re-check.

use zeroize::Zeroizing;

use shekyl_crypto_pq::account::{
    derive_spend_wide, derive_view_wide, wide_reduce_to_scalar, DerivationNetwork, SeedFormat,
    MASTER_SEED_BYTES,
};

use crate::capability::Capability;
use crate::handle::WalletFileHandle;

/// Refusal to extract classical spend + view secret keys from a wallet
/// that is not FULL-capable. Distinct variants per capability so the
/// C++ call site can translate each to its own capability-mode-branch
/// error rather than collapsing them into a generic failure.
///
/// This enum is **not** folded into [`crate::WalletFileError`] on
/// purpose: it is produced only by the transitional extract path and
/// should disappear from the crate entirely in 2m-keys. Keeping it
/// separate makes that deletion a single-symbol grep.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ExtractClassicalSecretsError {
    /// The wallet is a VIEW_ONLY wallet. The spend scalar was never
    /// present in the on-disk `cap_content` (VIEW_ONLY layout stores
    /// `view_sk || ml_kem_dk || spend_pk`, no spend secret). Callers
    /// must treat this as a hard refusal; there is no fallback.
    #[error("view-only wallet: spend secret is not on disk")]
    ViewOnly,

    /// The wallet is a HARDWARE_OFFLOAD wallet. The spend scalar lives
    /// on the hardware device; host-side extraction is a category
    /// error. Callers should dispatch to the hardware signing path.
    #[error("hardware-offload wallet: spend secret lives on device, not host")]
    HardwareOffload,
}

/// Paired Ed25519 spend + view secret scalars, derived from a FULL-mode
/// wallet's 64-byte `master_seed` via the canonical per-network HKDF
/// pipeline and `wide_reduce_to_scalar`.
///
/// Both fields wipe on drop via [`Zeroizing`]. Callers that copy the
/// bytes out must also use a zeroizing container (the FFI's
/// `crypto::secret_key` on the C++ side is a `scrubbed<ec_scalar>`,
/// which satisfies this).
pub struct ClassicalSecretKeys {
    pub spend_secret_key: Zeroizing<[u8; 32]>,
    pub view_secret_key: Zeroizing<[u8; 32]>,
}

impl WalletFileHandle {
    /// Extract the Ed25519 spend + view secret scalars for a FULL-mode
    /// wallet.
    ///
    /// TRANSITIONAL (2k → 2m-keys): this is called from the C++
    /// `wallet2::load_keys_buf` shim to populate `m_account` while
    /// wallet2 still holds plaintext secrets. 2m-keys deletes both
    /// this method and the wallet2 shim that calls it; every
    /// sign / derive / view-key path will by then route through
    /// dedicated FFIs that consume the handle directly.
    ///
    /// # Errors
    ///
    /// * [`ExtractClassicalSecretsError::ViewOnly`] — the wallet is
    ///   VIEW_ONLY. No fallback; the caller must refuse.
    /// * [`ExtractClassicalSecretsError::HardwareOffload`] — the wallet
    ///   is HARDWARE_OFFLOAD. The caller must dispatch to the
    ///   hardware signing path.
    ///
    /// # Panics
    ///
    /// Panics only on a programmer bug: the handle has already
    /// validated `(network, seed_format, capability)` at open/create
    /// time and a FULL-mode `cap_content` is exactly 64 bytes by
    /// envelope construction. If either invariant is violated this
    /// function panics rather than returning degraded material; the
    /// expectation is that every path into this function has been
    /// through the envelope's own validation.
    pub fn extract_classical_secret_keys(
        &self,
    ) -> Result<ClassicalSecretKeys, ExtractClassicalSecretsError> {
        match self.capability() {
            Capability::Full => {}
            Capability::ViewOnly => return Err(ExtractClassicalSecretsError::ViewOnly),
            Capability::HardwareOffload => {
                return Err(ExtractClassicalSecretsError::HardwareOffload);
            }
        }

        let opened = self.opened_keys();

        let net = DerivationNetwork::from_u8(opened.network).expect(
            "envelope validated network byte at open time; \
             reaching here with an unknown network is a programmer bug",
        );
        let fmt = SeedFormat::from_u8(opened.seed_format).expect(
            "envelope validated seed_format byte at open time; \
             reaching here with an unknown seed_format is a programmer bug",
        );
        debug_assert!(
            net.permitted_seed_format(fmt),
            "open-path validated (network, seed_format) pair; extract must see the same pair"
        );

        let cap_content: &[u8] = opened.cap_content.as_slice();
        assert_eq!(
            cap_content.len(),
            MASTER_SEED_BYTES,
            "FULL capability_mode cap_content length is pinned to 64 bytes by the envelope; \
             reaching here with a different length is a programmer bug"
        );
        let master_seed: &[u8; MASTER_SEED_BYTES] = cap_content
            .try_into()
            .expect("length checked by the assert above");

        let spend_wide = derive_spend_wide(master_seed, net, fmt);
        let view_wide = derive_view_wide(master_seed, net, fmt);

        let spend_scalar = wide_reduce_to_scalar(&spend_wide);
        let view_scalar = wide_reduce_to_scalar(&view_wide);

        let mut spend_bytes = Zeroizing::new([0u8; 32]);
        let mut view_bytes = Zeroizing::new([0u8; 32]);
        spend_bytes.copy_from_slice(spend_scalar.as_bytes());
        view_bytes.copy_from_slice(view_scalar.as_bytes());

        Ok(ClassicalSecretKeys {
            spend_secret_key: spend_bytes,
            view_secret_key: view_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::CreateParams;
    use crate::overrides::SafetyOverrides;
    use crate::WalletFileHandle;
    use shekyl_address::Network;
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_crypto_pq::wallet_envelope::{
        CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
    };
    use shekyl_wallet_state::WalletLedger;

    /// Minimum-wall-clock KDF profile; matches the KAT relaxation used
    /// by the rest of this crate's test suite. Argon2id at production
    /// settings would push this past multi-second territory.
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        }
    }

    /// Build a FULL wallet under `tmp` with a known 64-byte master
    /// seed and return the opened handle. The envelope stores
    /// `expected_classical_address` byte-for-byte without a FULL-mode
    /// derivation cross-check (see `wallet_envelope.rs` §1426 comment),
    /// so a dummy address is sufficient for this unit's scope.
    fn open_full_fixture(tmp: &tempfile::TempDir, master_seed_64: &[u8; 64]) -> WalletFileHandle {
        let base = tmp.path().join("w");
        let password: &[u8] = b"test-password";

        let mut addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        addr[0] = 0x01;

        let params = CreateParams {
            base_path: &base,
            password,
            // Testnet + Raw32 is a permitted (network, seed_format)
            // pair per `DerivationNetwork::permitted_seed_format`.
            network: Network::Testnet,
            seed_format: 0x02, // SEED_FORMAT_RAW32
            capability: &CapabilityContent::Full { master_seed_64 },
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 0,
            expected_classical_address: &addr,
            kdf: fast_kdf(),
            initial_ledger: &WalletLedger::empty(),
        };
        WalletFileHandle::create(&params).expect("create FULL fixture")
    }

    #[test]
    fn extract_full_returns_expected_scalars() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x42u8; 64];
        let h = open_full_fixture(&tmp, &seed);

        let secrets = h
            .extract_classical_secret_keys()
            .expect("FULL wallet must yield classical secrets");

        let spend_wide = derive_spend_wide(&seed, DerivationNetwork::Testnet, SeedFormat::Raw32);
        let view_wide = derive_view_wide(&seed, DerivationNetwork::Testnet, SeedFormat::Raw32);
        let expected_spend = wide_reduce_to_scalar(&spend_wide);
        let expected_view = wide_reduce_to_scalar(&view_wide);

        assert_eq!(
            secrets.spend_secret_key.as_slice(),
            expected_spend.as_bytes()
        );
        assert_eq!(secrets.view_secret_key.as_slice(), expected_view.as_bytes());
    }

    #[test]
    fn extract_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x77u8; 64];
        let h = open_full_fixture(&tmp, &seed);

        let a = h.extract_classical_secret_keys().unwrap();
        let b = h.extract_classical_secret_keys().unwrap();
        assert_eq!(a.spend_secret_key.as_slice(), b.spend_secret_key.as_slice());
        assert_eq!(a.view_secret_key.as_slice(), b.view_secret_key.as_slice());
    }

    /// VIEW_ONLY wallets must refuse extraction with the typed
    /// [`ExtractClassicalSecretsError::ViewOnly`] variant so the C++
    /// call site can dispatch to its view-only-only code path rather
    /// than propagating a generic failure.
    #[test]
    fn view_only_refuses_with_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("w");
        let password: &[u8] = b"test-password";

        let view_sk = [0x11u8; 32];
        let ml_kem_dk = [0x22u8; ML_KEM_768_DK_LEN];
        let spend_pk = [0x33u8; 32];
        let mut addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        addr[0] = 0x01;

        let params = CreateParams {
            base_path: &base,
            password,
            network: Network::Testnet,
            seed_format: 0x02,
            capability: &CapabilityContent::ViewOnly {
                view_sk: &view_sk,
                ml_kem_dk: &ml_kem_dk,
                spend_pk: &spend_pk,
            },
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 0,
            expected_classical_address: &addr,
            kdf: fast_kdf(),
            initial_ledger: &WalletLedger::empty(),
        };
        let h = WalletFileHandle::create(&params).expect("create VIEW_ONLY fixture");

        match h.extract_classical_secret_keys() {
            Err(ExtractClassicalSecretsError::ViewOnly) => {}
            Err(other) => panic!("expected ViewOnly, got {other:?}"),
            // Keep `ClassicalSecretKeys` off any `Debug` path: it
            // contains secret scalars and deliberately does not
            // implement `Debug` (see crate-level secret-locality rule).
            Ok(_) => panic!("expected ViewOnly refusal, got Ok(ClassicalSecretKeys)"),
        }
    }

    #[test]
    fn refusal_variants_are_distinct() {
        // Compile-time guard that the two refusal variants did not
        // collapse into a single "NotFull" variant during review.
        assert_ne!(
            ExtractClassicalSecretsError::ViewOnly,
            ExtractClassicalSecretsError::HardwareOffload
        );
    }

    // `SafetyOverrides::none()` is imported to keep the `open` API
    // reachable from this module without future import churn.
    #[allow(dead_code)]
    fn _keep_overrides_ref() -> SafetyOverrides {
        SafetyOverrides::none()
    }
}
