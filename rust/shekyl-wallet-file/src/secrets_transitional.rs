// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transitional master-seed extraction API for the 2k → 2m-keys rewire
//! window.
//!
//! **This module is scheduled for deletion in commit 2m-keys.** It exists
//! so the C++ `wallet2::load_keys` shim can pull the 64-byte
//! `master_seed` out of a FULL-mode `ShekylWallet` handle in order to
//! drive the existing (non-transitional)
//! `shekyl_account_rederive` FFI that reconstructs
//! `m_spend_secret_key`, `m_view_secret_key`, `m_ml_kem_decap_key`, and
//! `m_account_address` locally on the C++ side.
//!
//! # Why master-seed-only (Option A')
//!
//! The classical Ed25519 spend and view scalars are **outputs** of
//! `shekyl_account_rederive`, not independent secrets. The master seed
//! is the single piece of key material that needs to cross the FFI
//! boundary for C++ to finish populating `m_account`. Exposing only the
//! seed:
//!
//! 1. Keeps the derivation pipeline in one place on the Rust side
//!    (`shekyl_crypto_pq::account`). The transitional module does not
//!    run HKDF at all — it just authenticates the caller (capability
//!    gating) and returns the already-authenticated 64 bytes that the
//!    envelope stored under `cap_content`.
//!
//! 2. Preserves the atomic-consistency invariant: the master seed and
//!    its derivatives are *the same secret* viewed at different stages
//!    of the pipeline. Returning only the seed guarantees there is no
//!    intermediate state in which C++ holds the classical scalars
//!    without the seed, or vice versa.
//!
//! 3. Shrinks the deletion surface in 2m-keys to a single 64-byte
//!    out-parameter and a single error-enum definition.
//!
//! # Post-rederive scrub (Option β)
//!
//! After C++ drives `shekyl_account_rederive`, the master seed sits in
//! `m_account.m_keys.m_master_seed_64` alongside the freshly-built
//! `m_ml_kem_decap_key`. The 2k.a design pins (`docs/
//! wallet-state-promotion_ab273bfe.plan.md` pin 11) require the C++
//! caller to immediately scrub `m_master_seed_64` via
//! `account_base::forget_master_seed()` once the decap key has been
//! built. That keeps the `ShekylWallet` handle (this module's owner)
//! as the single in-memory source of truth for the master seed,
//! halving the memory-disclosure surface across the rewire window.
//!
//! # Invariants
//!
//! The handle has already validated at `open` / `create` time that
//! `(network, seed_format)` is a permitted pair per
//! [`DerivationNetwork::permitted_seed_format`]; this module does not
//! re-check. FULL-mode `cap_content` is pinned to 64 bytes by envelope
//! construction, so the returned slice always has that length on the
//! success edge.

use zeroize::Zeroizing;

use shekyl_crypto_pq::account::MASTER_SEED_BYTES;

use crate::capability::Capability;
use crate::handle::WalletFile;

/// Refusal to extract the master seed from a wallet that is not
/// FULL-capable. Distinct variants per capability so the C++ call site
/// can translate each to its own capability-mode-branch error rather
/// than collapsing them into a generic failure.
///
/// Not folded into [`crate::WalletFileError`] on purpose: produced
/// only by the transitional extract path and scheduled for wholesale
/// deletion in 2m-keys. Keeping it separate makes that deletion a
/// single-symbol grep.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ExtractRederivationInputsError {
    /// The wallet is a VIEW_ONLY wallet. The spend scalar — and the
    /// master seed — were never present on disk (VIEW_ONLY layout
    /// stores `view_sk || ml_kem_dk || spend_pk`). Callers must treat
    /// this as a hard refusal; there is no fallback.
    #[error("view-only wallet: master seed is not on disk")]
    ViewOnly,

    /// The wallet is a HARDWARE_OFFLOAD wallet. The master seed lives
    /// on the hardware device; host-side extraction is a category
    /// error. Callers should dispatch to the hardware signing path.
    #[error("hardware-offload wallet: master seed lives on device, not host")]
    HardwareOffload,
}

/// 64-byte master seed extracted from a FULL-mode wallet handle.
/// The inner `Zeroizing` wipes on drop, so any Rust-side intermediary
/// that holds this value in a local variable gets auto-wipe by
/// construction. The FFI layer copies the bytes into a caller-provided
/// C buffer under Rule 40 (zero-fill-on-failure); callers on the C++
/// side MUST receive the bytes into a wipe-disciplined container (see
/// `wallet2.cpp::TransitionalSecretKeys`).
///
/// Not `Debug`: secret material never prints.
pub struct RederivationInputs {
    pub master_seed_64: Zeroizing<[u8; MASTER_SEED_BYTES]>,
}

impl WalletFile {
    /// Extract the 64-byte master seed needed to drive
    /// `shekyl_account_rederive` on the C++ side.
    ///
    /// TRANSITIONAL (2k → 2m-keys): called once at wallet open from
    /// `wallet2::load_keys`. Not called from any other C++ site and
    /// not exposed outside the FFI.
    ///
    /// # Errors
    ///
    /// * [`ExtractRederivationInputsError::ViewOnly`] — the wallet is
    ///   VIEW_ONLY. No fallback; the caller must refuse.
    /// * [`ExtractRederivationInputsError::HardwareOffload`] — the
    ///   wallet is HARDWARE_OFFLOAD. The caller must dispatch to the
    ///   hardware signing path.
    ///
    /// # Panics
    ///
    /// Panics only on a programmer bug: the handle has already
    /// validated capability and FULL-mode `cap_content` length at
    /// open/create time. Reaching this function with a non-64-byte
    /// `cap_content` under FULL capability means the envelope's own
    /// invariant was violated, which is an internal inconsistency
    /// that we refuse to paper over.
    pub fn extract_rederivation_inputs(
        &self,
    ) -> Result<RederivationInputs, ExtractRederivationInputsError> {
        match self.capability() {
            Capability::Full => {}
            Capability::ViewOnly => return Err(ExtractRederivationInputsError::ViewOnly),
            Capability::HardwareOffload => {
                return Err(ExtractRederivationInputsError::HardwareOffload);
            }
        }

        let opened = self.opened_keys();
        let cap_content: &[u8] = opened.cap_content.as_slice();
        assert_eq!(
            cap_content.len(),
            MASTER_SEED_BYTES,
            "FULL capability_mode cap_content length is pinned to 64 bytes by the envelope; \
             reaching here with a different length is a programmer bug"
        );

        let mut seed_bytes = Zeroizing::new([0u8; MASTER_SEED_BYTES]);
        seed_bytes.copy_from_slice(cap_content);
        Ok(RederivationInputs {
            master_seed_64: seed_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::CreateParams;
    use crate::overrides::SafetyOverrides;
    use crate::WalletFile;
    use shekyl_address::Network;
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_crypto_pq::wallet_envelope::{
        CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
    };
    use shekyl_wallet_state::WalletLedger;

    /// Minimum-wall-clock KDF profile; matches the KAT relaxation used
    /// by the rest of this crate's test suite.
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        }
    }

    /// Build a FULL wallet under `tmp` with a known 64-byte master
    /// seed and return the opened handle.
    fn open_full_fixture(tmp: &tempfile::TempDir, master_seed_64: &[u8; 64]) -> WalletFile {
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
        WalletFile::create(&params).expect("create FULL fixture")
    }

    #[test]
    fn extract_full_returns_master_seed_bytewise() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x42u8; 64];
        let h = open_full_fixture(&tmp, &seed);

        let inputs = h
            .extract_rederivation_inputs()
            .expect("FULL wallet must yield the master seed");
        assert_eq!(inputs.master_seed_64.as_slice(), &seed);
    }

    #[test]
    fn extract_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x77u8; 64];
        let h = open_full_fixture(&tmp, &seed);

        let a = h.extract_rederivation_inputs().unwrap();
        let b = h.extract_rederivation_inputs().unwrap();
        assert_eq!(a.master_seed_64.as_slice(), b.master_seed_64.as_slice());
    }

    /// VIEW_ONLY wallets must refuse extraction with the typed
    /// [`ExtractRederivationInputsError::ViewOnly`] variant so the C++
    /// call site can dispatch to its view-only code path rather than
    /// propagating a generic failure.
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
        let h = WalletFile::create(&params).expect("create VIEW_ONLY fixture");

        match h.extract_rederivation_inputs() {
            Err(ExtractRederivationInputsError::ViewOnly) => {}
            Err(other) => panic!("expected ViewOnly, got {other:?}"),
            // Keep `RederivationInputs` off any `Debug` path: it holds
            // secret material and deliberately does not implement
            // `Debug` (see crate-level secret-locality rule).
            Ok(_) => panic!("expected ViewOnly refusal, got Ok(RederivationInputs)"),
        }
    }

    #[test]
    fn refusal_variants_are_distinct() {
        assert_ne!(
            ExtractRederivationInputsError::ViewOnly,
            ExtractRederivationInputsError::HardwareOffload
        );
    }

    /// `SafetyOverrides::none()` is imported to keep the `open` API
    /// reachable from this module without future import churn.
    #[allow(dead_code)]
    fn _keep_overrides_ref() -> SafetyOverrides {
        SafetyOverrides::none()
    }
}
