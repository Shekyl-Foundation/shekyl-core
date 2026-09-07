// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Master-seed extraction from an open wallet handle.
//!
//! **Live module.** It was written for the 2k → 2m-keys rewire window so
//! the C++ `wallet2::load_keys` shim could pull the master seed across
//! the FFI; that shim and the whole C++ wallet path were deleted in
//! Phase 5 (2026-08-19), and this module stayed because the Rust stack
//! uses the same extraction: the Engine's open path
//! (`shekyl-engine-core::engine::lifecycle::open`) drives
//! `shekyl_account_rederive`, and message signing
//! (`shekyl-engine-core::engine::message_signing`) rederives
//! `msg_sign_sk` from the seed on each call. The "transitional" in the
//! filename is historical; renaming it is a mechanical follow-up, not a
//! deletion.
//!
//! # Why master-seed-only (Option A')
//!
//! The classical Ed25519 spend and view scalars are **outputs** of
//! `shekyl_account_rederive`, not independent secrets. The master seed
//! is the single piece of key material a caller needs to rebuild the
//! account. Exposing only the seed:
//!
//! 1. Keeps the derivation pipeline in one place
//!    (`shekyl_crypto_pq::account`). This module does not run HKDF at
//!    all — it returns the already-authenticated 64 bytes that the
//!    envelope stored under `cap_content`.
//!
//! 2. Preserves the atomic-consistency invariant: the master seed and
//!    its derivatives are *the same secret* viewed at different stages
//!    of the pipeline. Returning only the seed guarantees there is no
//!    intermediate state in which a caller holds the classical scalars
//!    without the seed, or vice versa.
//!
//! # Invariants
//!
//! The handle has already validated at `open` / `create` time that
//! `(network, seed_format)` is a permitted pair per
//! [`DerivationNetwork::permitted_seed_format`]; this module does not
//! re-check. Every wallet is `Capability::Full` (rule 23: ViewOnly is
//! REJECTED, hardware-offload is DEFERRED with zero code — decision log
//! 2026-09-07), and FULL-mode `cap_content` is pinned to 64 bytes by
//! envelope construction, so extraction is infallible: the seed is
//! always on disk and always 64 bytes.

use zeroize::Zeroizing;

use shekyl_crypto_pq::account::MASTER_SEED_BYTES;

use crate::handle::WalletFile;

/// 64-byte master seed extracted from a wallet handle.
/// The inner `Zeroizing` wipes on drop, so any Rust-side intermediary
/// that holds this value in a local variable gets auto-wipe by
/// construction. The FFI layer copies the bytes into a caller-provided
/// C buffer under Rule 40 (zero-fill-on-failure); callers MUST receive
/// the bytes into a wipe-disciplined container.
///
/// Not `Debug`: secret material never prints.
pub struct RederivationInputs {
    pub master_seed_64: Zeroizing<[u8; MASTER_SEED_BYTES]>,
}

impl WalletFile {
    /// Extract the 64-byte master seed needed to drive
    /// `shekyl_account_rederive` and per-call signing-key rederivation.
    ///
    /// Infallible: every wallet is `Capability::Full`, validated at
    /// open/create time, and FULL-mode `cap_content` is pinned to
    /// 64 bytes by the envelope.
    ///
    /// # Panics
    ///
    /// Panics only on a programmer bug: reaching this function with a
    /// non-64-byte `cap_content` means the envelope's own invariant was
    /// violated, which is an internal inconsistency that we refuse to
    /// paper over.
    pub fn extract_rederivation_inputs(&self) -> RederivationInputs {
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
        RederivationInputs {
            master_seed_64: seed_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::handle::CreateParams;
    use crate::WalletFile;
    use shekyl_address::Network;
    use shekyl_crypto_pq::wallet_envelope::{
        CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
    };
    use shekyl_engine_state::WalletLedger;

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

        let inputs = h.extract_rederivation_inputs();
        assert_eq!(inputs.master_seed_64.as_slice(), &seed);
    }

    #[test]
    fn extract_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x77u8; 64];
        let h = open_full_fixture(&tmp, &seed);

        let a = h.extract_rederivation_inputs();
        let b = h.extract_rederivation_inputs();
        assert_eq!(a.master_seed_64.as_slice(), b.master_seed_64.as_slice());
    }
}
