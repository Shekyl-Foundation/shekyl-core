// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Seed extraction from an open wallet handle.
//!
//! The Engine's open path (`shekyl-engine-core::engine::lifecycle::open`)
//! rederives the account from what this returns, and message signing
//! (`shekyl-engine-core::engine::message_signing`) rederives `msg_sign_sk`
//! from it on each call.
//!
//! # One secret (`NETWORK_IDENTITY.md` NI-R7)
//!
//! A wallet's secret is its 32-byte seed; the keys file stores exactly
//! that, and the 24 words are its spelling. The master seed and every key
//! are **outputs** of the seed (`shekyl_crypto_pq::account`), not
//! independent secrets. This returns the seed and the master seed
//! normalised from it, so a caller can show the words or rebuild the
//! account, and holds nothing else.
//!
//! # Invariants
//!
//! Every wallet is `Capability::Full` (rule 23: ViewOnly is REJECTED,
//! hardware-offload is DEFERRED with zero code — decision log 2026-09-07),
//! and FULL-mode `cap_content` is pinned to 32 bytes by envelope
//! construction, so extraction is infallible.

use zeroize::Zeroizing;

use shekyl_crypto_pq::account::{normalize_seed, MASTER_SEED_BYTES, SEED_BYTES};

use crate::handle::WalletFile;

/// The seed and its master seed, extracted from a wallet handle.
/// The inner `Zeroizing` wipes on drop, so any Rust-side intermediary
/// that holds this value in a local variable gets auto-wipe by
/// construction.
///
/// Not `Debug`: secret material never prints.
pub struct RederivationInputs {
    /// The wallet's 32-byte seed: the bytes its 24 words spell.
    pub seed: Zeroizing<[u8; SEED_BYTES]>,
    /// `normalize_seed(seed)`: what every key expands from.
    pub master_seed_64: Zeroizing<[u8; MASTER_SEED_BYTES]>,
}

impl WalletFile {
    /// Extract the seed and its master seed, for rederivation and
    /// per-call signing-key rederivation.
    ///
    /// Infallible: every wallet is `Capability::Full`, validated at
    /// open/create time, and FULL-mode `cap_content` is pinned to
    /// 32 bytes by the envelope.
    ///
    /// # Panics
    ///
    /// Panics only on a programmer bug: reaching this function with a
    /// `cap_content` of any other length means the envelope's own
    /// invariant was violated, which we refuse to paper over.
    pub fn extract_rederivation_inputs(&self) -> RederivationInputs {
        let opened = self.opened_keys();
        let cap_content: &[u8] = opened.cap_content.as_slice();
        assert_eq!(
            cap_content.len(),
            SEED_BYTES,
            "FULL capability_mode cap_content length is pinned to 32 bytes by the envelope; \
             reaching here with a different length is a programmer bug"
        );

        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        seed.copy_from_slice(cap_content);
        let master_seed_64 = normalize_seed(seed.as_ref());
        RederivationInputs {
            seed,
            master_seed_64,
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

    /// Build a FULL wallet under `tmp` with a known 32-byte seed and
    /// return the opened handle.
    fn open_full_fixture(tmp: &tempfile::TempDir, seed: &[u8; 32]) -> WalletFile {
        let base = tmp.path().join("w");
        let password: &[u8] = b"test-password";

        let mut addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        addr[0] = 0x01;

        let params = CreateParams {
            base_path: &base,
            password,
            network: Network::Testnet,
            capability: &CapabilityContent::Full { seed },
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 0,
            expected_classical_address: &addr,
            kdf: fast_kdf(),
            initial_ledger: &WalletLedger::empty(),
        };
        WalletFile::create(&params).expect("create FULL fixture")
    }

    #[test]
    fn extract_full_returns_the_seed_and_its_master_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x42u8; 32];
        let h = open_full_fixture(&tmp, &seed);

        let inputs = h.extract_rederivation_inputs();
        assert_eq!(inputs.seed.as_slice(), &seed);
        assert_eq!(
            inputs.master_seed_64.as_slice(),
            shekyl_crypto_pq::account::normalize_seed(&seed).as_slice()
        );
    }

    #[test]
    fn extract_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = [0x77u8; 32];
        let h = open_full_fixture(&tmp, &seed);

        let a = h.extract_rederivation_inputs();
        let b = h.extract_rederivation_inputs();
        assert_eq!(a.seed.as_slice(), b.seed.as_slice());
        assert_eq!(a.master_seed_64.as_slice(), b.master_seed_64.as_slice());
    }
}
