// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's wallet side: the deterministic miner every fixture
//! coinbase pays, the recipients a scenario pays, and a coinbase composed
//! as that wallet will scan it.
//!
//! # Why a crate, and why this one is wallet-side only
//!
//! The rules crate's `harness` feature builds the coinbase every fixture
//! block carries, and the store's and the ingest's tests spend those
//! coinbases through a real prover. One wallet therefore has to be
//! reachable from both sides — the composer that pays it and the spender
//! that scans and spends what it was paid — and the rules crate's no-store
//! belt (`check_chain_rules_no_store.sh`, over normal **and** dev edges)
//! forbids the rules crate from reaching `shekyl-curve-tree`, which the
//! spender needs for the tree walk and `redb`-backs. So the identities and
//! the composition live here, with nothing of the tree in the closure, and
//! the spending half lives in a sibling crate that depends on this one.
//!
//! # The second-oracle property
//!
//! [`coinbase::paying`] composes a coinbase from the same two owners
//! `shekyl-block-template` composes its own from —
//! [`shekyl_crypto_pq::output::construct_output`] for the output and
//! [`shekyl_wire::tx_extra::build_coinbase_extra`] for the `extra` — and
//! shares no code with the template above those owners. It is written from
//! the census, not copied from the template: a test that validates both a
//! template's coinbase and a fixture's is judging two independent
//! producers against one validator, and a composition defect in either is
//! a disagreement the validator reports rather than a shared blind spot.
//! The template is production; this crate is not, and it must never become
//! what the template reads.
//!
//! # Determinism
//!
//! Every value here is a function of a seed and a height. The miner is
//! derived from [`HARNESS_SEED`] through the wallet stack's own seed
//! derivations (`SeedDerivation`, `ml_kem_keypair_from_d_z`), so the same
//! coinbase bytes come out of every test run and every crate — a fixture
//! pinned in one place is the fixture every other place builds. The one
//! thing a production wallet does that this one does not is draw the seed
//! at random.

#![forbid(unsafe_code)]

pub mod coinbase;

use std::sync::LazyLock;

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_crypto_pq::account::ml_kem_keypair_from_d_z;
use shekyl_crypto_pq::kem::{HybridKemSecretKey, SeedDerivation};
use zeroize::Zeroizing;

/// The seed the harness miner is derived from. Public on purpose: this
/// wallet exists so tests can spend what fixtures pay, and a secret that
/// every test binary carries is not a secret.
pub const HARNESS_SEED: [u8; 32] = *b"shekyl-harness-wallet-miner-v1\0\0";

/// What a payer needs of a wallet: the three public keys an output is
/// addressed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// The Edwards spend public key (`B`).
    pub spend_public: [u8; 32],
    /// X25519 half of the hybrid KEM target.
    pub x25519_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_ek: Vec<u8>,
}

/// A miner's wallet, secrets included: the Edwards spend pair and the
/// hybrid KEM decapsulation keys the coinbase's `0x06` field is
/// encapsulated to. Kept whole rather than reduced to its
/// [`Recipient`] because the point of the harness paying a wallet is that
/// a test can later spend what it was paid.
pub struct MinerWallet {
    /// The Edwards spend secret `b`; `spend_public = b·G`.
    spend_secret: Zeroizing<[u8; 32]>,
    /// The hybrid KEM decapsulation keys.
    kem_secret: HybridKemSecretKey,
    /// The public half, as a payer sees it.
    recipient: Recipient,
}

impl MinerWallet {
    /// The wallet `seed` derives, through the stack's own derivations:
    /// the spend secret is `derive_ed25519_spend`, the X25519 scalar is
    /// `derive_ed25519_view` (its public key the raw scalar times the
    /// basepoint, as `HybridX25519MlKem::keypair_generate` forms it), and
    /// the ML-KEM-768 pair is `ml_kem_keypair_from_d_z` over
    /// `derive_ml_kem_seed`.
    ///
    /// # Panics
    ///
    /// ML-KEM-768 key generation is total over a 64-byte seed; a failure
    /// is a broken primitive, not a seed to handle.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let spend = Zeroizing::new(Scalar::from_bytes_mod_order(
            SeedDerivation::derive_ed25519_spend(seed),
        ));
        let view = Zeroizing::new(Scalar::from_bytes_mod_order(
            SeedDerivation::derive_ed25519_view(seed),
        ));
        let d_z = Zeroizing::new(SeedDerivation::derive_ml_kem_seed(seed));
        let (ml_kem_ek, ml_kem_dk) =
            ml_kem_keypair_from_d_z(&d_z).expect("ML-KEM-768 keygen is total over a 64-byte seed");
        Self {
            spend_secret: Zeroizing::new(spend.to_bytes()),
            kem_secret: HybridKemSecretKey {
                x25519: view.to_bytes(),
                ml_kem: ml_kem_dk.as_canonical_bytes().to_vec(),
            },
            recipient: Recipient {
                spend_public: EdwardsPoint::mul_base(&spend).compress().to_bytes(),
                x25519_pk: (*view * X25519_BASEPOINT).to_bytes(),
                ml_kem_ek: ml_kem_ek.to_vec(),
            },
        }
    }

    /// The harness miner — [`from_seed`](Self::from_seed) over
    /// [`HARNESS_SEED`], derived once per process. Every
    /// [`coinbase::paying`] call the rules harness makes pays this wallet.
    #[must_use]
    pub fn harness() -> &'static MinerWallet {
        static HARNESS: LazyLock<MinerWallet> =
            LazyLock::new(|| MinerWallet::from_seed(&HARNESS_SEED));
        &HARNESS
    }

    /// The public half, as a payer addresses it.
    #[must_use]
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    /// The Edwards spend secret `b`.
    #[must_use]
    pub fn spend_secret(&self) -> &[u8; 32] {
        &self.spend_secret
    }

    /// The hybrid KEM decapsulation keys.
    #[must_use]
    pub fn kem_secret(&self) -> &HybridKemSecretKey {
        &self.kem_secret
    }
}

impl core::fmt::Debug for MinerWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinerWallet")
            .field("spend_secret", &"[REDACTED]")
            .field("kem_secret", &self.kem_secret)
            .field("recipient", &self.recipient)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_miner_is_a_function_of_its_seed() {
        let again = MinerWallet::from_seed(&HARNESS_SEED);
        assert_eq!(MinerWallet::harness().recipient(), again.recipient());
        assert_eq!(MinerWallet::harness().spend_secret(), again.spend_secret());
        assert_eq!(
            MinerWallet::harness().kem_secret().ml_kem,
            again.kem_secret().ml_kem
        );
    }

    #[test]
    fn two_seeds_are_two_wallets() {
        let other = MinerWallet::from_seed(&[0x11; 32]);
        assert_ne!(MinerWallet::harness().recipient(), other.recipient());
    }
}
