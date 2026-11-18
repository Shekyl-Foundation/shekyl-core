// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where the harness's signatures and proofs draw their randomness: the OS,
//! as the production signers draw it, or a seed the caller names for one
//! spend, so a chain built twice from one plan comes out byte for byte the
//! same (`CHAIN_FORGE.md` §5.3, seam T4). The seeded forms exist only under
//! this crate's TEST_ONLY `seeded-rng` feature, which forwards the seeded
//! signers and provers below it (`shekyl-tx-builder`, `shekyl-crypto-pq`,
//! `shekyl-fcmp`).

use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSecretKey, SignatureScheme as _};
#[cfg(feature = "seeded-rng")]
use zeroize::Zeroizing;

/// A signer's ML-DSA randomness: the OS's (the default), or under
/// `seeded-rng` one fixed seed for every signature the signer makes. A fixed
/// per-signer `rnd` is FIPS 204's deterministic signing with the zero `rnd`
/// replaced by the signer's own; ML-DSA reveals nothing about `rnd`, and a
/// signature stays bound to its message and key. The Ed25519 half is
/// deterministic either way.
#[derive(Clone, Default)]
pub(crate) struct MlDsaDraw {
    seed: Option<DrawSeed>,
}

/// A signer's fixed ML-DSA seed. In a build without `seeded-rng` the type
/// has no value, so a draw is always the OS's and the seeded arm is absent.
#[cfg(feature = "seeded-rng")]
type DrawSeed = Zeroizing<[u8; shekyl_crypto_pq::signature::ML_DSA_SIGNING_SEED_LEN]>;
#[cfg(not(feature = "seeded-rng"))]
#[derive(Clone)]
enum DrawSeed {}

impl MlDsaDraw {
    /// Every signature draws ML-DSA's `rnd` from `seed`.
    #[cfg(feature = "seeded-rng")]
    pub(crate) fn seeded(seed: &[u8; 32]) -> Self {
        Self {
            seed: Some(Zeroizing::new(*seed)),
        }
    }

    /// `sk`'s hybrid signature over `message` under `domain`, canonical
    /// bytes.
    ///
    /// # Panics
    ///
    /// If the key does not sign or the signature does not encode: a harness
    /// key that fails is a broken fixture.
    pub(crate) fn sign(&self, sk: &HybridSecretKey, domain: &[u8], message: &[u8]) -> Vec<u8> {
        let signature = match &self.seed {
            #[cfg(feature = "seeded-rng")]
            Some(seed) => HybridEd25519MlDsa.sign_with_ml_dsa_seed(sk, domain, message, seed),
            _ => HybridEd25519MlDsa.sign(sk, domain, message),
        };
        signature
            .expect("the harness key signs")
            .to_canonical_bytes()
            .expect("a hybrid signature encodes")
    }
}

/// The seeds one spend draws, one per source of randomness
/// (`CHAIN_FORGE.md` §5.2): the range proof's, the pseudo-out blinds', the
/// membership proof's ([`shekyl_tx_builder::ProofSeeds`]) and the spend
/// slots' signatures', apart, so no randomness is shared between them and
/// one source can be swapped for the OS's without moving the others.
///
/// One value per spend, drawn by [`SpendPlan::next_spend`] on the planning
/// thread (or built by the forge from its own derivation,
/// [`Self::from_parts`]) and moved to the worker that builds that spend. A
/// Schnorr-style proof must never reuse its randomness across two
/// statements: two responses that share a nonce over different challenges
/// solve for the secret. In a build without `seeded-rng` the type has no
/// value, so an `Option<SpendSeeds>` is always `None` and the seeded arms do
/// not exist.
#[cfg(feature = "seeded-rng")]
pub struct SpendSeeds {
    pub(crate) proofs: shekyl_tx_builder::ProofSeeds,
    pub(crate) slots: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "seeded-rng")]
impl SpendSeeds {
    /// One spend's seeds from the four a caller derived for it: the range
    /// proof's, the blinds', the membership proof's and the spend slots'.
    /// The caller's derivation must give every spend its own four (the
    /// forge's `seed_for` keys them by role and by the spend's place in the
    /// plan).
    #[must_use]
    pub fn from_parts(
        range: [u8; 32],
        blinds: [u8; 32],
        membership: [u8; 32],
        slots: [u8; 32],
    ) -> Self {
        Self {
            proofs: shekyl_tx_builder::ProofSeeds {
                range: Zeroizing::new(range),
                blinds: Zeroizing::new(blinds),
                membership: Zeroizing::new(membership),
            },
            slots: Zeroizing::new(slots),
        }
    }
}

/// An unseeded build has no seeded spend.
#[cfg(not(feature = "seeded-rng"))]
pub(crate) enum SpendSeeds {}

/// A plan's sequence of per-spend seeds. Owned by the caller, on the thread
/// that decides order. [`Self::next_spend`] is the index: call it once per
/// spend before that spend's thread starts, then move the [`SpendSeeds`] to
/// the worker (`CHAIN_FORGE.md` §5.1, §5.3). The spender never holds this
/// stream, so two threads that share a spender cannot draw in scheduler order.
#[cfg(feature = "seeded-rng")]
pub struct SpendPlan {
    stream: rand_chacha::ChaCha20Rng,
}

#[cfg(feature = "seeded-rng")]
impl SpendPlan {
    /// The sequence of spend seeds over `seed`. The same seed yields the
    /// same sequence, in the order [`Self::next_spend`] is called.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use rand_chacha::rand_core::SeedableRng;
        Self {
            stream: rand_chacha::ChaCha20Rng::from_seed(*seed),
        }
    }

    /// The next spend's seeds. Fresh for this spend, and not the seeds of
    /// any other: the range proof, the blinds, the membership proof and the
    /// ML-DSA spend slots each derive their nonces from their own bytes. Two spends from one
    /// seed would reuse those nonces over two different statements.
    ///
    /// Call this before the spend's thread starts. The bytes name the spend's
    /// place in this plan, which the caller chooses, and nothing about which
    /// thread runs first.
    #[must_use]
    pub fn next_spend(&mut self) -> SpendSeeds {
        use rand_chacha::rand_core::RngCore;
        let mut draw = || {
            let mut seed = Zeroizing::new([0u8; 32]);
            self.stream.fill_bytes(&mut *seed);
            seed
        };
        SpendSeeds {
            proofs: shekyl_tx_builder::ProofSeeds {
                range: draw(),
                blinds: draw(),
                membership: draw(),
            },
            slots: draw(),
        }
    }
}
