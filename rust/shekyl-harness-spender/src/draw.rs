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

/// The seeds one spend draws: the proofs' (range proof, pseudo-out blinds,
/// membership proof) and the spend slots' signatures', apart, so no
/// randomness is shared between them.
///
/// One value per spend, drawn by [`SpendPlan::next_spend`] on the planning
/// thread and moved to the worker that builds that spend. A Schnorr-style
/// proof must never reuse its randomness across two statements: two
/// responses that share a nonce over different challenges solve for the
/// secret. In a build without `seeded-rng` the type has no value, so an
/// `Option<SpendSeeds>` is always `None` and the seeded arms do not exist.
#[cfg(feature = "seeded-rng")]
pub struct SpendSeeds {
    pub(crate) sign: Zeroizing<[u8; 32]>,
    pub(crate) open: Zeroizing<[u8; 32]>,
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
    /// any other: the membership proof, the range proof and the ML-DSA spend
    /// slots all derive their nonces from these bytes. Two spends from one
    /// seed would reuse those nonces over two different statements.
    ///
    /// Call this before the spend's thread starts. The bytes name the spend's
    /// place in this plan, which the caller chooses, and nothing about which
    /// thread runs first.
    #[must_use]
    pub fn next_spend(&mut self) -> SpendSeeds {
        use rand_chacha::rand_core::RngCore;
        let mut sign = Zeroizing::new([0u8; 32]);
        let mut open = Zeroizing::new([0u8; 32]);
        self.stream.fill_bytes(&mut *sign);
        self.stream.fill_bytes(&mut *open);
        SpendSeeds { sign, open }
    }
}
