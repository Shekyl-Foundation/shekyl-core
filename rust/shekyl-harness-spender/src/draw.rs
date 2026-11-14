// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where the harness's signatures and proofs draw their randomness: the OS,
//! as the production signers draw it, or a seed, so that a chain built twice
//! from one seed comes out byte for byte the same (`CHAIN_FORGE.md` §5.3,
//! seam T4). The seeded forms exist only under this crate's TEST_ONLY
//! `seeded-rng` feature, which forwards the seeded signers and provers below
//! it (`shekyl-tx-builder`, `shekyl-crypto-pq`, `shekyl-fcmp`).

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

/// A seeded spender's stream of per-spend seeds, behind a lock because a
/// spender is shared by the threads that build a shard fill's spends. In a
/// build without `seeded-rng` the type has no value, as [`DrawSeed`].
#[cfg(feature = "seeded-rng")]
pub(crate) type SeedStream = std::sync::Mutex<rand_chacha::ChaCha20Rng>;
#[cfg(not(feature = "seeded-rng"))]
pub(crate) enum SeedStream {}

/// The seeds one seeded spend draws from: the proofs' (range proof,
/// pseudo-out blinds, membership proof) and the spend slots' signatures',
/// apart, so no randomness is shared between them. Drawn fresh for every
/// spend ([`crate::Spender::seeded`]): a Schnorr-style proof must never
/// reuse its randomness across two statements.
#[cfg(feature = "seeded-rng")]
pub(crate) struct SpendSeeds {
    pub(crate) sign: Zeroizing<[u8; 32]>,
    pub(crate) open: Zeroizing<[u8; 32]>,
}

/// An unseeded build has no seeded spend: the type has no value, so an
/// `Option<SpendSeeds>` is always `None` and the seeded arms do not exist.
#[cfg(not(feature = "seeded-rng"))]
pub(crate) enum SpendSeeds {}
