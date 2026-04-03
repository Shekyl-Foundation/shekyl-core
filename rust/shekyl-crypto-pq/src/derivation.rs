// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output PQC keypair derivation.
//!
//! From a combined KEM shared secret (X25519 + ML-KEM-768) and an output
//! index, deterministically derive an ML-DSA-65 keypair. The public key
//! hash `H(pqc_pk)` becomes the 4th scalar in the FCMP++ curve tree leaf.
//!
//! ```text
//! combined_ss ─── HKDF-Expand("shekyl-pqc-output" || output_index_le64)
//!                   └── 32-byte seed → ML-DSA-65 deterministic keygen
//! ```

use blake2::{Blake2b512, Digest};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use fips204::ml_dsa_65;
use fips204::traits::SerDes as _;

use crate::CryptoError;

/// Domain separator for per-output PQC leaf hash.
pub const DOMAIN_PQC_LEAF: &[u8] = b"shekyl-pqc-leaf";

/// Domain separator for per-output PQC keypair derivation.
pub const DOMAIN_PQC_OUTPUT: &[u8] = b"shekyl-pqc-output";

/// Size of the derivation seed extracted from HKDF for ML-DSA keygen.
const DERIVATION_SEED_LEN: usize = 32;

/// ML-DSA-65 public key length.
pub const ML_DSA_65_PK_LEN: usize = ml_dsa_65::PK_LEN;

/// ML-DSA-65 secret key length.
pub const ML_DSA_65_SK_LEN: usize = ml_dsa_65::SK_LEN;

/// A derived per-output ML-DSA-65 keypair.
pub struct DerivedPqcKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for DerivedPqcKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Derive a per-output ML-DSA-65 keypair from the combined KEM shared secret.
///
/// The derivation is deterministic: given the same `combined_ss` and
/// `output_index`, the same keypair is always produced. This enables
/// wallet restore-from-seed (the seed derives the KEM keys, KEM produces
/// the shared secret, and this function produces the per-output PQC keys).
///
/// Steps:
/// 1. Build info = DOMAIN_PQC_OUTPUT || output_index as LE u64
/// 2. HKDF-Expand(combined_ss, info) → 32-byte seed
/// 3. Use seed as deterministic RNG input for ML-DSA-65 keygen
pub fn derive_pqc_keypair(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<DerivedPqcKeypair, CryptoError> {
    let mut info = Vec::with_capacity(DOMAIN_PQC_OUTPUT.len() + 8);
    info.extend_from_slice(DOMAIN_PQC_OUTPUT);
    info.extend_from_slice(&output_index.to_le_bytes());

    let hk = Hkdf::<Sha512>::new(None, combined_ss);
    let mut seed = [0u8; DERIVATION_SEED_LEN];
    hk.expand(&info, &mut seed)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for PQC seed".into()))?;

    // ML-DSA-65 deterministic keygen from seed.
    // fips204 uses try_keygen() which reads from OsRng. For deterministic
    // derivation, we use try_keygen_with_rng() with a seeded CSPRNG.
    let (pk, sk) = keygen_from_seed(&seed)?;

    seed.zeroize();

    Ok(DerivedPqcKeypair {
        public_key: pk.into_bytes().to_vec(),
        secret_key: sk.into_bytes().to_vec(),
    })
}

/// ML-DSA-65 keygen from a deterministic seed.
///
/// Expands the seed into the `(xi, rho')` inputs that ML-DSA expects,
/// then performs standard keygen. This matches FIPS 204 Algorithm 1
/// with deterministic randomness.
fn keygen_from_seed(
    seed: &[u8; 32],
) -> Result<(ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey), CryptoError> {
    // fips204's try_keygen_with_rng expects a CryptoRng + RngCore.
    // We create a deterministic RNG seeded from our derived seed material.
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let mut rng = StdRng::from_seed(*seed);
    ml_dsa_65::try_keygen_with_rng(&mut rng)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("ML-DSA-65 keygen: {e}")))
}

/// Compute `H(pqc_pk)` — the PQC leaf scalar for the curve tree.
///
/// Uses domain-separated Blake2b-512, reduced to a 32-byte scalar:
/// `Blake2b-512(DOMAIN_PQC_LEAF || pqc_pk_bytes)[..32]` with high bit cleared.
pub fn hash_pqc_public_key(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(DOMAIN_PQC_LEAF);
    hasher.update(pqc_pk_bytes);
    let hash_512 = hasher.finalize();

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash_512[..32]);
    scalar[31] &= 0x7f;
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_deterministic() {
        let ss = [0xab; 64];
        let kp1 = derive_pqc_keypair(&ss, 0).unwrap();
        let kp2 = derive_pqc_keypair(&ss, 0).unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn different_indices_different_keys() {
        let ss = [0xab; 64];
        let kp0 = derive_pqc_keypair(&ss, 0).unwrap();
        let kp1 = derive_pqc_keypair(&ss, 1).unwrap();
        assert_ne!(kp0.public_key, kp1.public_key);
    }

    #[test]
    fn different_secrets_different_keys() {
        let ss1 = [0xab; 64];
        let ss2 = [0xcd; 64];
        let kp1 = derive_pqc_keypair(&ss1, 0).unwrap();
        let kp2 = derive_pqc_keypair(&ss2, 0).unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn derived_key_sizes() {
        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, 0).unwrap();
        assert_eq!(kp.public_key.len(), ML_DSA_65_PK_LEN);
        assert_eq!(kp.secret_key.len(), ML_DSA_65_SK_LEN);
    }

    #[test]
    fn derived_key_signs_and_verifies() {
        use fips204::traits::{Signer as _, Verifier as _};

        let ss = [0xab; 64];
        let kp = derive_pqc_keypair(&ss, 42).unwrap();

        let sk_bytes: [u8; ML_DSA_65_SK_LEN] = kp.secret_key.as_slice().try_into().unwrap();
        let pk_bytes: [u8; ML_DSA_65_PK_LEN] = kp.public_key.as_slice().try_into().unwrap();

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).unwrap();
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).unwrap();

        let msg = b"shekyl per-output pqc test";
        let sig = sk.try_sign(msg, &[]).unwrap();
        assert!(pk.verify(msg, &sig, &[]));
    }

    #[test]
    fn hash_pqc_pk_deterministic() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        let h1 = hash_pqc_public_key(&pk);
        let h2 = hash_pqc_public_key(&pk);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_pqc_pk_high_bit_cleared() {
        let pk = vec![0xff; ML_DSA_65_PK_LEN];
        let h = hash_pqc_public_key(&pk);
        assert_eq!(h[31] & 0x80, 0);
    }
}
