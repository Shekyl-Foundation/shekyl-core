// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hybrid key encapsulation mechanism: X25519 + ML-KEM-768.
//!
//! Used for per-output PQC key derivation in FCMP++ transactions.
//! The combined shared secret from both X25519 and ML-KEM-768 is
//! fed into HKDF-SHA-512 to produce a master shared secret, from
//! which per-output ML-DSA-65 keypairs are deterministically derived.

use crate::CryptoError;
use curve25519_dalek::{
    constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroize;

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// ML-KEM-768 encapsulation key size (FIPS 203).
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// ML-KEM-768 decapsulation key size (FIPS 203).
pub const ML_KEM_768_DK_LEN: usize = 2400;

/// ML-KEM-768 ciphertext size (FIPS 203).
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// ML-KEM-768 shared secret size (FIPS 203).
pub const ML_KEM_768_SS_LEN: usize = 32;

/// Domain separator for KEM shared-secret combination.
pub const KEM_DOMAIN_SALT: &[u8] = b"shekyl-kem-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct HybridKemSecretKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

impl std::fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKemSecretKey")
            .field("x25519", &"[REDACTED]")
            .field("ml_kem", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

/// Combined shared secret after HKDF combination of X25519 and ML-KEM.
/// 64 bytes: sufficient for HKDF-Expand derivation of per-output keys.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub [u8; 64]);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret").field(&"[REDACTED]").finish()
    }
}

pub trait KeyEncapsulation {
    fn keypair_generate(&self) -> Result<(HybridKemPublicKey, HybridKemSecretKey), CryptoError>;
    fn encapsulate(
        &self,
        public_key: &HybridKemPublicKey,
    ) -> Result<(SharedSecret, HybridCiphertext), CryptoError>;
    fn decapsulate(
        &self,
        secret_key: &HybridKemSecretKey,
        ciphertext: &HybridCiphertext,
    ) -> Result<SharedSecret, CryptoError>;
}

/// Hybrid X25519 + ML-KEM-768 KEM implementation.
///
/// Encapsulation produces two shared secrets which are combined via
/// `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1")`
/// into a single 64-byte combined secret.
pub struct HybridX25519MlKem;

impl KeyEncapsulation for HybridX25519MlKem {
    fn keypair_generate(&self) -> Result<(HybridKemPublicKey, HybridKemSecretKey), CryptoError> {
        // Generate X25519 key without clamping: raw scalar * basepoint.
        // In production, the X25519 secret is derived from the Ed25519 view key
        // and the public key from the Edwards-to-Montgomery birational map.
        // This standalone keygen is for testing; real wallets use
        // generate_pqc_key_material which derives from the view key.
        let x_secret_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let x_public_mont = &x_secret_scalar * &X25519_BASEPOINT;

        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| CryptoError::KeyGenerationFailed(format!("ML-KEM-768 keygen: {e}")))?;

        let ek_bytes: [u8; ML_KEM_768_EK_LEN] = ek.into_bytes();
        let dk_bytes: [u8; ML_KEM_768_DK_LEN] = dk.into_bytes();

        Ok((
            HybridKemPublicKey {
                x25519: x_public_mont.0,
                ml_kem: ek_bytes.to_vec(),
            },
            HybridKemSecretKey {
                x25519: x_secret_scalar.to_bytes(),
                ml_kem: dk_bytes.to_vec(),
            },
        ))
    }

    fn encapsulate(
        &self,
        public_key: &HybridKemPublicKey,
    ) -> Result<(SharedSecret, HybridCiphertext), CryptoError> {
        if public_key.ml_kem.len() != ML_KEM_768_EK_LEN {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        // X25519 ECDH with ephemeral key (unclamped Montgomery scalar)
        let eph_scalar = Scalar::random(&mut rand::rngs::OsRng);
        let eph_mont_pub = &eph_scalar * &X25519_BASEPOINT;
        let recipient_mont = MontgomeryPoint(public_key.x25519);
        if crate::montgomery::is_low_order_montgomery(&recipient_mont) {
            return Err(CryptoError::LowOrderPoint);
        }
        let x25519_ss = &eph_scalar * &recipient_mont;

        // ML-KEM-768 encapsulation
        let ek_bytes: [u8; ML_KEM_768_EK_LEN] = public_key
            .ml_kem
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
            .map_err(|e| CryptoError::EncapsulationFailed(format!("invalid encap key: {e}")))?;
        let (ml_ss, ml_ct) = ek
            .try_encaps()
            .map_err(|e| CryptoError::EncapsulationFailed(format!("ML-KEM-768 encaps: {e}")))?;

        let ml_ss_bytes: [u8; ML_KEM_768_SS_LEN] = ml_ss.into_bytes();
        let ml_ct_bytes: [u8; ML_KEM_768_CT_LEN] = ml_ct.into_bytes();

        let combined_ss = combine_shared_secrets(&x25519_ss.0, &ml_ss_bytes)?;

        Ok((
            combined_ss,
            HybridCiphertext {
                x25519: eph_mont_pub.0,
                ml_kem: ml_ct_bytes.to_vec(),
            },
        ))
    }

    fn decapsulate(
        &self,
        secret_key: &HybridKemSecretKey,
        ciphertext: &HybridCiphertext,
    ) -> Result<SharedSecret, CryptoError> {
        if secret_key.ml_kem.len() != ML_KEM_768_DK_LEN {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        if ciphertext.ml_kem.len() != ML_KEM_768_CT_LEN {
            return Err(CryptoError::DecapsulationFailed(
                "invalid ciphertext length".into(),
            ));
        }

        // X25519 ECDH (unclamped Montgomery scalar)
        let view_scalar = Scalar::from_bytes_mod_order(secret_key.x25519);
        let eph_mont = MontgomeryPoint(ciphertext.x25519);
        if crate::montgomery::is_low_order_montgomery(&eph_mont) {
            return Err(CryptoError::LowOrderPoint);
        }
        let x25519_ss = &view_scalar * &eph_mont;

        // ML-KEM-768 decapsulation
        let dk_bytes: [u8; ML_KEM_768_DK_LEN] = secret_key
            .ml_kem
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
            .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid decap key: {e}")))?;

        let ct_bytes: [u8; ML_KEM_768_CT_LEN] = ciphertext
            .ml_kem
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed("invalid ciphertext".into()))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
            .map_err(|e| CryptoError::DecapsulationFailed(format!("invalid ciphertext: {e}")))?;
        let ml_ss = dk
            .try_decaps(&ct)
            .map_err(|e| CryptoError::DecapsulationFailed(format!("ML-KEM-768 decaps: {e}")))?;
        let ml_ss_bytes: [u8; ML_KEM_768_SS_LEN] = ml_ss.into_bytes();

        combine_shared_secrets(&x25519_ss.0, &ml_ss_bytes)
    }
}

/// Combine X25519 and ML-KEM shared secrets via HKDF-SHA-512.
///
/// `ikm = x25519_ss || ml_kem_ss`
/// `salt = "shekyl-kem-v1"`
/// Output: 64-byte combined secret (OKM).
pub(crate) fn combine_shared_secrets(
    x25519_ss: &[u8],
    ml_kem_ss: &[u8],
) -> Result<SharedSecret, CryptoError> {
    let mut ikm = Vec::with_capacity(x25519_ss.len() + ml_kem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(ml_kem_ss);

    let hk = Hkdf::<Sha512>::new(Some(KEM_DOMAIN_SALT), &ikm);
    let mut okm = [0u8; 64];
    hk.expand(b"", &mut okm)
        .map_err(|_| CryptoError::EncapsulationFailed("HKDF expand failed".into()))?;

    ikm.zeroize();
    Ok(SharedSecret(okm))
}

/// Derive all key material from a master seed (genesis wallet format).
///
/// ```text
/// master_seed
///   ├── HKDF-Expand("shekyl-ed25519-spend", seed) → Ed25519 spend keypair
///   ├── HKDF-Expand("shekyl-ed25519-view", seed)  → Ed25519 view keypair
///   └── HKDF-Expand("shekyl-ml-kem-768", seed)    → ML-KEM-768 decap/encap keypair
/// ```
pub struct SeedDerivation;

impl SeedDerivation {
    /// Derive an Ed25519 spend secret key from the master seed.
    pub fn derive_ed25519_spend(seed: &[u8; 32]) -> [u8; 32] {
        Self::hkdf_expand_32(seed, b"shekyl-ed25519-spend")
    }

    /// Derive an Ed25519 view secret key from the master seed.
    pub fn derive_ed25519_view(seed: &[u8; 32]) -> [u8; 32] {
        Self::hkdf_expand_32(seed, b"shekyl-ed25519-view")
    }

    /// Derive ML-KEM-768 keypair seed material from the master seed.
    /// The 64-byte output is used as the `d || z` input to ML-KEM keygen.
    pub fn derive_ml_kem_seed(seed: &[u8; 32]) -> [u8; 64] {
        Self::hkdf_expand_64(seed, b"shekyl-ml-kem-768")
    }

    /// Fixed HKDF salt for master-seed child-key derivation.
    const HKDF_SALT_MASTER_DERIVE: &'static [u8] = b"shekyl-master-derive-v1";

    fn hkdf_expand_32(seed: &[u8; 32], info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha512>::new(Some(Self::HKDF_SALT_MASTER_DERIVE), seed);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("32 bytes < max HKDF output");
        okm
    }

    fn hkdf_expand_64(seed: &[u8; 32], info: &[u8]) -> [u8; 64] {
        let hk = Hkdf::<Sha512>::new(Some(Self::HKDF_SALT_MASTER_DERIVE), seed);
        let mut okm = [0u8; 64];
        hk.expand(info, &mut okm)
            .expect("64 bytes < max HKDF output");
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_encap_decap_roundtrip() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();

        assert_eq!(pk.ml_kem.len(), ML_KEM_768_EK_LEN);
        assert_eq!(sk.ml_kem.len(), ML_KEM_768_DK_LEN);

        let (sender_ss, ct) = kem.encapsulate(&pk).unwrap();
        assert_eq!(ct.ml_kem.len(), ML_KEM_768_CT_LEN);

        let recipient_ss = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(sender_ss.0, recipient_ss.0, "shared secrets must match");
    }

    #[test]
    fn kem_different_encapsulations_produce_different_secrets() {
        let kem = HybridX25519MlKem;
        let (pk, _sk) = kem.keypair_generate().unwrap();

        let (ss1, _ct1) = kem.encapsulate(&pk).unwrap();
        let (ss2, _ct2) = kem.encapsulate(&pk).unwrap();
        assert_ne!(
            ss1.0, ss2.0,
            "each encapsulation must produce a unique secret"
        );
    }

    #[test]
    fn kem_wrong_secret_key_fails() {
        let kem = HybridX25519MlKem;
        let (pk, _sk1) = kem.keypair_generate().unwrap();
        let (_pk2, sk2) = kem.keypair_generate().unwrap();

        let (_ss, ct) = kem.encapsulate(&pk).unwrap();
        let result = kem.decapsulate(&sk2, &ct);
        // ML-KEM decapsulation with wrong key produces a different shared secret
        // (implicit rejection), so it won't match the sender's. X25519 will also differ.
        // The function itself shouldn't error, but the secrets won't match.
        if let Ok(wrong_ss) = result {
            assert_ne!(
                wrong_ss.0, _ss.0,
                "wrong key should produce different secret"
            );
        }
    }

    #[test]
    fn kem_rejects_invalid_key_length() {
        let kem = HybridX25519MlKem;
        let bad_pk = HybridKemPublicKey {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; 100],
        };
        assert!(kem.encapsulate(&bad_pk).is_err());
    }

    #[test]
    fn kem_decapsulate_rejects_wrong_ct_length() {
        let kem = HybridX25519MlKem;
        let (_pk, sk) = kem.keypair_generate().unwrap();

        let bad_ct = HybridCiphertext {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; 100],
        };
        assert!(kem.decapsulate(&sk, &bad_ct).is_err());
    }

    #[test]
    fn kem_decapsulate_rejects_wrong_sk_length() {
        let kem = HybridX25519MlKem;
        let bad_sk = HybridKemSecretKey {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; 100],
        };
        let ct = HybridCiphertext {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; ML_KEM_768_CT_LEN],
        };
        assert!(kem.decapsulate(&bad_sk, &ct).is_err());
    }

    #[test]
    fn kem_shared_secret_is_64_bytes() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();
        let (ss, ct) = kem.encapsulate(&pk).unwrap();
        assert_eq!(ss.0.len(), 64);

        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss2.0.len(), 64);
    }

    #[test]
    fn kem_keypair_sizes_correct() {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();
        assert_eq!(pk.x25519.len(), 32);
        assert_eq!(pk.ml_kem.len(), ML_KEM_768_EK_LEN);
        assert_eq!(sk.x25519.len(), 32);
        assert_eq!(sk.ml_kem.len(), ML_KEM_768_DK_LEN);
    }

    #[test]
    fn seed_derivation_deterministic() {
        let seed = [0xab; 32];
        let spend1 = SeedDerivation::derive_ed25519_spend(&seed);
        let spend2 = SeedDerivation::derive_ed25519_spend(&seed);
        assert_eq!(spend1, spend2);

        let view1 = SeedDerivation::derive_ed25519_view(&seed);
        let view2 = SeedDerivation::derive_ed25519_view(&seed);
        assert_eq!(view1, view2);
    }

    #[test]
    fn seed_derivation_different_domains() {
        let seed = [0xab; 32];
        let spend = SeedDerivation::derive_ed25519_spend(&seed);
        let view = SeedDerivation::derive_ed25519_view(&seed);
        let kem_seed = SeedDerivation::derive_ml_kem_seed(&seed);
        assert_ne!(spend, view);
        assert_ne!(spend.as_slice(), &kem_seed[..32]);
    }
}
