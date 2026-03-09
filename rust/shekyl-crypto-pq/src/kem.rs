//! Hybrid key encapsulation mechanism: X25519 + ML-KEM (CRYSTALS-Kyber).
//!
//! Used for key exchange in wallet-to-wallet communication and
//! transaction output encryption.

use crate::CryptoError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct HybridKemSecretKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub [u8; 32]);

pub trait KeyEncapsulation {
    fn keypair_generate(&self) -> Result<(HybridKemPublicKey, HybridKemSecretKey), CryptoError>;
    fn encapsulate(&self, public_key: &HybridKemPublicKey) -> Result<(SharedSecret, HybridCiphertext), CryptoError>;
    fn decapsulate(&self, secret_key: &HybridKemSecretKey, ciphertext: &HybridCiphertext) -> Result<SharedSecret, CryptoError>;
}

/// Placeholder implementation -- actual PQ KEM libraries will be integrated
/// once the build pipeline is validated.
pub struct HybridX25519MlKem;

impl KeyEncapsulation for HybridX25519MlKem {
    fn keypair_generate(&self) -> Result<(HybridKemPublicKey, HybridKemSecretKey), CryptoError> {
        Err(CryptoError::KeyGenerationFailed("not yet implemented".into()))
    }

    fn encapsulate(&self, _public_key: &HybridKemPublicKey) -> Result<(SharedSecret, HybridCiphertext), CryptoError> {
        Err(CryptoError::EncapsulationFailed("not yet implemented".into()))
    }

    fn decapsulate(&self, _secret_key: &HybridKemSecretKey, _ciphertext: &HybridCiphertext) -> Result<SharedSecret, CryptoError> {
        Err(CryptoError::DecapsulationFailed("not yet implemented".into()))
    }
}
