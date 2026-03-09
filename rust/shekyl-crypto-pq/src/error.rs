use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("decapsulation failed: {0}")]
    DecapsulationFailed(String),

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("serialization error: {0}")]
    SerializationError(String),
}
