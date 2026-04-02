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

/// Error codes returned by `verify_multisig` and exposed via FFI debug function.
/// Each variant maps to one of the 10 adversarial checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[repr(u8)]
pub enum PqcVerifyError {
    #[error("scheme_id mismatch (expected 2)")]
    SchemeMismatch = 1,

    #[error("parameter bounds violation (n=0, m=0, m>n, or n>MAX)")]
    ParameterBounds = 2,

    #[error("key blob length mismatch")]
    KeyBlobLength = 3,

    #[error("sig blob length mismatch")]
    SigBlobLength = 4,

    #[error("threshold mismatch (sig_count != m_required)")]
    ThresholdMismatch = 5,

    #[error("signer index out of range")]
    IndexOutOfRange = 6,

    #[error("signer indices not strictly ascending")]
    IndicesNotAscending = 7,

    #[error("duplicate keys in multisig group")]
    DuplicateKeys = 8,

    #[error("group_id does not match expected")]
    GroupIdMismatch = 9,

    #[error("cryptographic signature verification failed")]
    CryptoVerifyFailed = 10,

    #[error("deserialization of key or signature blob failed")]
    DeserializationFailed = 11,
}
