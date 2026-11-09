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

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("low-order Montgomery point rejected")]
    LowOrderPoint,

    #[error("serialization error: {0}")]
    SerializationError(String),
}

/// Why a `pqc_auth` slot is refused: the multisig checks of
/// `verify_multisig` and the parse and signature refusals both schemes share.
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

    // Discriminant 9 (the former GroupIdMismatch) is **retired**: E′ deleted
    // the group_id check — the group's identity is the address fingerprint
    // (`shekyl-address`), not a per-output container hash. The numbers are
    // stable names for a refusal, so a retired one is never given a new
    // meaning.
    #[error("cryptographic signature verification failed")]
    CryptoVerifyFailed = 10,

    #[error("deserialization of key or signature blob failed")]
    DeserializationFailed = 11,

    #[error("multisig container version is not 0x02")]
    ContainerVersion = 12,

    #[error("a revealed multisig key does not hash to the committed hash at its index")]
    KeyHashMismatch = 13,

    #[error("multisig signer bitmap names a non-member or does not have m bits set")]
    SignerBitmap = 14,

    #[error("signature blob's signer indices are not the key blob's signer bitmap")]
    SignerListMismatch = 15,
}
