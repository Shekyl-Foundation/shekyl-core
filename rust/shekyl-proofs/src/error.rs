// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// Errors from proof generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("crypto error: {0}")]
    Crypto(#[from] shekyl_crypto_pq::CryptoError),

    #[error("invalid proof format: {0}")]
    InvalidFormat(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("KEM ciphertext mismatch: derived CT does not match on-chain")]
    KemCtMismatch,

    #[error("output key mismatch at index {index}")]
    OutputKeyMismatch { index: usize },

    #[error("commitment mismatch at index {index}: C != z*G + amount*H")]
    CommitmentMismatch { index: usize },

    #[error("DLEQ verification failed at index {index}: key_image != x*Hp(O)")]
    DleqFailed { index: usize },

    #[error("signature verification failed")]
    SignatureFailed,
}
