//! Post-quantum cryptographic primitives for Shekyl.
//!
//! This crate provides hybrid classical + post-quantum cryptographic operations
//! using NIST PQC standardized algorithms (ML-DSA, ML-KEM, SLH-DSA).

pub mod signature;
pub mod kem;
pub mod error;

pub use error::CryptoError;
