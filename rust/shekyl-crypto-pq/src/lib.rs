// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Post-quantum cryptographic primitives for Shekyl.
//!
//! This crate provides hybrid classical + post-quantum cryptographic operations
//! using NIST PQC standardized algorithms (ML-DSA, ML-KEM, SLH-DSA).

pub mod signature;
pub mod multisig;
pub mod kem;
pub mod derivation;
pub mod error;

pub use shekyl_address as address;
pub use error::CryptoError;
