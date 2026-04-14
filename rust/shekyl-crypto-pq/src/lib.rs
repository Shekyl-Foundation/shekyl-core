// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Post-quantum cryptographic primitives for Shekyl.
//!
//! This crate provides hybrid classical + post-quantum cryptographic operations
//! using NIST PQC standardized algorithms (ML-DSA, ML-KEM, SLH-DSA).

#![deny(unsafe_code)]

pub mod derivation;
pub mod error;
pub mod kem;
pub mod montgomery;
pub mod multisig;
pub mod multisig_receiving;
pub mod output;
pub mod signature;

pub use error::CryptoError;
pub use shekyl_address as address;
