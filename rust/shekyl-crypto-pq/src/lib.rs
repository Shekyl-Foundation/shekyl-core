// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Post-quantum cryptographic primitives for Shekyl.
//!
//! This crate provides hybrid classical + post-quantum cryptographic operations
//! using NIST PQC standardized algorithms (ML-DSA, ML-KEM, SLH-DSA).

#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// 64-bit-only gate — Chore #3, v3.1.0-alpha.5 (Tripwire A — primary).
//
// Matching gates (defense-in-depth; all four must be defeated to ship a
// 32-bit build):
//   - rust/shekyl-ffi/src/lib.rs           (Tripwire B, structural-not-observable)
//   - rust/shekyl-tx-builder/src/lib.rs    (Tripwire C, direct fips204 consumer)
//   - CMakeLists.txt (top)                 (Tripwire D, C++-side configure gate)
//
// This is the primary ML-KEM-768 / ML-DSA-65 consumer. The `fips203` /
// `fips204` constant-time guarantees are stated against native 64-bit
// arithmetic; on 32-bit targets the compiler emits libgcc helpers
// (`__muldi3`, `__udivdi3`, `__ashldi3`) with no constant-time guarantee,
// plus variable-latency u64 multiply on common 32-bit ARM cores. That is
// the threat model exploited by KyberSlash (Bernstein et al., 2024) against
// fielded CT implementations. The hybrid X25519+ML-KEM construction does
// not rescue the ML-KEM secret once it leaks via timing.
//
// See docs/CHANGELOG.md "Retired 32-bit build targets" and
// docs/audit_trail/ "Chore #3" before attempting to revert this gate.
// ---------------------------------------------------------------------------
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "shekyl-crypto-pq refuses to build on non-64-bit targets. \
     ML-KEM-768 (fips203) and ML-DSA-65 (fips204) constant-time \
     guarantees are stated against native 64-bit arithmetic; on 32-bit \
     targets the compiler emits libgcc helpers (__muldi3, __udivdi3, \
     __ashldi3) with no constant-time guarantee, plus variable-latency \
     u64 multiply on common 32-bit ARM cores. This is the threat model \
     exploited by KyberSlash (Bernstein et al., 2024) against fielded \
     CT implementations. The hybrid X25519+ML-KEM construction does not \
     rescue the ML-KEM secret once it leaks via timing. Matching gates \
     live in shekyl-ffi, shekyl-tx-builder, and the top-level CMakeLists.txt. \
     See docs/CHANGELOG.md entry 'Retired 32-bit build targets' before \
     attempting to revert this gate."
);

pub mod account;
pub mod bip39;
pub mod derivation;
pub mod error;
pub mod kem;
pub mod montgomery;
pub mod multisig;
pub mod multisig_receiving;
pub mod output;
pub mod signature;
pub mod wallet_envelope;

pub use error::CryptoError;
pub use shekyl_address as address;
