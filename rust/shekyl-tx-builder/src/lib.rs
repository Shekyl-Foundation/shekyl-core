//! # shekyl-tx-builder
//!
//! Native Rust transaction signing for Shekyl FCMP++ transactions.
//!
//! This crate consolidates Bulletproofs+ range proof generation, FCMP++
//! full-chain membership proof construction, and PQC (ML-DSA-65) signing
//! into a single Rust call path. It replaces the prior architecture where
//! the C++ wallet assembled a witness blob, serialized it across the FFI
//! boundary, and then the Rust prover decoded it — an error-prone round-trip
//! that caused the `tree_root` / `block_hash` confusion bug.
//!
//! ## Architecture
//!
//! ```text
//! Caller (wallet RPC or FFI) → sign_transaction()
//!   ├─ Input validation (typed errors before any crypto)
//!   ├─ Bulletproof+ range proof via shekyl-bulletproofs
//!   ├─ ECDH amount encoding (compact v2 format)
//!   ├─ Pseudo-output balancing
//!   ├─ FCMP++ membership proof via shekyl-fcmp::proof::prove
//!   └─ PQC signing (hybrid Ed25519 + ML-DSA-65) via shekyl-crypto-pq
//! ```
//!
//! ## Security
//!
//! - All secret key material (`spend_key_x`, `spend_key_y`, PQC secret keys,
//!   intermediate blinding factors) is wrapped in [`zeroize::Zeroizing`] and
//!   wiped on drop.
//! - Randomness comes exclusively from [`rand_core::OsRng`] (CSPRNG).
//! - No panics on malformed input — all failures surface as [`TxBuilderError`].
//!
//! ## Relationship to other crates
//!
//! - **shekyl-fcmp**: FCMP++ membership proofs (`proof::prove()`) and the
//!   `ProveInput` / `BranchLayer` types.
//! - **shekyl-bulletproofs**: Bulletproofs+ range proofs (`Bulletproof::prove_plus()`)
//!   over Pedersen commitments.
//! - **shekyl-crypto-pq**: Hybrid signature construction (`SignatureScheme::sign()`).
//! - **shekyl-primitives**: `Commitment` and scalar arithmetic.

#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// 64-bit-only gate — Chore #3, v3.1.0-alpha.5 (Tripwire C — direct fips204
// consumer).
//
// `shekyl-tx-builder` is the transaction-signing entry point and is a direct
// consumer of ML-DSA-65 (`fips204`) via `shekyl-crypto-pq::signature`. The
// ML-DSA-65 constant-time guarantees only hold on native 64-bit arithmetic;
// on 32-bit targets the compiler decomposes u64 ops into libgcc helpers
// (`__muldi3`, `__udivdi3`, `__ashldi3`) with no CT guarantee, opening the
// exact timing side channel exploited by KyberSlash (Bernstein et al., 2024)
// against fielded CT implementations. Because this crate sits on the hot
// transaction-signing path (every user signature flows through it), the
// tripwire is placed here independently of Tripwire A so a future refactor
// that narrows the dependency shape cannot silently drop the refusal.
//
// Matching gates: Tripwire A (shekyl-crypto-pq, primary), Tripwire B
// (shekyl-ffi, structural-not-observable), Tripwire D (top-level
// CMakeLists.txt, C++-side configure gate). All four duplicate the refusal
// by design; none of them should be deleted on "never fires" grounds.
//
// See docs/CHANGELOG.md "Retired 32-bit build targets" and
// docs/audit_trail/ "Chore #3" before attempting to revert this gate.
// ---------------------------------------------------------------------------
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "shekyl-tx-builder refuses to build on non-64-bit targets. This is \
     Tripwire C: direct fips204 (ML-DSA-65) consumer on the transaction \
     signing hot path. ML-DSA-65 constant-time guarantees are stated \
     against native 64-bit arithmetic; on 32-bit targets the compiler \
     emits libgcc helpers (__muldi3, __udivdi3, __ashldi3) with no CT \
     guarantee — the exact threat model exploited by KyberSlash (Bernstein \
     et al., 2024). Matching gates live in shekyl-crypto-pq (Tripwire A), \
     shekyl-ffi (Tripwire B), and the top-level CMakeLists.txt (Tripwire D). \
     See docs/CHANGELOG.md entry 'Retired 32-bit build targets' before \
     attempting to revert this gate."
);

mod error;
mod sign;
pub mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use error::TxBuilderError;
pub use sign::{sign_pqc_auths, sign_transaction};
pub use types::{LeafEntry, OutputInfo, PqcAuth, SignedProofs, SpendInput, TreeContext};

/// Maximum number of inputs per transaction (consensus limit, matches `shekyl-fcmp::MAX_INPUTS`).
pub const MAX_INPUTS: usize = shekyl_fcmp::MAX_INPUTS;

/// Maximum number of outputs per transaction.
pub const MAX_OUTPUTS: usize = 16;
