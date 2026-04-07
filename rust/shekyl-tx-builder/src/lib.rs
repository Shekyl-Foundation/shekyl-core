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

mod error;
mod types;
mod validate;
mod sign;
mod ecdh;

#[cfg(test)]
mod tests;

pub use error::TxBuilderError;
pub use types::{SpendInput, LeafEntry, OutputInfo, TreeContext, SignedProofs, PqcAuth};
pub use sign::{sign_pqc_auths, sign_transaction};

/// Maximum number of inputs per transaction (consensus limit, matches `shekyl-fcmp::MAX_INPUTS`).
pub const MAX_INPUTS: usize = shekyl_fcmp::MAX_INPUTS;

/// Maximum number of outputs per transaction.
pub const MAX_OUTPUTS: usize = 16;
