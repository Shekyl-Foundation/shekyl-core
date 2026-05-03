#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use shekyl_generators as generators;
pub use shekyl_io as io;
pub use shekyl_primitives as primitives;

/// Merkle tree functionality.
pub mod merkle;

/// FCMP++ proof types and supporting structures (range proofs, encrypted amounts, etc.).
pub mod fcmp;

/// Block structs and functionality.
pub mod block;
/// Transaction structs and functionality.
pub mod transaction;

#[cfg(test)]
mod tests;

/// The minimum amount of blocks an output is locked for.
///
/// Under Shekyl's FCMP++ design, outputs are proven against the full UTXO curve tree rather
/// than individual decoy rings. This lock window prevents chain reorganizations from
/// invalidating proofs that reference recently-added outputs.
pub const DEFAULT_LOCK_WINDOW: usize = 10;

/// The minimum amount of blocks a coinbase output is locked for.
pub const COINBASE_LOCK_WINDOW: usize = 60;

/// Block time target, in seconds.
pub const BLOCK_TIME: usize = 120;

/// The minimum transaction version accepted by Shekyl from genesis.
///
/// Shekyl does not support v1 (CryptoNote) transactions. All transactions must be v2 with
/// FCMP++ proofs.
pub const SHEKYL_MIN_TX_VERSION: u64 = 2;

/// The minimum hard fork version for Shekyl genesis.
pub const SHEKYL_MIN_HF_VERSION: u8 = 1;
