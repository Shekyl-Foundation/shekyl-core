//! Modular consensus system for Shekyl.
//!
//! Provides a pluggable proof mechanism supporting PoW, PoS, and hybrid
//! consensus modes. New proof types can be added by implementing the
//! `ConsensusProof` trait and registering with the `ConsensusRegistry`.

#![deny(unsafe_code)]

pub mod error;
pub mod proof;
pub mod randomx;
pub mod registry;
pub mod types;

pub use error::ConsensusError;
pub use proof::{ConsensusProof, ProofType};
pub use randomx::RandomXProof;
pub use registry::ConsensusRegistry;
pub use types::{BlockHeader, ChainState, Difficulty};

/// The minimum number of blocks a non-coinbase output is locked for before it is
/// spendable.
///
/// Under Shekyl's FCMP++ design, outputs are proven against the full UTXO curve tree
/// rather than individual decoy rings. This lock window prevents chain reorganizations
/// from invalidating proofs that reference recently-added outputs. Brought native off
/// the vendored `shekyl-oxide` in the un-vendor slice-2 dissolve.
pub const DEFAULT_LOCK_WINDOW: usize = 10;

/// The minimum number of blocks a coinbase output is locked for (coinbase maturity).
pub const COINBASE_LOCK_WINDOW: usize = 60;
