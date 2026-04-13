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
