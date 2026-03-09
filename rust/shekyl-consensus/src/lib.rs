//! Modular consensus system for Shekyl.
//!
//! Provides a pluggable proof mechanism supporting PoW, PoS, and hybrid
//! consensus modes. New proof types can be added by implementing the
//! `ConsensusProof` trait and registering with the `ConsensusRegistry`.

pub mod proof;
pub mod error;
pub mod types;
pub mod randomx;
pub mod registry;

pub use error::ConsensusError;
pub use proof::{ConsensusProof, ProofType};
pub use types::{BlockHeader, ChainState, Difficulty};
pub use randomx::RandomXProof;
pub use registry::ConsensusRegistry;
