//! RandomX proof-of-work module — the first concrete ConsensusProof implementation.
//!
//! RandomX is a CPU-friendly PoW algorithm used by Monero. This module wraps
//! the existing C++ RandomX implementation and exposes it through the
//! ConsensusProof trait, making it the first pluggable module in Shekyl's
//! modular consensus system.
//!
//! The actual hash computation remains in C++ (via RandomX library); this Rust
//! module handles proof verification logic and difficulty calculation at the
//! consensus layer.

use crate::error::ConsensusError;
use crate::proof::{ConsensusProof, ProofType};
use crate::types::{BlockHeader, ChainState, Difficulty};

pub struct RandomXProof {
    pub target_block_time: u64,
    pub difficulty_window: u64,
}

impl RandomXProof {
    pub fn new(target_block_time: u64, difficulty_window: u64) -> Self {
        Self {
            target_block_time,
            difficulty_window,
        }
    }
}

impl ConsensusProof for RandomXProof {
    fn verify_block(
        &self,
        header: &BlockHeader,
        _chain: &ChainState,
        proof_data: &[u8],
    ) -> Result<(), ConsensusError> {
        if proof_data.len() != 32 {
            return Err(ConsensusError::InvalidProofOfWork(
                "RandomX hash must be 32 bytes".into(),
            ));
        }

        // The actual RandomX hash verification is done in C++ via get_block_longhash().
        // This module validates the proof structure; the C++ side checks the actual hash.
        if header.nonce == 0 && header.height > 0 {
            return Err(ConsensusError::InvalidProofOfWork(
                "zero nonce not allowed after genesis".into(),
            ));
        }

        Ok(())
    }

    fn difficulty_for_next_block(&self, chain: &ChainState) -> Result<Difficulty, ConsensusError> {
        // Genesis is a convention, not a DAA output. Past genesis this
        // crate has no timestamp/difficulty window, so it cannot call
        // `shekyl_difficulty::lwma1_next` (the live next-block target).
        // Returning cumulative work as a target used to compile because
        // both were the same leftover newtype; after RTN-5 it is a unit
        // lie. Fail until a caller that owns the window invokes LWMA-1
        // — do not grow this ConsensusProof stub into a second DAA
        // (rule 70).
        if chain.height == 0 {
            return Ok(Difficulty::from_raw(1));
        }
        Err(ConsensusError::DifficultyError(
            "RandomXProof is not the DAA; next-block target is shekyl_difficulty::lwma1_next"
                .into(),
        ))
    }

    fn proof_type(&self) -> ProofType {
        ProofType::ProofOfWork
    }

    fn name(&self) -> &str {
        "RandomX"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChainState, CumulativeDifficulty};

    fn test_chain() -> ChainState {
        ChainState {
            height: 100,
            top_hash: [0u8; 32],
            cumulative_difficulty: CumulativeDifficulty::from_raw(1000),
            timestamp: 1700000000,
        }
    }

    #[test]
    fn test_verify_valid_block() {
        let rx = RandomXProof::new(120, 720);
        let header = BlockHeader {
            major_version: 17,
            minor_version: 0,
            timestamp: 1700000120,
            height: 101,
            prev_hash: [0u8; 32],
            nonce: 42,
        };
        let proof = [0u8; 32];
        assert!(rx.verify_block(&header, &test_chain(), &proof).is_ok());
    }

    #[test]
    fn test_verify_bad_proof_length() {
        let rx = RandomXProof::new(120, 720);
        let header = BlockHeader {
            major_version: 17,
            minor_version: 0,
            timestamp: 1700000120,
            height: 101,
            prev_hash: [0u8; 32],
            nonce: 42,
        };
        assert!(rx.verify_block(&header, &test_chain(), &[0u8; 16]).is_err());
    }

    #[test]
    fn test_genesis_difficulty() {
        let rx = RandomXProof::new(120, 720);
        let chain = ChainState {
            height: 0,
            top_hash: [0u8; 32],
            cumulative_difficulty: CumulativeDifficulty::ZERO,
            timestamp: 0,
        };
        assert_eq!(
            rx.difficulty_for_next_block(&chain).unwrap(),
            Difficulty::from_raw(1)
        );
    }

    #[test]
    fn next_block_difficulty_past_genesis_is_not_cumulative_work() {
        let rx = RandomXProof::new(120, 720);
        let err = rx
            .difficulty_for_next_block(&test_chain())
            .expect_err("this stub is not the DAA");
        assert!(
            matches!(err, ConsensusError::DifficultyError(_)),
            "{err:?} must not be a plausible Difficulty"
        );
    }

    #[test]
    fn test_proof_type() {
        let rx = RandomXProof::new(120, 720);
        assert!(matches!(rx.proof_type(), ProofType::ProofOfWork));
        assert_eq!(rx.name(), "RandomX");
    }
}
