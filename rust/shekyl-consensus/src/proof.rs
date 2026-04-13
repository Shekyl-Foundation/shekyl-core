use crate::error::ConsensusError;
use crate::types::{BlockHeader, ChainState, Difficulty};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    ProofOfWork,
    ProofOfStake,
    Hybrid { pow_weight: f64, pos_weight: f64 },
}

/// Core trait that all proof mechanisms must implement.
///
/// This is the primary extension point for the modular consensus system.
/// New proof types (e.g., proof of useful work, proof of storage) can be
/// added by implementing this trait and registering the module at startup.
pub trait ConsensusProof: Send + Sync {
    fn verify_block(
        &self,
        header: &BlockHeader,
        chain: &ChainState,
        proof_data: &[u8],
    ) -> Result<(), ConsensusError>;

    fn difficulty_for_next_block(&self, chain: &ChainState) -> Result<Difficulty, ConsensusError>;

    fn proof_type(&self) -> ProofType;

    fn name(&self) -> &str;
}
