use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid proof of work: {0}")]
    InvalidProofOfWork(String),

    #[error("invalid proof of stake: {0}")]
    InvalidProofOfStake(String),

    #[error("insufficient stake: required {required}, found {found}")]
    InsufficientStake { required: u64, found: u64 },

    #[error("block validation failed: {0}")]
    BlockValidationFailed(String),

    #[error("difficulty calculation error: {0}")]
    DifficultyError(String),

    #[error("unknown proof type: {0}")]
    UnknownProofType(String),
}
