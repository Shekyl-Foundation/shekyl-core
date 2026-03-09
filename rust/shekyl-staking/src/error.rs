use thiserror::Error;

#[derive(Debug, Error)]
pub enum StakingError {
    #[error("invalid stake tier: {0}")]
    InvalidTier(u8),
    #[error("stake amount must be non-zero")]
    ZeroAmount,
    #[error("stake lock has not expired (current: {current}, unlock: {unlock})")]
    LockNotExpired { current: u64, unlock: u64 },
    #[error("no active stakes in registry")]
    EmptyRegistry,
    #[error("stake entry not found")]
    NotFound,
}
