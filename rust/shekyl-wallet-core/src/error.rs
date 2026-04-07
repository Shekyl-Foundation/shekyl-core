// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Error types for wallet-core operations.

#[derive(Debug, thiserror::Error)]
pub enum WalletCoreError {
    #[error("no claimable outputs found")]
    NoClaimableOutputs,

    #[error("output {index} is not staked")]
    NotStaked { index: usize },

    #[error("output {index} has no unclaimed reward backlog")]
    NoBacklog { index: usize },

    #[error("output {index} is already spent")]
    AlreadySpent { index: usize },

    #[error("output {index} is not yet matured for unstaking (lock_until={lock_until}, current={current})")]
    NotMatured {
        index: usize,
        lock_until: u64,
        current: u64,
    },

    #[error("claim range exceeds MAX_CLAIM_RANGE ({range} > {max})")]
    ClaimRangeTooLarge { range: u64, max: u64 },

    #[error("insufficient staker pool data to estimate rewards")]
    InsufficientPoolData,

    #[error("total claimable reward is zero")]
    ZeroReward,

    #[error("invalid tier {tier}")]
    InvalidTier { tier: u8 },
}
