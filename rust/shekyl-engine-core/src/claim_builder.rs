// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Claim transaction builder.
//!
//! Constructs a plan for claiming staked rewards. The actual transaction
//! assembly (PQC signing, RCT proofs) is deferred to the FFI layer or
//! the tx-builder crate, but this module computes the correct claim
//! parameters: from_height, to_height, estimated reward, and splitting.
//!
//! The builder reads from the live `(LedgerBlock, LedgerIndexes)` pair:
//! `LedgerBlock` provides the persisted transfers + claim watermarks,
//! `LedgerIndexes` provides the runtime-only `staker_pool` accrual
//! aggregate. See `docs/V3_WALLET_DECISION_LOG.md` ("`RuntimeWalletState`
//! audit", 2026-04-25) for why the split exists.

use shekyl_scanner::{ClaimableInfo, LedgerBlock, LedgerIndexes};

use crate::error::EngineCoreError;

/// A plan for a single claim input within a claim transaction.
#[derive(Clone, Debug)]
pub struct ClaimInputPlan {
    /// Index into the wallet's transfer list.
    pub transfer_index: usize,
    /// Global output index of the staked output.
    pub global_output_index: u64,
    /// Claim range start (exclusive).
    pub from_height: u64,
    /// Claim range end (inclusive).
    pub to_height: u64,
    /// Estimated reward for this claim.
    pub estimated_reward: u64,
    /// Staking tier.
    pub tier: u8,
    /// Whether accrual has frozen (past lock_until).
    pub accrual_frozen: bool,
}

/// A complete plan for a claim transaction (potentially multiple inputs).
#[derive(Clone, Debug)]
pub struct ClaimTxPlan {
    /// Individual claim inputs.
    pub claims: Vec<ClaimInputPlan>,
    /// Total estimated reward across all claims.
    pub total_reward: u64,
}

/// Builder for constructing claim transaction plans.
pub struct ClaimTxBuilder {
    max_claim_range: u64,
}

impl ClaimTxBuilder {
    pub fn new(max_claim_range: u64) -> Self {
        ClaimTxBuilder { max_claim_range }
    }

    /// Build a claim plan for all claimable outputs in the wallet.
    pub fn plan_all<F>(
        &self,
        ledger: &LedgerBlock,
        indexes: &LedgerIndexes,
        current_height: u64,
        weight_fn: F,
    ) -> Result<ClaimTxPlan, EngineCoreError>
    where
        F: Fn(u64, u8) -> u64,
    {
        let claimable = ledger.claimable_outputs(current_height);
        if claimable.is_empty() {
            return Err(EngineCoreError::NoClaimableOutputs);
        }

        let pool = indexes.staker_pool();
        let mut claims = Vec::new();
        let mut total_reward = 0u64;

        for td in &claimable {
            let Some(idx) = ledger
                .transfers()
                .iter()
                .position(|t| t.global_output_index == td.global_output_index)
            else {
                return Err(EngineCoreError::TransferNotFound);
            };

            if let Some(info) = ClaimableInfo::from_transfer(td, idx, current_height) {
                let weight = weight_fn(td.amount(), td.stake_tier);

                let mut cursor = info.from_height;
                while cursor < info.to_height {
                    let chunk_end = std::cmp::min(cursor + self.max_claim_range, info.to_height);
                    let reward = pool.estimate_reward(cursor, chunk_end, weight);
                    claims.push(ClaimInputPlan {
                        transfer_index: idx,
                        global_output_index: td.global_output_index,
                        from_height: cursor,
                        to_height: chunk_end,
                        estimated_reward: reward,
                        tier: td.stake_tier,
                        accrual_frozen: info.accrual_frozen,
                    });
                    total_reward = total_reward.saturating_add(reward);
                    cursor = chunk_end;
                }
            }
        }

        if total_reward == 0 {
            return Err(EngineCoreError::ZeroReward);
        }

        Ok(ClaimTxPlan {
            claims,
            total_reward,
        })
    }

    /// Build a claim plan for a specific set of transfer indices.
    pub fn plan_specific<F>(
        &self,
        ledger: &LedgerBlock,
        indexes: &LedgerIndexes,
        indices: &[usize],
        current_height: u64,
        weight_fn: F,
    ) -> Result<ClaimTxPlan, EngineCoreError>
    where
        F: Fn(u64, u8) -> u64,
    {
        let transfers = ledger.transfers();
        let pool = indexes.staker_pool();
        let mut claims = Vec::new();
        let mut total_reward = 0u64;

        for &idx in indices {
            let td = transfers
                .get(idx)
                .ok_or(EngineCoreError::NotStaked { index: idx })?;

            if !td.staked {
                return Err(EngineCoreError::NotStaked { index: idx });
            }
            if td.spent {
                return Err(EngineCoreError::AlreadySpent { index: idx });
            }

            let info = ClaimableInfo::from_transfer(td, idx, current_height)
                .ok_or(EngineCoreError::NoBacklog { index: idx })?;

            let weight = weight_fn(td.amount(), td.stake_tier);

            let mut cursor = info.from_height;
            while cursor < info.to_height {
                let chunk_end = std::cmp::min(cursor + self.max_claim_range, info.to_height);
                let reward = pool.estimate_reward(cursor, chunk_end, weight);
                claims.push(ClaimInputPlan {
                    transfer_index: idx,
                    global_output_index: td.global_output_index,
                    from_height: cursor,
                    to_height: chunk_end,
                    estimated_reward: reward,
                    tier: td.stake_tier,
                    accrual_frozen: info.accrual_frozen,
                });
                total_reward = total_reward.saturating_add(reward);
                cursor = chunk_end;
            }
        }

        if total_reward == 0 {
            return Err(EngineCoreError::ZeroReward);
        }

        Ok(ClaimTxPlan {
            claims,
            total_reward,
        })
    }
}
