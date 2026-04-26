// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Combined claim-and-unstake workflow.
//!
//! When a user wants to unstake a matured output, they must first drain
//! any unclaimed reward backlog. This module computes a two-step plan:
//! 1. Claim transaction(s) to drain the backlog up to lock_until
//! 2. Unstake transaction to spend the matured staked output

use shekyl_scanner::{LedgerBlock, LedgerIndexes};

use crate::{
    claim_builder::{ClaimTxBuilder, ClaimTxPlan},
    error::WalletCoreError,
};

/// A two-step plan for claiming remaining rewards then unstaking.
#[derive(Clone, Debug)]
pub struct ClaimAndUnstakePlan {
    /// The claim step (None if backlog already fully drained).
    pub claim_plan: Option<ClaimTxPlan>,
    /// Transfer indices to unstake (after claim completes).
    pub unstake_indices: Vec<usize>,
    /// Total staked amount that will be recovered.
    pub total_unstake_amount: u64,
}

/// Build a combined claim-and-unstake plan for the given transfer indices.
///
/// Each index must refer to a staked, unspent, matured output.
/// If any output still has unclaimed backlog, the claim step is populated.
pub fn plan_claim_and_unstake<F>(
    ledger: &LedgerBlock,
    indexes: &LedgerIndexes,
    indices: &[usize],
    current_height: u64,
    max_claim_range: u64,
    weight_fn: F,
) -> Result<ClaimAndUnstakePlan, WalletCoreError>
where
    F: Fn(u64, u8) -> u64,
{
    let transfers = ledger.transfers();
    let mut needs_claim = Vec::new();
    let mut total_unstake = 0u64;

    for &idx in indices {
        let td = transfers
            .get(idx)
            .ok_or(WalletCoreError::NotStaked { index: idx })?;

        if !td.staked {
            return Err(WalletCoreError::NotStaked { index: idx });
        }
        if td.spent {
            return Err(WalletCoreError::AlreadySpent { index: idx });
        }
        if !td.is_unstakeable(current_height) {
            return Err(WalletCoreError::NotMatured {
                index: idx,
                lock_until: td.stake_lock_until,
                current: current_height,
            });
        }

        if td.has_claimable_rewards(current_height) {
            needs_claim.push(idx);
        }

        total_unstake = total_unstake.saturating_add(td.amount());
    }

    let claim_plan = if !needs_claim.is_empty() {
        let builder = ClaimTxBuilder::new(max_claim_range);
        Some(builder.plan_specific(ledger, indexes, &needs_claim, current_height, weight_fn)?)
    } else {
        None
    };

    Ok(ClaimAndUnstakePlan {
        claim_plan,
        unstake_indices: indices.to_vec(),
        total_unstake_amount: total_unstake,
    })
}
