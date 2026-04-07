// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Claim computation helpers for staked outputs.

use crate::transfer::TransferDetails;

/// Summary of claimable reward state for a single staked output.
#[derive(Clone, Debug)]
pub struct ClaimableInfo {
    /// Index into the wallet's transfer list.
    pub transfer_index: usize,
    /// Global output index on the blockchain.
    pub global_output_index: u64,
    /// Staking tier (0=short, 1=medium, 2=long).
    pub tier: u8,
    /// The start of the unclaimed range (exclusive).
    pub from_height: u64,
    /// The end of the unclaimed range (inclusive), capped at lock_until.
    pub to_height: u64,
    /// Whether accrual has frozen (current_height >= lock_until).
    pub accrual_frozen: bool,
    /// The output's staked amount (atomic units).
    pub staked_amount: u64,
}

impl ClaimableInfo {
    /// Build ClaimableInfo from a TransferDetails at the given chain height.
    ///
    /// Returns `None` if the output has no unclaimed backlog.
    pub fn from_transfer(td: &TransferDetails, index: usize, current_height: u64) -> Option<Self> {
        if !td.has_claimable_rewards(current_height) {
            return None;
        }

        let from_height = if td.last_claimed_height > 0 {
            td.last_claimed_height
        } else {
            td.block_height
        };
        let to_height = std::cmp::min(current_height, td.stake_lock_until);
        let accrual_frozen = current_height >= td.stake_lock_until;

        Some(ClaimableInfo {
            transfer_index: index,
            global_output_index: td.global_output_index,
            tier: td.stake_tier,
            from_height,
            to_height,
            accrual_frozen,
            staked_amount: td.amount(),
        })
    }

    /// The number of blocks in this claim range.
    pub fn range_blocks(&self) -> u64 {
        self.to_height.saturating_sub(self.from_height)
    }
}
