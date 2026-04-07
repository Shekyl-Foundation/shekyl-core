// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet state management: transfer tracking, key image deduplication, and spend detection.

use std::collections::HashMap;

use tracing::warn;

use crate::{
    scan::Timelocked,
    transfer::TransferDetails,
    balance::BalanceSummary,
    staker_pool::{StakerPoolState, AccrualRecord},
    claim::ClaimableInfo,
};

/// The wallet's in-memory state, tracking all known transfers and their statuses.
pub struct WalletState {
    /// All known transfers, ordered by discovery.
    transfers: Vec<TransferDetails>,
    /// Map from key image bytes to transfer index for spend tracking.
    key_images: HashMap<[u8; 32], usize>,
    /// Map from output public key (compressed) to transfer index for burning-bug detection.
    pub_keys: HashMap<[u8; 32], usize>,
    /// Current synced blockchain height.
    synced_height: u64,
    /// Chain of block hashes for reorg detection.
    blockchain: Vec<[u8; 32]>,
    /// Staker pool accrual data for local reward estimation.
    staker_pool: StakerPoolState,
}

impl WalletState {
    /// Create an empty wallet state.
    pub fn new() -> Self {
        WalletState {
            transfers: Vec::new(),
            key_images: HashMap::new(),
            pub_keys: HashMap::new(),
            synced_height: 0,
            blockchain: Vec::new(),
            staker_pool: StakerPoolState::new(),
        }
    }

    /// The current synced height.
    pub fn height(&self) -> u64 {
        self.synced_height
    }

    /// All tracked transfers.
    pub fn transfers(&self) -> &[TransferDetails] {
        &self.transfers
    }

    /// Process scanned outputs from a block and add new transfers.
    ///
    /// Returns the number of new transfers added.
    pub fn process_scanned_outputs(
        &mut self,
        block_height: u64,
        block_hash: [u8; 32],
        outputs: Timelocked,
    ) -> usize {
        let outputs = outputs.ignore_additional_timelock();
        let mut added = 0;

        for output in &outputs {
            let pub_key_bytes = output.key().compress().to_bytes();

            if self.pub_keys.contains_key(&pub_key_bytes) {
                warn!(
                    tx = hex::encode(output.transaction()),
                    output_idx = output.index_in_transaction(),
                    "duplicate output key detected (potential burning bug) -- skipping"
                );
                continue;
            }

            let td = TransferDetails::from_wallet_output(output, block_height);
            let idx = self.transfers.len();
            self.pub_keys.insert(pub_key_bytes, idx);

            if let Some(ref ki) = td.key_image {
                self.key_images.insert(*ki, idx);
            }

            self.transfers.push(td);
            added += 1;
        }

        self.synced_height = block_height;
        self.blockchain.push(block_hash);

        added
    }

    /// Mark an output as spent by its key image.
    ///
    /// Returns `true` if the key image was found and the output was marked spent.
    pub fn mark_spent(&mut self, key_image: &[u8; 32], spent_height: u64) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            if let Some(td) = self.transfers.get_mut(idx) {
                td.spent = true;
                td.spent_height = Some(spent_height);
                return true;
            }
        }
        false
    }

    /// Process incoming transaction inputs to detect spends of our outputs.
    pub fn detect_spends(&mut self, block_height: u64, key_images: &[[u8; 32]]) -> usize {
        let mut spent_count = 0;
        for ki in key_images {
            if self.mark_spent(ki, block_height) {
                spent_count += 1;
            }
        }
        spent_count
    }

    /// Set the key image for a transfer at the given index.
    pub fn set_key_image(&mut self, transfer_idx: usize, key_image: [u8; 32]) {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            if td.key_image.is_some() {
                return;
            }
            td.key_image = Some(key_image);
            self.key_images.insert(key_image, transfer_idx);
        }
    }

    /// Set staking info for a transfer at the given index.
    pub fn set_staking_info(&mut self, transfer_idx: usize, tier: u8) {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.staked = true;
            td.stake_tier = tier;
            let lock_blocks = shekyl_staking::tiers::tier_by_id(tier)
                .map(|t| t.lock_blocks)
                .unwrap_or(0);
            td.stake_lock_until = td.block_height + lock_blocks;
        }
    }

    /// Update the claim watermark for a staked output identified by global output index.
    pub fn update_claim_watermark(&mut self, global_output_index: u64, to_height: u64) {
        for td in &mut self.transfers {
            if td.staked && td.global_output_index == global_output_index {
                td.last_claimed_height = to_height;
                return;
            }
        }
    }

    /// Get staked outputs that have unclaimed reward backlog.
    pub fn claimable_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.has_claimable_rewards(current_height))
            .collect()
    }

    /// Get staked outputs that are eligible for unstaking (matured, unspent).
    pub fn unstakeable_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_unstakeable(current_height))
            .collect()
    }

    /// Compute balance summary at the given height.
    pub fn balance(&self, current_height: u64) -> BalanceSummary {
        BalanceSummary::compute(&self.transfers, current_height)
    }

    /// Get unspent, unfrozen transfers.
    pub fn unspent_transfers(&self) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| !td.spent && !td.frozen)
            .collect()
    }

    /// Get staked outputs (all states).
    pub fn staked_outputs(&self) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.staked && !td.spent)
            .collect()
    }

    /// Get matured staked outputs (lock period expired, still unspent).
    pub fn matured_staked_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_matured_stake(current_height) && !td.spent)
            .collect()
    }

    /// Get locked staked outputs (still within lock period).
    pub fn locked_staked_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_locked_stake(current_height) && !td.spent)
            .collect()
    }

    /// Handle a blockchain reorg by removing transfers at or above the given height.
    pub fn handle_reorg(&mut self, fork_height: u64) {
        let mut removed_indices = vec![];
        for (idx, td) in self.transfers.iter().enumerate() {
            if td.block_height >= fork_height {
                removed_indices.push(idx);
            }
        }

        for &idx in removed_indices.iter().rev() {
            let td = &self.transfers[idx];
            let pub_key_bytes = td.key.compress().to_bytes();
            self.pub_keys.remove(&pub_key_bytes);
            if let Some(ki) = &td.key_image {
                self.key_images.remove(ki);
            }
            self.transfers.remove(idx);
        }

        self.blockchain.truncate(
            (fork_height.saturating_sub(1)) as usize,
        );
        self.synced_height = fork_height.saturating_sub(1);

        // Reindex after removal
        self.key_images.clear();
        self.pub_keys.clear();
        for (idx, td) in self.transfers.iter().enumerate() {
            let pub_key_bytes = td.key.compress().to_bytes();
            self.pub_keys.insert(pub_key_bytes, idx);
            if let Some(ki) = &td.key_image {
                self.key_images.insert(*ki, idx);
            }
        }

        self.staker_pool.handle_reorg(fork_height);
    }

    /// Get spendable outputs with optional account/subaddress/amount filters.
    pub fn spendable_outputs(
        &self,
        current_height: u64,
        account: Option<u32>,
        subaddress: Option<crate::SubaddressIndex>,
        min_amount: Option<u64>,
    ) -> Vec<(usize, &TransferDetails)> {
        self.transfers
            .iter()
            .enumerate()
            .filter(|(_, td)| {
                if !td.is_spendable(current_height) {
                    return false;
                }
                if let Some(acct) = account {
                    match td.subaddress {
                        Some(sa) if sa.account() == acct => {}
                        None if acct == 0 => {} // primary account
                        _ => return false,
                    }
                }
                if let Some(sub) = subaddress {
                    if td.subaddress != Some(sub) {
                        return false;
                    }
                }
                if let Some(min) = min_amount {
                    if td.amount() < min {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Freeze an output, preventing it from being selected for spending.
    pub fn freeze(&mut self, transfer_idx: usize) -> bool {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.frozen = true;
            return true;
        }
        false
    }

    /// Thaw a frozen output, making it available for spending again.
    pub fn thaw(&mut self, transfer_idx: usize) -> bool {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.frozen = false;
            return true;
        }
        false
    }

    /// Freeze an output by its key image.
    pub fn freeze_by_key_image(&mut self, key_image: &[u8; 32]) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            return self.freeze(idx);
        }
        false
    }

    /// Thaw an output by its key image.
    pub fn thaw_by_key_image(&mut self, key_image: &[u8; 32]) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            return self.thaw(idx);
        }
        false
    }

    /// Get a mutable reference to a transfer by index.
    pub fn transfer_mut(&mut self, idx: usize) -> Option<&mut TransferDetails> {
        self.transfers.get_mut(idx)
    }

    /// Insert a staker pool accrual record.
    pub fn insert_accrual(&mut self, height: u64, record: AccrualRecord) {
        self.staker_pool.insert(height, record);
    }

    /// Access the staker pool state.
    pub fn staker_pool(&self) -> &StakerPoolState {
        &self.staker_pool
    }

    /// Compute a summary of claimable rewards for all staked outputs.
    ///
    /// `weight_fn` computes the tier-weighted stake for each output.
    /// `max_claim_range` is the protocol's MAX_CLAIM_RANGE constant.
    pub fn claimable_rewards_summary<F>(
        &self,
        current_height: u64,
        weight_fn: F,
        max_claim_range: u64,
    ) -> Vec<(ClaimableInfo, u64)>
    where
        F: Fn(u64, u8) -> u64,
    {
        let mut results = Vec::new();
        for (idx, td) in self.transfers.iter().enumerate() {
            if let Some(info) = ClaimableInfo::from_transfer(td, idx, current_height) {
                let weight = weight_fn(td.amount(), td.stake_tier);
                let (reward, _chunks) = self.staker_pool.estimate_reward_with_splitting(
                    info.from_height,
                    info.to_height,
                    weight,
                    max_claim_range,
                );
                results.push((info, reward));
            }
        }
        results
    }

    /// The number of tracked transfers.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new()
    }
}
