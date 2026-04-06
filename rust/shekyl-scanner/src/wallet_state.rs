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
    pub fn set_staking_info(&mut self, transfer_idx: usize, tier: u8, lock_until: u64) {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.staked = true;
            td.stake_tier = tier;
            td.stake_lock_until = lock_until;
        }
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
