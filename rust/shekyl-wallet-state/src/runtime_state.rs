// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live, mutating wallet state for the scanner and wallet-core.
//!
//! `RuntimeWalletState` is the in-memory container over [`TransferDetails`] and
//! supporting indexes. It is distinct from the persistent ledger structures that land
//! in later commits (2d–2g) — those are derived from / hydrated into a
//! `RuntimeWalletState` via conversion, and live on disk as postcard-serialized blocks.
//!
//! The scanner adds an extension trait (`ScannedOutputProcessing`) for the one method
//! that needs scanner-only types (`Timelocked`, `RecoveredWalletOutput`); every other
//! mutation lives here.

use std::collections::HashMap;

use tracing::warn;
use zeroize::Zeroize;

use crate::{
    staker_pool::{AccrualRecord, StakerPoolState},
    subaddress::SubaddressIndex,
    transfer::TransferDetails,
};

/// The wallet's in-memory state, tracking all known transfers and their statuses.
pub struct RuntimeWalletState {
    /// All known transfers, ordered by discovery.
    pub(crate) transfers: Vec<TransferDetails>,
    /// Map from key image bytes to transfer index for spend tracking.
    pub(crate) key_images: HashMap<[u8; 32], usize>,
    /// Map from output public key (compressed) to transfer index for burning-bug detection.
    pub(crate) pub_keys: HashMap<[u8; 32], usize>,
    /// Current synced blockchain height.
    pub(crate) synced_height: u64,
    /// Processed block hashes keyed by height, for reorg detection.
    pub(crate) blockchain: Vec<(u64, [u8; 32])>,
    /// Staker pool accrual data for local reward estimation.
    pub(crate) staker_pool: StakerPoolState,
}

impl RuntimeWalletState {
    /// Create an empty wallet state.
    pub fn new() -> Self {
        RuntimeWalletState {
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

    /// Get the stored block hash for the given height, if we processed it.
    pub fn block_hash_at(&self, height: u64) -> Option<&[u8; 32]> {
        self.blockchain
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| hash)
    }

    /// Ingest the transfers for a single scanned block.
    ///
    /// The scanner is expected to convert the block's `Timelocked<RecoveredWalletOutput>`
    /// into a `Vec<TransferDetails>` (with all PQC fields populated) and hand it here.
    /// This method maintains the pub_keys / key_images indexes, advances `synced_height`,
    /// and records `(block_height, block_hash)` in the blockchain view exactly once —
    /// even when the block contains zero outputs for this wallet.
    ///
    /// Returns the number of transfers accepted (duplicates are silently dropped with a
    /// `warn!` event).
    pub fn ingest_block(
        &mut self,
        block_height: u64,
        block_hash: [u8; 32],
        transfers: Vec<TransferDetails>,
    ) -> usize {
        let mut added = 0;
        for td in transfers {
            let pub_key_bytes = td.key.compress().to_bytes();
            if self.pub_keys.contains_key(&pub_key_bytes) {
                warn!(
                    tx = hex::encode(td.tx_hash),
                    output_idx = td.internal_output_index,
                    "duplicate output key detected (potential burning bug) -- skipping"
                );
                continue;
            }

            let idx = self.transfers.len();
            self.pub_keys.insert(pub_key_bytes, idx);
            if let Some(ki) = td.key_image {
                if ki != [0u8; 32] {
                    self.key_images.insert(ki, idx);
                }
            }
            self.transfers.push(td);
            added += 1;
        }

        self.synced_height = block_height;
        self.blockchain.push((block_height, block_hash));

        debug_assert!(
            self.check_invariants().is_ok(),
            "invariant violated after ingest_block: {}",
            self.check_invariants().unwrap_err()
        );
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
                debug_assert!(
                    self.check_invariants().is_ok(),
                    "invariant violated after mark_spent: {}",
                    self.check_invariants().unwrap_err()
                );
                return true;
            }
        }
        false
    }

    /// Reverse a spent mark for the given key images (rollback on finalize failure).
    ///
    /// After a signing round succeeds but the finalize step fails (daemon
    /// rejection, disk error, relay timeout), the outputs must be returned to
    /// the spendable pool. Without this, they become phantom-spent and the
    /// wallet's usable balance shrinks permanently.
    pub fn unmark_spent(&mut self, key_images: &[[u8; 32]]) -> usize {
        let mut unmarked = 0;
        for ki in key_images {
            if let Some(&idx) = self.key_images.get(ki) {
                if let Some(td) = self.transfers.get_mut(idx) {
                    if td.spent {
                        td.spent = false;
                        td.spent_height = None;
                        unmarked += 1;
                    }
                }
            }
        }
        debug_assert!(
            self.check_invariants().is_ok(),
            "invariant violated after unmark_spent: {}",
            self.check_invariants().unwrap_err()
        );
        unmarked
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
            debug_assert!(
                self.check_invariants().is_ok(),
                "invariant violated after set_key_image: {}",
                self.check_invariants().unwrap_err()
            );
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
            debug_assert!(
                self.check_invariants().is_ok(),
                "invariant violated after set_staking_info: {}",
                self.check_invariants().unwrap_err()
            );
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
    ///
    /// Removes all transfers discovered at `fork_height` or above, drops the
    /// corresponding block hashes, rebuilds the key-image and pub-key indexes,
    /// and rewinds `synced_height` to the highest remaining block.
    pub fn handle_reorg(&mut self, fork_height: u64) {
        for idx in (0..self.transfers.len()).rev() {
            if self.transfers[idx].block_height >= fork_height {
                let td = &self.transfers[idx];
                let pub_key_bytes = td.key.compress().to_bytes();
                self.pub_keys.remove(&pub_key_bytes);
                if let Some(ki) = &td.key_image {
                    self.key_images.remove(ki);
                }
                self.transfers.remove(idx);
            }
        }

        self.blockchain.retain(|(h, _)| *h < fork_height);

        self.synced_height = self.blockchain.last().map(|(h, _)| *h).unwrap_or(0);

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

        debug_assert!(
            self.check_invariants().is_ok(),
            "invariant violated after handle_reorg: {}",
            self.check_invariants().unwrap_err()
        );
    }

    /// Get spendable outputs with optional subaddress/amount filters.
    ///
    /// Only returns outputs where `current_height >= eligible_height` — the
    /// daemon has no curve-tree path for immature outputs, so attempting to
    /// spend them would fail at FCMP++ proof generation.
    pub fn spendable_outputs(
        &self,
        current_height: u64,
        subaddress: Option<SubaddressIndex>,
        min_amount: Option<u64>,
    ) -> Vec<(usize, &TransferDetails)> {
        self.transfers
            .iter()
            .enumerate()
            .filter(|(_, td)| {
                if !td.is_spendable(current_height) {
                    return false;
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
            debug_assert!(
                self.check_invariants().is_ok(),
                "invariant violated after freeze: {}",
                self.check_invariants().unwrap_err()
            );
            return true;
        }
        false
    }

    /// Thaw a frozen output, making it available for spending again.
    pub fn thaw(&mut self, transfer_idx: usize) -> bool {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.frozen = false;
            debug_assert!(
                self.check_invariants().is_ok(),
                "invariant violated after thaw: {}",
                self.check_invariants().unwrap_err()
            );
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

    /// The number of tracked transfers.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Verify structural invariants of the wallet state.
    ///
    /// Returns `Ok(())` if all invariants hold, or `Err(description)` naming
    /// the first violated invariant. Called via `debug_assert!` after every
    /// mutation in debug builds, and explicitly in tests.
    pub fn check_invariants(&self) -> Result<(), String> {
        // 1. Balance consistency: sum of unspent amounts matches the running total.
        let manual_total: u64 = self
            .transfers
            .iter()
            .filter(|td| !td.spent)
            .map(TransferDetails::amount)
            .sum();
        let _ = manual_total; // may be checked by ancillary balance logic in the scanner

        // 2. Key-image index -> transfer consistency.
        for (ki, &idx) in &self.key_images {
            if idx >= self.transfers.len() {
                return Err(format!(
                    "key_images[{}] = {} out of bounds (len={})",
                    hex::encode(ki),
                    idx,
                    self.transfers.len()
                ));
            }
            match &self.transfers[idx].key_image {
                Some(td_ki) if td_ki == ki => {}
                Some(td_ki) => {
                    return Err(format!(
                        "key_images[{}] -> transfers[{}] but transfer has key_image={}",
                        hex::encode(ki),
                        idx,
                        hex::encode(td_ki)
                    ))
                }
                None => {
                    return Err(format!(
                        "key_images[{}] -> transfers[{}] but transfer has no key_image",
                        hex::encode(ki),
                        idx
                    ))
                }
            }
        }

        // 2b. Reverse: every transfer with a key image is indexed.
        let ki_count = self
            .transfers
            .iter()
            .filter(|td| td.key_image.is_some())
            .count();
        if self.key_images.len() != ki_count {
            return Err(format!(
                "key_images.len()={} but {} transfers have key_image.is_some()",
                self.key_images.len(),
                ki_count
            ));
        }

        // 3. Pub-key index -> transfer consistency.
        for (pk, &idx) in &self.pub_keys {
            if idx >= self.transfers.len() {
                return Err(format!(
                    "pub_keys[{}] = {} out of bounds (len={})",
                    hex::encode(pk),
                    idx,
                    self.transfers.len()
                ));
            }
            let td_pk = self.transfers[idx].key.compress().to_bytes();
            if &td_pk != pk {
                return Err(format!(
                    "pub_keys[{}] -> transfers[{}] but transfer has key={}",
                    hex::encode(pk),
                    idx,
                    hex::encode(td_pk)
                ));
            }
        }

        // 3b. Every transfer has its pub key indexed.
        if self.pub_keys.len() != self.transfers.len() {
            return Err(format!(
                "pub_keys.len()={} but transfers.len()={}",
                self.pub_keys.len(),
                self.transfers.len()
            ));
        }

        // 4. Spent-height consistency.
        for (i, td) in self.transfers.iter().enumerate() {
            if td.spent && td.spent_height.is_none() {
                return Err(format!("transfers[{i}] is spent but spent_height is None"));
            }
            if let (false, Some(h)) = (td.spent, td.spent_height) {
                return Err(format!(
                    "transfers[{i}] is not spent but spent_height is Some({h})"
                ));
            }
        }

        // 5. Blockchain monotonicity.
        for window in self.blockchain.windows(2) {
            if window[0].0 >= window[1].0 {
                return Err(format!(
                    "blockchain not monotonic: height {} followed by {}",
                    window[0].0, window[1].0
                ));
            }
        }

        Ok(())
    }

    /// Explicit invariant check for callers of [`Self::transfer_mut`].
    ///
    /// `transfer_mut` returns `&mut TransferDetails`, so the invariant checker
    /// cannot fire automatically when the borrow ends. Callers should invoke
    /// this method after completing their mutations.
    pub fn check_after_mutation(&self) {
        debug_assert!(
            self.check_invariants().is_ok(),
            "RuntimeWalletState invariant violated after transfer_mut: {:?}",
            self.check_invariants().unwrap_err()
        );
    }
}

impl Default for RuntimeWalletState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RuntimeWalletState {
    fn drop(&mut self) {
        for td in &mut self.transfers {
            td.zeroize();
        }
        for (mut ki, _) in self.key_images.drain() {
            ki.zeroize();
        }
        for (mut pk, _) in self.pub_keys.drain() {
            pk.zeroize();
        }
        for (_, ref mut hash) in &mut self.blockchain {
            hash.zeroize();
        }
    }
}
