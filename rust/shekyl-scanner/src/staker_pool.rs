// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet-side staker pool state tracking.
//!
//! Mirrors the per-block accrual records from the daemon, enabling local
//! reward estimation without RPC round-trips for every block in a claim range.

use std::collections::BTreeMap;

/// A single block's accrual data as seen by the wallet.
#[derive(Clone, Debug, Default)]
pub struct AccrualRecord {
    /// Staker emission for this block (atomic units).
    pub staker_emission: u64,
    /// Fee pool contribution for this block (atomic units).
    pub staker_fee_pool: u64,
    /// Correctly tier-weighted total stake at this block height.
    pub total_weighted_stake: u64,
}

impl AccrualRecord {
    /// Total reward available at this block (emission + fee pool).
    pub fn total_reward(&self) -> u64 {
        self.staker_emission.saturating_add(self.staker_fee_pool)
    }
}

/// Wallet-side staker pool state, tracking per-block accrual records.
///
/// Used for local reward estimation. Populated from daemon RPC responses
/// and kept in sync during scanning.
pub struct StakerPoolState {
    /// Per-block accrual records, keyed by block height.
    records: BTreeMap<u64, AccrualRecord>,
    /// The highest block height for which we have an accrual record.
    max_height: u64,
}

impl StakerPoolState {
    pub fn new() -> Self {
        StakerPoolState {
            records: BTreeMap::new(),
            max_height: 0,
        }
    }

    /// Insert an accrual record for a block height.
    pub fn insert(&mut self, height: u64, record: AccrualRecord) {
        if height > self.max_height {
            self.max_height = height;
        }
        self.records.insert(height, record);
    }

    /// Get the accrual record for a specific height.
    pub fn get(&self, height: u64) -> Option<&AccrualRecord> {
        self.records.get(&height)
    }

    /// The highest tracked height.
    pub fn max_height(&self) -> u64 {
        self.max_height
    }

    /// Number of tracked blocks.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Estimate the claimable reward for a staked output over a range.
    ///
    /// Uses the same integer math as the consensus `check_stake_claim_input`:
    /// `reward = total_reward * weight / total_weighted_stake` per block,
    /// summed over `(from_height, to_height]`.
    ///
    /// The `weight` should be computed as `shekyl_stake_weight(amount, tier)`.
    pub fn estimate_reward(
        &self,
        from_height: u64,
        to_height: u64,
        weight: u64,
    ) -> u64 {
        if from_height >= to_height || weight == 0 {
            return 0;
        }

        let mut total: u64 = 0;
        for h in (from_height + 1)..=to_height {
            let Some(record) = self.records.get(&h) else {
                continue;
            };
            let block_total = record.total_reward();
            if block_total == 0 || record.total_weighted_stake == 0 {
                continue;
            }
            // Integer math: (block_total * weight) / total_weighted_stake
            // Uses u128 to avoid overflow on the multiplication
            let reward = ((block_total as u128) * (weight as u128)
                / (record.total_weighted_stake as u128)) as u64;
            total = total.saturating_add(reward);
        }

        total
    }

    /// Estimate reward with MAX_CLAIM_RANGE splitting.
    ///
    /// If the range exceeds `max_claim_range`, splits into multiple chunks
    /// and sums the rewards.
    pub fn estimate_reward_with_splitting(
        &self,
        from_height: u64,
        to_height: u64,
        weight: u64,
        max_claim_range: u64,
    ) -> (u64, Vec<(u64, u64)>) {
        if from_height >= to_height || weight == 0 {
            return (0, vec![]);
        }

        let mut chunks = vec![];
        let mut cursor = from_height;
        while cursor < to_height {
            let chunk_end = std::cmp::min(cursor + max_claim_range, to_height);
            chunks.push((cursor, chunk_end));
            cursor = chunk_end;
        }

        let total = chunks
            .iter()
            .map(|&(f, t)| self.estimate_reward(f, t, weight))
            .sum();

        (total, chunks)
    }

    /// Handle a reorg by removing records at or above the given height.
    pub fn handle_reorg(&mut self, fork_height: u64) {
        // split_off returns all entries >= fork_height; self.records keeps < fork_height
        let _removed = self.records.split_off(&fork_height);
        self.max_height = self
            .records
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0);
    }

    /// Verify the conservation property: for a given block, the sum of
    /// per-staker rewards should not exceed the block's total reward.
    ///
    /// `staker_weights` is a slice of (weight) values for all stakers at that height.
    pub fn check_conservation(
        &self,
        height: u64,
        staker_weights: &[u64],
    ) -> Option<ConservationCheck> {
        let record = self.records.get(&height)?;
        let block_total = record.total_reward();
        if block_total == 0 || record.total_weighted_stake == 0 {
            return Some(ConservationCheck {
                height,
                pool_inflow: block_total,
                total_distributed: 0,
                dust: block_total,
                conserved: true,
            });
        }

        let distributed: u64 = staker_weights
            .iter()
            .map(|&w| {
                ((block_total as u128) * (w as u128)
                    / (record.total_weighted_stake as u128)) as u64
            })
            .sum();

        Some(ConservationCheck {
            height,
            pool_inflow: block_total,
            total_distributed: distributed,
            dust: block_total.saturating_sub(distributed),
            conserved: distributed <= block_total,
        })
    }
}

impl Default for StakerPoolState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a conservation invariant check for a single block.
#[derive(Clone, Debug)]
pub struct ConservationCheck {
    pub height: u64,
    pub pool_inflow: u64,
    pub total_distributed: u64,
    pub dust: u64,
    pub conserved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(emission: u64, fee_pool: u64, total_weighted: u64) -> AccrualRecord {
        AccrualRecord {
            staker_emission: emission,
            staker_fee_pool: fee_pool,
            total_weighted_stake: total_weighted,
        }
    }

    #[test]
    fn basic_reward_estimation() {
        let mut pool = StakerPoolState::new();
        // Block 101: 100 emission, 50 fee, 1000 total weighted stake
        pool.insert(101, make_record(100, 50, 1000));
        pool.insert(102, make_record(200, 100, 2000));

        // Staker with weight 500 claims blocks 100..102
        let reward = pool.estimate_reward(100, 102, 500);
        // Block 101: (150 * 500) / 1000 = 75
        // Block 102: (300 * 500) / 2000 = 75
        assert_eq!(reward, 150);
    }

    #[test]
    fn reward_zero_when_no_records() {
        let pool = StakerPoolState::new();
        assert_eq!(pool.estimate_reward(100, 200, 500), 0);
    }

    #[test]
    fn reward_zero_when_weight_zero() {
        let mut pool = StakerPoolState::new();
        pool.insert(101, make_record(100, 50, 1000));
        assert_eq!(pool.estimate_reward(100, 102, 0), 0);
    }

    #[test]
    fn reward_skips_zero_blocks() {
        let mut pool = StakerPoolState::new();
        pool.insert(101, make_record(100, 0, 1000));
        pool.insert(102, make_record(0, 0, 0)); // zero block
        pool.insert(103, make_record(100, 0, 1000));

        let reward = pool.estimate_reward(100, 103, 500);
        // 101: 50, 102: skip, 103: 50
        assert_eq!(reward, 100);
    }

    #[test]
    fn reward_splitting() {
        let mut pool = StakerPoolState::new();
        for h in 101..=110 {
            pool.insert(h, make_record(100, 0, 1000));
        }

        let (total, chunks) = pool.estimate_reward_with_splitting(100, 110, 500, 3);
        // 10 blocks, each giving 50, split into chunks of 3
        assert_eq!(total, 500);
        assert_eq!(chunks.len(), 4); // 3+3+3+1
    }

    #[test]
    fn conservation_check_passes() {
        let mut pool = StakerPoolState::new();
        pool.insert(101, make_record(1000, 0, 3000));

        // 3 stakers: weights 1000, 1000, 1000
        let check = pool.check_conservation(101, &[1000, 1000, 1000]).unwrap();
        assert!(check.conserved);
        // Each gets floor(1000 * 1000 / 3000) = 333, total = 999, dust = 1
        assert_eq!(check.total_distributed, 999);
        assert_eq!(check.dust, 1);
    }

    #[test]
    fn reorg_removes_records() {
        let mut pool = StakerPoolState::new();
        pool.insert(100, make_record(100, 0, 1000));
        pool.insert(200, make_record(200, 0, 2000));
        pool.insert(300, make_record(300, 0, 3000));

        pool.handle_reorg(200);
        assert_eq!(pool.len(), 1);
        assert!(pool.get(100).is_some());
        assert!(pool.get(200).is_none());
        assert!(pool.get(300).is_none());
    }
}
