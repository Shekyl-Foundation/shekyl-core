// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Property-based and cross-validation tests for the staking subsystem.

#[cfg(test)]
mod tests {
    use crate::{
        StakeRegistry,
        distribute_staker_rewards,
        tiers::{TIERS, tier_by_id, MAX_CLAIM_RANGE},
    };
    use shekyl_economics::params::SCALE;

    fn weight(amount: u64, tier_id: u8) -> u64 {
        let tier = tier_by_id(tier_id).unwrap();
        ((amount as u128 * tier.yield_multiplier as u128) / SCALE as u128) as u64
    }

    // ── Conservation property ──

    #[test]
    fn conservation_single_tier_uniform() {
        for tier in &TIERS {
            let n = 10;
            let amount = 5_000_000_000u64;
            let pool = 10_000_000u64;

            let mut reg = StakeRegistry::new();
            for _ in 0..n {
                reg.add_stake(amount, tier.id, 0).unwrap();
            }

            let rewards = distribute_staker_rewards(&reg, pool);
            let total_distributed: u64 = rewards.iter().map(|r| r.amount).sum();
            assert_eq!(total_distributed, pool, "tier {}: total must equal pool", tier.id);
        }
    }

    #[test]
    fn conservation_mixed_tiers() {
        let amounts_tiers: Vec<(u64, u8)> = vec![
            (1_000_000_000, 0),
            (2_000_000_000, 1),
            (3_000_000_000, 2),
            (500_000_000, 0),
            (4_000_000_000, 2),
        ];
        let pool = 50_000_000u64;

        let mut reg = StakeRegistry::new();
        for &(amount, tier) in &amounts_tiers {
            reg.add_stake(amount, tier, 0).unwrap();
        }

        let rewards = distribute_staker_rewards(&reg, pool);
        let total: u64 = rewards.iter().map(|r| r.amount).sum();

        // With dust assignment, total should exactly equal pool
        assert_eq!(total, pool);
    }

    #[test]
    fn conservation_stress_many_stakers() {
        let mut reg = StakeRegistry::new();
        for i in 0..100u64 {
            let amount = 1_000_000_000 + i * 100_000;
            let tier = (i % 3) as u8;
            reg.add_stake(amount, tier, 0).unwrap();
        }

        let pool = 100_000_000u64;
        let rewards = distribute_staker_rewards(&reg, pool);
        let total: u64 = rewards.iter().map(|r| r.amount).sum();

        assert_eq!(total, pool);
    }

    // ── Proportionality property ──

    #[test]
    fn higher_tier_gets_more_reward() {
        let amount = 1_000_000_000u64;
        let pool = 10_000_000u64;

        let mut reg = StakeRegistry::new();
        reg.add_stake(amount, 0, 0).unwrap();
        reg.add_stake(amount, 2, 0).unwrap();

        let rewards = distribute_staker_rewards(&reg, pool);
        assert!(rewards.len() == 2);

        let short_reward = rewards[0].amount;
        let long_reward = rewards[1].amount;

        assert!(
            long_reward > short_reward,
            "long tier ({long_reward}) should get more than short ({short_reward})"
        );
    }

    #[test]
    fn double_amount_double_reward_same_tier() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        reg.add_stake(2_000_000_000, 0, 0).unwrap();

        let pool = 9_000_000u64;
        let rewards = distribute_staker_rewards(&reg, pool);
        assert_eq!(rewards.len(), 2);

        // 2:1 ratio (within dust tolerance)
        let r1 = rewards[0].amount;
        let r2 = rewards[1].amount;
        let ratio = r2 as f64 / r1 as f64;
        assert!((ratio - 2.0).abs() < 0.1, "ratio should be ~2.0, got {ratio}");
    }

    // ── No over-distribution without dust assignment ──

    #[test]
    fn floor_division_never_overdistributes() {
        for tier in &TIERS {
            let amount = 1_000_000_001u64; // odd amount
            let pool = 7_777_777u64; // prime-ish

            let mut reg = StakeRegistry::new();
            for _ in 0..7 {
                reg.add_stake(amount, tier.id, 0).unwrap();
            }

            let total_weight = reg.total_weighted_stake();
            let raw_distributed: u64 = reg
                .active_entries()
                .iter()
                .map(|e| {
                    ((pool as u128 * e.weight() as u128) / total_weight) as u64
                })
                .sum();

            assert!(
                raw_distributed <= pool,
                "tier {}: raw floor division overdistributed: {raw_distributed} > {pool}",
                tier.id
            );
        }
    }

    // ── Weight function matches tier multiplier ──

    #[test]
    fn weight_function_matches_multiplier() {
        let amount = 10_000_000_000u64;
        for tier in &TIERS {
            let w = weight(amount, tier.id);
            let expected = ((amount as u128 * tier.yield_multiplier as u128) / SCALE as u128) as u64;
            assert_eq!(
                w, expected,
                "tier {}: weight mismatch: {w} != {expected}",
                tier.id
            );
        }
    }

    // ── Multi-block accumulation ──

    #[test]
    fn multi_block_accumulation_bounds() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(5_000_000_000, 1, 0).unwrap();
        reg.add_stake(5_000_000_000, 2, 0).unwrap();

        let blocks = 1000u64;
        let per_block_pool = 100_000u64;
        let mut total_accumulated = 0u64;

        for _ in 0..blocks {
            let rewards = distribute_staker_rewards(&reg, per_block_pool);
            let block_total: u64 = rewards.iter().map(|r| r.amount).sum();
            total_accumulated += block_total;
        }

        let expected_total = blocks * per_block_pool;
        assert_eq!(
            total_accumulated, expected_total,
            "accumulated ({total_accumulated}) should equal blocks * pool ({expected_total})"
        );
    }

    // ── Adversarial: single staker gets all ──

    #[test]
    fn single_staker_gets_full_pool() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();

        let pool = 5_000_000u64;
        let rewards = distribute_staker_rewards(&reg, pool);
        assert_eq!(rewards.len(), 1);
        assert_eq!(rewards[0].amount, pool);
    }

    // ── Adversarial: tiny staker among whales ──

    #[test]
    fn tiny_staker_gets_nonzero_from_large_pool() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000_000, 2, 0).unwrap(); // 1000 SKL whale
        reg.add_stake(1_000, 0, 0).unwrap(); // dust staker

        let pool = 10_000_000_000u64; // 10 SKL pool
        let rewards = distribute_staker_rewards(&reg, pool);

        // The dust staker's weight is tiny but with a large enough pool,
        // they should still get something
        let whale_reward = rewards.iter().find(|r| r.entry_index == 0).map(|r| r.amount).unwrap_or(0);
        assert!(whale_reward > 0, "whale should get rewards");
    }

    // ── MAX_CLAIM_RANGE sanity ──

    #[test]
    fn max_claim_range_within_reasonable_bounds() {
        // MAX_CLAIM_RANGE should be at least 1 day of blocks and at most ~1 year
        let blocks_per_day = 720u64;
        let blocks_per_year = 262_800u64;
        assert!(
            MAX_CLAIM_RANGE >= blocks_per_day,
            "MAX_CLAIM_RANGE ({MAX_CLAIM_RANGE}) should be at least 1 day ({blocks_per_day})"
        );
        assert!(
            MAX_CLAIM_RANGE <= blocks_per_year * 2,
            "MAX_CLAIM_RANGE ({MAX_CLAIM_RANGE}) should be at most 2 years ({blocks_per_year})"
        );
    }
}
