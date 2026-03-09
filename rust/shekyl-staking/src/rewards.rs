//! Per-block staker reward distribution.
//!
//! Each block, the staker_pool_amount (a fraction of the fee burn) is
//! allocated to all active stakers weighted by stake * duration_multiplier.

use crate::registry::StakeRegistry;

/// A single staker's reward for a block.
#[derive(Debug, Clone)]
pub struct StakerReward {
    pub entry_index: usize,
    pub amount: u64,
}

/// Distribute the staker pool for a single block across active stakers.
///
/// Returns a list of (index, reward_amount) pairs. The total distributed
/// will equal `staker_pool_amount` minus any dust from rounding.
pub fn distribute_staker_rewards(
    registry: &StakeRegistry,
    staker_pool_amount: u64,
) -> Vec<StakerReward> {
    let total_weight = registry.total_weighted_stake();
    if total_weight == 0 || staker_pool_amount == 0 {
        return Vec::new();
    }

    let mut rewards = Vec::with_capacity(registry.active_entries().len());
    let mut distributed = 0u64;

    for (i, entry) in registry.active_entries().iter().enumerate() {
        let weight = entry.weight();
        let reward =
            (staker_pool_amount as u128 * weight as u128 / total_weight as u128) as u64;
        if reward > 0 {
            distributed += reward;
            rewards.push(StakerReward {
                entry_index: i,
                amount: reward,
            });
        }
    }

    // Assign rounding dust to first staker (if any)
    let dust = staker_pool_amount.saturating_sub(distributed);
    if dust > 0 && !rewards.is_empty() {
        rewards[0].amount += dust;
    }

    rewards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::StakeRegistry;

    #[test]
    fn test_proportional_distribution() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap(); // weight 1B (1.0x)
        reg.add_stake(1_000_000_000, 2, 0).unwrap(); // weight 2B (2.0x)

        let pool = 3_000_000u64;
        let rewards = distribute_staker_rewards(&reg, pool);

        assert_eq!(rewards.len(), 2);
        assert_eq!(rewards[0].amount, 1_000_000); // 1/3
        assert_eq!(rewards[1].amount, 2_000_000); // 2/3
    }

    #[test]
    fn test_empty_registry() {
        let reg = StakeRegistry::new();
        let rewards = distribute_staker_rewards(&reg, 1_000_000);
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_zero_pool() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        let rewards = distribute_staker_rewards(&reg, 0);
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_dust_assigned_to_first() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();

        // 10 / 3 = 3 each with 1 dust
        let rewards = distribute_staker_rewards(&reg, 10);
        let total: u64 = rewards.iter().map(|r| r.amount).sum();
        assert_eq!(total, 10);
    }
}
