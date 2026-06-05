//! Per-block staker reward distribution.
//!
//! Each block, the staker_pool_amount (a fraction of the fee burn) is
//! allocated to all active stakers weighted by stake * duration_multiplier.

use shekyl_units::AtomicUnits;

use crate::registry::StakeRegistry;

/// A single staker's reward for a block.
#[derive(Debug, Clone)]
pub struct StakerReward {
    pub entry_index: usize,
    pub amount: AtomicUnits,
}

/// Distribute the staker pool for a single block across active stakers.
///
/// Returns a list of (index, reward_amount) pairs. The total distributed
/// will equal `staker_pool_amount` minus any dust from rounding.
///
/// The proportional share is computed in `u128` against the raw atomic-unit
/// count: tier weights (`entry.weight()`, `total_weight`) are derived
/// governance quantities, not money, and stay `u64` (per
/// ATOMIC_UNITS_NEWTYPE.md edge inventory). The pool and each share **are**
/// money. The per-staker shares are floors, so their sum never exceeds the
/// pool; `distributed` accumulation and the `dust` remainder therefore route
/// through checked arithmetic whose `None` is corrupted-state evidence that
/// surfaces loudly (§7.2), never `unwrap_or(ZERO)`.
#[allow(clippy::cast_possible_truncation)] // CLIPPY: per-staker share < staker_pool_amount which is u64
pub fn distribute_staker_rewards(
    registry: &StakeRegistry,
    staker_pool_amount: AtomicUnits,
) -> Vec<StakerReward> {
    let total_weight = registry.total_weighted_stake();
    if total_weight == 0 || staker_pool_amount.is_zero() {
        return Vec::new();
    }

    let mut rewards = Vec::with_capacity(registry.active_entries().len());
    let mut distributed = AtomicUnits::ZERO;

    for (i, entry) in registry.active_entries().iter().enumerate() {
        let weight = entry.weight();
        let reward_raw =
            (u128::from(staker_pool_amount.to_raw()) * u128::from(weight) / total_weight) as u64;
        if reward_raw > 0 {
            let reward = AtomicUnits::from_raw(reward_raw);
            distributed = distributed
                .checked_add(reward)
                .expect("staker-reward distributed sum exceeds the pool (corrupted state)");
            rewards.push(StakerReward {
                entry_index: i,
                amount: reward,
            });
        }
    }

    // Assign rounding dust to the first *rewarded* staker (the first entry
    // whose floored share was non-zero), if any. The shares are floors, so
    // `distributed <= staker_pool_amount`; the subtraction cannot underflow.
    // Note: when every share floors to zero `rewards` is empty and the pool
    // is not distributed — a pre-existing edge of this wallet/sim-only path
    // (not on the consensus path; retirement target per CONFIDENTIAL_STAKING.md).
    let dust = staker_pool_amount
        .checked_sub(distributed)
        .expect("staker-reward dust underflow: distributed exceeds pool (corrupted state)");
    if !dust.is_zero() && !rewards.is_empty() {
        rewards[0].amount = rewards[0]
            .amount
            .checked_add(dust)
            .expect("staker-reward dust assignment overflow (corrupted state)");
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

        let pool = AtomicUnits::from_raw(3_000_000);
        let rewards = distribute_staker_rewards(&reg, pool);

        assert_eq!(rewards.len(), 2);
        assert_eq!(rewards[0].amount, AtomicUnits::from_raw(1_000_000)); // 1/3
        assert_eq!(rewards[1].amount, AtomicUnits::from_raw(2_000_000)); // 2/3
    }

    #[test]
    fn test_empty_registry() {
        let reg = StakeRegistry::new();
        let rewards = distribute_staker_rewards(&reg, AtomicUnits::from_raw(1_000_000));
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_zero_pool() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        let rewards = distribute_staker_rewards(&reg, AtomicUnits::ZERO);
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_dust_assigned_to_first() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();
        reg.add_stake(1_000_000_000, 0, 0).unwrap();

        // 10 / 3 = 3 each with 1 dust
        let rewards = distribute_staker_rewards(&reg, AtomicUnits::from_raw(10));
        let total = rewards
            .iter()
            .map(|r| r.amount)
            .fold(AtomicUnits::ZERO, |acc, a| {
                acc.checked_add(a).expect("test reward total overflow")
            });
        assert_eq!(total, AtomicUnits::from_raw(10));
    }
}
