use serde::{Deserialize, Serialize};

use crate::error::StakingError;
use crate::tiers::tier_by_id;
use shekyl_economics::params::SCALE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEntry {
    pub amount: u64,
    pub tier_id: u8,
    pub lock_until: u64,
}

impl StakeEntry {
    pub fn weight(&self) -> u64 {
        let tier = tier_by_id(self.tier_id).unwrap_or(&crate::tiers::TIERS[0]);
        ((self.amount as u128 * tier.yield_multiplier as u128) / SCALE as u128) as u64
    }

    pub fn is_unlocked(&self, current_height: u64) -> bool {
        current_height >= self.lock_until
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StakeRegistry {
    entries: Vec<StakeEntry>,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_stake(
        &mut self,
        amount: u64,
        tier_id: u8,
        current_height: u64,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        let tier = tier_by_id(tier_id).ok_or(StakingError::InvalidTier(tier_id))?;
        self.entries.push(StakeEntry {
            amount,
            tier_id,
            lock_until: current_height + tier.lock_blocks,
        });
        Ok(())
    }

    pub fn total_staked(&self) -> u64 {
        self.entries.iter().map(|e| e.amount).sum()
    }

    pub fn total_weighted_stake(&self) -> u64 {
        self.entries.iter().map(|e| e.weight()).sum()
    }

    /// Compute stake_ratio = total_staked / circulating_supply (fixed-point SCALE).
    pub fn stake_ratio(&self, circulating_supply: u64) -> u64 {
        if circulating_supply == 0 {
            return 0;
        }
        let staked = self.total_staked();
        (staked as u128 * SCALE as u128 / circulating_supply as u128) as u64
    }

    /// Remove stakes that have expired and return them.
    pub fn collect_expired(&mut self, current_height: u64) -> Vec<StakeEntry> {
        let (expired, active): (Vec<_>, Vec<_>) = self
            .entries
            .drain(..)
            .partition(|e| e.is_unlocked(current_height));
        self.entries = active;
        expired
    }

    pub fn active_entries(&self) -> &[StakeEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_total() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 100).unwrap();
        reg.add_stake(2_000_000_000, 1, 100).unwrap();
        assert_eq!(reg.total_staked(), 3_000_000_000);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn test_weighted_stake() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 100).unwrap(); // 1.0x
        reg.add_stake(1_000_000_000, 2, 100).unwrap(); // 2.0x
        assert_eq!(reg.total_weighted_stake(), 3_000_000_000);
    }

    #[test]
    fn test_zero_amount_rejected() {
        let mut reg = StakeRegistry::new();
        assert!(reg.add_stake(0, 0, 100).is_err());
    }

    #[test]
    fn test_invalid_tier_rejected() {
        let mut reg = StakeRegistry::new();
        assert!(reg.add_stake(1000, 99, 100).is_err());
    }

    #[test]
    fn test_collect_expired() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(1_000_000_000, 0, 100).unwrap(); // unlocks at 1100
        reg.add_stake(2_000_000_000, 2, 100).unwrap(); // unlocks at 150100
        let expired = reg.collect_expired(1200);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].amount, 1_000_000_000);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_stake_ratio() {
        let mut reg = StakeRegistry::new();
        reg.add_stake(500_000_000, 0, 0).unwrap();
        let ratio = reg.stake_ratio(1_000_000_000);
        assert_eq!(ratio, 500_000); // 0.5 in SCALE
    }
}
