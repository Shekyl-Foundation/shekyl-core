use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeTier {
    pub id: u8,
    pub lock_blocks: u64,
    pub yield_multiplier: u64, // fixed-point SCALE (1_000_000 = 1.0x)
    pub name: &'static str,
}

pub const TIERS: [StakeTier; 3] = [
    StakeTier {
        id: 0,
        lock_blocks: 1_000,
        yield_multiplier: 1_000_000,
        name: "Short",
    },
    StakeTier {
        id: 1,
        lock_blocks: 25_000,
        yield_multiplier: 1_500_000,
        name: "Medium",
    },
    StakeTier {
        id: 2,
        lock_blocks: 150_000,
        yield_multiplier: 2_000_000,
        name: "Long",
    },
];

pub fn tier_by_id(id: u8) -> Option<&'static StakeTier> {
    TIERS.iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_by_id_returns_none_for_3() {
        assert!(tier_by_id(3).is_none());
    }

    #[test]
    fn tier_by_id_returns_none_for_255() {
        assert!(tier_by_id(255).is_none());
    }

    #[test]
    fn all_valid_tiers_resolve() {
        for id in 0..=2u8 {
            let tier = tier_by_id(id);
            assert!(tier.is_some(), "tier {id} should resolve");
            assert_eq!(tier.unwrap().id, id);
        }
    }

    #[test]
    fn all_tiers_have_positive_lock_blocks() {
        for tier in &TIERS {
            assert!(tier.lock_blocks > 0, "tier {} has lock_blocks=0", tier.id);
        }
    }

    #[test]
    fn all_tiers_have_positive_yield_multiplier() {
        for tier in &TIERS {
            assert!(
                tier.yield_multiplier > 0,
                "tier {} has yield_multiplier=0",
                tier.id
            );
        }
    }

    #[test]
    fn yield_multiplier_ordering() {
        assert!(TIERS[2].yield_multiplier >= TIERS[1].yield_multiplier);
        assert!(TIERS[1].yield_multiplier >= TIERS[0].yield_multiplier);
    }

    #[test]
    fn lock_blocks_ordering() {
        assert!(TIERS[2].lock_blocks >= TIERS[1].lock_blocks);
        assert!(TIERS[1].lock_blocks >= TIERS[0].lock_blocks);
    }

    #[test]
    fn tier_ids_are_contiguous_from_zero() {
        for (i, tier) in TIERS.iter().enumerate() {
            assert_eq!(tier.id as usize, i, "tier ids must be 0, 1, 2");
        }
    }

    #[test]
    fn all_tiers_have_non_empty_name() {
        for tier in &TIERS {
            assert!(!tier.name.is_empty(), "tier {} has empty name", tier.id);
        }
    }

    #[test]
    fn exhaustive_invalid_tier_ids() {
        for id in 3..=255u8 {
            assert!(
                tier_by_id(id).is_none(),
                "tier_by_id({id}) should return None"
            );
        }
    }
}
