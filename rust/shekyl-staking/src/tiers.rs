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
