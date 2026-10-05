use serde::{Deserialize, Serialize};

/// Cumulative difficulty through a block — distinct from [`Difficulty`].
pub use shekyl_difficulty::CumulativeDifficulty;
/// Re-export of the transform-shaped difficulty target owned by
/// [`shekyl_difficulty`]. The leftover `Difficulty(pub u128)` that
/// lived here is deleted (RTN-5).
pub use shekyl_difficulty::Difficulty;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub nonce: u32,
}

#[derive(Debug, Clone)]
pub struct ChainState {
    pub height: u64,
    pub top_hash: [u8; 32],
    pub cumulative_difficulty: CumulativeDifficulty,
    pub timestamp: u64,
}
