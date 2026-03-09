use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Difficulty(pub u128);

impl Difficulty {
    pub fn zero() -> Self {
        Difficulty(0)
    }
}

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
    pub cumulative_difficulty: Difficulty,
    pub timestamp: u64,
}
