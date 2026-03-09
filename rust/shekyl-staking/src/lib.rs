//! Staking subsystem for Shekyl.
//!
//! Tracks active stakes, computes weighted rewards, and manages lock tiers.

pub mod tiers;
pub mod registry;
pub mod rewards;
pub mod error;

pub use error::StakingError;
pub use tiers::{StakeTier, TIERS};
pub use registry::{StakeEntry, StakeRegistry};
pub use rewards::distribute_staker_rewards;
