//! Staking subsystem for Shekyl.
//!
//! Tracks active stakes, computes weighted rewards, and manages lock tiers.

#![deny(unsafe_code)]

pub mod error;
pub mod registry;
pub mod rewards;
pub mod tiers;

pub use error::StakingError;
pub use registry::{StakeEntry, StakeRegistry};
pub use rewards::distribute_staker_rewards;
pub use tiers::{StakeTier, MAX_CLAIM_RANGE, TIERS};

#[cfg(test)]
mod property_tests;
