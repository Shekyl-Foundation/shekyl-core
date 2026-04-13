//! Staking subsystem for Shekyl.
//!
//! Tracks active stakes, computes weighted rewards, and manages lock tiers.

#![deny(unsafe_code)]

pub mod tiers;
pub mod registry;
pub mod rewards;
pub mod error;

pub use error::StakingError;
pub use tiers::{StakeTier, TIERS, MAX_CLAIM_RANGE};
pub use registry::{StakeEntry, StakeRegistry};
pub use rewards::distribute_staker_rewards;

#[cfg(test)]
mod property_tests;
