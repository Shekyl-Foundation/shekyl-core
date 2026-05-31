//! Four-component economic system for Shekyl.
//!
//! Implements:
//! 1. Transaction-responsive release rate multiplier
//! 2. Adaptive fee burn with staker pool allocation
//! 3. Staking tiers and implicit governance (via shekyl-staking crate)
//! 4. Decaying staker emission share (bootstrap subsidy)
//!
//! All calculations use u64 fixed-point with 10^6 scale (SCALE = 1_000_000).
//! A value of 1_000_000 represents 1.0, 400_000 represents 0.4, etc.

#![deny(unsafe_code)]

pub mod activity;
pub mod burn;
pub mod digest;
pub mod emission;
pub mod emission_share;
pub mod params;
pub mod release;

pub use activity::{ActivityInvariantViolation, ActivityMetric};
pub use burn::{calc_burn_pct, calc_burn_pct_from_activity, BurnSplit};
pub use digest::{params_digest, DIGEST_FORMAT_VERSION};
pub use emission::{
    base_block_reward, base_emission_at, projected_already_generated, EmissionError,
};
pub use emission_share::{calc_effective_emission_share, split_block_emission};
pub use params::{
    calc_stake_ratio, EconomicParams, BLOCKS_PER_YEAR, CALIBRATION_GENERATION, MONEY_SUPPLY,
    STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE,
};
pub use release::calc_release_multiplier;
