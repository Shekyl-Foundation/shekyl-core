//! Four-component economic system for Shekyl.
//!
//! Implements:
//! 1. Transaction-responsive release rate multiplier
//! 2. Adaptive fee burn with staker pool allocation
//! 3. Decaying staker emission share (bootstrap subsidy)
//!
//! (The claim-era staking-tier component was retired with the
//! confidential-staking sweep — `LEGACY_CLAIM_ERA_RETIREMENT.md`; genesis
//! staking is archival bonds, `shekyl-archival-retention`.)
//!
//! All calculations use u64 fixed-point with 10^6 scale (SCALE = 1_000_000).
//! A value of 1_000_000 represents 1.0, 400_000 represents 0.4, etc.

#![deny(unsafe_code)]

pub mod activity;
pub mod burn;
pub mod digest;
pub mod emission;
pub mod emission_share;
pub mod escalation;
pub mod params;
pub mod release;

pub use activity::{ActivityInvariantViolation, ActivityMetric};
pub use burn::{
    calc_burn_pct, calc_burn_pct_from_activity, compute_burn_split, compute_burn_split_at,
    BurnSplit,
};
pub use digest::{params_digest, DIGEST_FORMAT_VERSION};
pub use emission::{
    advance_already_generated, base_block_reward, base_emission_at, block_reward_with_penalty,
    block_weight_limit, projected_already_generated, EmissionError,
};
pub use emission_share::{calc_effective_emission_share, split_block_emission};
pub use escalation::{
    staker_pool_share_at, EscalationParams, EscalationShapeError, FrozenSegmentCount, ScaledShare,
};
pub use params::{
    calc_stake_ratio, EconomicParams, EconomicParamsError, BLOCKS_PER_YEAR, CALIBRATION_GENERATION,
    MONEY_SUPPLY, STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE,
};
pub use release::calc_release_multiplier;
