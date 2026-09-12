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
pub mod block_weight;
pub mod burn;
pub mod digest;
pub mod emission;
pub mod emission_share;
pub mod escalation;
pub mod fee;
pub mod params;
pub mod release;
pub mod volume;

pub use activity::{ActivityInvariantViolation, ActivityMetric};
pub use block_weight::{
    blocks_to_surge_saturation, effective_median, long_term_weight, BLOCK_WEIGHT_SURGE_FACTOR,
};
pub use burn::{
    calc_burn_pct, calc_burn_pct_from_activity, compute_burn_split, compute_burn_split_at,
    BurnSplit,
};
pub use digest::{params_digest, DIGEST_FORMAT_VERSION};
pub use emission::{
    advance_already_generated, base_block_reward, base_emission_at, block_reward_with_penalty,
    block_weight_limit, effective_emission, emission_speed_factor, paid_block_reward,
    projected_already_generated, tail_subsidy_per_block, EmissionError,
};
pub use emission_share::{calc_effective_emission_share, split_block_emission};
pub use escalation::{
    staker_pool_share_at, EscalationParams, EscalationShapeError, FrozenSegmentCount, ScaledShare,
};
pub use fee::{
    checked_corrected_fee_ladder, checked_relay_fee_floor, corrected_fee_ladder, fee_correction,
    fee_correction_quantized, hysteresis_fold, hysteresis_settled, hysteresis_step,
    quantize_pow2_ceil, relay_fee_floor, relay_floor_admits, round_money_up_2, FeeCorrection,
    FeeLadder, EMISSION_CLAIM_FEE_FLOOR, RELAY_ADMISSION_SLACK_BP, RELAY_FLOOR_LOOKBACK,
    RELAY_FLOOR_WINDOW,
};
pub use params::{
    calc_stake_ratio, EconomicParams, EconomicParamsError, BLOCKS_PER_YEAR, CALIBRATION_GENERATION,
    EMISSION_CURVE_ASYMPTOTE, STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE,
};
pub use release::calc_release_multiplier;
pub use volume::TxVolume;
