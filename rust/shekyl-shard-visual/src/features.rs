use crate::aggregate::ShardAggregate;
use serde::{Deserialize, Serialize};

const EXPECTED_TX_PER_BLOCK: f64 = 50.0;
const EXPECTED_OUTPUTS_PER_TX: f64 = 4.0;
const EXPECTED_STAKES_PER_BLOCK: f64 = 0.5;
const EXPECTED_VALUE_LOG_VARIANCE: f64 = 30.0;
const EXPECTED_VALUE_LOG_MEAN: f64 = 25.0;

/// Normalized semantic scalars in `[0, 1]`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Features {
    pub activity_density: f64,
    pub output_richness: f64,
    pub coinbase_ratio: f64,
    pub value_dispersion: f64,
    pub value_magnitude: f64,
    pub stake_intensity: f64,
    pub tier_skew_high: f64,
    pub claim_create_ratio: f64,
    pub time_density: f64,
}

fn saturate(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

pub fn features_from_aggregate(agg: &ShardAggregate) -> Features {
    let blocks = agg.block_count.max(1);
    let user_outputs = agg
        .output_count
        .saturating_sub(agg.coinbase_output_count);

    let activity_density = saturate(agg.tx_count as f64 / (blocks as f64 * EXPECTED_TX_PER_BLOCK));
    let output_richness = if agg.tx_count > 0 {
        saturate(
            (user_outputs as f64 / agg.tx_count as f64) / EXPECTED_OUTPUTS_PER_TX,
        )
    } else {
        0.0
    };
    let coinbase_ratio = saturate(agg.coinbase_ratio);
    let value_dispersion = saturate(agg.value_log_variance / EXPECTED_VALUE_LOG_VARIANCE);
    let value_magnitude = saturate(
        (agg.value_log_mean - 12.0).max(0.0) / (EXPECTED_VALUE_LOG_MEAN - 12.0).max(1.0),
    );
    let stake_intensity = saturate(
        agg.stake_events_created as f64 / (blocks as f64 * EXPECTED_STAKES_PER_BLOCK),
    );
    let total_tier: u64 = agg.tier_distribution.iter().sum();
    let tier_skew_high = if total_tier > 0 {
        agg.tier_distribution[2] as f64 / total_tier as f64
    } else {
        0.0
    };
    let claim_create_ratio = if agg.stake_events_created > 0 {
        saturate(
            agg.stake_events_claimed as f64 / agg.stake_events_created as f64,
        )
    } else {
        0.0
    };
    let expected_seconds = blocks * 120;
    let time_density = saturate(agg.time_range_seconds as f64 / expected_seconds.max(1) as f64);

    Features {
        activity_density,
        output_richness,
        coinbase_ratio,
        value_dispersion,
        value_magnitude,
        stake_intensity,
        tier_skew_high,
        claim_create_ratio,
        time_density,
    }
}
