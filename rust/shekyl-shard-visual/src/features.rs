use crate::aggregate::ShardAggregate;
use serde::{Deserialize, Serialize};

const EXPECTED_TX_PER_BLOCK: f64 = 50.0;
const EXPECTED_OUTPUTS_PER_TX: f64 = 4.0;

/// Normalized semantic scalars in `[0, 1]`.
///
/// Only features admitted by the ruling-A criterion appear here
/// (`docs/V3_SHARD_VISUALIZATION.md`, *Parameter admissibility*): each is
/// a deterministic function of counts and timestamps a shard holder reads
/// from the held block bytes. Rejected features (value moments, tier
/// skew, stake-event ratios) are recorded with their grounds in that
/// section; re-admitting one requires re-ratifying it there first.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Features {
    pub activity_density: f64,
    pub output_richness: f64,
    pub coinbase_ratio: f64,
    pub time_density: f64,
}

fn saturate(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

pub fn features_from_aggregate(agg: &ShardAggregate) -> Features {
    let blocks = agg.block_count.max(1);
    let user_outputs = agg.output_count.saturating_sub(agg.coinbase_output_count);

    let activity_density = saturate(agg.tx_count as f64 / (blocks as f64 * EXPECTED_TX_PER_BLOCK));
    let output_richness = if agg.tx_count > 0 {
        saturate((user_outputs as f64 / agg.tx_count as f64) / EXPECTED_OUTPUTS_PER_TX)
    } else {
        0.0
    };
    let coinbase_ratio = if agg.output_count > 0 {
        saturate(agg.coinbase_output_count as f64 / agg.output_count as f64)
    } else {
        1.0
    };
    let expected_seconds = blocks * 120;
    let time_density = saturate(agg.time_range_seconds as f64 / expected_seconds.max(1) as f64);

    Features {
        activity_density,
        output_richness,
        coinbase_ratio,
        time_density,
    }
}
