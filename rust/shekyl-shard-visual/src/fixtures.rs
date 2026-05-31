use crate::aggregate::ShardAggregate;

#[derive(Clone, Debug)]
pub struct PreviewFixture {
    pub id: String,
    pub label: String,
    pub aggregate: ShardAggregate,
}

fn parse_hash(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("fixture hash");
    bytes.try_into().expect("32-byte hash")
}

/// Six regime fixtures from the visualization explorer fake chain (shards 0–5).
pub fn all() -> Vec<PreviewFixture> {
    vec![
        PreviewFixture {
            id: "genesis".into(),
            label: "Genesis regime".into(),
            aggregate: ShardAggregate {
                shard_id: 0,
                shard_hash: parse_hash(
                    "50f27e5f6e1f0f6b31f903c151f4ad2cc93e26518e20e50b98448eebadc7c50f",
                ),
                block_count: 10_000,
                tx_count: 526,
                output_count: 11_319,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_197_432,
                coinbase_ratio: 0.8834702712253732,
                value_log_mean: 16.12014514756088,
                value_log_variance: 30.995250849833656,
                stake_events_created: 0,
                stake_events_claimed: 0,
                tier_distribution: [0, 0, 0],
                dominant_regime: "genesis".into(),
            },
        },
        PreviewFixture {
            id: "coinbase_heavy".into(),
            label: "Coinbase-heavy regime".into(),
            aggregate: ShardAggregate {
                shard_id: 1,
                shard_hash: parse_hash(
                    "7198050d153416499f641afd2489df0c76b1c823c07c0c100708ce8145fb04b2",
                ),
                block_count: 10_000,
                tx_count: 4_118,
                output_count: 20_767,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_197_923,
                coinbase_ratio: 0.4815332017142582,
                value_log_mean: 18.32882008525721,
                value_log_variance: 36.55946719892432,
                stake_events_created: 17,
                stake_events_claimed: 14,
                tier_distribution: [4, 5, 8],
                dominant_regime: "coinbase_heavy".into(),
            },
        },
        PreviewFixture {
            id: "quiet".into(),
            label: "Quiet regime".into(),
            aggregate: ShardAggregate {
                shard_id: 2,
                shard_hash: parse_hash(
                    "63a99039ed1dbbfdb6695ebd4ae512fc82bbf9ddf4184427a70ba2a30f2337c3",
                ),
                block_count: 10_000,
                tx_count: 14_903,
                output_count: 49_892,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_201_517,
                coinbase_ratio: 0.20043293513990218,
                value_log_mean: 20.723649371456283,
                value_log_variance: 42.70451932948547,
                stake_events_created: 50,
                stake_events_claimed: 61,
                tier_distribution: [14, 12, 24],
                dominant_regime: "quiet".into(),
            },
        },
        PreviewFixture {
            id: "active".into(),
            label: "Active regime".into(),
            aggregate: ShardAggregate {
                shard_id: 3,
                shard_hash: parse_hash(
                    "7b8e37387582778296d25fb55dad68c6f156e52f1bbd39020044c693c51ca0d2",
                ),
                block_count: 10_000,
                tx_count: 349_825,
                output_count: 1_092_281,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_200_124,
                coinbase_ratio: 0.009155153298464407,
                value_log_mean: 23.986867606612034,
                value_log_variance: 51.65638833911728,
                stake_events_created: 533,
                stake_events_claimed: 367,
                tier_distribution: [285, 169, 79],
                dominant_regime: "active".into(),
            },
        },
        PreviewFixture {
            id: "stake_heavy".into(),
            label: "Stake-heavy regime".into(),
            aggregate: ShardAggregate {
                shard_id: 4,
                shard_hash: parse_hash(
                    "7b6be3d079a46e054beb0c4a69df92efa3fd42d8740aef079e9d89b149a9d8d4",
                ),
                block_count: 10_000,
                tx_count: 80_132,
                output_count: 239_269,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_199_787,
                coinbase_ratio: 0.04179396411570241,
                value_log_mean: 25.117994187685895,
                value_log_variance: 52.29479164965705,
                stake_events_created: 4_510,
                stake_events_claimed: 3_542,
                tier_distribution: [1342, 1388, 1780],
                dominant_regime: "stake_heavy".into(),
            },
        },
        PreviewFixture {
            id: "whale".into(),
            label: "Whale regime".into(),
            aggregate: ShardAggregate {
                shard_id: 5,
                shard_hash: parse_hash(
                    "af48555a394cf46b97b268431f33a394b7bf10bd13239cc76b24c3f299763c34",
                ),
                block_count: 10_000,
                tx_count: 40_300,
                output_count: 194_603,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_200_249,
                coinbase_ratio: 0.05138666927025791,
                value_log_mean: 35.56956405881627,
                value_log_variance: 76.44540234814394,
                stake_events_created: 215,
                stake_events_claimed: 180,
                tier_distribution: [23, 47, 145],
                dominant_regime: "whale".into(),
            },
        },
    ]
}

pub fn by_id(id: &str) -> Option<PreviewFixture> {
    all().into_iter().find(|f| f.id == id)
}
