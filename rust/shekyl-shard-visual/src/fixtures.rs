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

/// Nine regime fixtures from the visualization explorer fake chain
/// (`shekyl-dev` corpus seed `shekyl-explorer-v2`, `tests/fixtures/shards_24.json`).
///
/// Regenerate via `visualization/scripts/export_rust_fixtures.py` after
/// `scripts/regenerate_test_corpus.py`.
pub fn all() -> Vec<PreviewFixture> {
    vec![
        PreviewFixture {
            id: "genesis".into(),
            label: "Genesis regime".into(),
            aggregate: ShardAggregate {
                shard_id: 0,
                shard_hash: parse_hash(
                    "82a866d2e033b952a133a0cb4595fa736d23584b20a88df66dbb5e4a8eedb750",
                ),
                block_count: 10_000,
                tx_count: 516,
                output_count: 11_324,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_196_437,
                coinbase_ratio: 0.8830801836806782,
                value_log_mean: 16.116390227686345,
                value_log_variance: 30.945513016617575,
                stake_events_created: 3,
                stake_events_claimed: 0,
                tier_distribution: [0, 0, 3],
                dominant_regime: "genesis".into(),
            },
        },
        PreviewFixture {
            id: "pre_drain".into(),
            label: "Pre-drain regime (CT-2 empty tree window)".into(),
            aggregate: ShardAggregate {
                shard_id: 1,
                shard_hash: parse_hash(
                    "28659414db2829e1649cd448d4c8979ae793f4a490223c210cc257317d2db2a9",
                ),
                block_count: 10_000,
                tx_count: 104,
                output_count: 10_248,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_198_310,
                coinbase_ratio: 0.975800156128025,
                value_log_mean: 15.55016153098693,
                value_log_variance: 28.52462599724527,
                stake_events_created: 0,
                stake_events_claimed: 0,
                tier_distribution: [0, 0, 0],
                dominant_regime: "pre_drain".into(),
            },
        },
        PreviewFixture {
            id: "coinbase_heavy".into(),
            label: "Coinbase-heavy regime".into(),
            aggregate: ShardAggregate {
                shard_id: 2,
                shard_hash: parse_hash(
                    "15f2ac79630f2d1b720083c8033dca0a2ea4282e7103836a977305d1c2a76849",
                ),
                block_count: 10_000,
                tx_count: 3_953,
                output_count: 20_322,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_202_032,
                coinbase_ratio: 0.49207755142210413,
                value_log_mean: 18.331173646116994,
                value_log_variance: 36.51388041637063,
                stake_events_created: 5,
                stake_events_claimed: 9,
                tier_distribution: [0, 3, 2],
                dominant_regime: "coinbase_heavy".into(),
            },
        },
        PreviewFixture {
            id: "drain_burst".into(),
            label: "Drain-burst regime (coinbase +60 maturity)".into(),
            aggregate: ShardAggregate {
                shard_id: 3,
                shard_hash: parse_hash(
                    "a7095fb4acc314aaedb64243c0c117801dd86428a2e9acfcdb86a6b611488369",
                ),
                block_count: 10_000,
                tx_count: 119_716,
                output_count: 417_836,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_200_015,
                coinbase_ratio: 0.023932834892158646,
                value_log_mean: 20.625127247872197,
                value_log_variance: 44.559989790462424,
                stake_events_created: 783,
                stake_events_claimed: 600,
                tier_distribution: [204, 249, 330],
                dominant_regime: "drain_burst".into(),
            },
        },
        PreviewFixture {
            id: "quiet".into(),
            label: "Quiet regime".into(),
            aggregate: ShardAggregate {
                shard_id: 4,
                shard_hash: parse_hash(
                    "d9df67a690eca8d02602a7e7228d7d09d385bcc581135771c1507f330d22f9b7",
                ),
                block_count: 10_000,
                tx_count: 14_903,
                output_count: 49_765,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_195_418,
                coinbase_ratio: 0.20094443886265448,
                value_log_mean: 20.721622499019848,
                value_log_variance: 42.75561175010279,
                stake_events_created: 50,
                stake_events_claimed: 61,
                tier_distribution: [22, 6, 22],
                dominant_regime: "quiet".into(),
            },
        },
        PreviewFixture {
            id: "active".into(),
            label: "Active regime".into(),
            aggregate: ShardAggregate {
                shard_id: 5,
                shard_hash: parse_hash(
                    "46018f32e3ad83e2a0b6f94b02d18c7d731bef5609a597dc18f4a88ad9557bff",
                ),
                block_count: 10_000,
                tx_count: 350_321,
                output_count: 1_094_388,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_199_878,
                coinbase_ratio: 0.00913752709276783,
                value_log_mean: 24.005264124406956,
                value_log_variance: 51.76197759767892,
                stake_events_created: 513,
                stake_events_claimed: 397,
                tier_distribution: [296, 141, 76],
                dominant_regime: "active".into(),
            },
        },
        PreviewFixture {
            id: "stake_heavy".into(),
            label: "Stake-heavy regime".into(),
            aggregate: ShardAggregate {
                shard_id: 6,
                shard_hash: parse_hash(
                    "f40a9e5742caf5a761fe85a67f32416208e7f14745ca4c26f0bb9b20326b0456",
                ),
                block_count: 10_000,
                tx_count: 79_893,
                output_count: 240_177,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_198_422,
                coinbase_ratio: 0.04163596014605895,
                value_log_mean: 25.124944591506782,
                value_log_variance: 52.401580925986245,
                stake_events_created: 4_449,
                stake_events_claimed: 3_536,
                tier_distribution: [1316, 1261, 1872],
                dominant_regime: "stake_heavy".into(),
            },
        },
        PreviewFixture {
            id: "confidential_stake".into(),
            label: "Confidential-staking regime".into(),
            aggregate: ShardAggregate {
                shard_id: 7,
                shard_hash: parse_hash(
                    "e4734e614d9b82e53548d9c0e480c0a233237fca98538555888135b835d0bc10",
                ),
                block_count: 10_000,
                tx_count: 60_195,
                output_count: 187_090,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_199_474,
                coinbase_ratio: 0.05345021112833396,
                value_log_mean: 25.943907885794548,
                value_log_variance: 57.00948272846666,
                stake_events_created: 5_476,
                stake_events_claimed: 4_835,
                tier_distribution: [1140, 1346, 2990],
                dominant_regime: "confidential_stake".into(),
            },
        },
        PreviewFixture {
            id: "whale".into(),
            label: "Whale regime".into(),
            aggregate: ShardAggregate {
                shard_id: 8,
                shard_hash: parse_hash(
                    "517945b2ead91ae478fbe2d0359b4ea8f33b8a8d1393e607ec63666c71296cbc",
                ),
                block_count: 10_000,
                tx_count: 40_290,
                output_count: 195_092,
                coinbase_output_count: 10_000,
                time_range_seconds: 1_197_938,
                coinbase_ratio: 0.0512578680827507,
                value_log_mean: 35.56001483823426,
                value_log_variance: 76.44088911020691,
                stake_events_created: 193,
                stake_events_claimed: 169,
                tier_distribution: [22, 41, 130],
                dominant_regime: "whale".into(),
            },
        },
    ]
}

pub fn by_id(id: &str) -> Option<PreviewFixture> {
    all().into_iter().find(|f| f.id == id)
}
