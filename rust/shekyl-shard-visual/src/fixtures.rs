use crate::aggregate::ShardAggregate;

#[derive(Clone, Debug)]
pub struct PreviewFixture {
    pub id: String,
    pub label: String,
    /// Fake-chain regime classifier for this fixture. Lives here, not on
    /// [`ShardAggregate`]: it is corpus annotation, not chain data, so it
    /// must not sit on the type the admissibility criterion governs.
    pub dominant_regime: String,
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
            dominant_regime: "genesis".into(),
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
            },
        },
        PreviewFixture {
            id: "pre_drain".into(),
            label: "Pre-drain regime (CT-2 empty tree window)".into(),
            dominant_regime: "pre_drain".into(),
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
            },
        },
        PreviewFixture {
            id: "coinbase_heavy".into(),
            label: "Coinbase-heavy regime".into(),
            dominant_regime: "coinbase_heavy".into(),
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
            },
        },
        PreviewFixture {
            id: "drain_burst".into(),
            label: "Drain-burst regime (coinbase +60 maturity)".into(),
            dominant_regime: "drain_burst".into(),
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
            },
        },
        PreviewFixture {
            id: "quiet".into(),
            label: "Quiet regime".into(),
            dominant_regime: "quiet".into(),
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
            },
        },
        PreviewFixture {
            id: "active".into(),
            label: "Active regime".into(),
            dominant_regime: "active".into(),
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
            },
        },
        PreviewFixture {
            id: "stake_heavy".into(),
            label: "Stake-heavy regime".into(),
            dominant_regime: "stake_heavy".into(),
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
            },
        },
        PreviewFixture {
            id: "confidential_stake".into(),
            label: "Confidential-staking regime".into(),
            dominant_regime: "confidential_stake".into(),
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
            },
        },
        PreviewFixture {
            id: "whale".into(),
            label: "Whale regime".into(),
            dominant_regime: "whale".into(),
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
            },
        },
    ]
}

pub fn by_id(id: &str) -> Option<PreviewFixture> {
    all().into_iter().find(|f| f.id == id)
}
