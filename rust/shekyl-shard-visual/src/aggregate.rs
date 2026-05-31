use serde::{Deserialize, Serialize};

/// Public chain properties that drive shard visual semantics.
///
/// Mirrors the Python `ShardAggregate` used in the visualization explorer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ShardAggregate {
    pub shard_id: u64,
    /// 32-byte shard content hash (hex-serialized on the wire).
    #[serde(with = "hex_bytes")]
    pub shard_hash: [u8; 32],
    pub block_count: u64,
    pub tx_count: u64,
    pub output_count: u64,
    pub coinbase_output_count: u64,
    pub time_range_seconds: u64,
    pub coinbase_ratio: f64,
    pub value_log_mean: f64,
    pub value_log_variance: f64,
    pub stake_events_created: u64,
    pub stake_events_claimed: u64,
    pub tier_distribution: [u64; 3],
    pub dominant_regime: String,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("shard_hash must be 32 bytes"))
    }
}
