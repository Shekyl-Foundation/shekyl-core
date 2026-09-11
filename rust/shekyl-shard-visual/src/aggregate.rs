use serde::{Deserialize, Serialize};

/// Public chain properties that drive shard visual semantics.
///
/// Every field must satisfy the admissibility criterion in
/// `docs/V3_SHARD_VISUALIZATION.md` (ruling A): a deterministic function
/// of data any shard holder can read from the held block bytes, with no
/// key, wallet state, or holder privilege. Adding a field here is a
/// violation of the closed-world artifact property by default and
/// requires re-ratifying that section.
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
}

/// Serde `with` module for a 32-byte hash encoded as lowercase hex on the
/// wire. Shared across the shard subsystem — `ShardAggregate::shard_hash` here
/// and the handle hashes in `shekyl-shard-source` — so the encoding has one
/// definition and cannot drift between crates.
pub mod hex_bytes {
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
            .map_err(|_| serde::de::Error::custom("hash must be exactly 32 bytes"))
    }
}
