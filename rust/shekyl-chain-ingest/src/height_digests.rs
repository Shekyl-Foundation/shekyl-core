// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The logical-state digest at a store's tip, and at every height of a
//! one-block-per-commit baseline (`DAEMON_REDB_STORE.md` §1.3a, PB-S1).
//!
//! Both are the store's own `logical_state_digest_v0`. Nothing here
//! recomputes a digest from its parts. The per-height table is what a
//! baseline recorded after each single-block commit; a replay point looks
//! a height up in it instead of replaying the chain again.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use shekyl_types::BlockHeight;

use crate::rebaseline::publish_bytes;
use crate::trace::Digest;

/// The on-disk table [`publish`] writes.
pub const HEIGHT_DIGESTS_SCHEMA: &str = "shekyl_height_digests_v1";

/// One store's recorded tip, as the replay tool prints it: `tip` is null
/// when the store is empty, and `hash` is empty in that same case.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct StoreDigestLine {
    /// The tip height, or null when the store holds no block.
    pub tip: Option<u64>,
    /// The tip's block hash, lowercase hex, or empty when there is no tip.
    pub hash: String,
    /// `logical_state_digest_v0`, lowercase hex.
    pub digest: String,
}

/// `store`'s digest line as one JSON object. Field order is `tip`, `hash`,
/// `digest`.
///
/// # Errors
///
/// Serialization only.
pub fn store_digest_line(
    tip: Option<u64>,
    hash: Option<&[u8]>,
    digest: &Digest,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&StoreDigestLine {
        tip,
        hash: hash.map(hex_of).unwrap_or_default(),
        digest: hex_of(digest),
    })
}

#[derive(Serialize)]
struct HeightDigestRow {
    height: u64,
    digest: String,
}

#[derive(Serialize)]
struct HeightDigestFile {
    schema: &'static str,
    rows: Vec<HeightDigestRow>,
}

/// Replace `path` with the digest at every height in `digests`, ascending.
/// The bytes are published by renaming a sibling, so a short write never
/// truncates a table the caller already has.
///
/// # Errors
///
/// The destination could not be replaced, or the table could not be serialized.
pub fn publish(path: &Path, digests: &BTreeMap<BlockHeight, Digest>) -> std::io::Result<()> {
    let file = HeightDigestFile {
        schema: HEIGHT_DIGESTS_SCHEMA,
        rows: digests
            .iter()
            .map(|(height, digest)| HeightDigestRow {
                height: height.to_raw(),
                digest: hex_of(digest),
            })
            .collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&file).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("height digests: {error}"),
        )
    })?;
    bytes.push(b'\n');
    publish_bytes(path, &bytes)
}

fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_store_is_a_null_tip_and_an_empty_hash() {
        let line = store_digest_line(None, None, &[0xab; 32]).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(
            value,
            serde_json::json!({
                "tip": null,
                "hash": "",
                "digest": "ab".repeat(32),
            })
        );
    }

    #[test]
    fn a_tip_carries_its_height_and_hash_ahead_of_the_digest() {
        let line = store_digest_line(Some(4), Some(&[0x10, 0x2a]), &[0x01; 32]).expect("serialize");
        assert!(line.starts_with("{\"tip\":4,\"hash\":\"102a\",\"digest\":\""));
    }

    #[test]
    fn a_table_is_the_heights_in_order_and_replaces_the_file_whole() {
        let path = crate::test_support::tmp("height-digests");
        std::fs::write(&path, b"previous").expect("seed");
        let mut digests = BTreeMap::new();
        digests.insert(BlockHeight::from_raw(1), [0x22; 32]);
        digests.insert(BlockHeight::from_raw(0), [0x11; 32]);
        publish(&path, &digests).expect("publish");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(value["schema"], HEIGHT_DIGESTS_SCHEMA);
        assert_eq!(value["rows"][0]["height"], 0);
        assert_eq!(value["rows"][1]["height"], 1);
        assert_eq!(value["rows"][0]["digest"], "11".repeat(32));
        crate::test_support::cleanup(&path);
    }
}
