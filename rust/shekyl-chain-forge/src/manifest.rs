// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A forged chain's manifest, format 6 (`CHAIN_FORGE.md` §7.2).
//!
//! The manifest names the chain without its bytes: the plan and its hash,
//! the seed, the network and its genesis, the schedule the plan derived,
//! the corpus's and trace's hashes, and the event index a consumer asks by
//! name. It is committed beside `blocks.txt` and compared byte for byte
//! with a fresh forging, so it holds nothing that changes when the chain
//! does not: no commit id and no time. The commit a hosted chain was
//! forged at belongs to its publication (`CF-4a`'s pin file and the
//! artifact's release notes), not to the chain; a manifest that carried it
//! would differ at every commit and stop being a known answer.
//!
//! `switches` names each switch the replay's fork choice made on the
//! corpus's `offer` records (corpus layout 5): the record that tipped it,
//! the fork's height and the depth. The replay test holds a fresh replay's
//! switches to them, so a change in the fork choice is a red test, not a
//! changed record.

use serde::{Deserialize, Serialize};

/// This manifest's format. Format 5 is the live capture's
/// (`regtest_e2e.rs`, `format_version` 5); a forged chain's is 6.
pub const MANIFEST_FORMAT_VERSION: u32 = 6;

/// The plan a chain was forged from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRef {
    /// Its path in the tree, from the repository root.
    pub path: String,
    /// The SHA-256 of its bytes, hex.
    pub sha256: String,
}

/// The schedule the chain ran, as the plan derived it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRecord {
    /// Blocks per settlement epoch.
    pub settlement_epoch_blocks: u64,
    /// The reorg cap, in blocks.
    pub reorg_cap_blocks: u64,
    /// The fixed difficulty; `None` for live LWMA.
    pub fixed_difficulty: Option<u64>,
    /// Seconds between consecutive blocks' timestamps.
    pub block_seconds: u64,
}

/// One indexed event: where a consumer finds it by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    /// The event's stable name.
    pub name: String,
    /// The height of the block that completed it.
    pub height: u64,
    /// `main`, or `alt:<n>` from `CF-3` on.
    pub branch: String,
    /// The corpus record that completed it, counted from zero.
    pub record: u64,
}

/// A switch the forge expects the replay's fork choice to make (`CF-3`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchRecord {
    /// The record after which the switch happens.
    pub at_record: u64,
    /// The fork's height.
    pub fork_height: u64,
    /// Blocks popped.
    pub depth: u64,
}

/// A forged chain's manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`MANIFEST_FORMAT_VERSION`].
    pub format_version: u32,
    /// The chain's name (`L`, `B`, `P`, `W`, `M`, or a plan's own).
    pub chain: String,
    /// The plan.
    pub plan: PlanRef,
    /// The plan's seed, hex (also in the plan; repeated so the manifest
    /// alone names the chain).
    pub seed: String,
    /// Always `regtest` (`CHAIN_FORGE.md` §6).
    pub network: String,
    /// The network's table genesis, which block 0 is.
    pub genesis_hash: String,
    /// The schedule.
    pub schedule: ScheduleRecord,
    /// The corpus's binary layout (`CORPUS_FORMAT_VERSION`).
    pub corpus_format_version: u32,
    /// Lines in `blocks.txt`: every block the corpus writes, a rewound one
    /// included.
    pub blocks: u64,
    /// The chain's tip height.
    pub tip_height: u64,
    /// Transactions the corpus lists, coinbases excluded.
    pub transactions: u64,
    /// The corpus's SHA-256, hex.
    pub corpus_sha256: String,
    /// The trace's SHA-256, hex.
    pub trace_sha256: String,
    /// The event index.
    pub events: Vec<EventRecord>,
    /// The switches the replay's fork choice made, which the forge held to
    /// the ones its plan expects: one per reorg.
    pub switches: Vec<SwitchRecord>,
}

/// Why a manifest did not parse.
#[derive(Debug, thiserror::Error)]
pub enum ManifestFault {
    /// Not a manifest's JSON.
    #[error("manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// Another format's manifest.
    #[error("manifest format {found}, this reader reads {MANIFEST_FORMAT_VERSION}")]
    Format {
        /// The format it names.
        found: u32,
    },
}

impl Manifest {
    /// The manifest's text: pretty JSON in the struct's field order, ending
    /// in a newline. One manifest, one text.
    ///
    /// # Panics
    ///
    /// Never: every field serializes.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("a manifest serializes");
        text.push('\n');
        text
    }

    /// Parse a manifest's text.
    ///
    /// # Errors
    ///
    /// [`ManifestFault`].
    pub fn parse(text: &str) -> Result<Self, ManifestFault> {
        let manifest: Self = serde_json::from_str(text)?;
        if manifest.format_version != MANIFEST_FORMAT_VERSION {
            return Err(ManifestFault::Format {
                found: manifest.format_version,
            });
        }
        Ok(manifest)
    }
}

/// SHA-256 of `bytes`, lower-case hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            chain: "small".into(),
            plan: PlanRef {
                path: "rust/shekyl-chain-forge/plans/small.toml".into(),
                sha256: sha256_hex(b"plan"),
            },
            seed: "00".repeat(32),
            network: "regtest".into(),
            genesis_hash: "11".repeat(32),
            schedule: ScheduleRecord {
                settlement_epoch_blocks: 300,
                reorg_cap_blocks: 10,
                fixed_difficulty: Some(1),
                block_seconds: 1,
            },
            corpus_format_version: 4,
            blocks: 3,
            tip_height: 2,
            transactions: 1,
            corpus_sha256: sha256_hex(b"corpus"),
            trace_sha256: sha256_hex(b"trace"),
            events: vec![EventRecord {
                name: "first-spend".into(),
                height: 2,
                branch: "main".into(),
                record: 2,
            }],
            switches: Vec::new(),
        }
    }

    #[test]
    fn a_manifest_round_trips_its_text() {
        let manifest = sample();
        let text = manifest.render();
        assert!(text.ends_with("}\n"));
        assert_eq!(Manifest::parse(&text).expect("parses"), manifest);
        assert_eq!(Manifest::parse(&text).expect("parses").render(), text);
    }

    #[test]
    fn another_format_and_an_unknown_field_are_refused() {
        let mut manifest = sample();
        manifest.format_version = 5;
        assert!(matches!(
            Manifest::parse(&manifest.render()),
            Err(ManifestFault::Format { found: 5 })
        ));
        let text = sample()
            .render()
            .replacen('{', "{\n  \"forged_at\": \"abc\",", 1);
        assert!(
            Manifest::parse(&text).is_err(),
            "no commit id rides the manifest"
        );
    }

    #[test]
    fn sha256_is_the_standard_digest() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
