//! Shard data-source abstraction for the wallet's shard view.
//!
//! The GUI lists shards and renders each one's deterministic identity visual
//! (candidate.v1, see `shekyl-shard-visual`). *Which* shards exist and their
//! aggregate statistics come from a [`ShardSource`]. Today the only
//! implementation is [`FixtureShardSource`], backed by the regime fixtures in
//! `shekyl_shard_visual::fixtures`. When `ArchivalEngine` (Stage 5, V3.x) lands
//! it provides an [`ArchivalShardSource`] reading live frozen segments; only
//! the source swaps — the wire types ([`ShardSummary`], [`ShardRenderHandle`])
//! and the renderer (`shekyl_shard_visual::render_candidate_png`) stay fixed.
//!
//! See `docs/V3_SHARD_VISUALIZATION.md` and the GUI's
//! `docs/SHARD_PREVIEW_CUTOVER.md` for the cutover contract.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use shekyl_shard_visual::{CandidateRecipe, ShardAggregate};

/// Errors a [`ShardSource`] can surface to the wallet.
#[derive(Debug, Error)]
pub enum ShardSourceError {
    /// No shard with the requested id is visible to this source.
    #[error("shard not found: id {0}")]
    NotFound(u64),
    /// The handle's `shard_hash` disagrees with the aggregate resolved for its
    /// `shard_id`: a stale handle, built before the source's shard set changed.
    /// The candidate.v1 visual is an identity signal, so a mismatched handle is
    /// rejected rather than rendered under the wrong hash (2026-07-10 decision
    /// in `docs/V3_WALLET_DECISION_LOG.md`).
    #[error("stale shard handle: id {shard_id} expected hash {expected}, source has {found}")]
    StaleHandle {
        shard_id: u64,
        expected: String,
        found: String,
    },
    /// The backing store (fixtures today, archival registry later) failed.
    #[error("shard source backend error: {0}")]
    Backend(String),
}

/// One entry in the shard list: a human label plus the full aggregate that
/// drives the visual.
///
/// Identity fields (`shard_id`, `shard_hash`, `dominant_regime`) live in
/// [`ShardAggregate`]; this type deliberately does not duplicate them — a
/// second copy would drift. Read them via [`ShardSummary::shard_id`] /
/// [`ShardSummary::shard_hash`] or directly from `aggregate`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ShardSummary {
    /// Human-facing label (e.g. the regime name for fixtures).
    pub label: String,
    /// Full chain-derived aggregate; seeds the candidate.v1 visual.
    pub aggregate: ShardAggregate,
}

impl ShardSummary {
    /// Numeric shard identifier.
    #[must_use]
    pub fn shard_id(&self) -> u64 {
        self.aggregate.shard_id
    }

    /// 32-byte shard content hash.
    #[must_use]
    pub fn shard_hash(&self) -> [u8; 32] {
        self.aggregate.shard_hash
    }
}

/// A request to render one shard at a given size.
///
/// `hash_override` is the GUI's existing "tweak" path: when present the
/// compositor is seeded from this hash instead of the shard's own, letting the
/// preview explore variants without changing the underlying aggregate. The
/// trait itself only needs `shard_id` to resolve the aggregate; the renderer
/// decides whether to apply the override.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ShardRenderHandle {
    /// Which shard to render.
    pub shard_id: u64,
    /// The shard's own content hash (hex on the wire).
    #[serde(with = "shekyl_shard_visual::hex_bytes")]
    pub shard_hash: [u8; 32],
    /// Optional compositor-seed override (hex on the wire). Absent when unset —
    /// never serialized as JSON `null`.
    #[serde(with = "hex32_opt", default, skip_serializing_if = "Option::is_none")]
    pub hash_override: Option<[u8; 32]>,
    /// Output edge length in pixels (square).
    pub size: u32,
}

/// Source of the shard list and per-shard aggregate lookup.
///
/// The renderer is *not* part of this trait — it lives in
/// `shekyl_shard_visual` and is the same across every implementation, so the
/// Stage 5 cutover is a trait-impl swap, not a render rewrite.
pub trait ShardSource {
    /// List every shard visible to this source.
    fn list_shards(&self) -> Result<Vec<ShardSummary>, ShardSourceError>;

    /// Resolve the aggregate for a single render request.
    fn aggregate_for(&self, handle: &ShardRenderHandle)
        -> Result<ShardAggregate, ShardSourceError>;
}

/// Regime fixtures from `shekyl-shard-visual`, built once as [`ShardSummary`]s.
///
/// `shekyl_shard_visual::fixtures::all()` allocates a fresh `PreviewFixture`
/// set (labels, ids, parsed hashes) on every call; building the list once lets
/// both `list_shards` and `aggregate_for` reuse it instead of rebuilding the
/// whole fixture set per lookup. The length tracks `fixtures::all()` — do not
/// hard-code a count here.
static FIXTURE_SUMMARIES: LazyLock<Vec<ShardSummary>> = LazyLock::new(|| {
    shekyl_shard_visual::fixtures::all()
        .into_iter()
        .map(|f| ShardSummary {
            label: f.label,
            aggregate: f.aggregate,
        })
        .collect()
});

/// Fixture-backed source: the regime fixtures shipped in `shekyl-shard-visual`.
///
/// This is the pre-ArchivalEngine implementation the wallet uses today.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureShardSource;

impl ShardSource for FixtureShardSource {
    fn list_shards(&self) -> Result<Vec<ShardSummary>, ShardSourceError> {
        Ok(FIXTURE_SUMMARIES.clone())
    }

    fn aggregate_for(
        &self,
        handle: &ShardRenderHandle,
    ) -> Result<ShardAggregate, ShardSourceError> {
        let summary = FIXTURE_SUMMARIES
            .iter()
            .find(|s| s.aggregate.shard_id == handle.shard_id)
            .ok_or(ShardSourceError::NotFound(handle.shard_id))?;
        // `shard_hash` is authoritative: a handle whose hash disagrees with the
        // resolved aggregate is stale and rejected, never rendered under the
        // wrong hash (2026-07-10 decision-log entry). Always passes on fixtures
        // (their hashes are static); the guard is the contract Stage 5's
        // mutable `ArchivalShardSource` must honor.
        if summary.aggregate.shard_hash != handle.shard_hash {
            return Err(ShardSourceError::StaleHandle {
                shard_id: handle.shard_id,
                expected: hex::encode(handle.shard_hash),
                found: hex::encode(summary.aggregate.shard_hash),
            });
        }
        Ok(summary.aggregate.clone())
    }
}

/// Stage 5 ArchivalEngine-backed source — **seam stub**.
///
/// When `ArchivalEngine` lands it enumerates frozen shard segments from the
/// archival registry and reconstructs each [`ShardAggregate`] from chain data.
/// The three cutover steps are enumerated in
/// `shekyl-gui-wallet/docs/SHARD_PREVIEW_CUTOVER.md`; this type is the swap
/// point. Gated behind the `archival` feature so it does not affect the
/// fixtures build.
#[cfg(feature = "archival")]
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchivalShardSource;

#[cfg(feature = "archival")]
impl ShardSource for ArchivalShardSource {
    fn list_shards(&self) -> Result<Vec<ShardSummary>, ShardSourceError> {
        // Stage 5: enumerate frozen segments from the archival registry.
        Err(ShardSourceError::Backend(
            "ArchivalShardSource not yet implemented (Stage 5)".into(),
        ))
    }

    fn aggregate_for(
        &self,
        _handle: &ShardRenderHandle,
    ) -> Result<ShardAggregate, ShardSourceError> {
        // Stage 5: reconstruct the aggregate from the frozen segment row.
        Err(ShardSourceError::Backend(
            "ArchivalShardSource not yet implemented (Stage 5)".into(),
        ))
    }
}

/// Optional 32-byte hash on the wire: lowercase hex when present, key omitted
/// when unset (`skip_serializing_if` on the field). Both encode and decode
/// delegate to [`shekyl_shard_visual::hex_bytes`] so the encoding has a single
/// definition and cannot drift from `shard_hash`.
mod hex32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            // Field-level `skip_serializing_if` normally prevents this arm from
            // running for `None`; keep `serialize_none` so the module stays a
            // correct Option adapter if reused without the skip attribute.
            Some(bytes) => shekyl_shard_visual::hex_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Hex32(#[serde(with = "shekyl_shard_visual::hex_bytes")] [u8; 32]);
        Ok(Option::<Hex32>::deserialize(deserializer)?.map(|h| h.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_map_one_to_one() {
        let src = FixtureShardSource;
        let shards = src.list_shards().unwrap();
        assert_eq!(shards.len(), shekyl_shard_visual::fixtures::all().len());
    }

    #[test]
    fn aggregate_lookup_returns_matching_fixture() {
        let src = FixtureShardSource;
        let first = src.list_shards().unwrap().remove(0);
        let handle = ShardRenderHandle {
            shard_id: first.shard_id(),
            shard_hash: first.shard_hash(),
            hash_override: None,
            size: 256,
        };
        let agg = src.aggregate_for(&handle).unwrap();
        assert_eq!(agg, first.aggregate);
    }

    #[test]
    fn stale_hash_is_rejected() {
        // A handle with a valid shard_id but a hash that no longer matches the
        // resolved aggregate (the shard set changed under it) is rejected, not
        // silently rendered under the wrong hash. See the 2026-07-10 decision.
        let src = FixtureShardSource;
        let first = src.list_shards().unwrap().remove(0);
        let handle = ShardRenderHandle {
            shard_id: first.shard_id(),
            shard_hash: [0xAA_u8; 32],
            hash_override: None,
            size: 256,
        };
        assert!(matches!(
            src.aggregate_for(&handle),
            Err(ShardSourceError::StaleHandle { shard_id, .. }) if shard_id == first.shard_id()
        ));
    }

    #[test]
    fn unknown_shard_is_not_found() {
        let src = FixtureShardSource;
        let handle = ShardRenderHandle {
            shard_id: 9_999,
            shard_hash: [0u8; 32],
            hash_override: None,
            size: 256,
        };
        assert!(matches!(
            src.aggregate_for(&handle),
            Err(ShardSourceError::NotFound(9_999))
        ));
    }

    #[test]
    fn summary_identity_survives_the_wire() {
        // The aggregate carries f64 "aesthetic scalar" fields (coinbase_ratio,
        // value_log_*) that the JSON float path does not round-trip bit-exactly
        // in this toolchain — which is fine: they are display-only and never
        // feed a consensus or rendered-on-the-wire decision (the renderer runs
        // Rust-side on the in-memory aggregate). The wire contract that matters
        // is that *identity* — shard id, hash, label, and the integer counts —
        // survives intact. That is what we assert.
        let src = FixtureShardSource;
        let shards = src.list_shards().unwrap();
        let json = serde_json::to_string(&shards).unwrap();
        let back: Vec<ShardSummary> = serde_json::from_str(&json).unwrap();
        assert_eq!(shards.len(), back.len());
        for (orig, round) in shards.iter().zip(back.iter()) {
            assert_eq!(orig.label, round.label);
            assert_eq!(orig.shard_id(), round.shard_id());
            assert_eq!(orig.shard_hash(), round.shard_hash());
            assert_eq!(orig.aggregate.block_count, round.aggregate.block_count);
            assert_eq!(orig.aggregate.tx_count, round.aggregate.tx_count);
            assert_eq!(
                orig.aggregate.tier_distribution,
                round.aggregate.tier_distribution
            );
            assert_eq!(
                orig.aggregate.dominant_regime,
                round.aggregate.dominant_regime
            );
        }
    }

    #[test]
    fn render_handle_serde_roundtrips_with_override() {
        let handle = ShardRenderHandle {
            shard_id: 3,
            shard_hash: [7u8; 32],
            hash_override: Some([9u8; 32]),
            size: 128,
        };
        let json = serde_json::to_string(&handle).unwrap();
        let back: ShardRenderHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle, back);
    }

    #[test]
    fn render_handle_serde_roundtrips_without_override() {
        let handle = ShardRenderHandle {
            shard_id: 0,
            shard_hash: [1u8; 32],
            hash_override: None,
            size: 256,
        };
        let json = serde_json::to_string(&handle).unwrap();
        // Wire contract: unset override is absent, not JSON null.
        assert!(
            !json.contains("hash_override"),
            "unset hash_override must be omitted from JSON, got {json}"
        );
        let back: ShardRenderHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle, back);
        assert!(back.hash_override.is_none());
    }
}
