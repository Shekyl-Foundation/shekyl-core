// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shard lookup behind the serving loop: the [`ShardProvider`] seam and its
//! production [`LeafStore`] implementation.
//!
//! The seam exists so the loop's wire behaviour is testable without a
//! store, and so the store read (synchronous redb) is confined behind one
//! trait the endpoint calls via `spawn_blocking`. It is **not** an
//! abstraction over storage backends — the store is `LeafStore`, and the
//! trait's second implementor is the test fixture.

use std::sync::Arc;

use shekyl_curve_tree::{LeafStore, SegmentId, StoreError};

/// A shard lookup failed for an infrastructure reason (store I/O, pruned
/// bytes). Counted locally by the endpoint and **never distinguishable on
/// the wire** — the peer sees the same 404 as any other miss, because a
/// distinct failure response would let a prober read store health through
/// the rendezvous.
#[derive(Debug)]
pub struct ProviderError {
    detail: String,
}

impl ProviderError {
    /// A lookup failure with a local diagnostic description. For
    /// [`ShardProvider`] implementors; the description never reaches the
    /// wire.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Wrap a store failure, keeping its debug rendering for the local
    /// (aggregate, operator-side) diagnostic only.
    fn store(err: &StoreError) -> Self {
        Self::new(format!("{err:?}"))
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shard lookup failed: {}", self.detail)
    }
}

impl std::error::Error for ProviderError {}

/// Serve-side shard lookup.
///
/// `Ok(None)` is the *unservable* case — unknown id, or a segment that has
/// not frozen yet (no committed `R_k`, so nothing content-verifiable to
/// serve). `Err` is infrastructure failure. The endpoint renders both as
/// the single shared 404; only the local counters tell them apart.
pub trait ShardProvider: Send + Sync + 'static {
    /// Full shard bytes for `shard_id` — the contiguous leaf bytes of the
    /// frozen segment, exactly what the witness hashes against `R_k`.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on store failure — including the pruned-bytes
    /// misconfiguration (`StoreError::FrozenSegmentPruned`), which means
    /// the serve-set was not pinned before a prune ran.
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<Arc<[u8]>>, ProviderError>;
}

/// Outcome of pinning one serve-set member at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeSetPin {
    /// The shard is frozen and now pinned: `prune_frozen` will retain its
    /// full leaf bytes.
    Pinned {
        /// The pinned shard.
        shard_id: u64,
    },
    /// The shard is bonded but its segment has not frozen yet — nothing to
    /// pin or serve until the freeze boundary crosses it. Bonding before
    /// freeze is legal by design (`bond_post.rs`: self-harm, not an
    /// attack); the daemon re-pins when the shard freezes.
    NotYetFrozen {
        /// The not-yet-frozen shard.
        shard_id: u64,
    },
}

/// The production provider: shard reads out of the persona's [`LeafStore`].
///
/// Shard ids are segment indices — "shard" and "frozen segment" are the
/// same object; the challenge path's `shard_id` is the segment index.
pub struct StoreShardProvider {
    store: Arc<LeafStore>,
}

impl StoreShardProvider {
    /// Wrap a store handle.
    #[must_use]
    pub fn new(store: Arc<LeafStore>) -> Self {
        Self { store }
    }

    /// Pin the frozen members of the persona's serve-set so
    /// `prune_frozen` cannot discard bytes the persona is bonded to serve
    /// — the silent-slash hazard, closed at startup rather than left to
    /// operator discipline. Call before serving; re-call as bonded shards
    /// freeze.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on the first store failure; pins already applied
    /// stay applied (pinning is idempotent, so a retry re-covers the set).
    pub fn pin_serve_set(&self, serve_set: &[u64]) -> Result<Vec<ServeSetPin>, ProviderError> {
        let mut out = Vec::with_capacity(serve_set.len());
        for &shard_id in serve_set {
            let Some(id) = segment_id(shard_id) else {
                // Beyond the store's id space: nothing exists to pin, and
                // the serving read for it is a plain miss.
                out.push(ServeSetPin::NotYetFrozen { shard_id });
                continue;
            };
            let frozen = self
                .store
                .frozen_segment(id)
                .map_err(|e| ProviderError::store(&e))?
                .is_some();
            if frozen {
                self.store
                    .pin_segment(id)
                    .map_err(|e| ProviderError::store(&e))?;
                out.push(ServeSetPin::Pinned { shard_id });
            } else {
                out.push(ServeSetPin::NotYetFrozen { shard_id });
            }
        }
        Ok(out)
    }
}

/// A shard id names a `SegmentId` iff it fits the store's `u32` id space;
/// anything larger cannot exist in this store and is an ordinary miss.
fn segment_id(shard_id: u64) -> Option<SegmentId> {
    u32::try_from(shard_id).ok().map(SegmentId)
}

impl ShardProvider for StoreShardProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<Arc<[u8]>>, ProviderError> {
        let Some(id) = segment_id(shard_id) else {
            return Ok(None);
        };
        match self.store.frozen_segment_leaf_bytes(id) {
            Ok(Some(chunks)) => {
                let mut flat = Vec::with_capacity(chunks.len() * 128);
                for chunk in &chunks {
                    flat.extend_from_slice(chunk);
                }
                Ok(Some(Arc::from(flat.into_boxed_slice())))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ProviderError::store(&e)),
        }
    }
}
