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
//!
//! PR-B wires [`StoreShardProvider`] + [`StoreShardProvider::pin_serve_set`]
//! into persona lifecycle; this module stays free of Tor and key material.

use std::sync::Arc;

use shekyl_curve_tree::{LeafStore, SegmentId, StoreError};

/// A shard lookup failed for an infrastructure reason (store I/O, pruned
/// bytes) or a serve-set construction bug. Counted locally by the endpoint
/// when it is a lookup failure and **never distinguishable on the wire** —
/// the peer sees the same 404 as any other miss, because a distinct failure
/// response would let a prober read store health through the rendezvous.
///
/// Variants are for operator-side / harness diagnostics only; the wire path
/// collapses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// redb / store failure other than a named pruned-segment case.
    Store {
        /// Local diagnostic (`Debug` of the store error); never on the wire.
        detail: String,
    },
    /// Frozen segment leaf bytes were pruned without a pin — the silent-slash
    /// precursor. Named so a non-zero [`crate::PServeEndpoint::lookup_failure_count`]
    /// can be correlated with the remedy without scraping free-text.
    FrozenSegmentPruned {
        /// Segment id that was frozen then pruned.
        segment_id: u32,
    },
    /// Serve-set entry cannot name a [`SegmentId`] (`u32`). Construction bug,
    /// not a freeze race.
    UnrepresentableShardId {
        /// The illegal shard id.
        shard_id: u64,
    },
    /// Non-store failure (tests, future callers).
    Other {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
}

impl ProviderError {
    /// A non-store lookup failure with a local diagnostic description.
    pub fn other(detail: impl Into<String>) -> Self {
        Self::Other {
            detail: detail.into(),
        }
    }

    /// Map a store error, preserving the pruned-segment case as its own arm.
    fn from_store(err: StoreError) -> Self {
        match err {
            StoreError::FrozenSegmentPruned { id } => {
                Self::FrozenSegmentPruned { segment_id: id.0 }
            }
            other => Self::Store {
                detail: format!("{other:?}"),
            },
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { detail } | Self::Other { detail } => {
                write!(f, "shard lookup failed: {detail}")
            }
            Self::FrozenSegmentPruned { segment_id } => write!(
                f,
                "shard lookup failed: frozen segment {segment_id} pruned (pin serve-set before prune)"
            ),
            Self::UnrepresentableShardId { shard_id } => {
                write!(
                    f,
                    "shard_id {shard_id} exceeds store SegmentId space (u32)"
                )
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// Contiguous body bytes for one served shard.
///
/// Production loads tree-ordered leaf arrays from the store and exposes
/// them as a zero-copy byte view ([`ShardBody::as_bytes`]) — no second
/// full-segment buffer on the wire path. Fixtures may carry an opaque
/// flat buffer of any length for header/path tests that do not need a
/// real segment.
#[derive(Clone, Debug)]
pub enum ShardBody {
    /// Full frozen-segment leaves in tree order (production).
    Leaves(Vec<[u8; 128]>),
    /// Opaque payload (tests / measurement harnesses).
    Flat(Arc<[u8]>),
}

impl ShardBody {
    /// Wire `content-length`.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Leaves(leaves) => leaves.len() * 128,
            Self::Flat(bytes) => bytes.len(),
        }
    }

    /// Contiguous body bytes. For [`Self::Leaves`], this is a zero-copy
    /// view of the leaf array's in-memory layout.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Leaves(leaves) => leaves.as_flattened(),
            Self::Flat(bytes) => bytes,
        }
    }
}

/// Serve-side shard lookup.
///
/// `Ok(None)` is the *unservable* case — unknown id, or a segment that has
/// not frozen yet (no committed `R_k`, so nothing content-verifiable to
/// serve). `Err` is infrastructure failure. The endpoint renders both as
/// the single shared 404; only the local counters tell them apart.
pub trait ShardProvider: Send + Sync + 'static {
    /// Full shard body for `shard_id` — the contiguous leaf bytes of the
    /// frozen segment, exactly what the witness hashes against `R_k`.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on store failure — including
    /// [`ProviderError::FrozenSegmentPruned`] when the serve-set was not
    /// pinned before a prune ran.
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError>;
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
    ///
    /// Only used when `shard_id` fits the store's [`SegmentId`] space. An
    /// unrepresentable id fails [`StoreShardProvider::pin_serve_set`] as
    /// [`ProviderError::UnrepresentableShardId`].
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
    /// freeze (PR-B lifecycle owns the re-pin trigger).
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on the first store failure, or
    /// [`ProviderError::UnrepresentableShardId`] if any entry does not fit
    /// the store's `u32` [`SegmentId`] space. Pins already applied stay
    /// applied (pinning is idempotent, so a retry re-covers the set).
    pub fn pin_serve_set(&self, serve_set: &[u64]) -> Result<Vec<ServeSetPin>, ProviderError> {
        let mut out = Vec::with_capacity(serve_set.len());
        for &shard_id in serve_set {
            let Some(id) = segment_id(shard_id) else {
                return Err(ProviderError::UnrepresentableShardId { shard_id });
            };
            let frozen = self
                .store
                .frozen_segment(id)
                .map_err(ProviderError::from_store)?
                .is_some();
            if frozen {
                self.store
                    .pin_segment(id)
                    .map_err(ProviderError::from_store)?;
                out.push(ServeSetPin::Pinned { shard_id });
            } else {
                out.push(ServeSetPin::NotYetFrozen { shard_id });
            }
        }
        Ok(out)
    }
}

/// A shard id names a `SegmentId` iff it fits the store's `u32` id space;
/// anything larger cannot exist in this store and is an ordinary miss on
/// the serve path (and [`ProviderError::UnrepresentableShardId`] in
/// [`StoreShardProvider::pin_serve_set`]).
fn segment_id(shard_id: u64) -> Option<SegmentId> {
    u32::try_from(shard_id).ok().map(SegmentId)
}

impl ShardProvider for StoreShardProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        let Some(id) = segment_id(shard_id) else {
            return Ok(None);
        };
        match self.store.frozen_segment_leaf_bytes(id) {
            Ok(Some(leaves)) => Ok(Some(ShardBody::Leaves(leaves))),
            Ok(None) => Ok(None),
            Err(e) => Err(ProviderError::from_store(e)),
        }
    }
}
