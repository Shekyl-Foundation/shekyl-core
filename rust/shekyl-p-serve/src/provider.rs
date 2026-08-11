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

use shekyl_curve_tree::{FrozenSegmentBody, LeafStore, SegmentId, SegmentPin, StoreError};

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
    /// Frozen segment leaf bytes were pruned without a pin — the
    /// silent-slash precursor. Named so a non-zero
    /// [`crate::PServeEndpoint::lookup_failure_count`] can be correlated
    /// with the cause without scraping free-text, and so
    /// [`StoreShardProvider::pin_serve_set`] can refuse a serve-set whose
    /// bytes are already gone instead of reporting it healthy. Raised only
    /// for an *unpinned* segment: missing bytes under a pin are corruption,
    /// which pinning cannot fix (the store crate draws that line).
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

/// The body of one served shard, read in bounded chunks.
///
/// **Chunked, not materialised.** The serving loop holds one body per
/// in-flight connection for as long as that connection takes, so a
/// whole-shard buffer would silently convert the endpoint's concurrency cap
/// into a resident-memory bound of `MAX_INFLIGHT × 3.33 MB` — a bill the
/// rule-76 provisioning floor cannot pay, and one the cap does not claim to
/// be charging. Peak cost here is one chunk.
///
/// [`Self::remaining_bytes`] is exact before the first chunk is read, which
/// is what lets the response head — including `content-length` — go out
/// before the store is touched at all.
#[derive(Debug)]
pub struct ShardBody(Source);

/// Where a body's bytes come from. Private: the production and fixture
/// sources differ in cost, not in contract, and the wire path must not be
/// able to tell them apart.
#[derive(Debug)]
enum Source {
    /// Frozen segment streamed from the store (production).
    Segment(FrozenSegmentBody),
    /// Opaque in-memory payload (tests, measurement harnesses).
    Flat { bytes: Arc<[u8]>, read: usize },
}

impl ShardBody {
    /// An in-memory body of arbitrary length — fixtures and measurement
    /// harnesses, which serve opaque bytes rather than a real segment.
    #[must_use]
    pub fn flat(bytes: Arc<[u8]>) -> Self {
        Self(Source::Flat { bytes, read: 0 })
    }

    /// A store-backed frozen-segment body.
    #[must_use]
    pub fn segment(body: FrozenSegmentBody) -> Self {
        Self(Source::Segment(body))
    }

    /// Bytes not yet read; before the first [`Self::next_chunk`], the wire
    /// `content-length`.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        match &self.0 {
            Source::Segment(body) => body.remaining_bytes(),
            Source::Flat { bytes, read } => bytes.len() - read,
        }
    }

    /// Next body chunk of at most `max_bytes`, or `None` at the end.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] if the store fails part-way through a body. The
    /// response head is already on the wire by then, so the loop can only
    /// close; the counter is the signal.
    pub fn next_chunk(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, ProviderError> {
        match &mut self.0 {
            Source::Segment(body) => body
                .next_chunk(max_bytes)
                .map_err(ProviderError::from_store),
            Source::Flat { bytes, read } => {
                if *read >= bytes.len() {
                    return Ok(None);
                }
                let stop = bytes.len().min(*read + max_bytes.max(1));
                let chunk = bytes[*read..stop].to_vec();
                *read = stop;
                Ok(Some(chunk))
            }
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
    /// Open the body for `shard_id` — the frozen segment's leaf bytes in
    /// tree order, exactly what the witness hashes against `R_k`.
    ///
    /// Servability is settled by this call, before any byte of response is
    /// written; the returned [`ShardBody`] then only streams. That
    /// ordering is what keeps store health off the wire — a body that
    /// discovered missing bytes half-way through would leak it as a
    /// truncated `200` that no 404 can be mistaken for.
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
    /// The shard is bonded and **pinned**, but its segment has not frozen
    /// yet, so there is nothing servable until the freeze boundary crosses
    /// it (no committed `R_k`, nothing content-verifiable). Bonding before
    /// freeze is legal by design (`bond_post.rs`: self-harm, not an
    /// attack); the pin is taken now precisely so the freeze cannot race a
    /// prune.
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

    /// Pin the persona's whole serve-set so `prune_frozen` cannot discard
    /// bytes the persona is bonded to serve — the silent-slash hazard,
    /// closed at startup rather than left to operator discipline.
    ///
    /// Every representable member is pinned, **including one that has not
    /// frozen yet**. Bonding before freeze is legal by design
    /// (`bond_post.rs`), and pinning in advance is what stops a prune from
    /// landing between the freeze and a lifecycle re-pin; without it, a
    /// bonded shard's survival would depend on the order two unrelated
    /// timers happen to fire. Re-calling after a freeze upgrades the
    /// reported outcome from [`ServeSetPin::NotYetFrozen`] to
    /// [`ServeSetPin::Pinned`] — useful, but no longer load-bearing.
    ///
    /// Each entry's check and pin share one store write transaction, so a
    /// concurrent prune cannot commit between them.
    ///
    /// # Errors
    ///
    /// [`ProviderError::UnrepresentableShardId`] if an entry does not fit
    /// the store's `u32` [`SegmentId`] space, and
    /// [`ProviderError::FrozenSegmentPruned`] if a member's bytes were
    /// already discarded — loud rather than mislabeled, because a pin
    /// cannot bring pruned bytes back and reporting the set as healthy is
    /// exactly how a persona reaches its challenge epoch unable to answer.
    /// The remedy is a store rebuild by chain replay, not a retry. Plus
    /// [`ProviderError::Store`] on store failure. Pins already applied stay
    /// applied; pinning is idempotent, so a retry re-covers the set.
    pub fn pin_serve_set(&self, serve_set: &[u64]) -> Result<Vec<ServeSetPin>, ProviderError> {
        let mut out = Vec::with_capacity(serve_set.len());
        for &shard_id in serve_set {
            let Some(id) = segment_id(shard_id) else {
                return Err(ProviderError::UnrepresentableShardId { shard_id });
            };
            let pin = self
                .store
                .pin_segment_for_serving(id)
                .map_err(ProviderError::from_store)?;
            out.push(match pin {
                SegmentPin::PinnedServable => ServeSetPin::Pinned { shard_id },
                SegmentPin::PinnedNotYetFrozen => ServeSetPin::NotYetFrozen { shard_id },
                SegmentPin::AlreadyPruned => {
                    return Err(ProviderError::FrozenSegmentPruned { segment_id: id.0 })
                }
            });
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
        match self.store.open_frozen_segment_body(id) {
            Ok(Some(body)) => Ok(Some(ShardBody::segment(body))),
            Ok(None) => Ok(None),
            Err(e) => Err(ProviderError::from_store(e)),
        }
    }
}
