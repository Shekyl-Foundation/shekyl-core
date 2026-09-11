// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The record-derived obligation: a shard list, or a CompleteTree prefix.

use shekyl_curve_tree::BlockHeight;

/// The shards a persona is bonded to serve, as read back from the chain.
///
/// # Where a serve-set may come from
///
/// **Not from the host, and not from its caller.** `ServeSet` has no public
/// constructor at all: the only way to obtain one is
/// [`ServeSetPinner::pin_serve_set`](super::ServeSetPinner::pin_serve_set),
/// which reports the shards it derived from the connected bond record *and
/// pinned*. A serving host cannot nominate its own obligations, because
/// there is no argument through which to nominate them.
///
/// That is the same move made twice elsewhere on this path — the store comes
/// from the pin ([`PinReport::reader`](super::PinReport::reader)), and now
/// the set does too — and it is one rule rather than three fixes: **the host
/// does not choose anything about its own duty.** Every such value is
/// reported by the side that holds the bond record and the store, because
/// that is the side that knows.
///
/// The residual is an *implementor* that reports the wrong set. That is one
/// engine-side implementor, reviewable by reading it, and it is a strictly
/// narrower surface than a constructor any caller could reach — the second
/// construction site never comes into existence rather than being permitted.
///
/// # The height stamp
///
/// A serve-set is a snapshot: holdings change on-chain (`HoldingsUpdate`),
/// and new segments freeze continuously — §9.6 item 3's point that `D` is a
/// moving number, not a plateau. [`Self::as_of_height`] records the chain
/// height the record was read at, so a set carries the provenance of the
/// claim it makes: *these shards, as the daemon's database had them at that
/// height*. Nothing here expires a set, and nothing here decides whether to
/// refresh: refresh is unconditional (pinning is idempotent; a "did holdings
/// change?" gate is the question §9.6 item 4 exists because nobody answers
/// it reliably).
///
/// **This stamp is provenance, not the staleness clock.** It is the
/// *daemon's* height, read over RPC, and the wallet's own ingest is
/// routinely far behind it — a wallet catching up after a week offline is
/// thousands of blocks below a record stamped at the daemon's tip.
/// Subtracting the two would measure how far this wallet trails its daemon,
/// which reads healthy for exactly as long as the catch-up lasts. The
/// tripwire is built from one clock read twice instead; see
/// [`Staleness`](super::Staleness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSet {
    derivation: SetDerivation,
    as_of_height: BlockHeight,
}

/// The two shapes an obligation can take — private so both stay
/// reported-only: a public enum's variants are public constructors, and the
/// no-public-constructor rule is the module's load-bearing property.
///
/// Callers that need to know which arm they are looking at match
/// [`ServeSet::obligation`], a *view* of this enum. Possessing a
/// [`ServeObligation`] does not mint a [`ServeSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum SetDerivation {
    /// Explicit holdings: the record's shard list, in the record's order.
    ShardList(Vec<u64>),
    /// The whole frozen corpus, as a structural prefix (`COMPLETETREE_
    /// ACTIVATION.md` D-1): frozen segments are exactly `[0, frozen_count)`,
    /// so the obligation is one number, never a stored list. `frozen_count`
    /// is the store's burial-gated freeze cursor (`LeafStore::
    /// next_freeze_seg`), **not** `shekyl_archival_retention::
    /// frozen_segment_count` — that helper is first-crossing completeness
    /// and would admit unburied segments as owed.
    CompleteTreePrefix { frozen_count: u64 },
}

/// A view of a [`ServeSet`]'s shape. **Not a constructor:** possessing one
/// does not mint a serve-set, and there is no path from this enum back into
/// [`ServeSet`]. Callers that need the arm match this rather than
/// reconstructing it from the two [`ServeSet::shard_ids`] /
/// [`ServeSet::complete_tree_frozen_count`] Options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeObligation<'a> {
    /// Explicit holdings, in the record's own order.
    ShardList(&'a [u64]),
    /// The whole frozen corpus as `[0, frozen_count)`.
    CompleteTreePrefix {
        /// The store's burial-gated freeze cursor at the time of the report.
        frozen_count: u64,
    },
}

impl ServeSet {
    /// Build the list-arm set the pinner reported. Crate-private on purpose:
    /// see the type doc — a serving host does not get to name its own
    /// obligations, and the only path to a `ServeSet` runs through
    /// [`ServeSetPinner::pin_serve_set`](super::ServeSetPinner::pin_serve_set).
    pub(crate) fn reported(shard_ids: Vec<u64>, as_of_height: BlockHeight) -> Self {
        Self {
            derivation: SetDerivation::ShardList(shard_ids),
            as_of_height,
        }
    }

    /// Build the prefix-arm set the pinner reported. Crate-private for the
    /// same reason as [`Self::reported`].
    pub(crate) fn reported_prefix(frozen_count: u64, as_of_height: BlockHeight) -> Self {
        Self {
            derivation: SetDerivation::CompleteTreePrefix { frozen_count },
            as_of_height,
        }
    }

    /// The obligation's shape — the one match site for the two arms.
    ///
    /// A view, not a constructor: see [`ServeObligation`].
    #[must_use]
    pub fn obligation(&self) -> ServeObligation<'_> {
        match &self.derivation {
            SetDerivation::ShardList(shard_ids) => ServeObligation::ShardList(shard_ids),
            SetDerivation::CompleteTreePrefix { frozen_count } => {
                ServeObligation::CompleteTreePrefix {
                    frozen_count: *frozen_count,
                }
            }
        }
    }

    /// The bonded shard ids, in the record's own order — `None` for the
    /// CompleteTree prefix arm, which has no list to return.
    ///
    /// Deliberately not an empty slice for the prefix arm: an empty list and
    /// a whole-corpus obligation are this arc's two-empties hazard (the
    /// `CompleteTree` wire form decodes to the same bytes as owing nothing),
    /// and an accessor that renders "everything" as `[]` would rebuild that
    /// conflation one layer up.
    ///
    /// Prefer [`Self::obligation`] when the caller needs to know *which*
    /// arm it is looking at. This getter is the list arm's contents, not
    /// the arm tag.
    #[must_use]
    pub fn shard_ids(&self) -> Option<&[u64]> {
        match self.obligation() {
            ServeObligation::ShardList(shard_ids) => Some(shard_ids),
            ServeObligation::CompleteTreePrefix { .. } => None,
        }
    }

    /// The frozen-prefix length — `None` for the shard-list arm.
    ///
    /// Prefer [`Self::obligation`] when the caller needs to know *which*
    /// arm it is looking at. This getter is the prefix arm's cursor, not
    /// the arm tag.
    #[must_use]
    pub fn complete_tree_frozen_count(&self) -> Option<u64> {
        match self.obligation() {
            ServeObligation::ShardList(_) => None,
            ServeObligation::CompleteTreePrefix { frozen_count } => Some(frozen_count),
        }
    }

    /// Whether `shard_id` is in this persona's obligation.
    ///
    /// List arm: set membership. Prefix arm: `shard_id < frozen_count`.
    ///
    /// **Exposed, not wired.** The request path does not consult serve-set
    /// membership anywhere today — `StoreShardProvider` answers from the
    /// store, whose per-read `Ok(None)` for an uncommitted segment is the
    /// live servability authority — and this slice deliberately does not
    /// invent request-path behavior for the predicate to gate (the brief's
    /// halt condition, honored by stopping here). It exists so the arm's
    /// meaning is a method callers share, not a comparison each consumer
    /// re-derives.
    #[must_use]
    pub fn contains(&self, shard_id: u64) -> bool {
        match self.obligation() {
            ServeObligation::ShardList(shard_ids) => shard_ids.contains(&shard_id),
            ServeObligation::CompleteTreePrefix { frozen_count } => shard_id < frozen_count,
        }
    }

    /// The chain height the record was read at.
    #[must_use]
    pub fn as_of_height(&self) -> BlockHeight {
        self.as_of_height
    }

    /// Whether this obligation is empty: an empty list, or a prefix over a
    /// store that has frozen nothing yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self.obligation() {
            ServeObligation::ShardList(shard_ids) => shard_ids.is_empty(),
            ServeObligation::CompleteTreePrefix { frozen_count } => frozen_count == 0,
        }
    }
}
