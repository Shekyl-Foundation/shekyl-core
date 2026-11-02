// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The model's view (CS-5 §7): read-only rows the node's facts render.
//!
//! It answers what `sync_info` is for: whether the node is syncing, toward
//! what, from whom and how fast, and whether it is stuck. The rows are the
//! model's own state copied out; nothing here holds the tree.

use std::time::{Duration, Instant};

use shekyl_types::{BlockCount, BlockHeight, ChainCount};

use crate::claim::PeerClaim;
use crate::state::SyncState;

/// The whole view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncView<K> {
    /// The derived state.
    pub state: SyncState,
    /// [`crate::Sync::stalled`].
    pub stalled: bool,
    /// What the node syncs toward: `H*`'s count.
    pub target: ChainCount,
    /// One row per open session, in session order.
    pub sessions: Vec<SessionView<K>>,
}

impl<K> SyncView<K> {
    /// The view before the model has observed anything.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            state: SyncState::NoView,
            stalled: false,
            target: ChainCount::ZERO,
            sessions: Vec::new(),
        }
    }
}

impl<K> SyncView<K> {
    /// The same view with each session renamed by `f`.
    #[must_use]
    pub fn map<L>(self, f: impl Fn(K) -> L) -> SyncView<L> {
        SyncView {
            state: self.state,
            stalled: self.stalled,
            target: self.target,
            sessions: self
                .sessions
                .into_iter()
                .map(|row| SessionView {
                    session: f(row.session),
                    claim: row.claim,
                    mode: row.mode,
                    header_request: row.header_request,
                    body_requests: row.body_requests,
                    transit: row.transit,
                    rate: row.rate,
                })
                .collect(),
        }
    }
}

/// One session's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView<K> {
    /// The session.
    pub session: K,
    /// What the session claims its chain is, once it has said.
    pub claim: Option<PeerClaim>,
    /// What the session's header run is doing.
    pub mode: SessionMode,
    /// The header request in flight to it, if one is.
    pub header_request: Option<HeaderInFlight>,
    /// The body spans in flight to it.
    pub body_requests: Vec<BodiesInFlight>,
    /// The transit the session opened with.
    pub transit: Duration,
    /// The rate its last header or body response arrived at, in bytes per
    /// second. `None` until one has.
    pub rate: Option<u64>,
}

/// A header request in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderInFlight {
    /// When it was sent.
    pub sent: Instant,
    /// When its response is late.
    pub deadline: Instant,
}

/// A body span in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodiesInFlight {
    /// The height of its first block.
    pub first: BlockHeight,
    /// How many blocks it asks for.
    pub count: BlockCount,
    /// The response budget its deadline is planned for, in bytes.
    pub planned_bytes: u64,
    /// When it was sent.
    pub sent: Instant,
    /// When its response is late.
    pub deadline: Instant,
}

/// What a session's header run is doing. A session with no run is
/// `Idle`: it may still serve bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    /// No header run.
    Idle,
    /// In cap; a proved header joins `T`.
    Reachable,
    /// The long-run slot; headers stay off `T` until they beat `H*`.
    Slot,
    /// Verifying a prefix to compare with the slot holder.
    Challenging,
    /// Past the reorg cap, not hashed.
    PastCap,
    /// Past the cap and heavier than the local chain, waiting for the draw.
    EvidenceCandidate,
    /// The evidence check.
    Evidence,
}

impl SessionMode {
    /// The mode's name, as the node's facts render it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Reachable => "reachable",
            Self::Slot => "slot",
            Self::Challenging => "challenging",
            Self::PastCap => "past_cap",
            Self::EvidenceCandidate => "evidence_candidate",
            Self::Evidence => "evidence",
        }
    }
}
