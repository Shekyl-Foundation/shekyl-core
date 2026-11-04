// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The derived sync state (CS-Q2 step 8). None of these is latched.
//! The alarm is the store's latch, read beside the state, and it never
//! replaces one of these.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHeight, ChainCount};

/// What sync publishes. Derived on every change from verified work, the
/// sessions, the operator's [`Declaration`], the opening and the fill. A
/// claim's value never appears here: a claim can only hold the opening
/// `NoView`, until the first session's header deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// No verified view of the network: an open network with no session,
    /// or sessions whose opening has not resolved.
    NoView,
    /// `work(L)` is less than the best verified work.
    Behind {
        /// Work through the local tip.
        have: CumulativeDifficulty,
        /// Work of the best verified chain.
        best: CumulativeDifficulty,
        /// The best verified chain's block count: what sync works towards.
        target: ChainCount,
    },
    /// On the best verified chain, while the backward fill is short of
    /// its checkpoint. `verified_to` is the fill's descending frontier.
    Following {
        /// The fill's frontier.
        verified_to: BlockHeight,
    },
    /// On the best verified chain, and the fill has reached its checkpoint.
    Synced,
}

impl SyncState {
    /// The RPC `sync` parameter under `mine.not_synced`.
    ///
    /// The spelling is the contract. The work and frontier payloads stay
    /// off the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoView => "no_view",
            Self::Behind { .. } => "behind",
            Self::Following { .. } => "following",
            Self::Synced => "synced",
        }
    }
}

/// The operator's declaration of the node's network (CS-Q2 step 8, Rick
/// 2026-11-01), read from the resolved configuration once at open. It is
/// local configuration, never the network type (rule 71): the same
/// declaration derives the same state on every network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Declaration {
    /// Both connectors off: the node has no network to be behind.
    Offline,
    /// The peer list is closed: the operator has named the node's whole
    /// network, and the node is synced when none of it is up.
    Closed,
    /// Everything else: a node with no session has no view.
    Open,
}

impl Declaration {
    /// The state with no session open: `Offline` and `Closed` are synced,
    /// subject to the backward fill, which is local; `Open` has no view.
    #[must_use]
    pub const fn state_without_sessions(self, following: Option<BlockHeight>) -> SyncState {
        match self {
            Self::Open => SyncState::NoView,
            Self::Offline | Self::Closed => match following {
                Some(verified_to) => SyncState::Following { verified_to },
                None => SyncState::Synced,
            },
        }
    }

    /// The state a node publishes at open, before any session or fill
    /// report: the derivation with no session open and the fill done.
    #[must_use]
    pub const fn state_at_open(self) -> SyncState {
        self.state_without_sessions(None)
    }
}
