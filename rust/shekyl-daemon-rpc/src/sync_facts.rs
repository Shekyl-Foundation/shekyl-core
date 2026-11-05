// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's view, as the RPC reads it (CS-5 §7): what `sync_info`
//! renders, and the claim and mode `get_connections` joins to each board
//! row. The node fills it from the sync owner's published view; this crate
//! does not depend on chain sync.

use shekyl_rpc_types::{ChainSyncState, SyncMode};

use crate::chain_facts::FactsFault;

/// The whole view, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncViewFacts {
    /// The derived state.
    pub state: ChainSyncState,
    /// Behind, with nothing moving toward the target.
    pub stalled: bool,
    /// The best verified chain's block count.
    pub target: u64,
    /// One row per session chain sync holds.
    pub sessions: Vec<SyncSessionFacts>,
}

impl SyncViewFacts {
    /// The row for the session whose connection id is `connection_id`.
    #[must_use]
    pub fn session(&self, connection_id: &[u8; 16]) -> Option<&SyncSessionFacts> {
        self.sessions
            .iter()
            .find(|session| session.connection_id == *connection_id)
    }
}

/// One session's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSessionFacts {
    /// The connection id the board and the C++ name the session by.
    pub connection_id: [u8; 16],
    /// The block count the peer claims, once it has.
    pub claimed_height: Option<u64>,
    /// What its header run is doing.
    pub mode: SyncMode,
    /// The header request in flight to it.
    pub header_request: Option<RequestTiming>,
    /// The body spans in flight to it.
    pub body_requests: Vec<BodySpanFacts>,
    /// Bytes per second its last response arrived at.
    pub rate: Option<u64>,
}

/// When a request was sent and when it is late, read against the instant
/// the view was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTiming {
    /// Milliseconds since it was sent.
    pub age_ms: u64,
    /// Milliseconds until its response is late; 0 once it is.
    pub due_in_ms: u64,
}

/// A body span in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodySpanFacts {
    /// The height of its first block.
    pub start_height: u64,
    /// How many blocks it asks for.
    pub count: u64,
    /// The response budget its deadline is planned for, in bytes.
    pub planned_bytes: u64,
    /// When it was sent and when it is late.
    pub timing: RequestTiming,
}

/// The read behind `sync_info` and the claim half of `get_connections`.
pub trait SyncViewRead: Send + Sync {
    /// Chain sync's view, as the owner last published it.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when the node has no owner yet.
    fn sync_view(&self) -> Result<SyncViewFacts, FactsFault>;
}
