// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the strand is asked to run, and the sync payload a handshake posts.
//!
//! The hub posts these. It does not parse them: the handshake owner already
//! decoded the response, and the strand reads the fields.

use shekyl_transport_layer::{CloseCause, ConnectorId, SocketId};

use crate::endpoint::Endpoint;

/// What the strand is asked to run. The post returns before the strand does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Post {
    /// Create the handler. The channel already exists.
    Established {
        /// The admission id.
        id: SocketId,
        /// The endpoint the adapter writes before arming the handler.
        endpoint: Endpoint,
    },
    /// One delivery. The handler parses these bytes.
    Deliver {
        /// The admission id.
        id: SocketId,
        /// The connector this id was established on. The adapter keeps one
        /// binding per connector and routes by this; a post without it went
        /// to the clearnet binding, which dropped every Tor delivery.
        connector: ConnectorId,
        /// One whole message.
        bytes: Vec<u8>,
    },
    /// The outbound handshake finished with a well-formed response, and the
    /// channel was adopted. The dialer has already recorded the kept
    /// session. The strand reads these fields and does not answer: nothing
    /// waits on a reply. A confirm dial does not post this. It is not a
    /// delivery: the handshake owner already decoded the response on the
    /// channel, and the strand does not parse it again.
    HandshakeResult {
        /// The admission id.
        id: SocketId,
        /// The connector this id was established on, as on `Deliver`.
        connector: ConnectorId,
        /// The peer's support flags, zero included.
        support_flags: u32,
        /// The peer's sync payload.
        sync: SyncPayload,
    },
    /// The socket is gone. Destroy the handler when its call count is zero.
    Closed {
        /// The admission id.
        id: SocketId,
        /// The connector this id was established on, as on `Deliver`.
        connector: ConnectorId,
        /// The cause that won.
        cause: CloseCause,
    },
}

/// The peer's `CORE_SYNC_DATA`, as fields. The strand reads them; it does
/// not parse a Levin response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPayload {
    /// The peer's chain height.
    pub current_height: u64,
    /// Low 64 bits of its cumulative difficulty.
    pub cumulative_difficulty: u64,
    /// High 64 bits of its cumulative difficulty.
    pub cumulative_difficulty_top64: u64,
    /// Its top block id.
    pub top_id: [u8; 32],
}

impl Post {
    /// The admission id this post names.
    #[must_use]
    pub const fn id(&self) -> SocketId {
        match self {
            Self::HandshakeResult { id, .. } => *id,
            Self::Established { id, .. } | Self::Deliver { id, .. } | Self::Closed { id, .. } => {
                *id
            }
        }
    }
}
