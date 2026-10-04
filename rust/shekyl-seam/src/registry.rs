// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sessions a reader may see.
//!
//! The hub is the only writer. It publishes a new [`Board`] when a session
//! arrives, finishes its handshake, or closes. A reader holds one board.
//! A later publish does not change that board.
//!
//! This is not the C++ connection context. A walker that needs a fact asks
//! the board. It does not borrow the row the strand is writing. Support
//! flags and the pull relationship are not here: the seam does not know
//! them, and a blank field would be a second context. They arrive when
//! their owner publishes them.
//!
//! Republishing copies the slice. An accept flood against a large inbound
//! cap is O(N) per accept, so O(N²) across the flood. The readers' guarantee
//! is that cost. D5's thread-budget flood leg is what measures it; that
//! measurement is the reopen, not a reason to publish a mutable row.

use std::net::IpAddr;
use std::sync::Arc;

use shekyl_onion_v3::v3_pubkey;
use shekyl_transport_layer::{ConnectorId, Direction, SocketId};

use crate::endpoint::Endpoint;

/// The peer address this node observed, written once when the row is created.
///
/// An onion is the 32-byte service key, not the hostname. Tor inbound has
/// no peer address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerEnd {
    /// A clearnet host and port.
    Host {
        /// The address the socket connected.
        ip: IpAddr,
        /// The port the socket connected.
        port: u16,
    },
    /// A v3 onion that was dialed.
    Onion {
        /// The service key.
        key: [u8; 32],
        /// The port that was dialed.
        port: u16,
    },
    /// No comparable peer address.
    ///
    /// Tor inbound is this. So is a dial whose host is not a v3 onion.
    Unaddressed,
}

impl PeerEnd {
    pub(crate) fn from_endpoint(endpoint: &Endpoint) -> Self {
        match endpoint {
            Endpoint::Clearnet { ip, port, .. } => Self::Host {
                ip: *ip,
                port: *port,
            },
            Endpoint::TorInbound => Self::Unaddressed,
            Endpoint::Tor { host, port } => match v3_pubkey(host) {
                Some(key) => Self::Onion { key, port: *port },
                None => Self::Unaddressed,
            },
        }
    }
}

/// One session on a [`Board`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    id: SocketId,
    connector: ConnectorId,
    direction: Direction,
    established: bool,
    end: PeerEnd,
}

impl Session {
    /// The admission id.
    #[must_use]
    pub const fn id(self) -> SocketId {
        self.id
    }

    /// The connector that carried this session.
    #[must_use]
    pub const fn connector(self) -> ConnectorId {
        self.connector
    }

    /// Accepted or dialed.
    #[must_use]
    pub const fn direction(self) -> Direction {
        self.direction
    }

    /// The Levin handshake has finished.
    #[must_use]
    pub const fn established(self) -> bool {
        self.established
    }

    /// The peer address observed when the row was created. It does not change.
    #[must_use]
    pub const fn end(self) -> PeerEnd {
        self.end
    }

    pub(crate) const fn new(
        id: SocketId,
        connector: ConnectorId,
        direction: Direction,
        established: bool,
        end: PeerEnd,
    ) -> Self {
        Self {
            id,
            connector,
            direction,
            established,
            end,
        }
    }
}

/// Sessions at one moment, ordered by admission id.
///
/// Cloning clones the `Arc`. The slice does not change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    sessions: Arc<[Session]>,
}

impl Board {
    pub(crate) fn from_sessions(mut sessions: Vec<Session>) -> Self {
        sessions.sort_by_key(|session| session.id.get());
        Self {
            sessions: Arc::from(sessions),
        }
    }

    /// No sessions.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sessions: Arc::from([]),
        }
    }

    /// Every session, in admission-id order.
    #[must_use]
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }

    /// The session with this id, if it was on this board.
    #[must_use]
    pub fn get(&self, id: SocketId) -> Option<&Session> {
        self.sessions
            .binary_search_by_key(&id.get(), |session| session.id.get())
            .ok()
            .map(|index| &self.sessions[index])
    }

    /// How many sessions this board carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether this board carries no session.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Inbound sessions. This is the board's count, not a cache refreshed
    /// on a timer.
    #[must_use]
    pub fn inbound(&self) -> usize {
        self.sessions
            .iter()
            .filter(|session| session.direction == Direction::Inbound)
            .count()
    }
}
