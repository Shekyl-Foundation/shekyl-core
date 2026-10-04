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
//! them yet, and a zeroed copy of those fields would be a second context.

use std::sync::Arc;

use shekyl_transport_layer::{ConnectorId, Direction, SocketId};

/// One session on a [`Board`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    id: SocketId,
    connector: ConnectorId,
    direction: Direction,
    established: bool,
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

    pub(crate) const fn new(
        id: SocketId,
        connector: ConnectorId,
        direction: Direction,
        established: bool,
    ) -> Self {
        Self {
            id,
            connector,
            direction,
            established,
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
