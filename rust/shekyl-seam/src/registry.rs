// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rows a reader may see.
//!
//! The hub is the only writer. It publishes a new [`Board`] when a row
//! arrives, finishes its handshake, or closes. A reader holds one board.
//! A later publish does not change that board.
//!
//! The live table is a hash map, keyed by admission id. Publish copies
//! the open rows and sorts that copy. The sort is the admission order a
//! reader sees. The hash map is the lookup.
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

use std::sync::Arc;

use shekyl_transport_layer::{ConnectorId, Direction, SocketId};

use crate::endpoint::Endpoint;

/// One session on a [`Board`].
///
/// The endpoint is the address, the connector, and the direction. Those
/// three are one fact, observed when the row was admitted, and they do
/// not change. `established` is the handshake, and it is a different fact:
/// a dial occupies its direction before the handshake finishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    id: SocketId,
    endpoint: Endpoint,
    established: bool,
}

impl Row {
    /// The admission id.
    #[must_use]
    pub const fn id(self) -> SocketId {
        self.id
    }

    /// The endpoint observed when the row was admitted.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }

    /// The connector that carried this session.
    #[must_use]
    pub const fn connector(self) -> ConnectorId {
        self.endpoint.connector()
    }

    /// Accepted or dialed.
    #[must_use]
    pub const fn direction(self) -> Direction {
        self.endpoint.direction()
    }

    /// The Levin handshake has finished.
    #[must_use]
    pub const fn established(self) -> bool {
        self.established
    }

    pub(crate) const fn new(id: SocketId, endpoint: Endpoint, established: bool) -> Self {
        Self {
            id,
            endpoint,
            established,
        }
    }
}

/// Rows at one moment, ordered by admission id.
///
/// Cloning clones the `Arc`. The slice does not change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    rows: Arc<[Row]>,
}

impl Board {
    /// Sort `rows` by admission id. The hub's table is a hash map, so the
    /// order is applied here, on the copy a reader holds.
    pub(crate) fn from_rows(mut rows: Vec<Row>) -> Self {
        rows.sort_by_key(|row| row.id.get());
        debug_assert!(rows.is_sorted_by_key(|row| row.id.get()));
        Self {
            rows: Arc::from(rows),
        }
    }

    /// No rows.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rows: Arc::from([]),
        }
    }

    /// Every open row, in admission-id order.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The row with this id, if it was on this board.
    #[must_use]
    pub fn get(&self, id: SocketId) -> Option<&Row> {
        self.rows
            .binary_search_by_key(&id.get(), |row| row.id.get())
            .ok()
            .map(|index| &self.rows[index])
    }

    /// How many rows this board carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether this board carries no row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Rows in `direction`, handshake or not.
    ///
    /// The handshake flag is not part of this count. A dial in flight
    /// still occupies an outbound slot, so the dial cap's predicate is
    /// [`Direction::Outbound`]. `established` is a separate fact on the
    /// row, and a count of established rows would let the node dial past
    /// the cap while handshakes are outstanding.
    #[must_use]
    pub fn direction_count(&self, direction: Direction) -> usize {
        self.rows
            .iter()
            .filter(|row| row.direction() == direction)
            .count()
    }
}
