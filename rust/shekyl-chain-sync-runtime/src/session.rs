// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One open connection, as the coordinator's map key.
//!
//! [`SocketId`] is an admission id. It does not order itself: two sockets
//! are not a sequence, and a reader that needs the sequence sorts the copy
//! it publishes. The coordinator's maps need an order so a draw is a uniform
//! index into a stable set. [`Session`] is that order. The order is the
//! admission number, and it means nothing else.

use std::cmp::Ordering;
use std::fmt;

use shekyl_seam::SocketId;

/// One open connection. Ordered by its admission id, for map stability only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Session(SocketId);

impl Session {
    /// The session on `socket`.
    #[must_use]
    pub const fn new(socket: SocketId) -> Self {
        Self(socket)
    }

    /// The socket the seam sends on and closes.
    #[must_use]
    pub const fn socket(self) -> SocketId {
        self.0
    }
}

impl PartialOrd for Session {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Session {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.get().cmp(&other.0.get())
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}
