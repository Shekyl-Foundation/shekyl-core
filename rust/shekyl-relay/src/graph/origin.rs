// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hop-0 verdict for a local origin (`GS-Q3`).
//!
//! Three states, because the class and the pin are not two independent
//! booleans. A local origin leaves only while an outbound session hides this
//! node's address, so [`OriginVerdict::Routable`] is that fact and the class
//! together. Health is every state but [`OriginVerdict::Absent`]. `OwnTx`
//! reads [`OriginVerdict::Routable`].
//!
//! The pin stays off health (`RPC_CHANNEL.md` §6.1). It moves when this
//! node's own-edge peers disconnect, and a peer who held `health` while being
//! the own edge would otherwise watch the boolean flip on its own disconnect.

/// Whether a local origin leaves on a session that hides this node's address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OriginVerdict {
    /// No outbound session hides this node's address, or the epoch does not
    /// reserve a slot.
    #[default]
    Absent,
    /// An outbound session hides this node's address, and a local origin
    /// does not leave on it.
    Connected,
    /// A local origin leaves on a session that hides this node's address.
    Routable,
}

impl OriginVerdict {
    /// An outbound session hides this node's address now.
    ///
    /// The `health` grant's boolean (`TSR-Q4`).
    #[must_use]
    pub const fn hides_address(self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// A local origin leaves on such a session now.
    ///
    /// The relay fact `OwnTx` reads, under the `status` grant.
    #[must_use]
    pub const fn origin_leaves(self) -> bool {
        matches!(self, Self::Routable)
    }
}
