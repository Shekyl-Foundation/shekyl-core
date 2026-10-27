// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How many Tor sessions are held, for the supervisor's posture line.
//!
//! Held is the outbound sessions this dialer kept plus the inbound Tor
//! rows on the seam's board. An inbound accept is not a dial: it does not
//! move `opened` or `unopened`, and the quiet stretch does not start
//! again (`TOR_SUPERVISOR.md` §4.2).
//!
//! The adopt poster calls [`Dialer::session_closed`] while it holds the
//! table lock, and that mutex is not re-entrant, so the close does not
//! read the board. It publishes the inbound count last stored here. This
//! module refreshes that count with the table lock held across the
//! dialer's lock, which is the order the hub's posters already take. A
//! dial outcome therefore cannot publish a count from before its row.
//! The seam's close poster does not hold the table lock. It refreshes
//! first ([`Dialer::session_closed_from_seam`]), and the row is already
//! off the board.

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{CloseCause, ConnectorId, Direction};
use shekyl_seam::SocketId;

use super::{Dialer, Shared};

impl Dialer {
    /// An inbound Tor session was accepted, or the board has dropped one.
    ///
    /// Held sessions are the outbound ones this dialer kept plus the
    /// inbound Tor rows on the board. The accept is not a dial: `opened`
    /// and `unopened` stay, and the quiet stretch does not start again.
    pub fn note_inbound_tor(&self) {
        self.with_inbound(Self::publish_tor_held);
    }

    /// A session closed, told by the seam's close poster. That poster does
    /// not hold the table lock, and the row is already off the board.
    /// The adopt poster calls [`Self::session_closed`] instead, while it
    /// still holds the lock.
    pub fn session_closed_from_seam<R: RelayRng + ?Sized>(
        &self,
        id: SocketId,
        cause: CloseCause,
        rng: &mut R,
    ) {
        self.note_inbound_tor();
        self.session_closed(id, cause, rng);
    }

    /// Read the inbound Tor rows into the cache, then run `body`.
    ///
    /// The table lock is held across the dialer's lock. `body` must not
    /// call back into the hub.
    pub(super) fn with_inbound<R>(&self, body: impl FnOnce(&mut Shared) -> R) -> R {
        self.hub.with_board(|board| {
            let mut shared = self.shared();
            shared.inbound_tor = board.count(ConnectorId::Tor, Direction::Inbound);
            body(&mut shared)
        })
    }

    /// Outbound Tor sessions this dialer kept, plus the inbound rows last
    /// read off the board.
    pub(super) fn tor_held(shared: &Shared) -> usize {
        shared
            .view(ConnectorId::Tor)
            .held()
            .saturating_add(shared.inbound_tor)
    }

    /// Publish the held count the supervisor reads.
    pub(super) fn publish_tor_held(shared: &mut Shared) {
        let held = Self::tor_held(shared);
        shared.tor_link.held(ConnectorId::Tor, held);
    }
}
