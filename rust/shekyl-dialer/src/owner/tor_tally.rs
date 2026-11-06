// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How many Tor sessions are held, for the supervisor's posture line.
//!
//! Held is the outbound sessions this dialer kept plus the inbound Tor
//! sessions whose handshake has finished. A handshake still open is not
//! one: the probe of this node's own onion is dropped in that handshake,
//! so it never moves the quiet line or the judge (`TOR_SUPERVISOR.md`
//! §4.5). An inbound session is not a dial: it does not move `opened` or
//! `unopened` (§4.2).
//!
//! [`Dialer::session_closed`] does not read the board: it publishes the
//! inbound count last stored here. This module refreshes that count from
//! the board the session layer publishes, read before the dialer's lock.
//! The layer's close hook refreshes first, when the row is already off the
//! board, and then applies the close.

use shekyl_peerlist::{ConnectorId, Direction};
use shekyl_timing_engine::Clock;

use super::{Dialer, Shared};

impl<C: Clock + Clone + Send + Sync + 'static> Dialer<C> {
    /// An inbound Tor session finished its handshake, or the board has
    /// dropped one.
    ///
    /// Held sessions are the outbound ones this dialer kept plus the
    /// inbound Tor sessions on the board. A handshake still open is not
    /// held. The session is not a dial: `opened` and `unopened` stay.
    pub fn note_inbound_tor(&self) {
        self.with_inbound(Self::publish_tor_held);
    }

    /// Read each connector's inbound rows into the cache, then run `body`.
    ///
    /// The board is the layer's published copy, read before the dialer's
    /// lock. `body` must not call back into the session layer.
    pub(super) fn with_inbound<R>(&self, body: impl FnOnce(&mut Shared) -> R) -> R {
        let board = self.board();
        let now = self.now();
        let mut shared = self.shared();
        for connector in ConnectorId::ALL {
            shared.inbound[connector.index()] =
                board.established_sessions(*connector, Direction::Inbound);
        }
        Self::observe_sessions(&board, &mut shared, now);
        body(&mut shared)
    }

    /// Outbound Tor sessions this dialer kept, plus the inbound rows last
    /// read off the board.
    pub(super) fn tor_held(shared: &Shared) -> usize {
        shared
            .view(ConnectorId::Tor)
            .held()
            .saturating_add(shared.inbound[ConnectorId::Tor.index()])
    }

    /// Publish the held count the supervisor reads.
    pub(super) fn publish_tor_held(shared: &mut Shared) {
        let held = Self::tor_held(shared);
        shared.tor_link.held(ConnectorId::Tor, held);
    }
}
