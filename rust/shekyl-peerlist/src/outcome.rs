// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the dialer reports, where an address came from, and why an admit
//! was refused.

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::ConnectionId;
use shekyl_transport_layer::ConnectorId;

/// Where an address offered to gray came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Learned over a session: a received peerlist, an inbound peer's
    /// advertisement. Counted against the session's intake cap (D-S1) and
    /// admitted only when the address's connector is the session's.
    Session {
        /// The session the address arrived over: the daemon's connection
        /// id, so the dialer does not convert.
        id: ConnectionId,
        /// That session's connector.
        connector: ConnectorId,
    },
    /// Named by the operator: `--add-peer`, `--add-exclusive-node`,
    /// `--add-priority-node`. Not capped. When gray is full, some other
    /// entry is evicted so the named one stays (brief §2) — the whole of
    /// the operator privilege.
    Operator,
    /// Read back from the address file at start. Not capped.
    Reload,
}

/// What the dialer reports about one dial. The only input that writes
/// white, through [`crate::Peerlist::apply`], whose match is total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialOutcome {
    /// The dial was kept as a session. An outstanding gray draw promotes;
    /// an address already white moves its clock; anything else leaves white
    /// unchanged.
    SessionAccepted(NetworkAddress),
    /// The dial confirmed the address and closed: outbound was already at
    /// target. The same white write as `SessionAccepted`; no session
    /// remains.
    Confirmed(NetworkAddress),
    /// A harvest closed. A Foundation-fleet address writes white from any
    /// seat (brief §3). Anyone else's harvest leaves white unchanged, and
    /// an outstanding draw of that address returns to drawable gray: the
    /// dial is over, and only [`crate::Peerlist::apply`] moves an
    /// outstanding draw.
    HarvestDone(NetworkAddress),
    /// The dial did not reach a handshake. An outstanding gray draw is
    /// dropped; a white address stays white.
    DialFailed(NetworkAddress),
    /// The peer's list was refused. As `DialFailed` for the lists.
    PeerlistRefused(NetworkAddress),
    /// A payload was refused. No promotion and no demotion. An outstanding
    /// draw returns to drawable gray.
    PayloadRefused(NetworkAddress),
}

impl DialOutcome {
    /// The address the outcome is about.
    #[must_use]
    pub fn address(&self) -> &NetworkAddress {
        match self {
            Self::SessionAccepted(a)
            | Self::Confirmed(a)
            | Self::HarvestDone(a)
            | Self::DialFailed(a)
            | Self::PeerlistRefused(a)
            | Self::PayloadRefused(a) => a,
        }
    }
}

/// Why an address was not admitted to gray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No local connector serves this address's type (brief §2).
    NoConnector,
    /// The address belongs to a different connector than this call is for.
    /// On a session admit, that is not the session's connector; on
    /// [`crate::Peerlist::set_own_address`], not the connector named.
    /// One such entry in a received list rejects the whole list
    /// (`net_node.inl:2460` to `:2466`).
    ForeignConnector,
    /// The address is under an active ban (D4): refused at admit while the
    /// ban lasts.
    Banned,
    /// The session has already put [`crate::SESSION_INTAKE_CAP`] distinct
    /// addresses into gray within the intake span (D-S1). The caller
    /// applies this to the session.
    PeerlistRefused,
}

/// Which list an address is on, for the read-only snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListName {
    /// Arrived, not confirmed.
    Gray,
    /// Confirmed by this node's own dial.
    White,
}
