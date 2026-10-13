// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the dialer reports, where an address came from, and why an admit
//! was refused.

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::ConnectionId;
use shekyl_transport_layer::{ConnectorId, Direction};

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
        /// Which way the session was opened. Peerlist records are
        /// accepted only on sessions this node initiated (PWD-I2): an
        /// inbound session is [`Refusal::InboundSession`] at
        /// [`crate::Peerlist::admit_gray`], and a list received over one
        /// admits nothing.
        direction: Direction,
    },
    /// Named by the operator: `--add-peer`, `--add-exclusive-node`, and
    /// the compiled seed addresses at each start (brief §3). No session, so
    /// nothing for the per-session cap to count against. The insert rule is
    /// the same as for every source (brief §2): the address just seated
    /// stays and, over the cap, a random other drawable seat goes. The
    /// refused set does not apply: the operator is trusted about the
    /// operator's own network.
    Operator,
    /// Read back from the address file at start. Not capped. The refused
    /// set applies, as a backstop: a file written under `--allow-local-ip`
    /// does not seed a node started without it.
    Reload,
}

/// The session a peerlist arrived over, as the registry holds it: its id,
/// its connector, and which way it was opened. The caller copies the three
/// from the session's row and does not choose them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRow {
    /// The daemon's connection id.
    pub id: ConnectionId,
    /// The session's connector.
    pub connector: ConnectorId,
    /// Which way the session was opened.
    pub direction: Direction,
}

/// What the dialer reports about one dial. The only input that writes
/// white, through [`crate::Peerlist::apply`], whose match is total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialOutcome {
    /// The dial was kept as a session. An outstanding gray draw moves to
    /// white and `last_observed` is set to the report's time. An address
    /// already white moves that clock, because the session stayed.
    /// Anything else leaves the lists unchanged.
    SessionAccepted(NetworkAddress),
    /// The dial confirmed the address and closed: outbound was already at
    /// target, and no session remains. An outstanding gray draw moves to
    /// white, the same write as `SessionAccepted`. An address already white
    /// keeps its clock: the session did not stay. Anything else leaves the
    /// lists unchanged.
    Confirmed(NetworkAddress),
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
            | Self::DialFailed(a)
            | Self::PeerlistRefused(a)
            | Self::PayloadRefused(a) => a,
        }
    }
}

/// What a confirmation does to `last_observed` on an address that is
/// already white.
///
/// An outstanding draw does not consult this: both confirmations write
/// white and stamp the report's time. The clock moves only when the
/// session stayed. A later confirmation picks one of these at
/// [`crate::Peerlist::apply`]; the seat match cannot forget it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WhiteClock {
    /// `SessionAccepted`. The session stayed, so `last_observed` becomes
    /// the report's time.
    Move,
    /// `Confirmed`. The session closed in that turn, so the clock stays.
    Hold,
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
    /// The address arrived over a session the peer opened (PWD-I2). An
    /// inbound peer chooses to connect and chooses what it says, so its
    /// addresses do not enter gray. This is not a judgment of the peer:
    /// the caller does not score it, close it, or remember the address.
    InboundSession,
    /// The address is in the refused set and the operator did not name it
    /// (brief §2, address validity): a private, reserved or otherwise
    /// non-global range, or port 0. In a received list, one such entry is
    /// [`Self::PeerlistRefused`] for the whole list (R4).
    NotGlobal,
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
