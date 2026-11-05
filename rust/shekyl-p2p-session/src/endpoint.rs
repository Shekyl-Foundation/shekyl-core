// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The endpoint a connector admitted.
//!
//! One enum. Clearnet carries the host and the direction. Tor inbound is
//! this zone with no peer address. Tor outbound is the onion that was dialed.

use std::net::IpAddr;

use shekyl_transport_layer::{ConnectorId, Direction};

/// What the connector observed, and what `established` posts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A clearnet host and the direction of the socket.
    Clearnet {
        /// The peer address.
        ip: IpAddr,
        /// The port of this socket.
        ///
        /// On an accept, this is the peer's ephemeral source port, not
        /// the port the peer advertised. The advertised port is a claim,
        /// and it is not this field.
        port: u16,
        /// Accepted or dialed.
        direction: Direction,
    },
    /// Tor inbound. This zone, no peer address.
    TorInbound,
    /// Tor outbound. The v3 service that was dialed.
    ///
    /// The hostname is not stored. A dial re-encodes it from the key (`shekyl_onion_v3::v3_onion_hostname`).
    /// A host that is not a v3 onion never becomes this variant.
    Tor {
        /// The service key.
        key: [u8; 32],
        /// The port that was dialed.
        port: u16,
    },
}

impl Endpoint {
    /// The connector this endpoint admits on.
    #[must_use]
    pub const fn connector(&self) -> ConnectorId {
        match self {
            Self::Clearnet { .. } => ConnectorId::Clearnet,
            Self::TorInbound | Self::Tor { .. } => ConnectorId::Tor,
        }
    }

    /// Inbound or outbound.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        match self {
            Self::Clearnet { direction, .. } => *direction,
            Self::TorInbound => Direction::Inbound,
            Self::Tor { .. } => Direction::Outbound,
        }
    }

    /// The clearnet host, when the endpoint has one.
    #[must_use]
    pub const fn clearnet_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Clearnet { ip, .. } => Some(*ip),
            Self::TorInbound | Self::Tor { .. } => None,
        }
    }
}
