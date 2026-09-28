// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The endpoint a connector admitted.
//!
//! One enum. Clearnet carries the host and the direction. Tor inbound is
//! this zone with no peer address. Tor outbound is the onion that was dialed.
//! The FFI struct is an encoding of this enum, decoded once at the boundary.

use std::net::IpAddr;

use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{
    CloseCause, CloseKind, ConnectorId, Direction, NetworkAddress, OpenError, OpenSocket, Sockets,
};

/// Octets of a v3 onion hostname, including `.onion`. The adapter's host
/// buffer is this long.
pub const TOR_HOST_MAX: usize = 62;

/// What the connector observed, and what `established` posts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A clearnet host and the direction of the socket.
    Clearnet {
        /// The peer address.
        ip: IpAddr,
        /// The port the union carries.
        port: u16,
        /// Accepted or dialed.
        direction: Direction,
    },
    /// Tor inbound. This zone, no peer address.
    TorInbound,
    /// Tor outbound. The onion we dialed.
    Tor {
        /// Hostname, including `.onion` when it is a hostname.
        host: String,
        /// The port the union carries.
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

/// Reserve a socket for `endpoint` on `sockets`.
///
/// Refusal is a D12 cause. Nothing is reserved in that case.
pub fn admit(
    sockets: &Sockets,
    endpoint: &Endpoint,
    now: Tick,
    ceiling: InboundCeiling,
) -> Result<OpenSocket, CloseCause> {
    let opened = match endpoint {
        Endpoint::Clearnet {
            ip,
            direction: Direction::Outbound,
            ..
        } => sockets.open_clearnet(*ip, now),
        Endpoint::Clearnet {
            ip,
            direction: Direction::Inbound,
            ..
        } => sockets.accept_clearnet(*ip, ceiling, now),
        Endpoint::TorInbound => sockets.accept_tor(ceiling),
        Endpoint::Tor { host, port } => {
            if host.is_empty() || host.len() > TOR_HOST_MAX {
                return Err(CloseCause::new(CloseKind::DialFailed));
            }
            sockets.open_tor(&NetworkAddress::Tor {
                host: host.clone(),
                port: *port,
            })
        }
    };
    match opened {
        Ok(open) => Ok(open),
        Err(OpenError::Refused(cause)) => Err(cause),
        Err(OpenError::Exhausted) => Err(CloseCause::new(CloseKind::AdmissionRefused)),
    }
}

/// `index` is the FFI connector word. Anything else is not a connector.
#[must_use]
pub fn connector_from_index(index: u32) -> Option<ConnectorId> {
    match index {
        0 => Some(ConnectorId::Clearnet),
        1 => Some(ConnectorId::Tor),
        _ => None,
    }
}

/// `index` is the FFI direction word. Anything else is not a direction.
#[must_use]
pub fn direction_from_index(index: u32) -> Option<Direction> {
    match index {
        0 => Some(Direction::Inbound),
        1 => Some(Direction::Outbound),
        _ => None,
    }
}

const _: () = {
    assert!(ConnectorId::Clearnet as u8 as u32 == 0);
    assert!(ConnectorId::Tor as u8 as u32 == 1);
    assert!(Direction::Inbound.index() == 0);
    assert!(Direction::Outbound.index() == 1);
};
