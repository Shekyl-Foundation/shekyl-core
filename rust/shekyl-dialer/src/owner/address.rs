// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A list address and a seam endpoint name the same peer.
//!
//! `shekyl-peerlist` and `shekyl-seam` do not depend on each other. The
//! dialer is the layer that holds both, so this is where one becomes the
//! other. An inbound Tor row has no list address: the peer's onion is not
//! on the socket.

use std::collections::BTreeSet;
use std::net::IpAddr;

use shekyl_peerlist::{ConnectorId, Direction, Host, NetworkAddress};
use shekyl_seam::{Endpoint, Hub};

/// The seam endpoint a list address dials. `None` for an onion host that
/// is not a v3 address: the lists do not admit one, and a dial of one is
/// a local close.
pub(super) fn endpoint_of(address: &NetworkAddress) -> Option<Endpoint> {
    match address {
        NetworkAddress::Ipv4 { ip, port } => Some(Endpoint::Clearnet {
            ip: IpAddr::V4(*ip),
            port: *port,
            direction: Direction::Outbound,
        }),
        NetworkAddress::Ipv6 { ip, port } => Some(Endpoint::Clearnet {
            ip: IpAddr::V6(*ip),
            port: *port,
            direction: Direction::Outbound,
        }),
        NetworkAddress::Tor { host, port } => {
            shekyl_onion_v3::v3_pubkey(host).map(|key| Endpoint::Tor { key, port: *port })
        }
    }
}

/// The list address of a board row. `None` for [`Endpoint::TorInbound`].
pub(super) fn address_of(endpoint: &Endpoint) -> Option<NetworkAddress> {
    match endpoint {
        Endpoint::Clearnet {
            ip: IpAddr::V4(ip),
            port,
            ..
        } => Some(NetworkAddress::Ipv4 {
            ip: *ip,
            port: *port,
        }),
        Endpoint::Clearnet {
            ip: IpAddr::V6(ip),
            port,
            ..
        } => Some(NetworkAddress::Ipv6 {
            ip: *ip,
            port: *port,
        }),
        Endpoint::Tor { key, port } => Some(NetworkAddress::Tor {
            host: shekyl_onion_v3::v3_onion_hostname(key),
            port: *port,
        }),
        Endpoint::TorInbound => None,
    }
}

/// Live sessions on one connector, read from the hub's board once per wake.
pub(super) struct LiveSessions {
    /// Every session's list address.
    pub(super) addresses: BTreeSet<NetworkAddress>,
    /// The host of every outbound session: one outbound session per host is
    /// read from this set.
    pub(super) outbound_hosts: BTreeSet<Host>,
}

/// Live sessions on `connector`.
pub(super) fn live_sessions(hub: &Hub, connector: ConnectorId) -> LiveSessions {
    let mut sessions = BTreeSet::new();
    let mut outbound_hosts = BTreeSet::new();
    for row in hub.board().rows() {
        if row.connector() != connector {
            continue;
        }
        let Some(address) = address_of(&row.endpoint()) else {
            continue;
        };
        if row.direction() == Direction::Outbound {
            outbound_hosts.insert(address.host());
        }
        sessions.insert(address);
    }
    LiveSessions {
        addresses: sessions,
        outbound_hosts,
    }
}
