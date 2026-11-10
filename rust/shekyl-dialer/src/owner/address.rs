// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A list address and a session endpoint name the same peer.
//!
//! `shekyl-peerlist` and `shekyl-p2p-session` do not depend on each other.
//! The dialer is the layer that holds both, so this is where one becomes
//! the other. An inbound Tor row has no list address: the peer's onion is not
//! on the socket.

use std::collections::BTreeSet;
use std::net::IpAddr;

use shekyl_p2p_session::{Board, Endpoint};
use shekyl_peerlist::{ConnectorId, Direction, Host, NetworkAddress};

/// What this node discloses of itself on `connector`, given its own
/// addresses there: the line [`super::Dialer::set_own_addresses`] logs when
/// they are set. With none, the connector is dial-only.
pub(super) fn disclosure(connector: ConnectorId, own: &[NetworkAddress]) -> String {
    if own.is_empty() {
        format!("{connector:?} is dial-only: this node discloses no address of its own there")
    } else {
        format!("{connector:?}: this node discloses {own:?} as its own")
    }
}

/// The session endpoint a list address dials. `None` for an onion host that
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
pub(crate) fn address_of(endpoint: &Endpoint) -> Option<NetworkAddress> {
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
///
/// Visible through the owner: the wake reads it, and the candidate filter
/// reads a different fact from the same board (do not redial a live host).
pub(in crate::owner) struct LiveSessions {
    /// Every session's list address.
    pub(in crate::owner) addresses: BTreeSet<NetworkAddress>,
    /// The host of every session, inbound and outbound: one session per
    /// host is read from this set, so a host that dialed in is not dialed.
    pub(in crate::owner) session_hosts: BTreeSet<Host>,
}

/// Live sessions on `connector`.
pub(super) fn live_sessions(board: &Board, connector: ConnectorId) -> LiveSessions {
    let mut sessions = BTreeSet::new();
    let mut session_hosts = BTreeSet::new();
    for row in board.rows() {
        if row.connector() != connector {
            continue;
        }
        // An inbound Tor session names no address, so it holds no host.
        let Some(address) = address_of(&row.endpoint()) else {
            continue;
        };
        session_hosts.insert(address.host());
        sessions.insert(address);
    }
    LiveSessions {
        addresses: sessions,
        session_hosts,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_peerlist::{ConnectorId, NetworkAddress};

    use super::disclosure;

    /// **The line states what this node discloses** (the dial profile
    /// brief, item 5): the own address when there is one, and dial-only
    /// when there is none.
    #[test]
    fn the_disclosure_line_names_the_own_address_or_dial_only() {
        let none = disclosure(ConnectorId::Clearnet, &[]);
        assert!(none.contains("dial-only"), "{none}");
        let own = NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(11, 16, 0, 9),
            port: 11021,
        };
        let line = disclosure(ConnectorId::Clearnet, &[own]);
        assert!(line.contains("11.16.0.9"), "{line}");
        assert!(!line.contains("dial-only"), "{line}");
    }
}
