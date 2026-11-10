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
use shekyl_peerlist::{ConnectorId, Direction, NetworkAddress};

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
///
/// An IPv4 peer that the socket reported as IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) is the IPv4 address it names. The clearnet listener
/// binds through tokio, which does not set `IPV6_V6ONLY`, so an IPv6
/// wildcard accepts IPv4 and `accept` returns the mapped form. The peer
/// lists refuse that spelling outright (`REFUSED_V6`), so a dial candidate
/// is the IPv4 variant. Folding here is what makes the host check see one
/// host. A real IPv6 address is left as IPv6.
pub(crate) fn address_of(endpoint: &Endpoint) -> Option<NetworkAddress> {
    match endpoint {
        Endpoint::Clearnet { ip, port, .. } => Some(network_address(ip.to_canonical(), *port)),
        Endpoint::Tor { key, port } => Some(NetworkAddress::Tor {
            host: shekyl_onion_v3::v3_onion_hostname(key),
            port: *port,
        }),
        Endpoint::TorInbound => None,
    }
}

/// `ip` as a list address on `port`. `ip` is already canonical: an
/// IPv4-mapped address has been folded by [`IpAddr::to_canonical`].
fn network_address(ip: IpAddr, port: u16) -> NetworkAddress {
    match ip {
        IpAddr::V4(ip) => NetworkAddress::Ipv4 { ip, port },
        IpAddr::V6(ip) => NetworkAddress::Ipv6 { ip, port },
    }
}

/// The list address of every live session on `connector`.
///
/// An inbound Tor row names no address, so it holds no host. The host
/// check reads this set; it is not projected into a second one.
pub(super) fn live_sessions(board: &Board, connector: ConnectorId) -> BTreeSet<NetworkAddress> {
    let mut sessions = BTreeSet::new();
    for row in board.rows() {
        if row.connector() != connector {
            continue;
        }
        let Some(address) = address_of(&row.endpoint()) else {
            continue;
        };
        sessions.insert(address);
    }
    sessions
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use shekyl_p2p_session::Endpoint;
    use shekyl_peerlist::{ConnectorId, Direction, NetworkAddress};

    use super::{address_of, disclosure};

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

    /// **A mapped IPv4 session is the IPv4 address** (`IpAddr::to_canonical`).
    /// The lists refuse `::ffff:a.b.c.d`, so the only way that spelling
    /// reaches the dialer is a socket accept on an IPv6 wildcard. A real
    /// IPv6 address stays IPv6.
    #[test]
    fn a_mapped_ipv4_session_is_the_ipv4_address() {
        let v4 = Ipv4Addr::new(203, 0, 113, 9);
        let mapped = Endpoint::Clearnet {
            ip: IpAddr::V6(v4.to_ipv6_mapped()),
            port: 18080,
            direction: Direction::Inbound,
        };
        assert_eq!(
            address_of(&mapped),
            Some(NetworkAddress::Ipv4 {
                ip: v4,
                port: 18080
            })
        );
        let real = Endpoint::Clearnet {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 18080,
            direction: Direction::Inbound,
        };
        assert_eq!(
            address_of(&real),
            Some(NetworkAddress::Ipv6 {
                ip: Ipv6Addr::LOCALHOST,
                port: 18080,
            })
        );
    }
}
