// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the RPC reads about the network (brief §2.1, "RPC facts"): the
//! connections from the board, the link totals, the peer lists, and the
//! relay's stem tallies. Read through [`crate::Network`]; nothing here
//! holds a session or a byte.
//!
//! The shapes are the ones `get_connections`, `get_net_stats`,
//! `get_peer_list` and `get_stem_tallies` already serve, so the RPC crate
//! maps them field for field. The connection id is the sixteen bytes the
//! relay and the peer lists name a session by ([`shekyl_dialer::session_of`]).

use std::fmt::Write as _;
use std::net::IpAddr;

use shekyl_capped_stream::node_gate;
use shekyl_dialer::{session_of, Dialer};
use shekyl_p2p_session::{Board, Endpoint, Row};
use shekyl_peerlist::{ListName, NetworkAddress, Peerlist};
use shekyl_relay::owner::RelaySnapshot;
use shekyl_timing_engine::MonotonicClock;
use shekyl_transport_layer::{ConnectorId, Direction, Sockets};

/// One connection as `get_connections` reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionFacts {
    /// `ip:port`, `[ip6]:port`, `host.onion:port`, or the unknown-Tor-host
    /// marker for an inbound Tor session.
    pub address: String,
    /// The host alone.
    pub host: String,
    /// The session's sixteen-byte id.
    pub connection_id: [u8; 16],
    /// Unix seconds when the socket was admitted.
    pub started: u64,
    /// Unix seconds of the last byte received; 0 before any.
    pub last_recv: u64,
    /// Unix seconds of the last byte sent; 0 before any.
    pub last_send: u64,
    /// Bytes received on this connection.
    pub recv_count: u64,
    /// Bytes sent on this connection.
    pub send_count: u64,
    /// Bytes per second down, as the link gate measures it.
    pub current_speed_down: f64,
    /// Bytes per second up.
    pub current_speed_up: f64,
    /// The peer's port; 0 for an inbound Tor session.
    pub port: u16,
    /// epee's `address_type`: 1 IPv4, 2 IPv6, 4 Tor.
    pub address_type: u8,
    /// Inbound.
    pub incoming: bool,
    /// The peer is a loopback address.
    pub localhost: bool,
    /// The peer is a private (RFC 1918) or link-local address.
    pub local_ip: bool,
    /// The Levin handshake completed.
    pub established: bool,
}

/// The connections, with the one clock read every elapsed quantity is
/// derived against.
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionsSnapshot {
    /// Unix seconds, read once for the whole snapshot.
    pub now: u64,
    pub connections: Vec<ConnectionFacts>,
}

/// The link totals since the gate was installed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkTotals {
    pub packets_in: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
}

/// One peer-list row as `get_peer_list` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedPeer {
    /// The ip string for IPv4, the bare host for IPv6, and `host:port`
    /// for Tor.
    pub host: String,
    /// The IPv4 address with its four octets in network order. Zero for
    /// every other arm.
    pub ip: u32,
    /// Zero for Tor, whose port is carried in [`Self::host`].
    pub port: u16,
    /// White list. Otherwise gray.
    pub white: bool,
    /// The transport layer bans this host now.
    pub blocked: bool,
}

/// The sockets per connector and direction, and the clearnet list sizes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerCounts {
    pub clearnet_in: u64,
    pub clearnet_out: u64,
    pub tor_in: u64,
    pub tor_out: u64,
    pub white: u64,
    pub gray: u64,
}

/// A count that does not fit the `u64` the RPC reports.
const COUNT_DOES_NOT_FIT: u64 = u64::MAX;

fn count_width(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(COUNT_DOES_NOT_FIT)
}

/// The marker epee's `tor_address::unknown()` renders for a Tor peer whose
/// onion this node does not know: every inbound Tor session.
const UNKNOWN_TOR_HOST: &str = "<unknown tor host>";

const ADDRESS_TYPE_IPV4: u8 = 1;
const ADDRESS_TYPE_IPV6: u8 = 2;
const ADDRESS_TYPE_TOR: u8 = 4;

/// The connections on `board`, read against one `now`.
pub(crate) fn connections(board: &Board, now: u64) -> ConnectionsSnapshot {
    let gate = node_gate();
    let connections = board
        .rows()
        .iter()
        .map(|row| {
            let id = row.id().get();
            let (send_ms, recv_ms) = gate.activity_unix(id);
            let observed = gate.connection(id);
            let (speed_up, speed_down) = gate.speed(id);
            let (address, host, port, address_type, localhost, local_ip) = render(*row);
            ConnectionFacts {
                address,
                host,
                connection_id: session_of(row.id()).0,
                started: row.started_unix(),
                last_recv: recv_ms / 1000,
                last_send: send_ms / 1000,
                recv_count: observed.bytes_down,
                send_count: observed.bytes_up,
                // The RPC field is a double; the gate counts whole bytes.
                #[allow(clippy::cast_precision_loss)]
                current_speed_down: speed_down as f64,
                #[allow(clippy::cast_precision_loss)]
                current_speed_up: speed_up as f64,
                port,
                address_type,
                incoming: row.endpoint().direction() == Direction::Inbound,
                localhost,
                local_ip,
                established: row.established(),
            }
        })
        .collect();
    ConnectionsSnapshot { now, connections }
}

/// epee's rendering of one endpoint: `str()`, `host_str()`, the port, the
/// type id, loopback and local.
fn render(row: Row) -> (String, String, u16, u8, bool, bool) {
    match row.endpoint() {
        Endpoint::Clearnet { ip, port, .. } => match ip {
            IpAddr::V4(ip) => (
                format!("{ip}:{port}"),
                ip.to_string(),
                port,
                ADDRESS_TYPE_IPV4,
                ip.is_loopback(),
                ip.is_private(),
            ),
            IpAddr::V6(ip) => (
                format!("[{ip}]:{port}"),
                ip.to_string(),
                port,
                ADDRESS_TYPE_IPV6,
                ip.is_loopback(),
                is_link_local_v6(ip),
            ),
        },
        Endpoint::Tor { key, port } => {
            let host = shekyl_onion_v3::v3_onion_hostname(&key);
            (
                format!("{host}:{port}"),
                host,
                port,
                ADDRESS_TYPE_TOR,
                false,
                false,
            )
        }
        Endpoint::TorInbound => (
            UNKNOWN_TOR_HOST.to_owned(),
            UNKNOWN_TOR_HOST.to_owned(),
            0,
            ADDRESS_TYPE_TOR,
            false,
            false,
        ),
    }
}

/// `fe80::/10`: what `boost::asio::ip::address_v6::is_link_local` answers.
fn is_link_local_v6(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// The link totals since the gate was installed.
pub(crate) fn link_totals() -> LinkTotals {
    let observed = node_gate().totals();
    LinkTotals {
        packets_in: observed.packets_down,
        bytes_in: observed.bytes_down,
        packets_out: observed.packets_up,
        bytes_out: observed.bytes_up,
    }
}

/// The peer lists, white then gray, for every connector or clearnet only.
pub(crate) fn listed_peers(dialer: &Dialer<MonotonicClock>, public_only: bool) -> Vec<ListedPeer> {
    let mut rows: Vec<(NetworkAddress, ListName, bool)> = {
        let shared = dialer.shared();
        shared
            .lists
            .snapshot()
            .into_iter()
            .filter(|(address, _)| {
                !public_only || Peerlist::connector_of(address) == Some(ConnectorId::Clearnet)
            })
            .map(|(address, list)| {
                let blocked = shared.lists.is_banned(&address);
                (address, list, blocked)
            })
            .collect()
    };
    rows.sort_by_key(|(_, list, _)| matches!(list, ListName::Gray));
    rows.into_iter()
        .map(|(address, list, blocked)| {
            let (host, ip, port) = render_listed(&address);
            ListedPeer {
                host,
                ip,
                port,
                white: matches!(list, ListName::White),
                blocked,
            }
        })
        .collect()
}

/// The host string and the numeric fields of one listed address.
fn render_listed(address: &NetworkAddress) -> (String, u32, u16) {
    match address {
        NetworkAddress::Ipv4 { ip, port } => {
            (ip.to_string(), u32::from_le_bytes(ip.octets()), *port)
        }
        NetworkAddress::Ipv6 { ip, port } => (ip.to_string(), 0, *port),
        NetworkAddress::Tor { host, port } => (format!("{host}:{port}"), 0, 0),
    }
}

/// The clearnet white and gray list sizes. White is counted against the
/// addresses the dialer holds, as the disclosure does.
pub(crate) fn clearnet_list_sizes(dialer: &Dialer<MonotonicClock>) -> (u64, u64) {
    let now = dialer.now();
    let (white, gray) = {
        let mut shared = dialer.shared();
        let mut kept = shared.kept_addresses(ConnectorId::Clearnet);
        let white = shared.lists.white_count(
            ConnectorId::Clearnet,
            now,
            &mut kept,
            &mut shekyl_relay::owner::SecureRelayRng,
        );
        let gray = shared.lists.gray_count(ConnectorId::Clearnet);
        (white, gray)
    };
    (count_width(white), count_width(gray))
}

/// The sockets per connector and direction, and the clearnet list sizes.
pub(crate) fn peer_counts(sockets: &Sockets, dialer: &Dialer<MonotonicClock>) -> PeerCounts {
    let (white, gray) = clearnet_list_sizes(dialer);
    PeerCounts {
        clearnet_in: sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
        clearnet_out: sockets.socket_count(ConnectorId::Clearnet, Direction::Outbound),
        tor_in: sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        tor_out: sockets.socket_count(ConnectorId::Tor, Direction::Outbound),
        white,
        gray,
    }
}

/// Established sessions, outbound then inbound.
pub(crate) fn session_counts(board: &Board) -> (u64, u64) {
    (
        count_width(board.established_count(Direction::Outbound)),
        count_width(board.established_count(Direction::Inbound)),
    )
}

/// `get_stem_tallies`' body: the relay's per-connector floor diagnostic and
/// the per-peer stem tallies, in the JSON the C++ served (§55; §18.4).
/// Rows are ordered by peer id; a connector with no floor data is omitted,
/// never zero-filled.
pub(crate) fn stem_tallies_json(snapshot: &RelaySnapshot) -> String {
    let mut out = String::from("{\"floor\":[");
    let mut wrote_floor = false;
    for connector in ConnectorId::ALL {
        let Some((_, floor)) = snapshot.floors.iter().find(|(c, _)| c == connector) else {
            continue;
        };
        if wrote_floor {
            out.push(',');
        }
        wrote_floor = true;
        write!(
            out,
            "{{\"connector\":\"{}\",\"achieved_out_connections\":{},\"floor\":{},\"below\":{}}}",
            connector_name(*connector),
            floor.achieved,
            floor.floor,
            floor.below
        )
        .expect("writes to a String do not fail");
    }
    out.push_str("],\"tallies\":[");
    let mut rows: Vec<_> = snapshot.tallies.iter().collect();
    rows.sort_by(|(a, _), (b, _)| a.0.cmp(&b.0));
    for (i, (peer, tally)) in rows.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"peer\":\"");
        for byte in peer.0 {
            write!(out, "{byte:02x}").expect("writes to a String do not fail");
        }
        write!(
            out,
            "\",\"connector\":\"{}\",\"propagated\":{},\"silent\":{},\"distinct_sources\":{}}}",
            tally.connector.map_or("unnamed", connector_name),
            tally.propagated,
            tally.silent,
            tally.distinct_sources
        )
        .expect("writes to a String do not fail");
    }
    out.push_str("]}");
    out
}

/// epee's `connector_id_to_string`.
fn connector_name(connector: ConnectorId) -> &'static str {
    match connector {
        ConnectorId::Clearnet => "clearnet",
        ConnectorId::Tor => "tor",
    }
}

#[cfg(test)]
mod tests {
    use shekyl_peerlist::ConnectionId;
    use shekyl_relay::{FloorSnapshot, StemTallySnapshot};

    use super::*;

    #[test]
    fn stem_tallies_render_as_the_cpp_did() {
        let mut second = [0u8; 16];
        second[15] = 1;
        let snapshot = RelaySnapshot {
            noise: false,
            live_stems: 0,
            stem_in_flight: 0,
            tallies: vec![
                (
                    ConnectionId(second),
                    StemTallySnapshot {
                        propagated: 2,
                        silent: 0,
                        distinct_sources: 1,
                        connector: None,
                    },
                ),
                (
                    ConnectionId([0u8; 16]),
                    StemTallySnapshot {
                        propagated: 5,
                        silent: 1,
                        distinct_sources: 3,
                        connector: Some(ConnectorId::Tor),
                    },
                ),
            ],
            floors: vec![(
                ConnectorId::Clearnet,
                FloorSnapshot {
                    achieved: 3,
                    floor: 8,
                    below: true,
                },
            )],
        };
        assert_eq!(
            stem_tallies_json(&snapshot),
            "{\"floor\":[{\"connector\":\"clearnet\",\"achieved_out_connections\":3,\"floor\":8,\
             \"below\":true}],\"tallies\":[{\"peer\":\"00000000000000000000000000000000\",\
             \"connector\":\"tor\",\"propagated\":5,\"silent\":1,\"distinct_sources\":3},\
             {\"peer\":\"00000000000000000000000000000001\",\"connector\":\"unnamed\",\
             \"propagated\":2,\"silent\":0,\"distinct_sources\":1}]}"
        );
    }

    #[test]
    fn link_local_v6_is_fe80_10() {
        assert!(is_link_local_v6("fe80::1".parse().expect("v6")));
        assert!(is_link_local_v6("febf::1".parse().expect("v6")));
        assert!(!is_link_local_v6("fec0::1".parse().expect("v6")));
        assert!(!is_link_local_v6("::1".parse().expect("v6")));
    }

    #[test]
    fn a_listed_tor_peer_carries_its_port_in_the_host() {
        let (host, ip, port) = render_listed(&NetworkAddress::Tor {
            host: "a".repeat(56) + ".onion",
            port: 18080,
        });
        assert_eq!(host, "a".repeat(56) + ".onion:18080");
        assert_eq!((ip, port), (0, 0));
        let (host, ip, port) = render_listed(&NetworkAddress::Ipv4 {
            ip: std::net::Ipv4Addr::new(1, 2, 3, 4),
            port: 7,
        });
        assert_eq!(host, "1.2.3.4");
        assert_eq!(ip, u32::from_le_bytes([1, 2, 3, 4]));
        assert_eq!(port, 7);
    }
}
