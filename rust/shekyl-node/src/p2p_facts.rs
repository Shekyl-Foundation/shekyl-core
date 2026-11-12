// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC's p2p facts, read from the network
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, "RPC facts"): `peer_connections`
//! and `net_stats` from the session board and the link gate, the peer list
//! from the peers owner, the stem tallies from the relay snapshot. An
//! offline node answers [`P2pRead::Offline`] where the read has that answer.
//!
//! This is the one place those domain values become RPC rows. The network
//! does not know the document.

use std::net::{IpAddr, Ipv6Addr};

use shekyl_daemon_rpc::chain_facts::{FactsFault, NetStats, P2pFacts};
use shekyl_daemon_rpc::core::{ConnectionFacts, ConnectionsSnapshot, P2pRead, PeerEntry};
use shekyl_p2p::{session_of, Endpoint, ListedAddress, Network, Row};
use shekyl_relay::owner::RelaySnapshot;
use shekyl_relay::{ConnectorId, StemTallySnapshot};
use shekyl_rpc_types::kinds::{Count, Text};
use shekyl_rpc_types::wire::p2p::{Connector, Floor, RelayStats, Tally};
use shekyl_transport_layer::{Direction, NetworkAddress};

/// Unix milliseconds in one second. The link gate stamps milliseconds; the
/// connection row reports seconds.
const MILLISECONDS_PER_SECOND: u64 = 1000;

/// epee address-type ids the connection row carries.
const ADDRESS_TYPE_IPV4: u8 = 1;
const ADDRESS_TYPE_IPV6: u8 = 2;
const ADDRESS_TYPE_TOR: u8 = 4;

/// The host string for an inbound Tor session, whose onion is not known
/// at accept.
const UNKNOWN_TOR_HOST: &str = "<unknown tor host>";

/// `fe80::/10`, the link-local prefix.
const LINK_LOCAL_V6_PREFIX: u16 = 0xfe80;
const LINK_LOCAL_V6_MASK: u16 = 0xffc0;

/// The node's network behind the RPC's p2p reads.
pub(crate) struct NodeP2pFacts {
    network: Network,
    /// `offline`: both connectors off by configuration.
    offline: bool,
    /// Unix seconds the node started, as `net_stats` reports it.
    started_at: u64,
}

impl NodeP2pFacts {
    pub(crate) const fn new(network: Network, offline: bool, started_at: u64) -> Self {
        Self {
            network,
            offline,
            started_at,
        }
    }
}

impl P2pFacts for NodeP2pFacts {
    fn net_stats(&self) -> Result<NetStats, FactsFault> {
        let totals = self.network.link_totals();
        Ok(NetStats {
            start_time: self.started_at,
            total_packets_in: totals.packets_in,
            total_bytes_in: totals.bytes_in,
            total_packets_out: totals.packets_out,
            total_bytes_out: totals.bytes_out,
        })
    }

    fn connections(&self) -> Result<ConnectionsSnapshot, FactsFault> {
        let now = crate::facts::unix_now();
        let board = self.network.board();
        let connections = board
            .rows()
            .iter()
            .map(|row| connection_of(row, self.network.socket_traffic(row.id().get())))
            .collect();
        Ok(ConnectionsSnapshot { now, connections })
    }

    fn peer_list(&self, public_only: bool) -> Result<P2pRead<Vec<PeerEntry>>, FactsFault> {
        if self.offline {
            return Ok(P2pRead::Offline);
        }
        Ok(P2pRead::Running(
            self.network
                .listed(public_only)
                .iter()
                .map(peer_entry)
                .collect(),
        ))
    }

    fn p2p_state(&self) -> Result<P2pRead<()>, FactsFault> {
        Ok(if self.offline {
            P2pRead::Offline
        } else {
            P2pRead::Running(())
        })
    }

    fn stem_tallies(&self) -> Result<RelayStats, FactsFault> {
        Ok(project_stem_tallies(&self.network.relay_snapshot()))
    }
}

/// One connection row: the endpoint's rendering plus the gate's traffic.
fn connection_of(row: &Row, traffic: shekyl_p2p::SocketTraffic) -> ConnectionFacts {
    let rendered = render_endpoint(row.endpoint());
    ConnectionFacts {
        address: rendered.address,
        host: rendered.host,
        connection_id: session_of(row.id()).0,
        started: row.started_unix(),
        last_recv: traffic.last_recv_ms / MILLISECONDS_PER_SECOND,
        last_send: traffic.last_send_ms / MILLISECONDS_PER_SECOND,
        recv_count: traffic.bytes_down,
        send_count: traffic.bytes_up,
        // The RPC field is a double; the gate counts whole bytes.
        #[allow(clippy::cast_precision_loss)]
        current_speed_down: traffic.speed_down as f64,
        #[allow(clippy::cast_precision_loss)]
        current_speed_up: traffic.speed_up as f64,
        port: rendered.port,
        address_type: rendered.address_type,
        incoming: row.endpoint().direction() == Direction::Inbound,
        localhost: rendered.localhost,
        local_ip: rendered.local_ip,
    }
}

struct RenderedEndpoint {
    address: String,
    host: String,
    port: u16,
    address_type: u8,
    localhost: bool,
    local_ip: bool,
}

/// The address string, the host, the port, the type id, loopback and local.
fn render_endpoint(endpoint: Endpoint) -> RenderedEndpoint {
    match endpoint {
        Endpoint::Clearnet { ip, port, .. } => match ip {
            IpAddr::V4(ip) => RenderedEndpoint {
                address: format!("{ip}:{port}"),
                host: ip.to_string(),
                port,
                address_type: ADDRESS_TYPE_IPV4,
                localhost: ip.is_loopback(),
                local_ip: ip.is_private(),
            },
            IpAddr::V6(ip) => RenderedEndpoint {
                address: format!("[{ip}]:{port}"),
                host: ip.to_string(),
                port,
                address_type: ADDRESS_TYPE_IPV6,
                localhost: ip.is_loopback(),
                local_ip: is_link_local_v6(ip),
            },
        },
        Endpoint::Tor { key, port } => {
            let host = shekyl_onion_v3::v3_onion_hostname(&key);
            RenderedEndpoint {
                address: format!("{host}:{port}"),
                host,
                port,
                address_type: ADDRESS_TYPE_TOR,
                localhost: false,
                local_ip: false,
            }
        }
        Endpoint::TorInbound => RenderedEndpoint {
            address: UNKNOWN_TOR_HOST.to_owned(),
            host: UNKNOWN_TOR_HOST.to_owned(),
            port: 0,
            address_type: ADDRESS_TYPE_TOR,
            localhost: false,
            local_ip: false,
        },
    }
}

fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & LINK_LOCAL_V6_MASK) == LINK_LOCAL_V6_PREFIX
}

fn peer_entry(listed: &ListedAddress) -> PeerEntry {
    let (host, ip, port) = render_listed(&listed.address);
    PeerEntry {
        host,
        ip,
        port,
        white: listed.white,
        blocked: listed.blocked,
    }
}

/// The host string and the numeric fields of one listed address.
///
/// An IPv4 `ip` is the four octets in little-endian `u32` form: that is
/// the value the wire has always carried beside the host string.
fn render_listed(address: &NetworkAddress) -> (String, u32, u16) {
    match address {
        NetworkAddress::Ipv4 { ip, port } => {
            (ip.to_string(), u32::from_le_bytes(ip.octets()), *port)
        }
        NetworkAddress::Ipv6 { ip, port } => (ip.to_string(), 0, *port),
        NetworkAddress::Tor { host, port } => (format!("{host}:{port}"), 0, 0),
    }
}

/// Floors in connector order, omitting a connector with no observation.
/// Tallies sorted by connection id. A tally whose connector has not been
/// observed has `connector` null (IG-Q83).
fn project_stem_tallies(snapshot: &RelaySnapshot) -> RelayStats {
    let mut floor = Vec::new();
    for connector in ConnectorId::ALL {
        let Some((_, observed)) = snapshot.floors.iter().find(|(id, _)| id == connector) else {
            continue;
        };
        floor.push(Floor {
            connector: wire_connector(*connector),
            outbound_count: Count(u64::from(observed.achieved)),
            outbound_min: Count(u64::from(observed.floor)),
            below: observed.below,
        });
    }
    let mut rows: Vec<&(shekyl_relay::ConnectionId, StemTallySnapshot)> =
        snapshot.tallies.iter().collect();
    rows.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
    let tally = rows
        .into_iter()
        .map(|(peer, tally)| Tally {
            connection: Text(hex::encode(peer.0)),
            connector: tally.connector.map(wire_connector).into(),
            propagated: Count(tally.propagated),
            silent: Count(tally.silent),
            sender_count: Count(tally.distinct_sources),
        })
        .collect();
    RelayStats { floor, tally }
}

/// A connector as the wire names it. Exhaustive: a new connector is a new
/// wire keyword, decided where it is added.
const fn wire_connector(connector: ConnectorId) -> Connector {
    match connector {
        ConnectorId::Clearnet => Connector::Clearnet,
        ConnectorId::Tor => Connector::Tor,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_relay::owner::RelaySnapshot;
    use shekyl_relay::{ConnectionId, ConnectorId, FloorSnapshot, StemTallySnapshot};
    use shekyl_rpc_types::kinds::{Count, Text};
    use shekyl_rpc_types::wire::p2p::{Connector, Floor, RelayStats, Tally};

    use super::{is_link_local_v6, project_stem_tallies, render_listed};

    #[test]
    fn stem_tallies_follow_the_relay_snapshot() {
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
            project_stem_tallies(&snapshot),
            RelayStats {
                floor: vec![Floor {
                    connector: Connector::Clearnet,
                    outbound_count: Count(3),
                    outbound_min: Count(8),
                    below: true,
                }],
                tally: vec![
                    Tally {
                        connection: Text("00000000000000000000000000000000".to_owned()),
                        connector: Some(Connector::Tor).into(),
                        propagated: Count(5),
                        silent: Count(1),
                        sender_count: Count(3),
                    },
                    // A connector not yet observed is null (IG-Q83).
                    Tally {
                        connection: Text("00000000000000000000000000000001".to_owned()),
                        connector: None.into(),
                        propagated: Count(2),
                        silent: Count(0),
                        sender_count: Count(1),
                    },
                ],
            }
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
        let (host, ip, port) = render_listed(&shekyl_transport_layer::NetworkAddress::Tor {
            host: "a".repeat(56) + ".onion",
            port: 18080,
        });
        assert_eq!(host, "a".repeat(56) + ".onion:18080");
        assert_eq!((ip, port), (0, 0));
        let (host, ip, port) = render_listed(&shekyl_transport_layer::NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port: 7,
        });
        assert_eq!(host, "1.2.3.4");
        assert_eq!(ip, u32::from_le_bytes([1, 2, 3, 4]));
        assert_eq!(port, 7);
    }
}
