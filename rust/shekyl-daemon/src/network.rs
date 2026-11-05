// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network's plan, from the sections (`DAEMON_CONFIG_CUTOVER.md` §2.2
//! steps 6 and 8, §3; `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2).
//!
//! The daemon reads its configuration once and hands the node a
//! [`NetworkPlan`]: the connectors to start, this node's own addresses,
//! the dialer's peers, the relay's posture, the descriptors reserved for
//! the inbound ceiling, the link bounds and the ban files' entries. The
//! node builds the [`shekyl_p2p::Network`] from it; nothing here reaches
//! a socket, and nothing here branches on the network: the sections
//! already did.

use std::net::SocketAddr;
use std::path::Path;

use shekyl_daemon_config::sections::{Ban, Clearnet, DaemonConfig, Socks, Tor};
use shekyl_daemon_config::Network as DaemonNet;
use shekyl_node::{
    BanTarget, ClearnetPlan, LinkLimits, NetworkPlan, PeerPlan, SeedNetwork, TorPlan,
};
use shekyl_options::kind::PeerEndpoint;
use shekyl_p2p::{
    clearnet_linger_descriptors, dial_profile, ConnectorId, Ipv4Subnet, NetworkAddress,
    PROBE_DESCRIPTORS,
};
use shekyl_socks::{Proxy, SocksUsername};

/// The address file the peer lists persist under the data directory.
pub const ADDRESS_FILE: &str = "p2pstate.bin";

/// The connectors the configuration turns on.
#[must_use]
pub fn connectors(config: &DaemonConfig) -> Vec<ConnectorId> {
    let mut on = Vec::with_capacity(2);
    if config.clearnet != Clearnet::Off {
        on.push(ConnectorId::Clearnet);
    }
    if config.tor != Tor::Off {
        on.push(ConnectorId::Tor);
    }
    on
}

/// The descriptors the daemon reserves beyond the p2p's own inbound: the
/// RPC connection cap, and for each configured connector its outbound
/// target plus its in-flight dial bound. A pending `Keep` counts toward the
/// target, but a `Confirm` dial does not: at the target a connector can
/// still hold its bound in `Confirm` dials, each one descriptor.
/// *Records-was (to 2026-10-25): the target alone, one descriptor short per
/// connector for a `Confirm` dial at target.*
///
/// A managed Tor adds [`PROBE_DESCRIPTORS`]: the probe of this node's own
/// onion holds one while it is in flight (`TOR_SUPERVISOR.md` §4.5). It is
/// not a peer dial and does not count against the in-flight bound, so the
/// bound does not cover it. An operator's Tor is not probed yet (§4.9).
///
/// A node that runs the bundle producer adds its reads' descriptors
/// ([`shekyl_node::producer_descriptors`]): it mines and has a Tor, managed
/// or the operator's, and each started settlement read holds a SOCKS
/// stream (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.11). Those are not peer
/// dials either.
///
/// Clearnet adds its linger cap
/// ([`shekyl_p2p::clearnet_linger_descriptors`]): a refused accept is held
/// half-closed until its first flight arrives or the handshake span passes
/// (`P2P_TRANSPORT_LAYER.md` D10.2), each one a descriptor outside the
/// inbound occupancy, up to that cap. With the written clearnet rates the
/// cap is the connector's burst plus the tokens it refills across the
/// handshake span, and every listener shares it.
#[must_use]
pub fn reserved_descriptors(config: &DaemonConfig) -> u64 {
    reservation(config, clearnet_linger_descriptors())
}

/// [`reserved_descriptors`] with the clearnet linger cap given.
fn reservation(config: &DaemonConfig, clearnet_linger: u64) -> u64 {
    let rpc = u64::from(config.rpc.connections_max.get());
    let linger = if config.clearnet == Clearnet::Off {
        0
    } else {
        clearnet_linger
    };
    let probe = if matches!(config.tor, Tor::Managed { .. }) {
        PROBE_DESCRIPTORS
    } else {
        0
    };
    let producer = shekyl_node::producer_descriptors(config);
    connectors(config)
        .into_iter()
        .map(|c| {
            let profile = dial_profile(c);
            let bound = u64::try_from(profile.in_flight_bound).unwrap_or(u64::MAX);
            u64::from(profile.target).saturating_add(bound)
        })
        .fold(
            rpc.saturating_add(probe)
                .saturating_add(producer)
                .saturating_add(linger),
            u64::saturating_add,
        )
}

/// This node's own clearnet addresses: `clearnet-advertise` (§2.8), the
/// lists' own entry, never a dial candidate. Empty is dial-only.
#[must_use]
pub fn own_clearnet(config: &DaemonConfig) -> Vec<NetworkAddress> {
    match &config.clearnet {
        Clearnet::On { advertise, .. } => advertise
            .iter()
            .map(|a| match a {
                SocketAddr::V4(v4) => NetworkAddress::Ipv4 {
                    ip: *v4.ip(),
                    port: v4.port(),
                },
                SocketAddr::V6(v6) => NetworkAddress::Ipv6 {
                    ip: *v6.ip(),
                    port: v6.port(),
                },
            })
            .collect(),
        Clearnet::Off => Vec::new(),
    }
}

/// This node's own onion on the operator's Tor, when one is named.
#[must_use]
pub fn own_onion(config: &DaemonConfig) -> Option<NetworkAddress> {
    match &config.tor {
        Tor::Operator {
            onion: Some(onion), ..
        } => Some(NetworkAddress::Tor {
            host: onion.host.clone(),
            port: onion.virtual_port,
        }),
        Tor::Operator { onion: None, .. } | Tor::Managed { .. } | Tor::Off => None,
    }
}

/// The proxy a section names, with its RFC 1929 pair when the operator gave
/// one (DC-Q7). The pair is bound to that proxy's address.
#[must_use]
pub fn proxy_of(socks: &Socks) -> Proxy {
    match &socks.credential {
        None => Proxy::unauthenticated(socks.endpoint),
        Some(pair) => Proxy::authenticated(
            socks.endpoint,
            SocksUsername::new(pair.username(), pair.password())
                .expect("the sections admit 1 to 255 bytes for each half, as RFC 1929 does"),
        ),
    }
}

/// The address file's path under the data directory.
#[must_use]
pub fn address_file(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(ADDRESS_FILE)
}

/// A configured peer as the lists hold it.
fn network_address(peer: &PeerEndpoint) -> NetworkAddress {
    match peer {
        PeerEndpoint::Ip(SocketAddr::V4(a)) => NetworkAddress::Ipv4 {
            ip: *a.ip(),
            port: a.port(),
        },
        PeerEndpoint::Ip(SocketAddr::V6(a)) => NetworkAddress::Ipv6 {
            ip: *a.ip(),
            port: a.port(),
        },
        PeerEndpoint::Onion { host, port } => NetworkAddress::Tor {
            host: host.clone(),
            port: *port,
        },
    }
}

/// Which compiled seed list the dialer admits: mainnet's and testnet's
/// are compiled; stagenet and regtest have none and dial only what the
/// operator names.
fn seeds(network: DaemonNet) -> SeedNetwork {
    match network {
        DaemonNet::Mainnet => SeedNetwork::Mainnet,
        DaemonNet::Testnet => SeedNetwork::Testnet,
        DaemonNet::Stagenet | DaemonNet::Regtest => SeedNetwork::None,
    }
}

/// The ban files' entries as the network applies them before its first
/// accept: a host and a subnet are banned for the life of the process; a
/// peer entry bans its host.
fn bans(config: &DaemonConfig) -> Vec<BanTarget> {
    config
        .p2p
        .bans
        .iter()
        .filter_map(|ban| match ban {
            Ban::Subnet(ip, prefix) => Ipv4Subnet::new(*ip, *prefix).map(BanTarget::Subnet),
            Ban::Host(ip) => Some(BanTarget::Host(*ip)),
            Ban::Peer(endpoint) => Some(BanTarget::Host(endpoint.ip())),
        })
        .collect()
}

/// The network's plan from the sections. The connectors whose own
/// addresses the configuration knows state them here: clearnet, when it
/// is on, with `clearnet-advertise` or none for dial-only; Tor on the
/// operator's arm with the named onion, or none for dial-only
/// (`INPUT_GRAMMAR.md` IG-Q18). A managed Tor states its per-boot onion
/// when Tor publishes it ([`shekyl_p2p::Network::note_own_onion`]).
///
/// Offline (both connectors off) plans no connector: the network starts
/// its session layer and owners with nothing to accept or dial, and the
/// sections already refuse a peer in that configuration.
#[must_use]
pub fn plan(config: &DaemonConfig, network_id: [u8; 16]) -> NetworkPlan {
    let clearnet = match &config.clearnet {
        Clearnet::Off => None,
        Clearnet::On { listen, socks, .. } => Some(ClearnetPlan {
            listen: listen.clone(),
            proxy: socks.as_ref().map(proxy_of),
            encrypt: config.dev.clearnet_encrypt,
            own: own_clearnet(config),
        }),
    };
    let tor = match &config.tor {
        Tor::Off => TorPlan::None,
        Tor::Managed { .. } => TorPlan::Managed,
        Tor::Operator { socks, onion } => TorPlan::Operator {
            socks: proxy_of(socks),
            onion_listen: onion.as_ref().map(|onion| onion.listen),
            own: own_onion(config).into_iter().collect(),
        },
    };
    NetworkPlan {
        network_id,
        seeds: seeds(config.network),
        allow_local: config.p2p.local,
        reserved_descriptors: reserved_descriptors(config),
        limits: LinkLimits {
            upload: config.p2p.upload_max,
            download: config.p2p.download_max,
        },
        relay_noise: config.dev.relay_cover,
        clearnet,
        tor,
        peers: PeerPlan {
            address_file: address_file(&config.data_dir),
            operator: config.p2p.peers.iter().map(network_address).collect(),
            exclusive: config
                .p2p
                .closed_peers
                .iter()
                .map(network_address)
                .collect(),
            disclose_early: config.p2p.disclose_early,
        },
        bans: bans(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::platform::Platform;
    use shekyl_daemon_config::sections::build;
    use shekyl_daemon_config::{choosers, resolve, TABLE};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn config(cli: &[&str]) -> DaemonConfig {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, mode) = choosers(&cli);
        let mut resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        build(&mut resolved, network, mode, &platform, None).unwrap()
    }

    /// A valid v3 onion: the Ed25519 base point's hostname.
    fn onion_host() -> String {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        shekyl_onion_v3::v3_onion_hostname(&b)
    }

    /// The reservation is the RPC cap plus, for each configured connector,
    /// its outbound target and its in-flight dial bound: the most
    /// descriptors its dials can hold, `Confirm` dials at target included.
    /// A managed Tor adds its probe's one (the probe brief, amendment 2):
    /// dropping that term, or adding it for an operator's Tor, fails this.
    /// Clearnet adds its linger cap (D10.2).
    #[test]
    fn the_reservation_is_the_rpc_cap_plus_each_connectors_target_and_bound() {
        let held = |c: ConnectorId| {
            let profile = dial_profile(c);
            u64::from(profile.target) + u64::try_from(profile.in_flight_bound).expect("small")
        };
        // Clearnet's refused accepts linger half-closed, up to its cap.
        let linger = clearnet_linger_descriptors();
        assert!(
            linger > 0,
            "clearnet's accept rates are written, so it lingers"
        );
        let both = config(&["--rpc-connections-max", "25"]);
        assert!(
            matches!(both.tor, Tor::Managed { .. }),
            "Tor is managed by default"
        );
        assert_eq!(
            reserved_descriptors(&both),
            25 + held(ConnectorId::Clearnet) + linger + held(ConnectorId::Tor) + PROBE_DESCRIPTORS,
            "the managed Tor's probe holds one more"
        );
        let operator = config(&[
            "--tor",
            "operator",
            "--tor-socks",
            "127.0.0.1:9050",
            "--rpc-connections-max",
            "25",
        ]);
        assert_eq!(
            reserved_descriptors(&operator),
            25 + held(ConnectorId::Clearnet) + linger + held(ConnectorId::Tor),
            "an operator's Tor is not probed"
        );
        let offline = config(&[
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--rpc-connections-max",
            "7",
        ]);
        assert_eq!(reserved_descriptors(&offline), 7);
        assert!(connectors(&offline).is_empty());
    }

    /// Clearnet's linger cap joins the reservation when clearnet is on, so
    /// the inbound ceiling makes room for refused accepts held half-closed;
    /// with clearnet off it adds nothing. The growth is shown with a given
    /// cap of 37, and the daemon's own figure is the reservation at the
    /// real cap.
    #[test]
    fn the_reservation_grows_by_the_clearnet_linger_cap() {
        let on = config(&["--rpc-connections-max", "25"]);
        assert_eq!(reservation(&on, 37), reservation(&on, 0) + 37);
        let off = config(&["--clearnet", "off", "--rpc-connections-max", "25"]);
        assert_eq!(reservation(&off, 37), reservation(&off, 0));
        assert_eq!(
            reserved_descriptors(&on),
            reservation(&on, clearnet_linger_descriptors())
        );
    }

    /// A full mainnet address the parser accepts as `mine-address`. The
    /// reservation follows that row, so the test goes through the same door
    /// as the daemon.
    fn mining_address() -> String {
        shekyl_address::ShekylAddress::new(
            shekyl_address::Network::Mainnet,
            [0xaa; 32],
            [0xbb; 32],
            [0xee; shekyl_address::MSG_SIGN_PK_LEN],
            vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN],
        )
        .encode()
        .expect("a full address encodes")
    }

    /// A node that mines adds the bundle producer's reads to the
    /// reservation, under a managed Tor and under an operator's: each
    /// started settlement read holds a SOCKS stream. With Tor off it runs
    /// no producer and adds nothing. Leaving the term out, or adding it for
    /// one Tor only, fails this. The mining row is a parsed `mine-address`.
    #[test]
    fn a_mining_node_with_a_tor_reserves_its_settlement_reads() {
        let address = mining_address();
        let with_tor = |tor: &[&str]| {
            let mut args = vec!["--rpc-connections-max", "25"];
            args.extend_from_slice(tor);
            config(&args)
        };
        let mining = |tor: &[&str]| {
            let mut args = vec![
                "--mine-address",
                address.as_str(),
                "--rpc-connections-max",
                "25",
            ];
            args.extend_from_slice(tor);
            let config = config(&args);
            assert!(
                config.mine.address.is_some(),
                "the parser accepted the address"
            );
            config
        };
        for tor in [
            &[][..],
            &["--tor", "operator", "--tor-socks", "127.0.0.1:9050"][..],
        ] {
            let idle = with_tor(tor);
            let mining = mining(tor);
            let reads = shekyl_node::producer_descriptors(&mining);
            assert!(reads > 0, "{:?}: the producer runs", mining.tor);
            assert_eq!(
                reserved_descriptors(&mining),
                reserved_descriptors(&idle) + reads,
                "{:?}: the reads are reserved",
                mining.tor
            );
        }
        let off = &["--tor", "off"][..];
        assert_eq!(
            reserved_descriptors(&mining(off)),
            reserved_descriptors(&with_tor(off)),
            "Tor off runs no producer"
        );
    }

    /// The operator's onion (`tor-onion`) is this node's own Tor address,
    /// from the section.
    /// A dial-only Tor has no own address, so the lists' own entry stays
    /// empty and the disclosure carries no per-node Tor value.
    #[test]
    fn the_operators_onion_is_the_own_tor_address_and_dial_only_has_none() {
        let host = onion_host();
        let c = config(&[
            "--tor",
            "operator",
            "--tor-socks",
            "127.0.0.1:9050",
            "--tor-onion",
            &format!("{host}:11021"),
            "--tor-onion-listen",
            "127.0.0.1:41021",
        ]);
        assert_eq!(
            own_onion(&c),
            Some(NetworkAddress::Tor { host, port: 11021 })
        );
        let dial_only = config(&["--tor", "operator", "--tor-socks", "127.0.0.1:9050"]);
        assert_eq!(own_onion(&dial_only), None);
        assert_eq!(
            own_onion(&config(&[])),
            None,
            "managed: the onion is published later"
        );
    }

    /// **What this node states as its own at start** (the dial profile
    /// brief, item 5; IG-Q18): clearnet when it is on, with
    /// `clearnet-advertise` or none for dial-only; Tor on the operator's
    /// arm, with its onion or none for dial-only. A managed Tor states its
    /// per-boot onion when Tor publishes it, so the plan carries none for
    /// it, and an off connector is not planned.
    #[test]
    fn own_addresses_are_planned_only_where_the_config_knows_them() {
        let defaults = plan(&config(&[]), [1; 16]);
        assert_eq!(
            defaults.connectors(),
            [ConnectorId::Clearnet, ConnectorId::Tor]
        );
        assert!(
            defaults
                .clearnet
                .as_ref()
                .expect("clearnet is on")
                .own
                .is_empty(),
            "defaults: clearnet dial-only"
        );
        assert!(
            matches!(defaults.tor, TorPlan::Managed),
            "the managed onion comes when published"
        );
        let offline = plan(&config(&["--clearnet", "off", "--tor", "off"]), [1; 16]);
        assert!(offline.connectors().is_empty());
        assert!(offline.clearnet.is_none());
        assert!(matches!(offline.tor, TorPlan::None));
        let dial_only = plan(
            &config(&["--tor", "operator", "--tor-socks", "127.0.0.1:9050"]),
            [1; 16],
        );
        match &dial_only.tor {
            TorPlan::Operator {
                own, onion_listen, ..
            } => {
                assert!(
                    own.is_empty(),
                    "the operator's Tor with no onion is dial-only"
                );
                assert_eq!(*onion_listen, None);
            }
            other => panic!("{other:?}"),
        }
        let host = onion_host();
        let with_onion = plan(
            &config(&[
                "--clearnet",
                "off",
                "--tor",
                "operator",
                "--tor-socks",
                "127.0.0.1:9050",
                "--tor-onion",
                &format!("{host}:11021"),
                "--tor-onion-listen",
                "127.0.0.1:41021",
            ]),
            [1; 16],
        );
        assert_eq!(with_onion.connectors(), [ConnectorId::Tor]);
        match &with_onion.tor {
            TorPlan::Operator {
                own, onion_listen, ..
            } => {
                assert_eq!(own, &[NetworkAddress::Tor { host, port: 11021 }]);
                assert_eq!(*onion_listen, Some("127.0.0.1:41021".parse().unwrap()));
            }
            other => panic!("{other:?}"),
        }
    }

    /// The sections' peers, bans and bounds reach the plan as the network
    /// takes them: operator peers and the closed set as list addresses, a
    /// ban file's host and subnet as permanent targets (the C++
    /// `--ban-list` tests' subject) with a peer entry banning its host,
    /// the link bounds, and the seed list by network (mainnet's and
    /// testnet's compiled; stagenet and regtest none).
    #[test]
    fn the_sections_peers_bans_and_bounds_reach_the_plan() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("bans");
        std::fs::write(&file, "203.0.113.9\n198.51.100.0/24\n").unwrap();
        let c = config(&[
            "--p2p-peer",
            "203.0.113.5:18080",
            "--p2p-ban-file",
            file.to_str().unwrap(),
            "--p2p-upload-max",
            "1MiB/s",
        ]);
        assert_eq!(c.p2p.bans.len(), 2);
        let plan = plan(&c, [7; 16]);
        assert_eq!(plan.network_id, [7; 16]);
        assert_eq!(plan.seeds, SeedNetwork::Mainnet);
        assert_eq!(
            plan.peers.operator,
            [NetworkAddress::Ipv4 {
                ip: std::net::Ipv4Addr::new(203, 0, 113, 5),
                port: 18080
            }]
        );
        assert!(plan.peers.exclusive.is_empty());
        assert_eq!(plan.peers.address_file, c.data_dir.join(ADDRESS_FILE));
        assert_eq!(plan.limits.upload, c.p2p.upload_max);
        assert!(plan.limits.upload.is_some(), "the row parsed");
        assert_eq!(plan.limits.download, None);
        assert_eq!(plan.reserved_descriptors, reserved_descriptors(&c));
        assert_eq!(
            plan.bans,
            [
                BanTarget::Host("203.0.113.9".parse().unwrap()),
                BanTarget::Subnet(
                    Ipv4Subnet::new(std::net::Ipv4Addr::new(198, 51, 100, 0), 24).unwrap()
                ),
            ]
        );
        for (args, seeds) in [
            (&["--network", "testnet"][..], SeedNetwork::Testnet),
            (&["--network", "stagenet"][..], SeedNetwork::None),
            (&["--network", "regtest"][..], SeedNetwork::None),
        ] {
            assert_eq!(super::plan(&config(args), [0; 16]).seeds, seeds, "{args:?}");
        }
    }

    /// `clearnet-advertise` is the lists' own clearnet entry (§2.8); unset
    /// is dial-only with no own entry.
    #[test]
    fn clearnet_advertise_is_the_own_clearnet_address() {
        let c = config(&["--clearnet-advertise", "8.8.8.8:1234"]);
        assert_eq!(
            own_clearnet(&c),
            vec![NetworkAddress::Ipv4 {
                ip: std::net::Ipv4Addr::new(8, 8, 8, 8),
                port: 1234
            }]
        );
        assert!(own_clearnet(&config(&[])).is_empty());
        assert!(own_clearnet(&config(&["--clearnet", "off"])).is_empty());
    }
}
