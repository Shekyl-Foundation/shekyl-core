// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network owners, each reading its section (`DAEMON_CONFIG_CUTOVER.md`
//! §2.2 steps 6 and 8, §3).
//!
//! Two moments. [`record`] runs before the remnant is constructed: what
//! the owners read at their build, which the seam's bind in the remnant's
//! `init` triggers — offline, the local-address rule, the relay's
//! posture, the descriptors reserved for the inbound ceiling, the link
//! bounds and the ban file's entries. [`start`] runs at step 8, once the
//! remnant's one RPC start has completed: this node's own addresses and
//! the dialer's peers first, then the zone host's listeners and owner
//! loops. The loops start after the p2p section, so a closed network is
//! the population at the first wake.
//!
//! Nothing here branches on the network: the sections already did.

use std::net::SocketAddr;
use std::path::Path;

use shekyl_daemon_config::sections::{Ban, Clearnet, DaemonConfig, Socks, Tor};
use shekyl_ffi::dialer_ffi::{ConnectorId, NetworkAddress};
use shekyl_ffi::zone_ffi::ZoneStart;
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
/// ([`shekyl_ffi::zone_ffi::clearnet_linger_descriptors`]): a refused
/// accept is held half-closed until its first flight arrives or the
/// handshake span passes (`P2P_TRANSPORT_LAYER.md` D10.2), each one a
/// descriptor outside the inbound occupancy, up to that cap. It scales
/// with the clearnet accept rates, and is zero until they are ruled.
#[must_use]
pub fn reserved_descriptors(config: &DaemonConfig) -> u64 {
    reservation(config, shekyl_ffi::zone_ffi::clearnet_linger_descriptors())
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
            let profile = shekyl_ffi::dialer_ffi::dial_profile(c);
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

/// The descriptors the managed Tor's probe holds: its SOCKS stream, one
/// probe at a time.
pub const PROBE_DESCRIPTORS: u64 = 1;

/// What the owners read at their build, recorded before the remnant is
/// constructed (step 6). The relay identity and the reserved descriptor
/// count are one preparation. A second install that disagrees is refused.
///
/// # Errors
/// [`shekyl_ffi::remnant_prep::PrepDisagreement`] when the preparation was
/// already installed with different facts.
pub fn record(config: &DaemonConfig) -> Result<(), shekyl_ffi::remnant_prep::PrepDisagreement> {
    let prep = shekyl_ffi::remnant_prep::RemnantPrep {
        relay: shekyl_ffi::relay_zone_ffi::relay_identity(
            &connectors(config),
            config.dev.relay_cover,
        ),
        reserved_descriptors: reserved_descriptors(config),
    };
    shekyl_ffi::remnant_prep::install(prep)?;
    shekyl_ffi::peerlist_ffi::allow_local(config.p2p.local);
    shekyl_ffi::link_ffi::set_limits(config.p2p.upload_max, config.p2p.download_max);
    for ban in &config.p2p.bans {
        match ban {
            Ban::Subnet(ip, prefix) => {
                if let Some(subnet) = shekyl_ffi::seam_ffi::bans::Subnet::new(*ip, *prefix) {
                    shekyl_ffi::seam_ffi::bans::ban_subnet_permanent(subnet);
                }
            }
            Ban::Host(ip) => shekyl_ffi::seam_ffi::bans::ban_host_permanent(*ip),
            Ban::Peer(endpoint) => shekyl_ffi::seam_ffi::bans::ban_host_permanent(endpoint.ip()),
        }
    }
    Ok(())
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

/// What this node states as its own on each connector when it starts: the
/// connectors whose own addresses the configuration knows. Clearnet, when
/// it is on: `clearnet-advertise`, none for dial-only. Tor, on the
/// operator's arm: the named onion, none for dial-only (`INPUT_GRAMMAR.md`
/// IG-Q18). A managed Tor always publishes: its per-boot onion is stated
/// when Tor publishes it (`dialer_ffi::note_own_onion`). A connector that
/// is off states nothing.
#[must_use]
pub fn own_at_start(config: &DaemonConfig) -> Vec<(ConnectorId, Vec<NetworkAddress>)> {
    let mut own = Vec::new();
    if matches!(config.clearnet, Clearnet::On { .. }) {
        own.push((ConnectorId::Clearnet, own_clearnet(config)));
    }
    if matches!(config.tor, Tor::Operator { .. }) {
        own.push((ConnectorId::Tor, own_onion(config).into_iter().collect()));
    }
    own
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

/// The Tor SOCKS proxy the zone host dials through at step 8: the
/// operator's, with its pair, or the managed Tor's once it bootstrapped,
/// which takes none.
#[derive(Clone, Debug)]
pub enum TorSocks {
    /// No Tor this boot.
    None,
    /// The operator's Tor. Its route is published now.
    Operator {
        /// The SOCKS proxy.
        socks: Proxy,
        /// The operator's onion listen endpoint, when that Tor forwards an
        /// onion to this node.
        onion_listen: Option<SocketAddr>,
    },
    /// The managed Tor. The connector starts with no route. The supervisor
    /// publishes one when Tor is running.
    Managed,
}

/// What step 8 started.
#[derive(Debug, Default)]
pub struct Started {
    /// The clearnet endpoints bound.
    pub clearnet: Vec<SocketAddr>,
    /// The loopback endpoint the managed onion forwards to, when the Tor
    /// zone listens.
    pub tor_forward: Option<SocketAddr>,
}

/// Why step 8 failed; the daemon stops with status 1.
#[derive(Debug)]
pub enum StartError {
    /// A connector could not start.
    Zone(ZoneStart),
    /// The dialer does not exist: the remnant did not bind the seam.
    NoDialer,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zone(e) => write!(f, "{e}"),
            Self::NoDialer => f.write_str("the remnant did not bind the seam"),
        }
    }
}

impl From<ZoneStart> for StartError {
    fn from(e: ZoneStart) -> Self {
        Self::Zone(e)
    }
}

impl From<shekyl_ffi::dialer_ffi::NoDialer> for StartError {
    fn from(_: shekyl_ffi::dialer_ffi::NoDialer) -> Self {
        Self::NoDialer
    }
}

/// Step 8: this node's own addresses and the dialer's peers, then the
/// zone host's connectors. `tor` is what the Tor owner resolved at this
/// point.
///
/// The p2p section is applied before any owner loop. The loop arms its
/// first wake half a second after it starts, and until a closed network
/// is installed every gray address is eligible, including the compiled
/// seeds. Listeners come up after that declaration.
///
/// # Errors
/// [`StartError`]; nothing started is undone here, the stop path does that.
pub fn start(
    config: &DaemonConfig,
    network_id: [u8; 16],
    tor: TorSocks,
) -> Result<Started, StartError> {
    let mut started = Started::default();
    // Offline: no connector, so the remnant bound no seam and there is no
    // dialer to tell; the sections already refuse a peer with both
    // connectors off, and the lists' own entry has nothing to be own on.
    if config.offline() {
        return Ok(started);
    }
    for (connector, own) in own_at_start(config) {
        shekyl_ffi::dialer_ffi::set_own_addresses(connector, own)?;
    }
    shekyl_ffi::dialer_ffi::apply_p2p(&config.p2p, &address_file(&config.data_dir))?;
    if let Clearnet::On { listen, socks, .. } = &config.clearnet {
        started.clearnet = shekyl_ffi::zone_ffi::start_clearnet(
            listen,
            socks.as_ref().map(proxy_of),
            config.dev.clearnet_encrypt,
            network_id,
        )?;
        for bound in &started.clearnet {
            tracing::info!(target: "global", "clearnet bound to {bound}");
        }
    }
    match tor {
        TorSocks::None => {}
        TorSocks::Managed => {
            started.tor_forward = Some(shekyl_ffi::zone_ffi::start_managed_tor(network_id)?);
        }
        TorSocks::Operator {
            socks,
            onion_listen,
        } => {
            if onion_listen.is_some() {
                let forward = shekyl_ffi::zone_ffi::start_tor(socks, onion_listen, network_id)?;
                started.tor_forward = Some(forward);
            } else {
                shekyl_ffi::zone_ffi::dial_through_tor(socks, network_id)?;
            }
        }
    }
    Ok(started)
}

/// The address file's path under the data directory.
#[must_use]
pub fn address_file(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(ADDRESS_FILE)
}

/// Stops the dialer and the zone host (step 9, first).
pub fn stop() {
    shekyl_ffi::zone_ffi::shutdown();
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
            let profile = shekyl_ffi::dialer_ffi::dial_profile(c);
            u64::from(profile.target) + u64::try_from(profile.in_flight_bound).expect("small")
        };
        // Clearnet's refused accepts linger half-closed, up to its cap.
        let linger = shekyl_ffi::zone_ffi::clearnet_linger_descriptors();
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
    /// with clearnet off it adds nothing. The real cap is zero until the
    /// clearnet rates are ruled, so the growth is shown with a given cap,
    /// and the daemon's own figure is the reservation at the real one.
    #[test]
    fn the_reservation_grows_by_the_clearnet_linger_cap() {
        let on = config(&["--rpc-connections-max", "25"]);
        assert_eq!(reservation(&on, 37), reservation(&on, 0) + 37);
        let off = config(&["--clearnet", "off", "--rpc-connections-max", "25"]);
        assert_eq!(reservation(&off, 37), reservation(&off, 0));
        assert_eq!(
            reserved_descriptors(&on),
            reservation(&on, shekyl_ffi::zone_ffi::clearnet_linger_descriptors())
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
    /// per-boot onion when Tor publishes it, so nothing is stated for it
    /// here, and an off connector states nothing.
    #[test]
    fn own_addresses_are_stated_at_start_only_where_the_config_knows_them() {
        let connectors = |c: &DaemonConfig| -> Vec<ConnectorId> {
            own_at_start(c)
                .into_iter()
                .map(|(connector, _)| connector)
                .collect()
        };
        assert_eq!(
            own_at_start(&config(&[])),
            vec![(ConnectorId::Clearnet, Vec::new())],
            "defaults: clearnet dial-only; the managed onion comes when published"
        );
        assert_eq!(
            connectors(&config(&["--clearnet", "off", "--tor", "off"])),
            Vec::<ConnectorId>::new()
        );
        let dial_only = config(&["--tor", "operator", "--tor-socks", "127.0.0.1:9050"]);
        assert_eq!(
            own_at_start(&dial_only),
            vec![
                (ConnectorId::Clearnet, Vec::new()),
                (ConnectorId::Tor, Vec::new())
            ],
            "the operator's Tor with no onion is dial-only on Tor"
        );
        let host = onion_host();
        let with_onion = config(&[
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
        ]);
        assert_eq!(
            own_at_start(&with_onion),
            vec![(
                ConnectorId::Tor,
                vec![NetworkAddress::Tor { host, port: 11021 }]
            )]
        );
    }

    /// Offline starts nothing and needs no seam: the remnant binds none
    /// when both connectors are off, and that is not a refusal.
    #[test]
    fn offline_starts_nothing_and_needs_no_dialer() {
        let c = config(&["--clearnet", "off", "--tor", "off"]);
        let started = start(&c, [1u8; 16], TorSocks::None).expect("nothing to start");
        assert!(started.clearnet.is_empty());
        assert_eq!(started.tor_forward, None);
    }

    /// The ban file's entries are permanent bans, applied at the record
    /// (the C++ `--ban-list` tests' subject): a host and a subnet from the
    /// file are banned for the life of the process, and a host outside
    /// the subnet is not.
    #[test]
    fn the_ban_files_entries_are_permanent_bans() {
        // `main` replaces the process socket table. This test writes bans
        // onto it, so it takes the same lock the daemon-start test holds.
        let _serial = crate::run::hold_process_table();
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("bans");
        std::fs::write(&file, "203.0.113.9\n198.51.100.0/24\n").unwrap();
        let c = config(&[
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--p2p-ban-file",
            file.to_str().unwrap(),
        ]);
        assert_eq!(c.p2p.bans.len(), 2);
        record(&c).expect("the ban file's preparation installs");
        let banned =
            |host: &str| shekyl_ffi::seam_ffi::bans::is_banned_permanently(host.parse().unwrap());
        assert!(banned("203.0.113.9"), "permanent");
        assert!(banned("198.51.100.77"), "in the subnet: permanent");
        assert!(!banned("198.51.101.1"), "outside it: not banned");
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
