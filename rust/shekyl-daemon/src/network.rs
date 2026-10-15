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
//! remnant's one RPC start has completed: the zone host's listeners and
//! dialers, this node's own addresses, and the dialer's peers.
//!
//! Nothing here branches on the network: the sections already did.

use std::net::SocketAddr;
use std::path::Path;

use shekyl_daemon_config::sections::{Ban, Clearnet, DaemonConfig, Tor};
use shekyl_ffi::dialer_ffi::{ConnectorId, NetworkAddress};
use shekyl_ffi::zone_ffi::ZoneStart;

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
/// RPC connection cap and each configured connector's outbound target.
#[must_use]
pub fn reserved_descriptors(config: &DaemonConfig) -> u64 {
    let rpc = u64::from(config.rpc.connections_max.get());
    connectors(config)
        .into_iter()
        .map(|c| u64::from(shekyl_ffi::dialer_ffi::default_target(c)))
        .fold(rpc, u64::saturating_add)
}

/// What the owners read at their build, recorded before the remnant is
/// constructed (step 6).
pub fn record(config: &DaemonConfig) {
    shekyl_ffi::rpc_peerlist_ffi::record_offline(config.offline());
    shekyl_ffi::peerlist_ffi::allow_local(config.p2p.local);
    shekyl_ffi::relay_zone_ffi::record_posture(&connectors(config), config.dev.relay_cover);
    shekyl_ffi::inbound_ceiling_ffi::record_reserved(reserved_descriptors(config));
    shekyl_ffi::link_ffi::set_limits(config.p2p.upload_max, config.p2p.download_max);
    for ban in &config.p2p.bans {
        match ban {
            Ban::Subnet(ip, prefix) => {
                if let Some(subnet) = shekyl_ffi::seam_ffi::bans::Subnet::new(*ip, *prefix) {
                    shekyl_ffi::seam_ffi::bans::ban_subnet_permanent(subnet);
                }
            }
            Ban::Host(ip) => shekyl_ffi::seam_ffi::bans::ban_host_permanent(*ip),
            Ban::Peer(shekyl_options::PeerEndpoint::Ip(endpoint)) => {
                shekyl_ffi::seam_ffi::bans::ban_host_permanent(endpoint.ip());
            }
            // The parser admits no onion line (the table is keyed by IP).
            Ban::Peer(shekyl_options::PeerEndpoint::Onion { .. }) => {}
        }
    }
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

/// The Tor SOCKS endpoint the zone host dials through at step 8: the
/// operator's, or the managed Tor's once it bootstrapped.
#[derive(Clone, Copy, Debug)]
pub enum TorSocks {
    /// No Tor this boot.
    None,
    /// The endpoint, and whether the zone host also listens for an onion
    /// (the managed one, or the operator's named onion).
    At {
        /// The SOCKS endpoint.
        socks: SocketAddr,
        /// The operator's onion listen endpoint, when the operator's Tor
        /// forwards an onion to this node.
        onion_listen: Option<SocketAddr>,
        /// Whether a forward listener for a managed onion is wanted.
        managed: bool,
    },
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

/// Step 8: the zone host's connectors from their sections, this node's
/// own addresses, and the dialer's peers. `tor` is what the Tor owner
/// resolved at this point.
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
    if let Clearnet::On { listen, socks, .. } = &config.clearnet {
        started.clearnet = shekyl_ffi::zone_ffi::start_clearnet(
            listen,
            socks.as_ref().map(|s| s.endpoint),
            config.dev.clearnet_encrypt,
            network_id,
        )?;
        for bound in &started.clearnet {
            tracing::info!(target: "global", "clearnet bound to {bound}");
        }
    }
    match tor {
        TorSocks::None => {}
        TorSocks::At {
            socks,
            onion_listen,
            managed,
        } => {
            if managed || onion_listen.is_some() {
                let forward = shekyl_ffi::zone_ffi::start_tor(socks, onion_listen, network_id)?;
                started.tor_forward = Some(forward);
            } else {
                shekyl_ffi::zone_ffi::dial_through_tor(socks, network_id)?;
            }
        }
    }
    shekyl_ffi::dialer_ffi::set_own_addresses(ConnectorId::Clearnet, own_clearnet(config))?;
    if let Some(onion) = own_onion(config) {
        shekyl_ffi::dialer_ffi::set_own_addresses(ConnectorId::Tor, vec![onion])?;
    }
    shekyl_ffi::dialer_ffi::apply_p2p(&config.p2p, &address_file(&config.data_dir))?;
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
        let resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        build(&resolved, network, mode, &platform, None).unwrap()
    }

    /// A valid v3 onion: the Ed25519 base point's hostname.
    fn onion_host() -> String {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        shekyl_onion_v3::v3_onion_hostname(&b)
    }

    /// The reservation is the RPC cap plus each configured connector's
    /// outbound target: the sum the C++ ceiling computed from the dialer's
    /// targets and the RPC instances' caps, now from the sections.
    #[test]
    fn the_reservation_is_the_rpc_cap_plus_each_connectors_target() {
        let both = config(&["--rpc-connections-max", "25"]);
        assert_eq!(
            reserved_descriptors(&both),
            25 + u64::from(shekyl_ffi::dialer_ffi::default_target(
                ConnectorId::Clearnet
            )) + u64::from(shekyl_ffi::dialer_ffi::default_target(ConnectorId::Tor))
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

    /// The operator's onion is this node's own Tor address, from the
    /// section: the C++ `--anonymous-inbound` advertisement, read in Rust.
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
        record(&c);
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
