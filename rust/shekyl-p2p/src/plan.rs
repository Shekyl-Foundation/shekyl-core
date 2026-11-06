// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the daemon tells the network once, from its configuration. Plain
//! values: this crate reads no configuration table and knows no section.
//! The daemon resolves its rows into a [`NetworkPlan`] and hands it over.

use std::net::SocketAddr;
use std::path::PathBuf;

use shekyl_socks::Proxy;
use shekyl_transport_layer::{ConnectorId, NetworkAddress};

use crate::bans::BanTarget;

/// The whole network, as configured.
#[derive(Clone, Debug)]
pub struct NetworkPlan {
    /// This node's network id: the handshake's `network_id`, and the
    /// clearnet channel's.
    pub network_id: [u8; 16],
    /// The network whose row's seeds the connectors admit at start
    /// (`shekyl_dialer::seeds`); `None` admits none. A row's list may be
    /// empty (stagenet, regtest).
    pub seeds: Option<shekyl_network::Network>,
    /// `allow-local-ip`: whether non-global addresses are kept, disclosed
    /// and stored.
    pub allow_local: bool,
    /// Descriptors the daemon has promised elsewhere (RPC connections, the
    /// dial profiles, the producer, the probe) but has not opened: the
    /// inbound ceiling is the process limit less these
    /// ([`crate::descriptors::inbound_ceiling`]).
    pub reserved_descriptors: u64,
    /// The operator's link budget.
    pub limits: LinkLimits,
    /// Whether the relay carries noise (`dev` relay cover).
    pub relay_noise: bool,
    /// The clearnet connector, or none.
    pub clearnet: Option<ClearnetPlan>,
    /// The Tor connector.
    pub tor: TorPlan,
    /// The peer lists' inputs.
    pub peers: PeerPlan,
    /// Bans from the ban files: permanent, applied before any accept.
    pub bans: Vec<BanTarget>,
}

impl NetworkPlan {
    /// The connectors this plan starts, in declaration order.
    #[must_use]
    pub fn connectors(&self) -> Vec<ConnectorId> {
        let mut connectors = Vec::new();
        if self.clearnet.is_some() {
            connectors.push(ConnectorId::Clearnet);
        }
        if !matches!(self.tor, TorPlan::None) {
            connectors.push(ConnectorId::Tor);
        }
        connectors
    }

    /// The listening sockets the connectors bind: one per clearnet listen
    /// address, the managed Tor's forward listener, and the operator's
    /// onion forward when one is named. The inbound ceiling is resolved
    /// before they bind, so they are reserved with the rest.
    #[must_use]
    pub fn listener_descriptors(&self) -> u64 {
        let clearnet = self.clearnet.as_ref().map_or(0, |c| c.listen.len());
        let tor = match &self.tor {
            TorPlan::None => 0,
            TorPlan::Managed => 1,
            TorPlan::Operator { onion_listen, .. } => usize::from(onion_listen.is_some()),
        };
        u64::try_from(clearnet + tor).unwrap_or(u64::MAX)
    }
}

/// Upload and download bounds in bytes per second; `None` is unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkLimits {
    /// `p2p-upload-max`.
    pub upload: Option<u64>,
    /// `p2p-download-max`.
    pub download: Option<u64>,
}

/// The clearnet connector.
#[derive(Clone, Debug)]
pub struct ClearnetPlan {
    /// The endpoints to listen on. Empty is dial-only.
    pub listen: Vec<SocketAddr>,
    /// The operator's SOCKS proxy for outbound clearnet, with its pair.
    pub proxy: Option<Proxy>,
    /// Whether the clearnet channel is encrypted (the `dev` lever).
    pub encrypt: bool,
    /// This node's own clearnet addresses, as advertised.
    pub own: Vec<NetworkAddress>,
}

/// The Tor connector.
#[derive(Clone, Debug)]
pub enum TorPlan {
    /// No Tor.
    None,
    /// The operator's own Tor.
    Operator {
        /// Its SOCKS proxy, with the configured pair.
        socks: Proxy,
        /// Where the operator's onion forwards to, when the operator
        /// publishes one and names the endpoint.
        onion_listen: Option<SocketAddr>,
        /// The operator's onion as this node's own Tor address.
        own: Vec<NetworkAddress>,
    },
    /// The Tor this daemon launches and supervises. The forward listener
    /// is bound at start; the route arrives later
    /// ([`crate::Network::publish_managed_running`]).
    Managed,
}

/// The peer lists' inputs.
#[derive(Clone, Debug)]
pub struct PeerPlan {
    /// The address file (`p2pstate.bin`), read at start and written back.
    pub address_file: PathBuf,
    /// Operator-named peers, admitted to gray first.
    pub operator: Vec<NetworkAddress>,
    /// A closed network: only these are dialed.
    pub exclusive: Vec<NetworkAddress>,
    /// Disclose addresses before the white diversity floor is reached.
    pub disclose_early: bool,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use shekyl_socks::Proxy;

    use super::{ClearnetPlan, LinkLimits, NetworkPlan, PeerPlan, TorPlan};

    fn plan(listen: usize, tor: TorPlan) -> NetworkPlan {
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        NetworkPlan {
            network_id: [7; 16],
            seeds: None,
            allow_local: true,
            reserved_descriptors: 8,
            limits: LinkLimits::default(),
            relay_noise: false,
            clearnet: (listen > 0).then(|| ClearnetPlan {
                listen: vec![at; listen],
                proxy: None,
                encrypt: false,
                own: Vec::new(),
            }),
            tor,
            peers: PeerPlan {
                address_file: PathBuf::from("p2pstate.bin"),
                operator: Vec::new(),
                exclusive: Vec::new(),
                disclose_early: false,
            },
            bans: Vec::new(),
        }
    }

    /// Every listener the connectors bind is counted: the ceiling is
    /// resolved before they exist.
    #[test]
    fn every_listener_the_connectors_bind_is_reserved() {
        let socks = Proxy::unauthenticated(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050)));
        let operator = |onion_listen| TorPlan::Operator {
            socks: socks.clone(),
            onion_listen,
            own: Vec::new(),
        };
        assert_eq!(plan(0, TorPlan::None).listener_descriptors(), 0);
        assert_eq!(plan(2, TorPlan::None).listener_descriptors(), 2);
        assert_eq!(plan(1, TorPlan::Managed).listener_descriptors(), 2);
        assert_eq!(plan(0, operator(None)).listener_descriptors(), 0);
        let forward = SocketAddr::from((Ipv4Addr::LOCALHOST, 18083));
        assert_eq!(plan(1, operator(Some(forward))).listener_descriptors(), 2);
    }
}
