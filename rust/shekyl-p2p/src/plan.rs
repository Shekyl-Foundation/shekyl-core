// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the daemon tells the network once, from its configuration. Plain
//! values: this crate reads no configuration table and knows no section.
//! The daemon resolves its rows into a [`NetworkPlan`] and hands it over.

use std::net::SocketAddr;
use std::path::PathBuf;

use shekyl_dialer::SeedNetwork;
use shekyl_socks::Proxy;
use shekyl_transport_layer::{ConnectorId, NetworkAddress};

use crate::bans::BanTarget;

/// The whole network, as configured.
#[derive(Clone, Debug)]
pub struct NetworkPlan {
    /// This node's network id: the handshake's `network_id`, and the
    /// clearnet channel's.
    pub network_id: [u8; 16],
    /// Which compiled seed list the connectors admit at start.
    pub seeds: SeedNetwork,
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
