// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network layer of `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2: the
//! composition that builds the connectors the configuration names
//! (clearnet, an operator's Tor, the managed Tor), the session layer
//! (`shekyl-p2p-session`) and the three owners (`shekyl-dialer` for peers,
//! the node's sync port, `shekyl-relay` for transactions), starts them in
//! dependency order and stops them in reverse, and serves the RPC facts
//! (`get_connections`, `net_stats`, the peer lists, the stem tallies) from
//! the session board, the link gate and the owners' snapshots, with no FFI.
//!
//! The node builds a [`Network`] from a [`NetworkPlan`] and never reaches
//! below it: the connectors, the socket table's ban verbs and the Tor link
//! are reached through this crate's verbs.

#![deny(unsafe_code)]

mod bans;
mod descriptors;
mod dial;
mod facts;
mod network;
mod peers;
mod plan;
mod reports;
mod tor;

pub use bans::{BanSpan, BanTarget, Bans};
pub use descriptors::{observe_descriptors, PROBE_DESCRIPTORS};
pub use facts::{ConnectionFacts, ConnectionsSnapshot, LinkTotals, ListedPeer, PeerCounts};
pub use network::{Listening, Network, NetworkParts, StartError};
pub use plan::{ClearnetPlan, LinkLimits, NetworkPlan, PeerPlan, TorPlan};
pub use tor::{TOR_DIAL_WITHIN, TOR_SOCKS_TIMEOUT};

pub use shekyl_dialer::{session_of, SeedNetwork, TorLinkTally};
pub use shekyl_p2p_session::{
    ClaimCarrier, CoreSyncData, Established, ProbeArrival, ProbeHandshake, SyncInbound, SyncOwner,
    Taken,
};
pub use shekyl_peer_policy::InboundCeiling;
pub use shekyl_relay::owner::{Admit, PoolDoor, RelayHandle};
pub use shekyl_relay::{NodeSync, OriginVerdict, TxId};
pub use shekyl_transport_layer::{
    BanLeft, ConnectorId, DownCause, InboundFacet, Ipv4Subnet, ListedBan, NetworkAddress, Sockets,
};
