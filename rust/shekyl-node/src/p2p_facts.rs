// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC's p2p facts, read from the network
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, "RPC facts"): `get_connections`
//! and `net_stats` from the session layer's board, the peer list from the
//! peers owner, the stem tallies from the relay owner. An offline node
//! answers [`P2pRead::Offline`] where the read has that answer.

use shekyl_daemon_rpc::chain_facts::{FactsFault, NetStats, P2pFacts};
use shekyl_daemon_rpc::core::{ConnectionFacts, ConnectionsSnapshot, P2pRead, PeerEntry};
use shekyl_p2p::Network;

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
        let snapshot = self.network.connections(crate::facts::unix_now());
        Ok(ConnectionsSnapshot {
            now: snapshot.now,
            connections: snapshot
                .connections
                .into_iter()
                .map(|row| ConnectionFacts {
                    address: row.address,
                    host: row.host,
                    connection_id: row.connection_id,
                    started: row.started,
                    last_recv: row.last_recv,
                    last_send: row.last_send,
                    recv_count: row.recv_count,
                    send_count: row.send_count,
                    current_speed_down: row.current_speed_down,
                    current_speed_up: row.current_speed_up,
                    port: row.port,
                    address_type: row.address_type,
                    incoming: row.incoming,
                    localhost: row.localhost,
                    local_ip: row.local_ip,
                })
                .collect(),
        })
    }

    fn peer_list(&self, public_only: bool) -> Result<P2pRead<Vec<PeerEntry>>, FactsFault> {
        if self.offline {
            return Ok(P2pRead::Offline);
        }
        Ok(P2pRead::Running(
            self.network
                .peer_list(public_only)
                .into_iter()
                .map(|peer| PeerEntry {
                    host: peer.host,
                    ip: peer.ip,
                    port: peer.port,
                    white: peer.white,
                    blocked: peer.blocked,
                })
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

    fn stem_tallies(&self) -> Result<String, FactsFault> {
        Ok(self.network.stem_tallies_json())
    }
}
