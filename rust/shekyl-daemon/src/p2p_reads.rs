// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peer-list and session reads the RPC asks for.
//!
//! `shekyl-daemon-rpc` does not depend on `shekyl-ffi` (DC-F30). This
//! crate sees both, so it is the one place an owned [`ListedPeer`] becomes
//! the RPC's [`PeerEntry`]. The two rows name the same five fields; a
//! field added to either fails to compile here.

use shekyl_daemon_rpc::core::PeerEntry;
use shekyl_daemon_rpc::info_facts::SessionCounts;
use shekyl_daemon_rpc::p2p_reads::{P2pFault, P2pReads};
use shekyl_ffi::rpc_peerlist_ffi::{clearnet_list_sizes, listed_peers, session_counts, ListedPeer};

/// The reads [`shekyl_daemon_rpc::p2p_reads::install`] takes.
pub(crate) fn installed() -> P2pReads {
    P2pReads {
        peers,
        sizes,
        sessions,
    }
}

/// One row, field by field. The compile fails when the two rows disagree.
fn peer_entry(row: ListedPeer) -> PeerEntry {
    PeerEntry {
        host: row.host,
        ip: row.ip,
        port: row.port,
        white: row.white,
        blocked: row.blocked,
    }
}

fn peers(public_only: bool) -> Result<Vec<PeerEntry>, P2pFault> {
    listed_peers(public_only)
        .map(|rows| rows.into_iter().map(peer_entry).collect())
        .ok_or(P2pFault::NoLists)
}

fn sizes() -> Result<(u64, u64), P2pFault> {
    clearnet_list_sizes().ok_or(P2pFault::NoLists)
}

fn sessions() -> Result<SessionCounts, P2pFault> {
    session_counts()
        .map(|(outbound, inbound)| SessionCounts { outbound, inbound })
        .ok_or(P2pFault::NoHub)
}
