// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain-sync loopback harness (CS-Q11, `P2P_3_CHAIN_SYNC_BRIEF.md`).
//!
//! Scripted sync peers over real Levin framing, on loopback connectors
//! whose channels end in those peers, against a real `ChainStore`, the
//! real ingest service, the daemon's hasher budget and RandomX. The node
//! runs the session layer (`shekyl-p2p-session`) with the sync owner on
//! its dispatch table through the owner's port; the peers and relay
//! owners are a recorder.

mod chain;
mod dial;
mod node;
mod peer;

pub use chain::{fork_headers, open_store, own_hasher, Chain, Corpus, OwnHasher, Step};
pub use dial::{empty_claim, PeerDial, Silent, SyncPeer};
pub use node::{MinerSeat, Node, Record, NETWORK_ID};
pub use peer::{
    announcement, frame, request_headers, Bodies, HeaderChainPeer, MutePeer, Seen, ServingPeer,
};
