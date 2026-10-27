// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain-sync loopback harness (CS-Q11, `P2P_3_CHAIN_SYNC_BRIEF.md`).
//!
//! Scripted sync peers over real Levin framing, on a seam dialer whose
//! channels end in those peers, against a real `ChainStore`, the real
//! ingest service, the daemon's hasher budget and RandomX. The node runs
//! the Rust router as the hub's post sink and the sync owner on its own
//! row; the C++ Levin handler is a stub that records what the router
//! forwards.

mod chain;
mod dial;
mod node;
mod peer;

pub use chain::{fork_headers, open_store, store_path, Chain, Corpus, Step};
pub use dial::{Buckets, PeerDial, Silent, SyncPeer};
pub use node::{caches, substrate, Node, StubLog};
pub use peer::{announcement, frame, request_headers, Bodies, HeaderChainPeer, Seen, ServingPeer};
