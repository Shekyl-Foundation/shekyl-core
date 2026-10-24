// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's model (CS-2, `P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2).
//!
//! Two machines. A peer machine (`peer`) owns one session's conversation: its run
//! mode, its follow-up, its body span, and any announce proving beside
//! the run. [`Sync`] is the coordinator: which peer to ask, how much to
//! ask for, when the node is synced, and how a heavier fork is selected.
//! Events come in, commands go out, and nothing here waits, hashes, or
//! reads a store. The caller passes the main chain as a [`HeaderView`]
//! snapshot with each event, and the instant. PoW leaves as a command
//! the executor runs. The executor, the owner, the router and serving are
//! `shekyl-chain-sync-runtime`'s (CS-3).

#![deny(unsafe_code)]

#[cfg(test)]
mod announce_tests;
#[cfg(test)]
mod continuation_tests;
#[cfg(test)]
mod harness;
#[cfg(all(test, feature = "cs2-long-run"))]
mod long_run;
#[cfg(test)]
mod proof;
#[cfg(test)]
mod scaling_tests;
#[cfg(test)]
mod scenarios;
#[cfg(test)]
mod select_tests;

mod arrivals;
mod branch;
mod claim;
mod locator;
mod model;
mod peer;
mod runs;
mod state;
mod tree;

pub use claim::{PayloadRefused, PeerClaim};
pub use model::{
    BoundArrival, CachePlan, ClaimError, CloseCause, Command, Event, HashClass, Job, Outcome,
    ProveItem, Proved, Sync, BODY_REQUESTS_IN_FLIGHT, SYNC_RATE_FLOOR,
};
pub use shekyl_chain_rules::HeaderView;
pub use state::SyncState;
