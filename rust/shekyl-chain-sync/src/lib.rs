// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's model (CS-2, `P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2).
//!
//! A deterministic state machine. Events come in, commands go out, and
//! nothing here waits, hashes, or reads a store. The caller passes the
//! main chain as a [`HeaderView`] snapshot with each event, and the
//! instant. PoW leaves as a command the executor (CS-3) runs.
//!
//! What is here is the CS-2 model: hints, the header tree, runs and the
//! work test, the long-run slot, bodies along the selected chain, and
//! the entry's outcomes. Proof of work leaves as a command.

#![deny(unsafe_code)]

#[cfg(test)]
mod harness;
#[cfg(test)]
mod proof;
#[cfg(test)]
mod select_tests;

mod branch;
mod claim;
mod locator;
mod model;
mod runs;
mod state;
mod tree;

pub use claim::{PayloadRefused, PeerClaim};
pub use model::{
    BoundArrival, CachePlan, ClaimError, CloseCause, Command, Event, HashClass, Job, ProveItem,
    Proved, Sync, BODY_REQUESTS_IN_FLIGHT, SYNC_RATE_FLOOR,
};
pub use shekyl_chain_rules::HeaderView;
pub use state::SyncState;
