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
//! This crate grows by the brief's steps. What is here: a hint is
//! refused only when it is structurally impossible, and the published
//! state is derived from sessions, the chain, and the fill.

#![deny(unsafe_code)]

mod claim;
mod locator;
mod model;
mod state;
mod tree;

pub use claim::{PayloadRefused, PeerClaim};
pub use model::{ClaimError, Command, Event, Sync};
pub use shekyl_chain_rules::HeaderView;
pub use state::SyncState;
