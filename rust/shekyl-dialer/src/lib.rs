// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound dialer (`P2P_3_SLICE_3_DIALER_BRIEF.md`).
//!
//! One owner per connector decides, at each wake, which list to draw from
//! and what the dial is for. This crate is that decision, the state it
//! reads, and the handshake that holds one channel for the span of the
//! dial: the fill rule, the wake spacing and the retries within a test.
//! The peer lists are `shekyl-peerlist`'s, and
//! [`shekyl_peerlist::Peerlist::apply`] stays the only writer of gray and
//! white. The session layer (`shekyl-p2p-session`) opens the channel,
//! speaks the handshake and drives the session; this crate is its peers
//! owner (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1): it answers the layer's
//! disclosure question, admits the lists peers send, and is told of each
//! session's open and close.
//!
//! Lock order: this crate never calls into the session layer while it
//! holds its own lock. A board read is taken first, and the lists lock is
//! taken after it returns. The ban list's events wait in the dialer's
//! queue, which the ban list fills without the dialer's lock; the dialer
//! drains it under its own. [`Dialer::session_closed`] does not read the
//! board: the layer's close hook reads it first.
//!
//! Placement (Rick, 2026-10-13): a crate of its own over the session layer
//! and `shekyl-peerlist`, which do not depend on each other.

#![deny(unsafe_code)]

pub mod attempts;
pub mod candidate;
pub mod fill;
pub mod judge;
pub mod link_tally;
pub mod owner;
pub mod pace;
mod reach;
pub mod seeds;
pub mod store;

pub use attempts::Attempts;
pub use candidate::{CandidateFilter, Skip};
pub use fill::{plan, Census, DialAim, DrawList, FillRule, Plan};
pub use judge::{closes_the_bracket, judge, Judgement, Observations};
pub use link_tally::{TallySink, TorLinkTally};
pub use owner::{session_of, Applied, Dialer, Launch, NotReady, OwnerRng, Shared};
pub use pace::{attempts_per_test, draw, next_wake_nanos, retry_wait_nanos};
pub use seeds::{seeds, SeedNetwork};
pub use store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};
