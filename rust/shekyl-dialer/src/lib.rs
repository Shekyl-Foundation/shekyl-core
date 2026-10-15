// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound dialer (`P2P_3_SLICE_3_DIALER_BRIEF.md`).
//!
//! One owner per connector decides, at each wake, which list to draw from
//! and what the dial is for. This crate is that decision, the state it
//! reads, and the handshake that holds one channel for the span of the
//! dial: the fill rule, the wake spacing, the failed-address memory and
//! the self-connection nonces. The peer lists are `shekyl-peerlist`'s,
//! and [`shekyl_peerlist::Peerlist::apply`] stays the only writer of gray
//! and white. The seam drives the channel once the handshake has adopted it.
//!
//! Placement (Rick, 2026-10-13): a crate of its own over `shekyl-seam` and
//! `shekyl-peerlist`, which do not depend on each other. The C++ reaches
//! it only through `shekyl-ffi`.

#![deny(unsafe_code)]

pub mod attempts;
mod bans;
pub mod candidate;
pub mod fill;
pub mod memory;
pub mod nonce;
pub mod owner;
pub mod pace;
pub mod seeds;
pub mod store;

pub use attempts::Attempts;
pub use bans::HubBans;
pub use candidate::{CandidateFilter, Skip};
pub use fill::{plan, Census, DialAim, DrawList, FillRule, Plan, IN_FLIGHT_BOUND};
pub use memory::FailedAddresses;
pub use nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
pub use owner::{session_of, Dialer, Shared, SnapshotSource};
pub use pace::{next_wake_nanos, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
pub use seeds::{seeds, SeedNetwork};
pub use store::{AddressStore, LoadError, STORE_INTERVAL_NANOS};
