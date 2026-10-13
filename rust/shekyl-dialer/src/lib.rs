// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound dialer (`P2P_3_SLICE_3_DIALER_BRIEF.md`).
//!
//! One owner per connector decides, at each wake, which list to draw from
//! and what the dial is for. This crate is that decision and the state it
//! reads: the fill rule, the wake spacing, the failed-address memory and
//! the self-connection nonces. It holds no socket. The peer lists are
//! `shekyl-peerlist`'s, and [`shekyl_peerlist::Peerlist::apply`] stays the
//! only writer of gray and white.
//!
//! Placement (Rick, 2026-10-13): a crate of its own over `shekyl-seam` and
//! `shekyl-peerlist`, which do not depend on each other. The C++ reaches
//! it only through `shekyl-ffi`.

#![deny(unsafe_code)]

pub mod attempts;
pub mod candidate;
pub mod fill;
pub mod memory;
pub mod nonce;
pub mod pace;

pub use attempts::Attempts;
pub use candidate::{CandidateFilter, Skip};
pub use fill::{plan, Census, DialAim, DrawList, FillRule, Plan, IN_FLIGHT_BOUND};
pub use memory::FailedAddresses;
pub use nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
pub use pace::{next_wake_nanos, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
