// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peer-list protocol constants two layers read.
//!
//! `shekyl-peerlist` sends [`DISCLOSE_COUNT`] entries in a disclosure
//! sample and refuses a received list above it; `shekyl-levin` bounds a
//! handshake or timed-sync frame by it. Neither crate may depend on the
//! other (the frame layer knows no list), so the number lives here, with
//! nothing else: one constant, read by both, so the frame bound and the
//! list's limit cannot drift apart.

#![no_std]

/// How many addresses a disclosure sample carries, and the most a
/// received message may carry (D3, Rick, 2026-10-09;
/// `P2P_3_SLICE_1_PEERLIST_BRIEF.md` §5a). A protocol constant: the same
/// on every node and every connector, not tied to the outbound target.
/// Replaces the C++ `P2P_DEFAULT_PEERS_IN_HANDSHAKE` and
/// `P2P_MAX_PEERS_IN_HANDSHAKE` (both 250), deleted with the C++ peerlist.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97): the interim outbound
/// target carried over, derived on the Rust path after PR-3 from intake
/// diversity, honest fill and per-reply exposure.
pub const DISCLOSE_COUNT: usize = 12;
