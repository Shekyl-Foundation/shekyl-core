// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! The live daemon relay scheduler — RP-3a of `docs/design/DAEMON_RELAY_PRIVACY.md`.
//!
//! # Why this is not part of `shekyl-relay-privacy`
//!
//! That crate's scope boundary is explicit: *"Timing only. Nothing here
//! serializes a message, chooses eligible peers, or touches a socket."* A zone
//! actor does the last two, so folding it in would violate the crate's own
//! charter — and the charter is load-bearing, not tidiness. The primitives stay
//! dependency-light, synchronous, and pure `&mut self` steps precisely because
//! that is what the daemon's `run_epoch` / `run_stems` / `run_fluff` force-step
//! hooks forward into, and therefore what keeps the 33 `levin_notify` cases
//! usable as an oracle across the loop-cut (§18.1). If the actor lived in the
//! timing crate, the timing crate would grow an async surface and the next
//! reader would reasonably make the primitives async "for consistency" —
//! eroding the property that made this round tractable.
//!
//! # The ownership invariant (§18.5)
//!
//! RP-3 reverses a decision `shekyl-relay-privacy`'s `lib.rs` sealed against
//! accidental reopening: the relay loop moves to Rust, so asio keeps sockets
//! and the p2p path while a Rust driver takes relay timing. There **is** a
//! second reactor. It is a handoff rather than a race only because **every
//! piece of relay state has exactly one owner**, and that inventory is an
//! invariant this crate maintains rather than a check it passed once:
//!
//! - Zone state — peer fluff queues, the stem map, the epoch role — is owned
//!   **here**, mutated only through `&mut Zone`. C++ connection events do not
//!   mutate it; they are delivered as calls on the owning task.
//! - `connection_count` was the one genuine straddle in the inherited code
//!   (*"only update in strand, can be read at any time"*). It stays derived
//!   here and is published by the boundary as a single-writer atomic.
//! - The stem-slot snapshot flows **outward** (Rust → C++) as a push. C++ never
//!   pulls it: with the zone strand gone, a caller-initiated read would race
//!   this crate's mutations, which is exactly the hazard the seal named.
//!
//! Any new shared state is a new inventory line that must resolve to
//! single-owner-or-atomic before it lands.
//!
//! # Sync core, driven from outside
//!
//! [`Zone`] is a plain `&mut self` state machine that returns deadlines —
//! deliberately the same shape as [`shekyl_relay_privacy::schedule`]. Nothing
//! here spawns, sleeps, or awaits. The production driver arms a timer against
//! the returned deadline; a test drives the same steps directly, which is how
//! the force-step hooks stay honest and how this crate's own tests avoid
//! wall-clock dependence.

pub mod zone;

pub use zone::{PeerFluff, Zone};
