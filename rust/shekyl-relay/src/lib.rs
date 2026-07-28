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
//! RP-3a adds **no reactor**. This crate owns the zone state and every timing
//! *decision*; the existing `boost::asio` timer is armed from the deadline
//! returned here and owns the *sleep*. That is what
//! `shekyl-relay-privacy`'s `lib.rs` reason 2 prescribes — pure state machines
//! returning deadlines *"precisely so the existing timer stays in charge"* — so
//! this crate is seal-consistent, not seal-breaking. (An earlier RP-3 note
//! recorded that seal as reversed; it is withdrawn there, with the reasoning.)
//!
//! Single ownership still matters, for two reasons that outlive the reactor
//! question: `get_status()` is callable from any thread, so *something* crosses
//! threads and must be published rather than shared; and when the reactor does
//! eventually move at C++ removal, an inventory already at single-owner is what
//! makes that move a non-event. So the inventory is an invariant this crate
//! maintains rather than a check it passed once:
//!
//! - Zone state — peer fluff queues, the stem map, the epoch role — is owned
//!   **here**, mutated only through `&mut Zone`. C++ connection events do not
//!   mutate it; they arrive as calls into the owner.
//! - `connection_count` was the one genuine straddle in the inherited code
//!   (*"only update in strand, can be read at any time"*). It stays derived
//!   here and is published by the boundary as a single-writer atomic.
//! - The stem-slot snapshot flows **outward** (Rust → C++) as a push. C++ never
//!   pulls it: once the map is owned here, a caller-initiated read would race
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

pub mod driver;
pub mod zone;

pub use driver::{Driver, Effect};
pub use zone::{PeerFluff, RelayPlan, Zone};
