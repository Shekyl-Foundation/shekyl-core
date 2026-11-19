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
//! that is what the daemon's `run_epoch` / `run_next_wake` / `run_fluff`
//! force-step hooks forward into, and therefore what keeps the `levin_notify`
//! cases usable as an oracle across the loop-cut (§18.1). If the actor lived in the
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
//! - Relay state — peer fluff queues, the stem map, the epoch role, and
//!   whether the zone carries — is owned by the relay owner, mutated only
//!   through `&mut Relay`. Connection events do not mutate it; they arrive
//!   as calls into the owner. The inherited covert branch in `send_txs` is
//!   already deleted (§2.9 step 4).
//! - **The carrier is the second owner, and on purpose** (`CVR-R6`; Rick,
//!   2026-11-18). Its schedule ([`Carrier`]), each channel's binding and
//!   tail, its buffers ([`NoiseQueues`]) and the session writers it sends
//!   on live in their own task (`owner::carrier`), so a busy relay owner
//!   delays what it hands the carrier and never a window: on 2026-11-05 an
//!   owner blocked behind the pool's commit stopped the cover on both
//!   channels for 28 s and 32 s. Nothing is shared: the owner sends the
//!   carrier copies (the slots and the covered sessions, each message to
//!   carry, the session handles), and the carrier sends back what became of
//!   each message. This narrows the single-owner invariant above to the
//!   relay state; the carrier's state is single-owner in its own task.
//! - `connection_count` was the one genuine straddle in the inherited code
//!   (*"only update in strand, can be read at any time"*). It stays derived
//!   here and is published by the boundary as a single-writer atomic.
//! - The stem map is never read across tasks. The carrier is handed a copy
//!   of its slots when they change ([`Relay::carrier_view`]); a
//!   caller-initiated read would race this crate's mutations (§18.5
//!   finding 3).
//!
//! Any new shared state is a new inventory line that must resolve to
//! single-owner-or-atomic before it lands.
//!
//! The boundary named above is [`owner`], one task in this crate on the
//! session layer's dispatch table (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1):
//! the callbacks are direct calls, the published atomics a
//! [`owner::RelaySnapshot`], and the registry the owner's own map of
//! `Established` handles.
//!
//! # Sync core, driven from outside
//!
//! [`Relay`] is a plain `&mut self` state machine that returns deadlines —
//! deliberately the same shape as [`shekyl_relay_privacy::schedule`]. Nothing
//! here spawns, sleeps, or awaits. The production driver arms a timer against
//! the returned deadline; a test drives the same steps directly, which is how
//! the force-step hooks stay honest and how this crate's own tests avoid
//! wall-clock dependence.

pub mod carrier;
pub mod driver;
pub mod floor_diag;
pub mod graph;
mod noise_queue;
pub mod owner;
pub mod stem_watch;

pub use carrier::{Carrier, CarrierView, NoiseDue};
pub use driver::{Driver, Effect};
pub use floor_diag::{AchievedOutConnections, FloorSnapshot, FloorTransition, FloorWatch};
pub use graph::{
    address_hidden_from_peer, any_hides_address_from_peer, link_encrypted, longest_transit,
    origin_publication_budget_ms, origin_retry_ms, origin_retry_secs, timing_visible, transit_ms,
    ConnectorId, EmbargoWork, NodeSync, OriginPublication, OriginVerdict, PeerFluff, Relay,
    RelayCarrier, RelayDispatch, RelayNewError, RelayPlan, StemWork, TxBlob, NEVER_SENT_RETRY_MS,
};
pub use noise_queue::{CarrierOutcome, CarrierToken, NoiseQueues, NoiseSend, Starts};
pub use shekyl_relay_privacy::{ConnectionId, SlotIndex};
pub use stem_watch::{StemOutcome, StemTally, StemTallySnapshot, StemWatch, TxId};
