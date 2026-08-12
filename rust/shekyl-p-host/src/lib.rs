// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona **serving host** — the composition slice of the archival
//! inbound path (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5 item 3).
//!
//! Two halves landed separately and are inert on their own: the loopback
//! serving loop (`shekyl-p-serve`, PR-A) answers shard reads from the store,
//! and the onion supervisor (`shekyl-tor`, PR-B + VG-1…VG-3) publishes a v3 service
//! behind full vanguards. Neither knows about the other, and neither knows
//! what a bonded persona is obligated to serve. This crate is where those
//! three facts meet, and it exists because the ways of getting the meeting
//! wrong are all silent:
//!
//! | Hazard | Closed by |
//! |---|---|
//! | Serve-set drifts from the consensus bond record → own node prunes bonded bytes → slash (§9.6 item 4) | [`ServeSet`] has no constructor from a bare id list |
//! | Serving starts before the pins are applied | [`PersonaServingHost::start`] takes a [`PinnedServeSet`] witness |
//! | Loopback endpoint rebinds under an unchanged onion mapping → published address answers nothing | The host binds once and owns the endpoint for its life |
//! | A serving persona runs on vanguards-lite | `ServingPosture::Serving` carries the onion *and* `Managed` as one value |
//! | Teardown leaves a live descriptor at a closed port | [`PersonaServingHost::shutdown`] stops tor before the listener |
//!
//! Every one of those failures has the same signature: the persona looks
//! healthy, publishes at its advertised address, and learns otherwise from
//! a slash an epoch later. None of them has a runtime symptom worth
//! alarming on, which is why each is answered with a type rather than a
//! check.
//!
//! # Where this runs, and what it holds
//!
//! In-process with the wallet. The store it reads is the wallet's redb
//! `LeafStore` (the daemon's LMDB curve tree is the consensus copy and is
//! not involved), and the tor it publishes through is the wallet's own
//! instance. Nothing in this path crosses the FFI boundary.
//!
//! What the host can hold is deliberately narrow — an expanded
//! `OnionIdentity`, a read-only `ServingReader`, and a list of shard ids.
//! No seed, no bond spend authority, no store write handle. §7.2(iii)'s
//! custody boundary is *which secret crosses into the serving side*, and
//! here it is enforced by the types of the inputs; see
//! [`PersonaServingHost`] for the assumption that framing carries when the
//! serving side is in-process rather than a separate address space.
//!
//! # What is not here
//!
//! The pass-record axis, the response wire format, and the countersignature
//! are all format-round decisions, and the provisional framing this host
//! serves over (`x-provisional/v0`) is **THROWAWAY and gets no vote** in
//! that round. Refreshing the serve-set as holdings change and segments
//! freeze is the wiring slice's job, on the crate that owns the claim-source
//! decode and the curve-tree actor; this crate provides the seam
//! ([`ServeSetPinner`]) it plugs into.

#![forbid(unsafe_code)]

pub mod host;
pub mod serve_set;

pub use host::{HostError, PersonaServing, PersonaServingHost};
pub use serve_set::{PinError, PinnedServeSet, ServeSet, ServeSetPinner};
