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
//! | Serve-set drifts from the consensus bond record → own node prunes bonded bytes → slash (§9.6 item 4) | [`ServeSet`] has no public constructor; the pinner reports it |
//! | Serving starts before the pins are applied | [`PersonaServingHost::start`] takes a pinner and acquires the witness itself |
//! | Pins land on one store while another is served | The witness carries its own reader; `start` takes no store argument |
//! | Loopback endpoint rebinds under an unchanged onion mapping → published address answers nothing | The host binds once and owns the endpoint for its life |
//! | A serving persona runs on vanguards-lite | `ServingPosture::Serving` carries the onion *and* `Managed` as one value |
//! | Teardown leaves a live descriptor at a closed port | [`PersonaServingHost::shutdown`] stops tor before the listener |
//! | Holdings move on-chain and the pins do not follow | [`PersonaServingHost::refresh`] re-pins the whole set, unconditionally |
//! | The refresh itself stops firing | [`PersonaServingHost::staleness`] reads two clocks with independent drivers |
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
//! `OnionIdentity`, a read-only `ServingReader` (via the live pin
//! witness), and the one [`ServeSetPinner`] taken at start. No seed, no
//! bond spend authority, no store write handle of its own: pinning writes
//! go through the pinner to the curve-tree actor. §7.2(iii)'s custody
//! boundary is *which secret crosses into the serving side*, and here it
//! is enforced by the types of the inputs; see [`PersonaServingHost`] for
//! the assumption that framing carries when the serving side is
//! in-process rather than a separate address space.
//!
//! # What is not here
//!
//! The pass-record axis and the countersignature are format-round decisions,
//! and the provisional **transport** framing this host serves over
//! (`x-provisional/v0` — status line, header set, route) is **THROWAWAY and
//! gets no vote** in that round. The response *payload* is no longer open:
//! `RF-D4` ruled it on 2026-08-20 and `shekyl-p-serve` emits the frame
//! (`shekyl_curve_tree::served_frame`). Nothing in this crate reads or
//! writes it — the host wires lifecycle, not bytes — but "the response wire
//! format is undecided" has stopped being true and should not be repeated
//! from here. Calling [`PersonaServingHost::refresh`] from the P-scan
//! sweep is the wiring slice's job (SH-2b), on the crate that owns the
//! claim-source decode and the curve-tree actor; this crate owns the
//! refresh *behaviour* and the seam ([`ServeSetPinner`]) the sweep plugs
//! into.
//!
//! # One rule the seam keeps applying
//!
//! [`ServeSetPinner`] reports three things and takes none: **the
//! obligation** (a shard list or a CompleteTree prefix), **the evidence
//! that retains it** (per-member pins, or the prune-disabled posture), and
//! **which store** that evidence landed in. **The host does not choose
//! anything about its own duty** — each of those was once a parameter, and
//! each removal closed a real call-site defect of the same shape. What a
//! caller cannot supply, a caller cannot get wrong; what is left is one
//! engine-side implementor, reviewable by reading it.

#![forbid(unsafe_code)]

pub mod host;
pub mod serve_set;

pub use host::{HostError, PersonaServing, PersonaServingHost};
pub use serve_set::{
    PinError, PinReport, PinnedServeSet, ReportedSet, ServeObligation, ServeSet, ServeSetPinner,
    Staleness, StalenessBound,
};
