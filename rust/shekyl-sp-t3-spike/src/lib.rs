// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **NOTHING IN THIS CRATE IS CANONICAL. IT IS DISPOSABLE DEBT, LABELLED AS DEBT
//! AT BIRTH (rule 15), AND IT MUST BE DELETED OR FULLY REWRITTEN BEFORE TJ-B.**
//!
//! This crate exists to produce **one number**: the empirical distribution of
//! total challenge→response latency for a 3.33 MB shard read over a persona's
//! Tor rendezvous, so that
//! [`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](../../docs/design/ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
//! §8.3's open gate — *is `q ≥ 0.10` forceable inside the challenge deadline?* —
//! stops being an argument and becomes a measurement.
//!
//! # Why the name says `spike`
//!
//! §9.4 records a freeze consequence to accept deliberately: making the test the
//! read path promotes the **response semantics** to consensus-critical, so they
//! freeze at genesis. Anything in this crate that looked canonical would be a
//! candidate for someone later mistaking it for that frozen format. So:
//!
//! - the crate is named `shekyl-sp-t3-spike`, not `shekyl-sp-t3`;
//! - the wire framing is no longer defined here at all. This crate used to
//!   carry its own `x-spike/v0` copy of the serving loop; that copy is
//!   deleted and the framing now comes from `shekyl_p_serve`, whose
//!   `x-provisional/v0` route is disclaimed in exactly the same terms and
//!   gets exactly as many votes in the format round: none;
//! - the request/response shape is a placeholder for *transport
//!   measurement*, and carries no claim about what TJ-B should freeze.
//!
//! One thing the shape inherited rather than chose: since `RF-D4`
//! (2026-08-20) the served body leads with the frame header, so a measured
//! response is the fixture plus a few bytes. It is below the noise floor of
//! a Tor-transit measurement, and it is noted only so a future reader does
//! not treat the difference between `SHARD_BYTES` and the observed length as
//! a discrepancy to chase.
//!
//! # What is disposable and what might survive
//!
//! Disposable: everything in this crate. The fixture plumbing, the harness,
//! the measurement binaries.
//!
//! Candidates to survive into TJ-B, having been *validated here rather than
//! designed here*:
//!
//! - the D1 onion surface, which lives in `shekyl_tor::control::onion` and is
//!   already production-shaped (it is not in this crate);
//! - the **construction** of [`onion_key`]'s derivation — seed-derived,
//!   `p_slot`-bound, nothing at rest — though not its *location*: see the
//!   single-source-of-truth finding in that module's docs;
//! - the inbound hardening shape this crate validated (decoupled accept,
//!   per-step timeouts, pre-allocation request bound) — the transport plan's
//!   §6a requirement list made concrete. It **has** survived: it is
//!   `shekyl_p_serve`, which this crate now consumes rather than
//!   re-implements, so the shape being measured is the shape that ships and
//!   a fix to one is not a fix to one of two.
//!
//! # What this crate deliberately does not do
//!
//! No `ServeCredit` construction, no countersignature, no receipt, no bond
//! binding, no epoch settlement, no consensus surface, no wire format, no FFI.
//! The measurement is of a *transport*, and the charter's non-goals are enforced
//! by this crate's dependency list: it does not depend on `shekyl-wire`,
//! `shekyl-daemon-rpc`, or `shekyl-ffi`, so it cannot reach a consensus surface
//! even by accident.

pub mod fixture;
pub mod harness;
pub mod measure;
pub mod onion_key;
