// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block-ingest pipeline — production code, with the DRS-E2 replay
//! driver as its first source (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q1).
//!
//! ```text
//! Source ──► Form (N workers) ──► Sequencer ──► Validate+Connect ──► Sinks
//! ```
//!
//! **Why one pipeline.** The C++ codebase's deepest defect is that its tests
//! admit blocks through a path the network never runs. So the ingest spine
//! is built once: E2 drives it from a corpus and grades the redb digest
//! against LMDB's; E3's cutover swaps the source for p2p and drops the
//! grader. There is no second connect path to fall back to (§1.2).
//!
//! **What this crate owns**, stage by stage:
//!
//! - [`source`] — the [`Source`] trait and its event model
//!   ([`IngestEvent::Extend`] / [`IngestEvent::Rewind`], RD-Q13): a source
//!   yields a **totally ordered event stream**, not a height-ordered block
//!   stream, because a fork is a `Rewind` followed by `Extend`s and a source
//!   that cannot say *rewind* cannot express one.
//! - [`substrate`] — the production [`Substrate`](shekyl_chain_rules::Substrate):
//!   a wall clock and RandomX v2 through `shekyl-pow-randomx`'s
//!   `compute_hash` over a shared two-slot [`CacheStore`](shekyl_pow_randomx::CacheStore)
//!   (RD-Q3; per-worker `compute_hash`, not the bench-only pool, RD-F14).
//! - [`sequencer`] — order restoration after parallel `form`: workers finish
//!   out of order, the [`Sequencer`] releases items in sequence order and
//!   never past a gap.
//!
//! **What it does not own.** No consensus value is computed here (C2-R8
//! Q4): `form` and `validate` are `shekyl-chain-rules`', `connect` is the
//! store's. No fault becomes a verdict: a substrate fault, a store fault, a
//! `Corrupt` each map to a lifecycle in §1.1's supervision table, and the
//! Validate+Connect actor that executes that table lands with its
//! no-restart test (§7 commit 5). This crate at commit 3 is the stage
//! contracts and the two stateless stages; the actor, the corpus and trace
//! readers, and the grader follow on the plan's named commits.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sequencer;
pub mod source;
pub mod substrate;

pub use sequencer::{SequenceError, Sequencer};
pub use source::{CorpusBlock, IngestEvent, Seq, Sequenced, Source};
pub use substrate::{ChainSubstrate, Clock, ClockFault, SubstrateFault, SystemClock};
