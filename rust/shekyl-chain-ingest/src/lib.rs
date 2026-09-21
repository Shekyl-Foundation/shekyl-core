// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's block-ingest pipeline — the spine every block enters
//! Shekyl's chain store through, built once as production code
//! (`docs/design/DRS_E2_REPLAY_DRIVER.md` §0–§1, ruled 2026-09-19).
//!
//! ```text
//! Source ──► Form (N workers) ──► Sequencer ──► Validate+Connect ──► Sinks
//! (corpus │  (stateless; real     (restore the  (one actor; owns    (digest/grader,
//!  now,   │   RandomX per worker)  source order; the ChainStore;     checkpoints,
//!  p2p at │                        Rewind is a   one write closure   metrics)
//!  E3)    │                        barrier)      per handler)
//! ```
//!
//! DRS-E2's replay driver is this pipeline with a corpus [`Source`] and a
//! grader sink; E3's cutover swaps the source for the p2p feed and drops the
//! grader. There is no second connect path — a harness that admitted blocks
//! through code production never runs is the C++ defect (`core_tests` /
//! `chaingen`) this crate exists not to reproduce.
//!
//! # What lives here
//!
//! - [`source`] — the [`Source`] trait and its event model: an **ordered
//!   event stream**, not a height-ordered block stream. A reorg is a
//!   [`IngestEvent::Rewind`] followed by [`IngestEvent::Extend`]s; a source
//!   that cannot say *rewind* cannot express a fork (RD-Q13).
//! - [`corpus`] — the replay driver's first source: a chain's blocks with
//!   full bodies as one Rust-minted, versioned artifact whose writer
//!   **verifies** completeness against each header (RD-F15) and whose
//!   reader re-verifies on every record. Network-shaped only; the trace is
//!   a different artifact with a different door (RD-Q2).
//! - [`substrate`] — the production [`Substrate`](shekyl_chain_rules::Substrate):
//!   RandomX verification through `shekyl-pow-randomx`'s cache path and the
//!   system clock. The only hasher any Shekyl validator runs (§1.3).
//!
//! The stages themselves (form workers, sequencer, the validate+connect
//! actor, sinks) land with the commits that give each its first test
//! (§7); this crate does not carry a stage before its behaviour is pinned.
//!
//! # What this crate never does
//!
//! Compute a consensus value — every fact it hands `connect` that the
//! validator does not yet derive is **borrowed** from a trace and marked so
//! (C2-R8 Q4; RD-Q2's typed doors). Map a fault onto a verdict — the
//! conversion ban's discipline applies here by intent even though the gate's
//! clause 2 is scoped to the store crate. Consult the mining JIT — replay
//! validates with the hasher production validates with, or it tests a
//! different daemon.

#![deny(unsafe_code)]

#[cfg(test)]
mod artifact_tests;
pub mod connector;
pub mod corpus;
pub mod fetch;
pub mod grader;
pub mod metrics;
pub mod pipeline;
#[cfg(test)]
mod pipeline_tests;
pub mod schedule;
pub mod seed;
pub mod sequencer;
pub mod source;
pub mod stage;
pub mod substrate;
#[cfg(test)]
pub(crate) mod test_support;
pub mod trace;

pub use connector::{Applied, Apply, Connector, ConnectorArgs, Digest, Rewind, Rewound, RunFault};
pub use corpus::{CorpusFault, CorpusNet, CorpusReader, CorpusWriter, CORPUS_FORMAT_VERSION};
pub use fetch::{fetch_corpus, FetchFault};
pub use grader::{grade_run, GradedRun, Observations, Register};
pub use metrics::{Metrics, MetricsArtifact};
pub use pipeline::{run, PipelineConfig, PipelineFault, RunReport, Switch};
pub use schedule::{Chain, ChainRules, FixedDifficultyRefused};
pub use seed::{SeedLedger, SeedSchedule};
pub use sequencer::{SequenceError, Sequencer};
pub use source::{IngestEvent, SequenceNo, Sequenced, Source};
pub use stage::{form_extend, Staged};
pub use substrate::{EpochPin, ProductionSubstrate, SubstrateFault};
pub use trace::{Facts, Trace, TraceFault, TraceWriter};
