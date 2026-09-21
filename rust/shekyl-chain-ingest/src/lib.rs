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
//!  now,   │   RandomX per worker)  source order; the ChainStore;     checkpoint,
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
//! - [`trace`] — the LMDB-only facts and one digest checkpoint at the
//!   covered tip (RD-F18), with typed [`trace::Borrowed`] / [`trace::Expected`]
//!   doors. This is the harvest artifact `shekyl-ffi` compiles; the pipeline
//!   stages sit behind the `pipeline` feature so the daemon image does not
//!   pull the replay driver to write a trace.
//! - [`substrate`] — the production [`Substrate`](shekyl_chain_rules::Substrate):
//!   RandomX verification through `shekyl-pow-randomx`'s cache path and the
//!   system clock. The only hasher any Shekyl validator runs (§1.3).
//! - [`metrics`] — the RandomX measurement sink (RD-F11), shared by the
//!   substrate and the pipeline.
//!
//! Form is `shekyl_chain_rules::form`. The sequencer, the validate+connect
//! actor, the grader and the driver live behind `feature = "pipeline"`.
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
#[cfg(feature = "pipeline")]
pub mod connector;
pub mod corpus;
#[cfg(feature = "fetch")]
pub mod fetch;
#[cfg(feature = "pipeline")]
pub mod grader;
pub mod metrics;
#[cfg(feature = "pipeline")]
pub mod pipeline;
#[cfg(all(test, feature = "pipeline"))]
mod pipeline_tests;
#[cfg(feature = "pipeline")]
pub mod schedule;
#[cfg(feature = "pipeline")]
pub mod seed;
#[cfg(feature = "pipeline")]
pub mod sequencer;
pub mod source;
pub mod substrate;
#[cfg(test)]
pub(crate) mod test_support;
pub mod trace;

#[cfg(feature = "pipeline")]
pub use connector::{
    Applied, Apply, Connector, ConnectorArgs, Digest, HashAt, Rewind, Rewound, RunEnd, RunFault,
};
pub use corpus::{CorpusFault, CorpusNet, CorpusReader, CorpusWriter, CORPUS_FORMAT_VERSION};
#[cfg(feature = "fetch")]
pub use fetch::{fetch_corpus, FetchFault};
#[cfg(feature = "pipeline")]
pub use grader::{grade_run, GradedRefusal, GradedRun, Observations, Register};
pub use metrics::{Concurrency, Metrics, MetricsArtifact};
#[cfg(feature = "pipeline")]
pub use pipeline::{
    run, Checkpoint, Disagreement, PipelineConfig, PipelineFault, RunReport, Switch,
};
#[cfg(feature = "pipeline")]
pub use schedule::{Chain, ChainRules, FixedDifficultyRefused};
#[cfg(feature = "pipeline")]
pub use seed::{SeedClaim, SeedLedger};
#[cfg(feature = "pipeline")]
pub use sequencer::{SequenceError, Sequencer};
pub use source::{IngestEvent, SequenceNo, Sequenced, Source};
pub use substrate::{ProductionSubstrate, SubstrateFault};
pub use trace::{Facts, Trace, TraceFault, TraceWriter};
