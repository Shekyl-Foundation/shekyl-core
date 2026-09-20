// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The run record, and the two ruled budgets applied to it.
//!
//! The schema is versioned because the `FOLLOWUPS` discharge will cite runs by
//! it: a record whose shape moves silently cannot be compared across the
//! prover-pin re-grades §6.3.4 requires.
//!
//! **The harness never declares `WSS-Q1`(b) discharged.** It emits
//! measurements and, on the pinned rig, applies the ruled arithmetic. The
//! verdict is the maintainer's.

use serde::Serialize;

use crate::corpus::LeafRate;
use crate::rig::{Environment, RigVerdict};
use crate::timing::Series;

/// Record schema version. Bump on any field removal or meaning change.
pub const SCHEMA_VERSION: u32 = 1;

/// The spend-edge budget's absolute floor, in seconds (§6.3.4 row 2).
pub const SPEND_DELTA_FLOOR_S: f64 = 2.0;
/// The spend-edge budget's relative arm, as a fraction of proving time.
pub const SPEND_DELTA_RELATIVE: f64 = 0.15;
/// The open-edge budget, in seconds, local-daemon posture (§6.3.4 row 3).
pub const OPEN_EDGE_BUDGET_S: f64 = 5.0;

/// Whether a measurement met its budget — or was not graded at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Measured on the pinned rig, within budget.
    Pass,
    /// Measured on the pinned rig, over budget.
    Miss,
    /// Measured somewhere else. The numbers are real; the grading is not.
    Ungraded,
}

/// The spend-edge budget, with both arms shown.
///
/// §6.3.4 requires the absolute delta beside the ratio, *"because 15 % of an
/// unknown denominator is an unknown number of seconds"*. Both arms are
/// therefore always serialized, and the binding one is named — at shallow
/// depths the 2 s floor binds and the ratio is slack, which is the case a
/// ratio-only record would misreport.
#[derive(Clone, Debug, Serialize)]
pub struct SpendBudget {
    /// The measured delta: spend-intent through constructed `Path`.
    pub delta_s: f64,
    /// The denominator: the prover invocation alone.
    pub proving_s: f64,
    /// `delta_s / proving_s`.
    pub ratio: f64,
    /// `max(2, 0.15 * proving_s)`.
    pub threshold_s: f64,
    /// Which arm produced [`SpendBudget::threshold_s`].
    pub binding_arm: &'static str,
    /// The verdict.
    pub verdict: Verdict,
}

impl SpendBudget {
    /// Apply §6.3.4 row 2's ruled arithmetic.
    #[must_use]
    pub fn grade(delta_s: f64, proving_s: f64, grading: bool) -> Self {
        let relative = SPEND_DELTA_RELATIVE * proving_s;
        let (threshold_s, binding_arm) = if relative > SPEND_DELTA_FLOOR_S {
            (relative, "relative (15% of proving)")
        } else {
            (SPEND_DELTA_FLOOR_S, "absolute floor (2 s)")
        };
        let verdict = if !grading {
            Verdict::Ungraded
        } else if delta_s <= threshold_s {
            Verdict::Pass
        } else {
            Verdict::Miss
        };
        Self {
            delta_s,
            proving_s,
            ratio: if proving_s > 0.0 {
                delta_s / proving_s
            } else {
                f64::INFINITY
            },
            threshold_s,
            binding_arm,
            verdict,
        }
    }
}

/// The open-edge budget.
#[derive(Clone, Debug, Serialize)]
pub struct OpenBudget {
    /// Wall time to refetch the held buffer.
    pub refetch_s: f64,
    /// [`OPEN_EDGE_BUDGET_S`].
    pub threshold_s: f64,
    /// The verdict.
    pub verdict: Verdict,
    /// Which term the cost sits in — see [`crate::openedge::Attribution`].
    pub attribution: crate::openedge::Attribution,
}

/// A complete spend-edge run.
#[derive(Clone, Debug, Serialize)]
pub struct SpendEdgeRecord {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The measurement this record is of.
    pub measurement: &'static str,
    /// The machine.
    pub environment: Environment,
    /// What was enforced and what was attested.
    pub rig: RigVerdict,
    /// The prover the denominator was taken against.
    pub prover_pin: ProverPin,
    /// The corpus the delta scales by.
    pub corpus: SpendCorpus,
    /// Per-iteration replay series.
    pub replay: Series,
    /// Per-iteration path-construction series.
    pub path_construction: Series,
    /// Per-iteration prover series.
    pub proving: Series,
    /// The graded budget.
    pub budget: SpendBudget,
    /// **The amortized form's refresh-side cost**: worst-case replay seconds
    /// divided by the blocks replayed.
    ///
    /// Derived rather than left to a reader with a calculator, because it is
    /// the number that decides what a miss on the spend edge *means*. A delta
    /// that misses by 48× as a spend-time copy-and-replay is not the same
    /// finding as one whose amortized form costs a fraction of a block
    /// interval — the first kills the design, the second moves the work.
    /// Compare it against the block cadence: at 120 s, this figure over 1.2 s
    /// is a 1 % duty cycle.
    pub per_block_advance_worst_case_s: f64,
    /// The sparse-versus-dense control, one arm per depth. The record carries
    /// these because the denominator's path provenance depends on them: a
    /// reader who does not see the control cannot tell whether the sparse path
    /// was licensed or merely assumed.
    pub controls: Vec<crate::fixture::ControlExperiment>,
    /// Whether every measured `Path` round-tripped through `verify`.
    pub paths_verified: bool,
    /// The proxy's stated direction of error.
    pub proxy_note: &'static str,
}

/// The corpus terms a spend-edge record scales by.
#[derive(Clone, Debug, Serialize)]
pub struct SpendCorpus {
    /// [`crate::corpus::REPLAY_WINDOW_BLOCKS`].
    pub replay_window_blocks: u64,
    /// [`crate::corpus::HELD_BUFFER_BLOCKS`].
    pub held_buffer_blocks: u64,
    /// The worst-case rate and every term behind it.
    pub leaf_rate: LeafRate,
    /// Leaves actually replayed.
    pub window_leaves: u64,
    /// The tree depth the denominator was proved at.
    pub tree_depth: u8,
    /// Canonical shape, by citation to `FCMP_PLUS_PLUS.md` §13.
    pub canonical_shape: &'static str,
    /// Whether the graded path was a real dense path or a synthesized sparse
    /// one — and, for a sparse run, whether the control experiment justified it.
    pub path_provenance: &'static str,
}

/// The prover the denominator was measured against.
///
/// §6.3.4: *"Re-graded on a material prover-pin change."* A record that does
/// not name its prover cannot tell a later reader whether it still applies.
#[derive(Clone, Debug, Serialize)]
pub struct ProverPin {
    /// The crate whose `prove` was called.
    pub crate_name: &'static str,
    /// Its version.
    pub crate_version: &'static str,
    /// The repository revision, where the build recorded one.
    pub revision: Option<String>,
}

impl ProverPin {
    /// The pin for this build.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            crate_name: "shekyl-fcmp",
            crate_version: env!("CARGO_PKG_VERSION"),
            revision: option_env!("SHEKYL_GIT_REVISION").map(str::to_owned),
        }
    }
}
