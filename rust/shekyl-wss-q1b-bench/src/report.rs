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

/// Write a run record to `path`, or to stdout when no path is given.
///
/// **One home, because there were three.** `spend_edge` carried an `emit`,
/// `open_edge` inlined the same match, and `verify_edge` arrived with a third
/// copy that spelled its flag `--json` as a *bool* rather than a path — a
/// divergence that cost a run on the first A72 session (§7.2). Three copies of
/// one behaviour is how the spellings drift apart in the first place, so the
/// behaviour lives here and the binaries share it.
///
/// An explicitly requested artifact that silently fails to appear leaves a
/// measurement with no evidence behind it, which is worse than no run — so a
/// write failure is an error, never a warning.
///
/// # Errors
///
/// Serialization failure, or a write that does not land.
pub fn emit<T: Serialize>(record: &T, path: Option<&str>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(record).map_err(|e| format!("serialize: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("could not write {p}: {e}")),
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

use crate::corpus::LeafRate;
use crate::rig::{Environment, RigVerdict};
use crate::timing::Series;

/// Record schema version. Bump on any field removal or meaning change.
///
/// - **`1`** — the schema the first graded runs emitted.
/// - **`2`** (2026-09-21) — [`Series::stopped_because`]'s value domain
///   changed: `"iteration cap"` is gone and `"limits met, unconverged"`
///   names the exit it was silently standing in for. No field is added or
///   removed, which is why this needs saying out loud: it is a **meaning**
///   change, and the sharper kind. A `v1` record reading `"iteration cap"`
///   does **not** mean a cap truncated the run — that exit was unreachable
///   — it means the run met both limits and never settled. **So `v1`'s
///   value is not merely worded differently, it is wrong**, and a reader who
///   has learned the `v2` semantics would draw the opposite remedy from it
///   (raise the cap, rather than: the machine has no steady state). The bump
///   is what stops a corrected reader from misreading an uncorrected record.
///
/// **No CI arm enforces this constant** — the `schema-snapshot` workflow's
/// version-bump job covers `shekyl-chain-store`'s persisted schema, not this
/// record. Bumping it is a reviewer obligation, which is why the history
/// above is kept here rather than only in the changelog.
pub const SCHEMA_VERSION: u32 = 2;

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
    /// The repository revision the record describes.
    pub revision: Option<String>,
    /// Where [`ProverPin::revision`] came from, because the two sources carry
    /// different guarantees.
    pub revision_source: &'static str,
}

impl ProverPin {
    /// The pin for this run.
    ///
    /// **Captured at run time, not only at build time.** A build script cannot
    /// close the staleness window: its rerun triggers watch git metadata, so
    /// editing `shekyl-fcmp` after a clean build changes none of them, and
    /// Cargo may relink a *dirty* prover behind a stamp that still says clean.
    /// Cargo exposes no trigger for "a dependency's sources changed", so the
    /// window cannot be closed from inside the build.
    ///
    /// Asking git **when the measurement runs** removes the window entirely
    /// for the ordinary case — the harness is a dev and rig tool, run from a
    /// checkout. The build-time stamp is kept as the fallback for the case
    /// runtime capture cannot serve: a binary cross-built and copied to the
    /// rig without the repo. The record says which was used, so a reader never
    /// has to guess which guarantee they hold.
    #[must_use]
    pub fn capture() -> Self {
        let (revision, revision_source) = match runtime_revision() {
            Some(rev) => (Some(rev), "runtime (git, at measurement time)"),
            None => match option_env!("SHEKYL_GIT_REVISION") {
                Some(rev) => (
                    Some(rev.to_owned()),
                    "build-time stamp (no git at run time; may predate a dependency edit)",
                ),
                None => (None, "unavailable"),
            },
        };
        Self {
            crate_name: "shekyl-fcmp",
            crate_version: env!("CARGO_PKG_VERSION"),
            revision,
            revision_source,
        }
    }
}

/// `<short sha>` or `<short sha>-dirty`, asked of git **in this crate's own
/// source directory**.
///
/// Not the caller's working directory: run from another checkout, that would
/// record an unrelated repository's SHA as the `shekyl-core` revision and
/// defeat the pin silently — worse than the build-time staleness it replaced,
/// because a wrong revision reads exactly like a right one. `CARGO_MANIFEST_DIR`
/// is baked in at compile time, so a binary copied away from the tree finds no
/// such directory, git fails, and the build-time stamp takes over — which is
/// precisely the case that fallback exists for.
///
/// A dirty tree is marked because a record produced from uncommitted changes
/// names a revision that does not describe what ran.
fn runtime_revision() -> Option<String> {
    let rev = git(&["rev-parse", "--short=9", "HEAD"])?;
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    Some(if dirty { format!("{rev}-dirty") } else { rev })
}

fn git(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        // `-C` before the subcommand: git changes to this directory first, so
        // the answer describes this crate's repository whatever the caller's
        // cwd. A path that no longer exists makes git exit non-zero, which the
        // success check below turns into the build-time fallback.
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// The block target the cadence ratio is reported against, in seconds.
///
/// Informational only — see [`VerifyEdgeRecord::grading`]. Named here rather
/// than inlined at the format site so a reader can see what the duty cycle is
/// a fraction *of*.
pub const BLOCK_TARGET_S: f64 = 120.0;

/// A complete verify-edge run — the per-block `root_at_count` cost.
///
/// **Carries no [`Verdict`].** `CT-6 Q4` is pending as a derivation and grades
/// the *amortized* advance in any case; this is the naive cost that form would
/// replace. Reusing [`Verdict::Ungraded`], whose meaning is *"measured off the
/// pinned rig"*, for *"no ruled threshold exists"* would put one value in front
/// of two meanings — the defect [`SCHEMA_VERSION`] 2 exists to correct. The
/// status is prose in [`VerifyEdgeRecord::grading`] instead, where it cannot be
/// mistaken for a grade.
#[derive(Clone, Debug, Serialize)]
pub struct VerifyEdgeRecord {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The measurement this record is of.
    pub measurement: &'static str,
    /// Why no verdict appears, in words a later reader can act on.
    pub grading: &'static str,
    /// The machine.
    pub environment: Environment,
    /// What was enforced and what was attested.
    pub rig: RigVerdict,
    /// The population the call read.
    pub population: crate::verifyedge::Population,
    /// Which density this run used, and why that one.
    pub density: &'static str,
    /// The leaf count `root_at_count` was asked for.
    pub leaf_count: u64,
    /// Per-call series with the population **unfrozen** — the production state
    /// inside the burial window, and the quantity this measurement is of.
    pub unfrozen: Series,
    /// Per-call series after `maybe_freeze_segments` — the control.
    pub frozen: Series,
    /// `unfrozen.median_s / frozen.median_s`.
    ///
    /// The red-bite reads off this: removing the recompute must collapse the
    /// cost. A ratio near 1 means the measurement never contained what it
    /// claims to measure.
    pub recompute_ratio: f64,
    /// Whether the mixed-composition path ran, rather than the `full_build_root`
    /// fallback.
    ///
    /// Determined **behaviourally**, not by restating the store's internal
    /// decomposition: the fallback ignores frozen sub-roots, so a population
    /// whose time collapses when frozen was on the mixed path.
    pub mixed_path_confirmed: bool,
    /// Whether both phases produced the same root. A control that changed the
    /// answer would not be a control.
    pub root_stable_across_freeze: bool,
    /// Per-call seconds as a fraction of [`BLOCK_TARGET_S`] — the duty cycle
    /// this cost imposes on refresh. **Informational.**
    pub cadence_fraction: f64,
    /// Where the cost is paid, by citation, so the record says why it is not
    /// covered by rows 2 and 3.
    pub call_site: &'static str,
}
