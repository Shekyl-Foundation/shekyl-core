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
/// **That applies to the stdout arm too, which is why it is an explicit
/// stream write rather than `println!`.** `println!` *panics* on an I/O
/// failure, so piping a run into `head` aborted it mid-measurement instead of
/// reporting a write that did not land — the stdout arm was breaking the rule
/// the path arm above states. Both arms now return the same `Err`.
///
/// The `flush` is part of that, not politeness: stdout is block-buffered when
/// redirected, so a failure on the final flush is exactly the "silently fails
/// to appear" case, and dropping the handle would swallow it.
///
/// *(This is also why the production-Rust debug-macro lint was right to fire.
/// `report.rs` is library code shared by three binaries; the lint excludes
/// `main.rs` and `src/bin/*` because a CLI's contract is to print, and this
/// file is neither.)*
///
/// # Errors
///
/// Serialization failure, or a write that does not land.
pub fn emit<T: Serialize>(record: &T, path: Option<&str>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(record).map_err(|e| format!("serialize: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("could not write {p}: {e}")),
        None => {
            use std::io::Write as _;
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(json.as_bytes())
                .and_then(|()| handle.write_all(b"\n"))
                .and_then(|()| handle.flush())
                .map_err(|e| format!("could not write the record to stdout: {e}"))
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
/// **v3 (CT-6 increment 4)** re-derives `per_block_advance_worst_case_s` and
/// carries `per_block_advance_load_control` beside it.
///   In `v1`/`v2` it was `replay_median / REPLAY_WINDOW_BLOCKS` — a share of
///   the spend replay, which is a pre-build *model* of an advance that did
///   not exist yet. In `v3` it is the median of a measured series over the
///   built advance: frontier fold, snapshot encode, ring commit
///   ([`crate::advance::AdvanceRig`]). **The field name did not change and
///   the meaning did**, which is exactly the shape `CT-6 Q4` was left open to
///   catch, so the bump is what stops a `v2` figure and a `v3` figure being
///   read off the same axis. A `v2` record's value is not wrong for what it
///   was — it is a model estimate — but it is not the graded quantity, and
///   `per_block_advance_provenance` now says which one a record carries.
///   The retired quotient beside the measurement divides by `replayed_blocks`
///   — the blocks the corpus covers, `window_leaves / leaves_per_block` — and
///   not by `REPLAY_WINDOW_BLOCKS`. At the default window the two denominators
///   match; under `--window-leaves` they do not. The quotient is an observation
///   of that run. The measured advance is what a later run may compare.
///
/// **No CI arm enforces this constant** — the `schema-snapshot` workflow's
/// version-bump job covers `shekyl-chain-store`'s persisted schema, not this
/// record. Bumping it is a reviewer obligation, which is why the history
/// above is kept here rather than only in the changelog.
pub const SCHEMA_VERSION: u32 = 3;

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
/// What the run's own controls say about the board the advance was timed on.
///
/// Carried in the record rather than only printed, so a contaminated run
/// cannot be read later as a clean one. This exists because a 2026-09-28
/// advance record was superseded on 2026-09-29 partly for having been taken
/// on a loaded box: its model term was 63 % slower for identical work, and
/// the ratio between the two terms moved 0.69x -> 0.95x. Load does not cancel
/// between a memory-bandwidth-bound replay and an `fsync`-bound advance.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct LoadControl {
    /// Largest absolute dense-vs-sparse divergence across the run's controls,
    /// in percent. The two arms do identical work, so this is the board
    /// talking, not the workload.
    pub max_divergence_pct: f64,
    /// The bound `max_divergence_pct` is judged against.
    pub tolerance_pct: f64,
    /// Whether every control stayed inside the bound **and** converged.
    ///
    /// `false` does not invalidate the median on its own — it says the run
    /// cannot claim its figure is a property of the work rather than of the
    /// machine, which is precisely the claim a grade would make.
    pub quiet: bool,
    /// Controls the verdict was taken over. Zero is not quiet: a run with no
    /// control has not measured its board, and absence of a signal is first
    /// evidence the subject is absent (rule 47).
    pub controls: usize,
}

impl LoadControl {
    /// Judge the board from a run's controls, each `(divergence_pct,
    /// converged)`.
    ///
    /// The pair is the whole input: a run maps the experiments it already
    /// holds, and a test hands the pairs. The rest of a control experiment
    /// is not an input to the bound, and the pass does not collect the pairs
    /// into a second list.
    #[must_use]
    pub fn over<I>(controls: I, tolerance_pct: f64) -> Self
    where
        I: IntoIterator<Item = (f64, bool)>,
    {
        let mut max_divergence_pct = 0.0_f64;
        let mut count = 0_usize;
        let mut every_arm_quiet = true;
        for (divergence, converged) in controls {
            let magnitude = divergence.abs();
            max_divergence_pct = max_divergence_pct.max(magnitude);
            every_arm_quiet &= converged && magnitude <= tolerance_pct;
            count += 1;
        }
        // Zero controls is not quiet. No reading is an unmeasured board,
        // and absence of the signal is first evidence the subject is absent.
        Self {
            max_divergence_pct,
            tolerance_pct,
            quiet: count > 0 && every_arm_quiet,
            controls: count,
        }
    }
}

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
    /// **The amortized form's refresh-side cost**, `CT-6 Q4`'s subject: the
    /// median of [`SpendEdgeRecord::per_block_advance`], a series over the
    /// **built** advance — frontier fold, snapshot encode, ring commit.
    ///
    /// Derived rather than left to a reader with a calculator, because it is
    /// the number that decides what a miss on the spend edge *means*. A delta
    /// that misses by 48× as a spend-time copy-and-replay is not the same
    /// finding as one whose amortized form costs a fraction of a block
    /// interval — the first kills the design, the second moves the work.
    /// Compare it against [`BLOCK_TARGET_S`]; `Q4` pre-registers 10 % of it.
    ///
    /// Through schema `v2` this was
    /// `per_block_advance_retired_quotient_s` under this name. See
    /// [`SCHEMA_VERSION`].
    pub per_block_advance_worst_case_s: f64,
    /// The measured advance series behind the figure above — so a reader can
    /// see whether it converged before treating it as a grade.
    pub per_block_advance: Series,
    /// **The retired derivation, kept beside its replacement**:
    /// `replay_median / replayed_blocks`, where `replayed_blocks` is the blocks
    /// the corpus covers (`window_leaves / leaves_per_block`). At the default
    /// window that denominator matches `REPLAY_WINDOW_BLOCKS`; under
    /// `--window-leaves` it does not.
    ///
    /// Emitted in the same record as the measured advance so the two can be
    /// compared within the run that produced them. The measured advance is
    /// what a later run may compare. This quotient is an observation of one
    /// run's replay; it is not an extrapolation input, and it does not speak
    /// for the pinned rig.
    pub per_block_advance_retired_quotient_s: f64,
    /// Which derivation `per_block_advance_worst_case_s` carries.
    ///
    /// A record whose field changed derivation under an unchanged name is the
    /// defect `Q4` names; this string is the field saying which one it is,
    /// for a reader who has only the JSON.
    pub per_block_advance_provenance: &'static str,
    /// Whether the run's own controls say the board was quiet enough for
    /// `per_block_advance_worst_case_s` to mean anything.
    ///
    /// The advance is **load-sensitive**, and a contaminated run does not
    /// merely widen its spread — it biases it. The controls already measure
    /// the board (a dense/sparse pair doing identical work), so the signal
    /// exists in every run; it was simply never read on this side, because
    /// when the advance was added the controls only licensed the *sparse
    /// denominator*, which the advance does not depend on.
    pub per_block_advance_load_control: LoadControl,
    /// `per_block_advance_worst_case_s` as a fraction of [`BLOCK_TARGET_S`].
    /// Reported, never graded here: `Q4`'s threshold is graded on the pinned
    /// rig by increment 6, and a fraction computed anywhere else is a
    /// property of the machine that computed it.
    pub per_block_advance_cadence_fraction: f64,
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

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;

/// One arm of the path-assembly cost instrument, as measured.
///
/// The role, the population and the depth travel with the series: a cost is
/// evidence for one half of the flatness claim only once a reader can see
/// which rung it was measured on.
#[derive(Clone, Debug, Serialize)]
pub struct AssembleArmRecord {
    /// [`crate::assembleedge::ArmRole::as_str`].
    pub role: &'static str,
    /// Drained leaves the call assembled against.
    pub leaf_count: u64,
    /// Depth that leaf count implies, read from the population and confirmed
    /// against the client.
    pub depth: u8,
    /// Owned outputs assembled per call — the `k` in `n + k`.
    pub owned_inputs: usize,
    /// Per-call series.
    pub series: Series,
}

/// The path-assembly cost record (`CT-6` increment 5).
///
/// Carries the **pre-registered** [`crate::assembleedge::FlatnessCriterion`]
/// and the grade it yields, so increment 6's re-grade reads the same criterion
/// this run was written under rather than one chosen after seeing the curve.
#[derive(Clone, Debug, Serialize)]
pub struct AssembleEdgeRecord {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The measurement this record is of.
    pub measurement: &'static str,
    /// What the grade means for this era, in words a later reader can act on.
    pub grading: &'static str,
    /// The machine.
    pub environment: Environment,
    /// What was enforced and what was attested.
    pub rig: RigVerdict,
    /// Where the measured call is paid in production.
    pub call_site: &'static str,
    /// Which plan ran, as a type rather than prose.
    ///
    /// Load-bearing. Every plan's arms carry the same roles and the same
    /// criterion, so without this field a reader cannot tell a one-day-old
    /// chain's figure from a rung chosen to fit in minutes.
    pub plan: crate::assembleedge::PlanKind,
    /// What [`Self::plan`]'s figures do and do not mean, from
    /// [`crate::assembleedge::PlanKind::note`] — one source for the record and
    /// the console, so they cannot disagree.
    pub plan_note: &'static str,
    /// The criterion, fixed before capture existed.
    pub criterion: crate::assembleedge::FlatnessCriterion,
    /// Every arm, in plan order.
    pub arms: Vec<AssembleArmRecord>,
    /// Spread across the same-rung pair, in percent of the cheaper arm. The
    /// half that must go to zero for capture's claim to hold.
    pub same_rung_spread_pct: f64,
    /// Measured ratio across the rung boundary.
    pub cross_rung_ratio: f64,
    /// Ratio one layer's work predicts across that boundary.
    pub cross_rung_expected: f64,
    /// Change from the canonical owned count to `MAX_INPUTS` at one
    /// population, in percent — `#842`'s `n + k` claim, measured.
    ///
    /// **Signed.** A negative value means the `MAX_INPUTS` arm was *cheaper*,
    /// which is evidence the `k` term is lost in the noise of `n` rather than
    /// a cost at all. An absolute spread reported that case as a 70 % cost and
    /// said raising `k` was dearer, which inverts the finding.
    pub input_cap_change_pct: f64,
    /// The criterion's reading of this run, or why it was withheld.
    pub grade: crate::assembleedge::FlatnessOutcome,
    /// Whether the board stayed quiet across the run.
    pub load_control: LoadControl,
    /// The control: [`crate::assembleedge::ArmRole::RungTop`] re-timed at the
    /// end of the run, on the same client, over identical work.
    ///
    /// Two terms with one sensitivity profile, so whatever separates this from
    /// the arm's own series is the board and not the workload. That is the
    /// cancellation `CT6_PROVING_STATE.md` §10.4's retired ratio could not
    /// claim: a memory-bandwidth-bound replay and an `fsync`-bound advance are
    /// taxed by load at different rates, while two `assemble_paths` calls over
    /// the same leaves are taxed identically.
    pub control_series: Series,
}
