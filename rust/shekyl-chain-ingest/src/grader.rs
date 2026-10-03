// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CSR-3a grading of a run (`DRS_E2_REPLAY_DRIVER.md` RD-Q6, RD-Q9, §1.3).
//!
//! The register is prose and the grader is pure logic
//! (`shekyl_chain_store::conformance`); this module is the wiring between
//! them and the run. The register arrives as JSON from
//! `scripts/ci/export_conformance_register.py`, which serializes what the
//! coverage gate already derives — the denominator is never a hand-copied
//! figure. The run arrives as [`Observations`]: which rules' verdicts the
//! connected blocks exercised (the union of every `ChainValid`'s coverage),
//! the refusal if one ended the run, whether the redb digest agreed with
//! the trace's checkpoint, the per-height root oracle, and the archival
//! oracle at the checkpoint. Each oracle is its own fact: the digest
//! carries only the live root, and no archival state at all — the archival
//! rows travel beside it as the checkpoint's other encoding
//! (`DRS_E4_ARCHIVAL_WRITER.md` §3.8.1) and are diffed, not hashed, so a
//! disagreement names its row (`shekyl_e2_grade_v3`).
//!
//! # The two clauses (RD-Q9, RULED)
//!
//! Every graded row carries **two typed evidence fields**, neither
//! recoverable from the other:
//!
//! - [`VerdictEvidence`] — *the rule's verdict grades on its own evidence*.
//!   A rule the run exercised on blocks both stores accepted agreed with
//!   C++ (`identical = true`); a rule that refused a block the C++ chain
//!   holds disagreed (`identical = false`); a rule no connected block
//!   exercised has no verdict evidence. A **consumer** of a borrowed fact
//!   (B5's equality against the recorded root) is a real check whose oracle
//!   happens to be borrowed — its verdict counts.
//! - [`ComponentEvidence`] — *the digest component the rule feeds*: the
//!   digest identity at the checkpoint, or nothing when no checkpoint was
//!   compared. Until E6 slice 7 wave B a third arm, `Borrowed`, graded a
//!   **producer** of a passed-through fact not-evidence — the rows
//!   `ConnectFacts::DELETED_BY` named, read from the store's own
//!   declaration so a slice deriving a fact flipped its rows to real
//!   evidence with no harness change (RD-Q6). The last fact derived on
//!   2026-09-29 and the arm went with the declaration: every row's
//!   component is real replay output now (`shekyl_e2_grade_v2`; `v3` added
//!   the archival oracle beside the root oracle, 2026-10-01).
//!
//! # The grader's law and the adjudication sentence (§1.3)
//!
//! The register types deserialize (Rust reads the extractor's JSON); the
//! graded-run types only serialize (Rust writes the artifact, Python and
//! humans read it) — two artifacts, two directions.
//!
//! A borrowed value is never evidence. The trace is evidence, not a target:
//! a disagreement resolves to *fix Rust* or *`ReviewedDivergence` with Rust
//! canonical* — there is no third arm — and the run's success condition is
//! **no unadjudicated disagreement**, never "matches C++". Concretely a
//! [`GradedRun`] passes when [`GradedRun::unadjudicated`] is empty: every
//! `Failed(..)` acceptance — a CHECKED-CONFORMANT row that differed, or a
//! DIVERGENT row that **matched** (the port reproduced the defect) — is an
//! open adjudication. `NeedsReviewedDivergence` is listed as owed, not as
//! failed: the reviewed record that would license it is CI's to resolve
//! when discharge sites exist (`conformance.rs`).
//!
//! # The refusal is graded once, on its own
//!
//! A refusal ends the run: Rust refused a block the chain holds, and
//! nothing after it was compared. That is a disagreement whatever the
//! register says of the refusing row, so it is graded as its own typed
//! field ([`GradedRun::refusal`]) rather than only as one register row's
//! verdict clause — a row the register does not carry at all (a bucket-3/4
//! rule the census does not ratify, hence outside the coverage gate's
//! denominator) is UNREVIEWED **by absence**, exactly as an unrecorded
//! ratified row is. The register licenses the refusal only by recording
//! the row DIVERGENT (owed a reviewed record); a CHECKED-CONFORMANT row
//! failed, and an UNREVIEWED row's refusal is observed and **unlicensed**,
//! so both are open adjudications. "UNREVIEWED is observed-only" governs
//! what a match grants — nothing — not whether a run that stopped on a
//! refusal may pass.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use shekyl_chain_rules::CenRow;
use shekyl_chain_store::archival_snapshot::{hex, SnapshotDiff};
use shekyl_chain_store::conformance::{grade, Acceptance, ConformanceState, FailureReason};
use shekyl_types::BlockHeight;

/// The JSON the extractor emits.
pub const REGISTER_SCHEMA: &str = "shekyl_e2_register_v1";
/// The JSON this module emits.
pub const GRADE_SCHEMA: &str = "shekyl_e2_grade_v3";

/// One register row as extracted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRow {
    /// `CEN-…`.
    pub id: String,
    /// The recorded state, in the register's vocabulary.
    pub state: RecordedState,
}

/// The register's state vocabulary, as the gate spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordedState {
    /// `CHECKED-CONFORMANT`.
    #[serde(rename = "CHECKED-CONFORMANT")]
    CheckedConformant,
    /// `DIVERGENT`.
    #[serde(rename = "DIVERGENT")]
    Divergent,
    /// `UNREVIEWED`, explicitly recorded.
    #[serde(rename = "UNREVIEWED")]
    Unreviewed,
}

impl From<RecordedState> for ConformanceState {
    fn from(s: RecordedState) -> Self {
        match s {
            RecordedState::CheckedConformant => Self::CheckedConformant,
            RecordedState::Divergent => Self::Divergent,
            RecordedState::Unreviewed => Self::Unreviewed,
        }
    }
}

impl From<ConformanceState> for RecordedState {
    /// The inverse, so a fourth state added to either enum is a compile
    /// error here rather than a mislabelled row.
    fn from(s: ConformanceState) -> Self {
        match s {
            ConformanceState::CheckedConformant => Self::CheckedConformant,
            ConformanceState::Divergent => Self::Divergent,
            ConformanceState::Unreviewed => Self::Unreviewed,
        }
    }
}

/// The register as the extractor serializes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Must equal [`REGISTER_SCHEMA`].
    pub schema_version: String,
    /// Recorded rows, sorted by id.
    pub rows: Vec<RegisterRow>,
    /// Ratified rules with no record — UNREVIEWED by absence (CSR-3a).
    pub unrecorded_ratified: Vec<String>,
}

/// Why a register could not be used.
#[derive(Debug, thiserror::Error)]
pub enum RegisterFault {
    /// Not the schema this grader reads.
    #[error("register schema {found:?} is not {REGISTER_SCHEMA:?}")]
    Schema {
        /// What the file said.
        found: String,
    },
    /// The JSON did not parse as a register.
    #[error("register does not parse: {0}")]
    Parse(#[from] serde_json::Error),
    /// A register with no rows summarizes nothing (rule 47).
    #[error("register has no rows")]
    Empty,
}

impl Register {
    /// Parse and check the extractor's JSON.
    ///
    /// # Errors
    ///
    /// [`RegisterFault`].
    pub fn from_json(text: &str) -> Result<Self, RegisterFault> {
        let reg: Self = serde_json::from_str(text)?;
        if reg.schema_version != REGISTER_SCHEMA {
            return Err(RegisterFault::Schema {
                found: reg.schema_version,
            });
        }
        if reg.rows.is_empty() {
            return Err(RegisterFault::Empty);
        }
        Ok(reg)
    }

    /// Every row the grader will grade: the recorded ones with their state,
    /// and the ratified-without-record ones as UNREVIEWED by absence
    /// ([`ConformanceState::for_row`] over `None`).
    fn states(&self) -> BTreeMap<String, ConformanceState> {
        let mut m: BTreeMap<String, ConformanceState> = self
            .rows
            .iter()
            .map(|r| (r.id.clone(), r.state.into()))
            .collect();
        for id in &self.unrecorded_ratified {
            m.entry(id.clone())
                .or_insert(ConformanceState::for_row(None));
        }
        m
    }
}

/// What a run showed the grader.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    /// Rows some connected block's `ChainValid` coverage contained — rules
    /// whose verdict was *accepted* on a block the C++ chain also holds.
    pub exercised: BTreeSet<&'static str>,
    /// The refusal that ended the run, if a verdict did: the refusing row
    /// and where.
    pub refused: Option<(&'static str, BlockHeight)>,
    /// Whether the redb digest equalled the trace's checkpoint. `None` when
    /// no checkpoint was compared.
    pub digest_identical: Option<bool>,
    /// Derived root against the trace, per covered height. Independent of
    /// [`Self::digest_identical`]: the digest carries only the live root.
    pub roots: RootOracle,
    /// The redb archival rows against the trace's `0x04` record at the
    /// checkpoint (DRS-E4 §3.8.1). Independent of the digest, which
    /// carries no archival state at all.
    pub archival: ArchivalOracle,
}

/// The per-height derived-vs-trace root comparison (DRS-E3 CTW-5), as the
/// grade records it.
///
/// `compared == 0` means the run did not compare. A non-empty
/// [`Self::diverged_at`] fails the run on its own ([`GradedRun::passes`]).
/// The checkpoint digest stays the digest clause: it carries only the live
/// root, so an interior miss is a fact of this oracle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RootOracle {
    /// Connected heights whose trace carried a root.
    pub compared: u64,
    /// Heights where the derived root differed from the trace, in the order
    /// the run saw them.
    pub diverged_at: Vec<BlockHeight>,
}

/// The covered-tip archival comparison (DRS-E4 §3.8.1, `ARW-25`), as the
/// grade records it: the redb side's rows against the trace's, family by
/// family, with every disagreeing row named by its key. Rows, not a hash —
/// at one checkpoint per chain a diff says *which* row, which a digest
/// cannot; the digest clause stays what it was.
///
/// `compared == false` is a run that never connected the checkpoint
/// height: **not compared**, never identical. A
/// non-empty [`Self::diverged`] fails the run on its own
/// ([`GradedRun::passes`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchivalOracle {
    /// Whether the two sides' rows were taken and diffed.
    pub compared: bool,
    /// The checkpoint height, when compared.
    pub at: Option<u64>,
    /// Rows present on both sides with equal bytes, summed over the ten
    /// families.
    pub rows_equal: u64,
    /// Every family with at least one disagreeing row; empty when the
    /// sides agree or were not compared.
    pub diverged: Vec<ArchivalFamilyDivergence>,
}

/// One family's disagreement, keys and values as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArchivalFamilyDivergence {
    /// The family's §3.8.1 name.
    pub family: &'static str,
    /// Rows under the same key with different bytes.
    pub unequal: Vec<ArchivalUnequalRow>,
    /// Keys only the redb side holds.
    pub only_ours: Vec<String>,
    /// Keys only the trace holds.
    pub only_theirs: Vec<String>,
}

/// A key both sides hold under different bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArchivalUnequalRow {
    /// The row key.
    pub key: String,
    /// The redb side's value bytes.
    pub ours: String,
    /// The trace's value bytes.
    pub theirs: String,
}

impl ArchivalOracle {
    /// The oracle a compared checkpoint yields.
    #[must_use]
    pub fn from_diff(at: BlockHeight, diff: &SnapshotDiff) -> Self {
        Self {
            compared: true,
            at: Some(at.to_raw()),
            rows_equal: diff.families.iter().map(|f| f.equal).sum(),
            diverged: diff
                .diverged()
                .map(|f| ArchivalFamilyDivergence {
                    family: f.family.name(),
                    unequal: f
                        .unequal
                        .iter()
                        .map(|r| ArchivalUnequalRow {
                            key: hex(&r.key),
                            ours: hex(&r.ours),
                            theirs: hex(&r.theirs),
                        })
                        .collect(),
                    only_ours: f.only_ours.iter().map(|k| hex(k)).collect(),
                    only_theirs: f.only_theirs.iter().map(|k| hex(k)).collect(),
                })
                .collect(),
        }
    }
}

impl Observations {
    /// Fold one connected block's coverage in.
    pub fn exercised_rows(&mut self, rows: impl IntoIterator<Item = CenRow>) {
        self.exercised.extend(rows.into_iter().map(CenRow::as_str));
    }

    /// Record the one covered-tip checkpoint comparison.
    pub fn checkpoint(&mut self, identical: bool) {
        self.digest_identical = Some(identical);
    }
}

/// Clause (1): the rule's own verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum VerdictEvidence {
    /// The rule was exercised: it accepted blocks C++ accepted (`true`), or
    /// it refused one C++ holds (`false`).
    Exercised {
        /// Whether Rust's verdict agreed with the chain's existence.
        agreed: bool,
    },
    /// No connected block exercised the rule.
    NotExercised,
}

/// Clause (2): the digest component the rule feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ComponentEvidence {
    /// The component is real replay output; `identical` is the checkpoint's
    /// verdict.
    Real {
        /// Digest identity at the checkpoint(s).
        identical: bool,
    },
    /// No checkpoint was compared in this run.
    NotCompared,
}

/// One graded row: both clauses, each with its acceptance where evidence
/// exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GradedRow {
    /// `CEN-…`.
    pub id: String,
    /// The register's state (UNREVIEWED when by absence).
    pub state: RecordedState,
    /// Whether the state came from a record or from absence.
    pub recorded: bool,
    /// Clause (1).
    pub verdict: VerdictEvidence,
    /// `grade(state, agreed)` when exercised.
    pub verdict_acceptance: Option<GradedAcceptance>,
    /// Clause (2).
    pub component: ComponentEvidence,
    /// `grade(state, identical)` when the component is real and compared.
    pub component_acceptance: Option<GradedAcceptance>,
}

/// [`Acceptance`], serializable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum GradedAcceptance {
    /// The match is correctness evidence.
    AcceptedAsCorrect,
    /// A CHECKED-CONFORMANT row differed.
    FailedConformantDiffered,
    /// A DIVERGENT row matched — the defect was reproduced.
    FailedReproducedDefect,
    /// Observed only; no acceptance.
    RegressionSignalOnly,
    /// Diverged as expected; a reviewed record is owed.
    NeedsReviewedDivergence,
}

impl From<Acceptance> for GradedAcceptance {
    fn from(a: Acceptance) -> Self {
        match a {
            Acceptance::AcceptedAsCorrect => Self::AcceptedAsCorrect,
            Acceptance::Failed(FailureReason::ConformantRowDiffered) => {
                Self::FailedConformantDiffered
            }
            Acceptance::Failed(FailureReason::ReproducedKnownDefect) => {
                Self::FailedReproducedDefect
            }
            Acceptance::RegressionSignalOnly => Self::RegressionSignalOnly,
            Acceptance::NeedsReviewedDivergence => Self::NeedsReviewedDivergence,
        }
    }
}

impl GradedAcceptance {
    const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::FailedConformantDiffered | Self::FailedReproducedDefect
        )
    }
}

/// The refusal that ended the run, graded on its own (module docs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GradedRefusal {
    /// The refusing row.
    pub id: String,
    /// Where the run ended.
    pub height: u64,
    /// The register's state for the row — UNREVIEWED by absence when the
    /// register does not carry it.
    pub state: RecordedState,
    /// Whether the register records the row at all.
    pub recorded: bool,
    /// `grade(state, agreed = false)`.
    pub acceptance: GradedAcceptance,
}

/// An open adjudication: a row whose evidence says the stores disagreed in
/// a way the register does not license.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unadjudicated {
    /// The row.
    pub id: String,
    /// Which clause.
    pub clause: Clause,
    /// The failing acceptance.
    pub acceptance: GradedAcceptance,
}

/// Which of RD-Q9's two clauses a finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Clause {
    /// The rule's verdict.
    Verdict,
    /// The digest component.
    Component,
}

/// The graded run — the artifact (RD-Q6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GradedRun {
    /// [`GRADE_SCHEMA`].
    pub schema_version: String,
    /// Every row, in id order.
    pub rows: Vec<GradedRow>,
    /// The refusal that ended the run, if one did (module docs).
    pub refusal: Option<GradedRefusal>,
    /// The root oracle. A non-empty `diverged_at` fails the run even when
    /// [`Self::unadjudicated`] is empty.
    pub root_oracle: RootOracle,
    /// The archival oracle (DRS-E4 §3.8.1). A non-empty `diverged` fails
    /// the run even when [`Self::unadjudicated`] is empty.
    pub archival_oracle: ArchivalOracle,
    /// Rows with a verdict clause that accepted as correct — **progress is
    /// this count** (RD-Q6).
    pub derived_and_conformant: usize,
    /// Rows no connected block exercised.
    pub not_exercised: usize,
    /// Open census adjudications (§1.3). The run also fails when
    /// [`Self::root_oracle`] diverged; that miss is not a row of this list.
    pub unadjudicated: Vec<Unadjudicated>,
    /// DIVERGENT rows that diverged as expected and owe a reviewed record.
    pub owed_reviewed_divergence: Vec<String>,
}

impl GradedRun {
    /// §1.3's success condition: no open census adjudication, and neither
    /// the root oracle nor the archival oracle diverged. An oracle that was
    /// not compared does not fail the run.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.unadjudicated.is_empty()
            && self.root_oracle.diverged_at.is_empty()
            && self.archival_oracle.diverged.is_empty()
    }

    /// The artifact as JSON.
    ///
    /// # Errors
    ///
    /// Serialization only.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Grade a run against the register (module docs).
#[must_use]
pub fn grade_run(register: &Register, obs: &Observations) -> GradedRun {
    let recorded: BTreeSet<&str> = register.rows.iter().map(|r| r.id.as_str()).collect();
    let states = register.states();
    let mut rows = Vec::new();
    let mut unadjudicated = Vec::new();
    let mut owed = Vec::new();
    let (mut derived_and_conformant, mut not_exercised) = (0, 0);

    // ---- the refusal, graded once whether or not the register has its row
    let refusal = obs.refused.map(|(id, height)| {
        let state = states
            .get(id)
            .copied()
            .unwrap_or_else(|| ConformanceState::for_row(None));
        GradedRefusal {
            id: id.to_owned(),
            height: height.to_raw(),
            state: state.into(),
            recorded: recorded.contains(id),
            acceptance: grade(state, false).into(),
        }
    });
    if let Some(r) = &refusal {
        match r.acceptance {
            GradedAcceptance::NeedsReviewedDivergence => owed.push(r.id.clone()),
            acceptance => unadjudicated.push(Unadjudicated {
                id: r.id.clone(),
                clause: Clause::Verdict,
                acceptance,
            }),
        }
    }

    for (id, state) in states {
        // ---- clause (1): the verdict ---------------------------------
        let refused_here = obs.refused.is_some_and(|(row, _)| row == id);
        let verdict = if refused_here {
            VerdictEvidence::Exercised { agreed: false }
        } else if obs.exercised.contains(id.as_str()) {
            VerdictEvidence::Exercised { agreed: true }
        } else {
            VerdictEvidence::NotExercised
        };
        let verdict_acceptance = match verdict {
            VerdictEvidence::Exercised { agreed } => {
                Some(GradedAcceptance::from(grade(state, agreed)))
            }
            VerdictEvidence::NotExercised => None,
        };
        // ---- clause (2): the component --------------------------------
        let component = match obs.digest_identical {
            Some(identical) => ComponentEvidence::Real { identical },
            None => ComponentEvidence::NotCompared,
        };
        let component_acceptance = match component {
            ComponentEvidence::Real { identical } => {
                Some(GradedAcceptance::from(grade(state, identical)))
            }
            ComponentEvidence::NotCompared => None,
        };
        // ---- tallies ---------------------------------------------------
        if verdict_acceptance == Some(GradedAcceptance::AcceptedAsCorrect) {
            derived_and_conformant += 1;
        }
        if verdict == VerdictEvidence::NotExercised {
            not_exercised += 1;
        }
        // The refusing row's verdict clause was adjudicated above, once.
        for (clause, acceptance) in [
            (
                Clause::Verdict,
                verdict_acceptance.filter(|_| !refused_here),
            ),
            (Clause::Component, component_acceptance),
        ] {
            match acceptance {
                Some(a) if a.is_failure() => unadjudicated.push(Unadjudicated {
                    id: id.clone(),
                    clause,
                    acceptance: a,
                }),
                Some(GradedAcceptance::NeedsReviewedDivergence) => {
                    if !owed.contains(&id) {
                        owed.push(id.clone());
                    }
                }
                _ => {}
            }
        }
        rows.push(GradedRow {
            state: state.into(),
            recorded: recorded.contains(id.as_str()),
            id,
            verdict,
            verdict_acceptance,
            component,
            component_acceptance,
        });
    }
    GradedRun {
        schema_version: GRADE_SCHEMA.to_owned(),
        rows,
        refusal,
        root_oracle: obs.roots.clone(),
        archival_oracle: obs.archival.clone(),
        derived_and_conformant,
        not_exercised,
        unadjudicated,
        owed_reviewed_divergence: owed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register() -> Register {
        Register::from_json(
            r#"{
              "schema_version": "shekyl_e2_register_v1",
              "rows": [
                {"id": "CEN-A1", "state": "CHECKED-CONFORMANT"},
                {"id": "CEN-B5", "state": "CHECKED-CONFORMANT"},
                {"id": "CEN-F17", "state": "DIVERGENT"},
                {"id": "CEN-L8", "state": "UNREVIEWED"},
                {"id": "CEN-Z9", "state": "DIVERGENT"}
              ],
              "unrecorded_ratified": ["CEN-X1"]
            }"#,
        )
        .expect("parses")
    }

    fn row<'a>(g: &'a GradedRun, id: &str) -> &'a GradedRow {
        g.rows.iter().find(|r| r.id == id).expect("row")
    }

    #[test]
    fn a_matching_run_grades_exercised_conformant_rows_correct_and_inverts_divergent() {
        let mut obs = Observations::default();
        obs.exercised_rows([CenRow::A1, CenRow::B5]);
        obs.checkpoint(true);
        let g = grade_run(&register(), &obs);
        // The inversion, live: Z9 and F17 are DIVERGENT, so the digest
        // *matching* on them is the port reproducing the defect — the open
        // adjudications in an otherwise clean run. (F17 was a *producer*
        // until wave B and graded borrowed, not-evidence; the store
        // declares no producers now, so it is graded like every row.)
        assert_eq!(
            g.unadjudicated,
            vec![
                Unadjudicated {
                    id: "CEN-F17".to_owned(),
                    clause: Clause::Component,
                    acceptance: GradedAcceptance::FailedReproducedDefect,
                },
                Unadjudicated {
                    id: "CEN-Z9".to_owned(),
                    clause: Clause::Component,
                    acceptance: GradedAcceptance::FailedReproducedDefect,
                }
            ]
        );
        // A1: exercised and agreed, component real and identical.
        let a1 = row(&g, "CEN-A1");
        assert_eq!(a1.verdict, VerdictEvidence::Exercised { agreed: true });
        assert_eq!(
            a1.verdict_acceptance,
            Some(GradedAcceptance::AcceptedAsCorrect)
        );
        assert_eq!(a1.component, ComponentEvidence::Real { identical: true });
        // B5: until DRS-E3 a consumer of the *borrowed* root — a producer
        // per DELETED_BY (`root_after`), so its component clause was never
        // evidence. `validate` now derives the root and the field is gone
        // from DELETED_BY, so the grader — reading the store's own
        // declaration — reports the component real and identical: the
        // derived tree's root agreed with the daemon's digest. Both clauses
        // count.
        let b5 = row(&g, "CEN-B5");
        assert_eq!(
            b5.verdict_acceptance,
            Some(GradedAcceptance::AcceptedAsCorrect)
        );
        assert_eq!(b5.component, ComponentEvidence::Real { identical: true });
        assert_eq!(
            b5.component_acceptance,
            Some(GradedAcceptance::AcceptedAsCorrect)
        );
        // F17: DIVERGENT and not exercised — no verdict clause; its
        // component is real (the checkpoint matched) and so the inversion
        // above. Until wave B it was the burn's producer per DELETED_BY and
        // graded borrowed; until slice 7 this fixture row was CEN-G6, a
        // producer of the weights.
        let f17 = row(&g, "CEN-F17");
        assert_eq!(f17.verdict, VerdictEvidence::NotExercised);
        assert_eq!(f17.component, ComponentEvidence::Real { identical: true });
        // X1: unrecorded → UNREVIEWED by absence; component real but grants nothing.
        let x1 = row(&g, "CEN-X1");
        assert!(!x1.recorded);
        assert_eq!(x1.state, RecordedState::Unreviewed);
        assert_eq!(
            x1.component_acceptance,
            Some(GradedAcceptance::RegressionSignalOnly)
        );
        assert_eq!(g.derived_and_conformant, 2);
        assert_eq!(g.not_exercised, 4);
    }

    #[test]
    fn a_refusal_on_a_conformant_row_is_unadjudicated_and_a_matching_divergent_row_reproduces_the_defect(
    ) {
        let mut obs = Observations::default();
        obs.exercised_rows([CenRow::A1]);
        obs.refused = Some(("CEN-A1", BlockHeight::from_raw(4)));
        // Z9 is DIVERGENT, exercised and agreed: the port reproduced the defect.
        obs.exercised.insert("CEN-Z9");
        obs.checkpoint(true);
        let g = grade_run(&register(), &obs);
        assert!(!g.passes());
        let ids: Vec<(&str, Clause, GradedAcceptance)> = g
            .unadjudicated
            .iter()
            .map(|u| (u.id.as_str(), u.clause, u.acceptance))
            .collect();
        assert!(ids.contains(&(
            "CEN-A1",
            Clause::Verdict,
            GradedAcceptance::FailedConformantDiffered
        )));
        assert!(ids.contains(&(
            "CEN-Z9",
            Clause::Verdict,
            GradedAcceptance::FailedReproducedDefect
        )));
        // Z9's component (real, identical) also reproduces the defect: the
        // digest matched on a row whose spec says it should not.
        assert!(ids.contains(&(
            "CEN-Z9",
            Clause::Component,
            GradedAcceptance::FailedReproducedDefect
        )));
    }

    #[test]
    fn a_refusal_is_open_on_an_absent_row_and_an_unreviewed_row_and_owed_on_a_divergent_one() {
        // CEN-B2 is implemented and bucket 4: never in the register. Its
        // refusal ended the run; nothing licensed it.
        let obs = Observations {
            refused: Some(("CEN-B2", BlockHeight::from_raw(9))),
            ..Observations::default()
        };
        let g = grade_run(&register(), &obs);
        assert!(!g.passes(), "a refusal the register cannot see is open");
        let r = g.refusal.as_ref().expect("graded");
        assert_eq!((r.id.as_str(), r.height, r.recorded), ("CEN-B2", 9, false));
        assert_eq!(r.state, RecordedState::Unreviewed, "by absence");
        assert_eq!(
            g.unadjudicated,
            vec![Unadjudicated {
                id: "CEN-B2".to_owned(),
                clause: Clause::Verdict,
                acceptance: GradedAcceptance::RegressionSignalOnly,
            }]
        );
        assert!(
            g.rows.iter().all(|row| row.id != "CEN-B2"),
            "not a register row"
        );

        // An UNREVIEWED row's refusal is observed and unlicensed: open.
        let obs = Observations {
            refused: Some(("CEN-L8", BlockHeight::from_raw(3))),
            ..Observations::default()
        };
        let g = grade_run(&register(), &obs);
        assert!(!g.passes());
        assert!(g.refusal.as_ref().is_some_and(|r| r.recorded));
        let l8 = row(&g, "CEN-L8");
        assert_eq!(l8.verdict, VerdictEvidence::Exercised { agreed: false });
        assert_eq!(
            g.unadjudicated.iter().filter(|u| u.id == "CEN-L8").count(),
            1,
            "adjudicated once, not once per clause"
        );

        // A DIVERGENT row's refusal is the divergence the register expects:
        // owed a reviewed record, not open.
        let obs = Observations {
            refused: Some(("CEN-Z9", BlockHeight::from_raw(3))),
            ..Observations::default()
        };
        let g = grade_run(&register(), &obs);
        assert!(g.passes());
        assert_eq!(g.owed_reviewed_divergence, vec!["CEN-Z9".to_owned()]);
        assert_eq!(
            g.refusal.as_ref().map(|r| r.acceptance),
            Some(GradedAcceptance::NeedsReviewedDivergence)
        );
    }

    #[test]
    fn a_digest_divergence_owes_a_reviewed_record_on_divergent_rows_and_fails_conformant_ones() {
        let mut obs = Observations::default();
        obs.checkpoint(false);
        let g = grade_run(&register(), &obs);
        assert!(g.owed_reviewed_divergence.contains(&"CEN-Z9".to_owned()));
        assert!(
            g.owed_reviewed_divergence.contains(&"CEN-F17".to_owned()),
            "graded like every row since wave B (it borrowed until then)"
        );
        assert!(g
            .unadjudicated
            .iter()
            .any(|u| u.id == "CEN-A1" && u.clause == Clause::Component));
    }

    #[test]
    fn a_root_divergence_fails_the_run_and_leaves_the_digest_clause_alone() {
        // The checkpoint matched. The interior root diverged at height 1.
        // The digest clause records the checkpoint. The run fails on the
        // oracle.
        let mut obs = Observations::default();
        obs.checkpoint(true);
        obs.roots = RootOracle {
            compared: 4,
            diverged_at: vec![BlockHeight::from_raw(1)],
        };
        // Conformant rows only. A divergent row whose digest matched would
        // already be an open adjudication, and would hide the oracle.
        let conformant = Register::from_json(
            r#"{"schema_version":"shekyl_e2_register_v1","rows":[{"id":"CEN-B5","state":"CHECKED-CONFORMANT"},{"id":"CEN-A1","state":"CHECKED-CONFORMANT"}],"unrecorded_ratified":[]}"#,
        )
        .expect("register");
        let g = grade_run(&conformant, &obs);
        assert!(!g.passes());
        assert!(
            g.unadjudicated.is_empty(),
            "the oracle fails the run with the census list empty"
        );
        assert_eq!(g.root_oracle.diverged_at, vec![BlockHeight::from_raw(1)]);
        assert_eq!(
            row(&g, "CEN-B5").component,
            ComponentEvidence::Real { identical: true }
        );
        assert_eq!(
            row(&g, "CEN-A1").component,
            ComponentEvidence::Real { identical: true }
        );
    }

    #[test]
    fn an_archival_divergence_fails_the_run_and_names_its_row() {
        // The digest matched and the roots agreed; one archival row —
        // the open epoch's accrued total — differed. The run fails on the
        // archival oracle with the census list empty, and the artifact
        // names the family and the key (ARW-25: a diff, not a hash).
        use shekyl_chain_store::archival_snapshot::ArchivalSnapshot;
        use shekyl_types::SettlementEpoch;
        use shekyl_units::AtomicUnits;

        let mut ours = ArchivalSnapshot::empty();
        ours.set_budget_accruing(SettlementEpoch::from_raw(0), AtomicUnits::from_raw(7))
            .expect("one row");
        let mut theirs = ArchivalSnapshot::empty();
        theirs
            .set_budget_accruing(SettlementEpoch::from_raw(0), AtomicUnits::from_raw(8))
            .expect("one row");
        let mut obs = Observations::default();
        obs.checkpoint(true);
        obs.archival = ArchivalOracle::from_diff(BlockHeight::from_raw(3), &ours.diff(&theirs));
        let conformant = Register::from_json(
            r#"{"schema_version":"shekyl_e2_register_v1","rows":[{"id":"CEN-A1","state":"CHECKED-CONFORMANT"}],"unrecorded_ratified":[]}"#,
        )
        .expect("register");
        let g = grade_run(&conformant, &obs);
        assert!(!g.passes());
        assert!(g.unadjudicated.is_empty());
        assert!(g.root_oracle.diverged_at.is_empty());
        assert!(g.archival_oracle.compared);
        assert_eq!(g.archival_oracle.at, Some(3));
        assert_eq!(g.archival_oracle.rows_equal, 0);
        assert_eq!(g.archival_oracle.diverged.len(), 1);
        let family = &g.archival_oracle.diverged[0];
        assert_eq!(family.family, "archival_budget_accruing");
        assert_eq!(family.unequal.len(), 1);
        assert_eq!(family.unequal[0].key, "0000000000000000");
        assert_eq!(family.unequal[0].ours, "0700000000000000");
        assert_eq!(family.unequal[0].theirs, "0800000000000000");
        assert!(family.only_ours.is_empty() && family.only_theirs.is_empty());

        // Agreement is a compared oracle with nothing diverged.
        obs.archival = ArchivalOracle::from_diff(BlockHeight::from_raw(3), &ours.diff(&ours));
        let g = grade_run(&conformant, &obs);
        assert!(g.passes());
        assert!(g.archival_oracle.compared);
        assert_eq!(g.archival_oracle.rows_equal, 1);
        // Not compared is the default: `compared == false`, and it does not
        // fail the run.
        assert!(!ArchivalOracle::default().compared);
    }

    #[test]
    fn no_checkpoint_means_no_component_evidence_and_the_schema_is_checked() {
        let obs = Observations::default();
        let g = grade_run(&register(), &obs);
        assert!(g
            .rows
            .iter()
            .all(|r| matches!(r.component, ComponentEvidence::NotCompared)));
        assert!(g.passes(), "nothing compared, nothing disagreed");
        let json = g.to_json().expect("json");
        assert!(json.contains(GRADE_SCHEMA));
        assert!(matches!(
            Register::from_json(r#"{"schema_version":"nope","rows":[],"unrecorded_ratified":[]}"#),
            Err(RegisterFault::Schema { .. })
        ));
        assert!(matches!(
            Register::from_json(
                r#"{"schema_version":"shekyl_e2_register_v1","rows":[],"unrecorded_ratified":[]}"#
            ),
            Err(RegisterFault::Empty)
        ));
    }

    #[test]
    fn the_extractors_committed_output_parses_as_a_register() {
        // The cross-language check: `scripts/ci/export_conformance_register.py`
        // emitted this file (docs-gates holds it equal to the live register,
        // `--check-fixture`); this side parses it. A key renamed in either
        // place fails here or there, never at the end of a replay.
        let register = Register::from_json(include_str!("../fixtures/conformance_register.json"))
            .expect("the extractor's own output parses");
        assert!(!register.rows.is_empty());
        for row in &register.rows {
            assert!(row.id.starts_with("CEN-"), "{}", row.id);
        }
        let ids: Vec<&str> = register.rows.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(
            register.states().contains_key("CEN-A1"),
            "the first ratified row is in the register"
        );
    }
}
