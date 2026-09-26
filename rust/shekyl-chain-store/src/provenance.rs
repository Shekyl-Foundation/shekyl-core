// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a store's rows were written under (DRS-E1 increment 2; widened at
//! increment 3 / S-CHAIN-W).
//!
//! # Session intent versus file history
//!
//! [`ApplyPolicy`] is what **this run**
//! intends: which archival applies it will skip. It says nothing about the
//! rows already in the file. Increment 1 conflated the two and had to
//! invent `ApplyPolicy::Unknown` for every reopen — fail-closed, but it
//! meant a file's own history was unknowable from the file, so no reopen
//! could ever be parity evidence.
//!
//! [`Provenance`] is the file's answer: three monotone sets, each the
//! union over every **committed** batch, each persisted in its own header
//! cell and widened in the same transaction as the rows it describes.
//!
//! - **stubbed** — the archival families some batch's apply skipped
//!   (`apply_policy` cell; increment 2).
//! - **coverage gaps** — census rows some `connect` was handed a verdict
//!   for without the row having been evaluated (`rule_coverage_gaps`;
//!   C2-R8 §9.4 *"persisted with anything it writes"*).
//! - **passed-through facts** — `ConnectFacts` fields some `connect`
//!   recorded as passed through rather than derived
//!   (`passed_through_facts`; SCW-1).
//!
//! A store created under [`ApplyPolicy::Full`] starts [`Provenance::FULL`];
//! one created under a stub is sealed with that stub already recorded,
//! since it has been written under it from its first byte. A stubbed
//! session's commit, a partial-coverage connect, or a pass-through connect
//! taints it; nothing untaints it short of a rebuild. Reopen therefore
//! reads the record instead of guessing, and `Unknown` has no reason to
//! exist.
//!
//! # What it vouches for
//!
//! Only [`FULL`](Provenance::FULL) is parity evidence. That is the §7.1.1
//! hazard closed at the file: a green produced over a file that ever took
//! a stubbed commit — or a connect that skipped a rule, or one that
//! recorded a value the validator did not derive — carries the stamp, so
//! it cannot be mistaken for parity no matter which session produced it.
//! The floor is monotone per file, which is severe on purpose: **every
//! evidential run starts from a fresh file** (`DRS_E1_SCHAIN_W.md` §8).

use crate::apply_policy::ApplyPolicy;
use crate::codec::{CoverageGaps, PassedThroughFacts};
use crate::family_set::FamilySet;

/// What some committed batch over this file skipped, did not evaluate, or
/// did not derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Provenance {
    stubbed: FamilySet,
    coverage_gaps: CoverageGaps,
    passed_through: PassedThroughFacts,
}

impl Provenance {
    /// No committed batch ever skipped an apply, a row, or a derivation.
    /// The only provenance a parity claim may cite.
    pub const FULL: Self = Self {
        stubbed: FamilySet::EMPTY,
        coverage_gaps: CoverageGaps::NONE,
        passed_through: PassedThroughFacts::NONE,
    };

    /// A provenance whose skipped set is exactly `stubbed` and whose other
    /// two components are empty — the increment-2 shape, kept for the
    /// callers that only reason about applies.
    #[must_use]
    pub const fn of(stubbed: FamilySet) -> Self {
        Self {
            stubbed,
            coverage_gaps: CoverageGaps::NONE,
            passed_through: PassedThroughFacts::NONE,
        }
    }

    /// All three components, as read back from the header cells.
    #[must_use]
    pub const fn of_parts(
        stubbed: FamilySet,
        coverage_gaps: CoverageGaps,
        passed_through: PassedThroughFacts,
    ) -> Self {
        Self {
            stubbed,
            coverage_gaps,
            passed_through,
        }
    }

    /// The families some committed batch skipped.
    #[must_use]
    pub const fn stubbed(self) -> FamilySet {
        self.stubbed
    }

    /// The census rows some committed connect did not evaluate.
    #[must_use]
    pub const fn coverage_gaps(self) -> CoverageGaps {
        self.coverage_gaps
    }

    /// The facts some committed connect recorded without deriving.
    #[must_use]
    pub const fn passed_through(self) -> PassedThroughFacts {
        self.passed_through
    }

    /// Whether a comparator result over this file may be cited as parity
    /// evidence, or archived under §8.1.
    #[must_use]
    pub const fn is_parity_evidence(self) -> bool {
        self.stubbed.is_empty() && self.coverage_gaps.is_empty() && self.passed_through.is_empty()
    }

    /// This provenance after a batch begun under `policy` commits.
    ///
    /// Monotone: the result contains `self`. A `Full` session leaves it
    /// unchanged; a stubbed one adds its set.
    #[must_use]
    pub const fn widened_by(self, policy: ApplyPolicy) -> Self {
        Self {
            stubbed: self.stubbed.union(policy.stubbed_set()),
            ..self
        }
    }

    /// This provenance after a connect that left `gaps` unevaluated commits.
    #[must_use]
    pub const fn widened_by_gaps(self, gaps: CoverageGaps) -> Self {
        Self {
            coverage_gaps: self.coverage_gaps.union(gaps),
            ..self
        }
    }

    /// This provenance after a connect that passed `facts` through commits.
    #[must_use]
    pub const fn widened_by_passed_through(self, facts: PassedThroughFacts) -> Self {
        Self {
            passed_through: self.passed_through.union(facts),
            ..self
        }
    }

    /// `self ∪ other`, componentwise. What the mirror holds after a commit.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            stubbed: self.stubbed.union(other.stubbed),
            coverage_gaps: self.coverage_gaps.union(other.coverage_gaps),
            passed_through: self.passed_through.union(other.passed_through),
        }
    }

    /// A short tag for stamping artifacts.
    ///
    /// `apply-policy=full`, or the non-empty components spelled out with
    /// `NOT-PARITY-EVIDENCE`: `apply-policy=STUBBED[<tables>]`,
    /// `coverage-gaps=[<rows>]`, `passed-through=[<fields>]`. The
    /// `apply-policy=` key spelling is kept from increment 1 so existing
    /// artifact readers find it.
    #[must_use]
    pub fn artifact_stamp(self) -> String {
        if self.is_parity_evidence() {
            return "apply-policy=full".to_owned();
        }
        let mut parts = Vec::new();
        if self.stubbed.is_empty() {
            parts.push("apply-policy=full".to_owned());
        } else {
            parts.push(format!("apply-policy=STUBBED[{}]", self.stubbed));
        }
        if !self.coverage_gaps.is_empty() {
            parts.push(format!("coverage-gaps=[{}]", self.coverage_gaps));
        }
        if !self.passed_through.is_empty() {
            parts.push(format!("passed-through=[{}]", self.passed_through));
        }
        parts.push("NOT-PARITY-EVIDENCE".to_owned());
        parts.join(" ")
    }
}

impl core::fmt::Display for Provenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.artifact_stamp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_policy::ArchivalFamily;
    use shekyl_chain_rules::CenRow;

    #[test]
    fn only_all_three_empty_is_parity_evidence_and_each_widening_is_monotone() {
        assert!(Provenance::FULL.is_parity_evidence());
        assert_eq!(Provenance::FULL.artifact_stamp(), "apply-policy=full");

        let stubbed = Provenance::of(FamilySet::of(&[ArchivalFamily::Bond]));
        assert!(!stubbed.is_parity_evidence());
        assert!(stubbed
            .artifact_stamp()
            .starts_with("apply-policy=STUBBED["));

        let gaps = Provenance::FULL.widened_by_gaps(CoverageGaps::of([CenRow::ALL[0]]));
        assert!(!gaps.is_parity_evidence());
        assert_eq!(
            gaps.artifact_stamp(),
            format!(
                "apply-policy=full coverage-gaps=[{}] NOT-PARITY-EVIDENCE",
                CenRow::ALL[0]
            )
        );

        let passed =
            Provenance::FULL.widened_by_passed_through(PassedThroughFacts::of_positions([3]));
        assert!(!passed.is_parity_evidence());
        assert_eq!(
            passed.artifact_stamp(),
            "apply-policy=full passed-through=[burned] NOT-PARITY-EVIDENCE"
        );

        // Widening never narrows: union with FULL is identity, union is a
        // superset of both operands, and widening by nothing changes nothing.
        let all = stubbed.union(gaps).union(passed);
        assert_eq!(all.union(Provenance::FULL), all);
        assert_eq!(all.widened_by(ApplyPolicy::Full), all);
        assert_eq!(all.widened_by_gaps(CoverageGaps::NONE), all);
        assert_eq!(all.widened_by_passed_through(PassedThroughFacts::NONE), all);
        assert_eq!(all.stubbed(), stubbed.stubbed());
        assert_eq!(all.coverage_gaps(), gaps.coverage_gaps());
        assert_eq!(all.passed_through(), passed.passed_through());
        assert!(all.artifact_stamp().ends_with("NOT-PARITY-EVIDENCE"));
    }
}
