// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What agreement between the two stores *means* (CSR-3a, DRS-E2).
//!
//! DRS-E1's comparator is a direct table diff, LMDB against redb. **What
//! it compares changed; what agreement means did not.**
//! [`DAEMON_REDB_STORE.md`](../../../docs/design/DAEMON_REDB_STORE.md)
//! DRS-E2 rules it in terms: *"The acceptance condition is per conformance
//! state (CSR-3a), **not blanket digest identity** — blanket identity
//! requires redb to reproduce CEN-L11's silent omission in order to
//! pass."* A raw table diff **is** blanket identity, so its output is
//! graded per row rather than reduced to one pass/fail.
//!
//! This module is that grading, and it lands **before** the comparator it
//! grades. A grader written after the fact gets shaped by whatever the
//! comparator happened to emit.
//!
//! # The inversion that makes this necessary
//!
//! For a **DIVERGENT** row, *matching is failing*. CEN-L11 is the worked
//! case: a bucket-1 ratified rule whose implementation silently dropped an
//! accepted output. A byte-identical redb would have to **reproduce the
//! defect** to match — so on those rows identity is evidence against the
//! port, not for it. Every other state reads the obvious way, which is
//! precisely why this one needs a type rather than a convention.
//!
//! # UNREVIEWED arrives two ways, and a grader must accept both
//!
//! It is the register's **default by absence** — a live bucket-1/2 rule
//! with no conformance record is UNREVIEWED without anything saying so —
//! **and** an explicitly recorded state: `CEN-L8` carries
//! `**UNREVIEWED** — partial findings recorded; deliberately not promoted`,
//! which is a row that *failed closed* rather than one nobody looked at.
//! The two mean the same thing for acceptance and must not be collapsed in
//! the other direction: absence cannot be read as "fine".
//!
//! So [`ConformanceState::for_row`] is total over `Option`: `Some(state)`
//! for a recorded row, `None` for the by-absence case, and the caller that
//! can see both the register and the live rule set resolves which. The
//! by-absence set is a **computed set difference**, never a figure read
//! from prose.
//!
//! # The register at `origin/dev` `25e596632`
//!
//! **130 rows — 127 CHECKED-CONFORMANT, 2 DIVERGENT, 1 UNREVIEWED.**
//! `CEN-G6` and `CEN-G6b` are DIVERGENT for one shared cause: the ratified
//! short-term surge factor `S = 4` (C2-R2 Q3) against a shipped `×50`. So
//! the inversion above has **live rows to exercise it** — a byte-identical
//! redb reproduces the wrong constant and must fail.
//!
//! Reading that register needs its documented instrument: the state is
//! **anchored to the start of the state cell**. Matching the word anywhere
//! in the row over-counts, because promoted rows carry history
//! parentheticals like *"(was DIVERGENT, re-reviewed post-fix)"*; slicing
//! the section by heading under-counts, because §5.4.1 is **seven**
//! sub-tables at different pins rather than one. Both errors were made
//! while writing this module — in opposite directions — which is why the
//! gate cross-checks the per-row extraction against the stated totals
//! instead of trusting either alone.

/// A row's conformance state (CSR-3a).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConformanceState {
    /// Reviewed against the implementation and found to match its spec.
    CheckedConformant,
    /// Reviewed and found to diverge from its ratified spec. **Matching is
    /// failing** — see the module note.
    Divergent,
    /// Not reviewed to a conclusion. Arrives **two ways** and both grade the
    /// same: the default **by absence** (a live bucket-1/2 rule with no
    /// conformance record at all), or an **explicitly recorded** state — the
    /// register's `CEN-L8` carries `**UNREVIEWED**` because its review
    /// *failed closed* on an unwired clause. Neither grants correctness, and
    /// absence must never be read as "fine". An earlier version of this doc
    /// said "by absence" only, contradicting the module note and the CEN-L8
    /// test two screens down.
    Unreviewed,
}

impl ConformanceState {
    /// Resolve a row's state from the register.
    ///
    /// `recorded` is the state the register carries, or `None` when the row
    /// has no conformance record — which **is** [`Unreviewed`]. Written as
    /// a total function over `Option` so that "no record" cannot be
    /// silently dropped on the floor by a lookup that returns nothing.
    ///
    /// [`Unreviewed`]: ConformanceState::Unreviewed
    #[must_use]
    pub const fn for_row(recorded: Option<Self>) -> Self {
        match recorded {
            Some(s) => s,
            None => Self::Unreviewed,
        }
    }
}

/// What a compared row's result licenses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Acceptance {
    /// The row passes and the match **is** correctness evidence.
    AcceptedAsCorrect,
    /// The row fails: the port must be changed.
    Failed(FailureReason),
    /// Observed, but grants no correctness acceptance — regression signal
    /// only. No row leaves this without a DRS-P0f record.
    RegressionSignalOnly,
    /// The row diverged as its DIVERGENT record expects, but acceptance
    /// needs an explicitly reviewed expected-divergence or a replacement
    /// KAT asserting the corrected behaviour. **Not** an automatic pass.
    NeedsReviewedDivergence,
}

/// Why a graded row failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureReason {
    /// A CHECKED-CONFORMANT row differed between the stores.
    ConformantRowDiffered,
    /// A DIVERGENT row **matched** — the port reproduced the defect.
    ReproducedKnownDefect,
}

/// Grade one compared row.
///
/// `identical` is whether the two stores' logical projections agreed for
/// this row. The whole point of the function is that `identical == true`
/// is **not** uniformly good.
#[must_use]
pub const fn grade(state: ConformanceState, identical: bool) -> Acceptance {
    match (state, identical) {
        // Reviewed and conformant: a match is correctness evidence.
        (ConformanceState::CheckedConformant, true) => Acceptance::AcceptedAsCorrect,
        (ConformanceState::CheckedConformant, false) => {
            Acceptance::Failed(FailureReason::ConformantRowDiffered)
        }
        // Reviewed and divergent: matching means the port reproduced the
        // defect, which fails. Differing is expected but still needs a
        // reviewed expected-divergence or a replacement KAT.
        (ConformanceState::Divergent, true) => {
            Acceptance::Failed(FailureReason::ReproducedKnownDefect)
        }
        (ConformanceState::Divergent, false) => Acceptance::NeedsReviewedDivergence,
        // No record: observable either way, decisive neither way.
        (ConformanceState::Unreviewed, _) => Acceptance::RegressionSignalOnly,
    }
}

/// A reviewed expected-divergence or replacement KAT, **keyed to one row**.
///
/// A free citation would license *a* divergence; a row-keyed one licenses
/// only the row it names — the same distinction the register itself
/// enforces. **A `ReviewedDivergence` is not transferable between rows**: a
/// caller holding two DIVERGENT rows and one reviewed record may not reuse
/// it, or the row-keying means nothing.
///
/// # What this constructor checks, and what it deliberately does not
///
/// `new` keeps **arity and non-emptiness** only. It cannot resolve a
/// citation at const time, and faking validation at the type level would be
/// worse than none — a non-empty string that resolves to nothing is exactly
/// as much evidence as an empty one (rule 47). The real validation is a CI
/// leg that lands with the comparator, when discharge sites exist to check:
/// it asserts `row_id` is DIVERGENT in the live register
/// (`check_conformance_coverage.py` already parses that tally) and that
/// `citation` resolves as a `symbol (path:range)` reference
/// (`check_doc_code_citations.py` already resolves those). Wiring, not
/// machinery — but not yet wired, and this doc says so rather than implying
/// the constructor does it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReviewedDivergence {
    row_id: &'static str,
    citation: &'static str,
}

impl ReviewedDivergence {
    /// Cite the KAT or reviewed record that licenses `row_id`'s DIVERGENT
    /// mismatch — and only that row's.
    ///
    /// Returns `None` if either field is empty. Shape is gated here;
    /// resolution is gated in CI (see the type doc).
    #[must_use]
    pub const fn new(row_id: &'static str, citation: &'static str) -> Option<Self> {
        if row_id.is_empty() || citation.is_empty() {
            None
        } else {
            Some(Self { row_id, citation })
        }
    }

    /// The register row this evidence licenses, e.g. `"CEN-G6"`.
    #[must_use]
    pub const fn row_id(self) -> &'static str {
        self.row_id
    }

    /// The citation this evidence carries.
    #[must_use]
    pub const fn citation(self) -> &'static str {
        self.citation
    }
}

/// What [`discharge`] licenses after grading.
///
/// [`grade`] is the mechanical six-cell table. This is the frozen promotion
/// path E2's DIVERGENT rows actually use: a mismatch is not an automatic
/// pass. Adding an arm here is a signature change; adding a cell to
/// [`grade`] is not a way to sneak a DIVERGENT pass through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FinalVerdict {
    /// CHECKED-CONFORMANT match: correctness evidence.
    AcceptedAsCorrect,
    /// DIVERGENT mismatch with reviewed, row-keyed evidence: the port
    /// implemented the ratified spec, not the shipped defect. Carries the
    /// typed evidence rather than an unwrapped string, so the row-keying and
    /// non-emptiness survive into every consumer.
    AcceptedAsCorrected(ReviewedDivergence),
    /// The row failed. The port must change.
    Failed(FailureReason),
    /// UNREVIEWED: observed, grants no correctness.
    RegressionSignalOnly,
    /// DIVERGENT mismatch with no reviewed citation yet.
    AwaitingReview,
}

/// Promote a [`grade`] result. Evidence is meaningful only for
/// [`Acceptance::NeedsReviewedDivergence`]; it does not pardon a failure
/// and it does not decorate a conformant match.
#[must_use]
pub const fn discharge(graded: Acceptance, evidence: Option<ReviewedDivergence>) -> FinalVerdict {
    match graded {
        Acceptance::AcceptedAsCorrect => FinalVerdict::AcceptedAsCorrect,
        Acceptance::Failed(reason) => FinalVerdict::Failed(reason),
        Acceptance::RegressionSignalOnly => FinalVerdict::RegressionSignalOnly,
        Acceptance::NeedsReviewedDivergence => match evidence {
            Some(ev) => FinalVerdict::AcceptedAsCorrected(ev),
            None => FinalVerdict::AwaitingReview,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole truth table, stated once. Six cells, no gaps — a grader
    /// with an unreachable arm is a grader nobody has read.
    const TRUTH_TABLE: &[(ConformanceState, bool, Acceptance)] = &[
        (
            ConformanceState::CheckedConformant,
            true,
            Acceptance::AcceptedAsCorrect,
        ),
        (
            ConformanceState::CheckedConformant,
            false,
            Acceptance::Failed(FailureReason::ConformantRowDiffered),
        ),
        (
            ConformanceState::Divergent,
            true,
            Acceptance::Failed(FailureReason::ReproducedKnownDefect),
        ),
        (
            ConformanceState::Divergent,
            false,
            Acceptance::NeedsReviewedDivergence,
        ),
        (
            ConformanceState::Unreviewed,
            true,
            Acceptance::RegressionSignalOnly,
        ),
        (
            ConformanceState::Unreviewed,
            false,
            Acceptance::RegressionSignalOnly,
        ),
    ];

    #[test]
    fn the_truth_table_is_exhaustive_and_holds() {
        for &(state, identical, expected) in TRUTH_TABLE {
            assert_eq!(
                grade(state, identical),
                expected,
                "{state:?} identical={identical}"
            );
        }
        // Three states times two outcomes; if a state is added, this fails
        // rather than the new state silently inheriting a neighbour's arm.
        assert_eq!(TRUTH_TABLE.len(), 3 * 2);
    }

    #[test]
    fn a_divergent_row_that_matches_is_a_failure() {
        // The inversion, asserted on its own because it is the one arm a
        // reader will assume backwards, and the reason DRS-E2 forbids
        // blanket identity. CEN-L11 is the worked case.
        assert_eq!(
            grade(ConformanceState::Divergent, true),
            Acceptance::Failed(FailureReason::ReproducedKnownDefect)
        );
        // And it must NOT be confused with the conformant failure: the two
        // failures are different findings with different remedies.
        assert_ne!(
            grade(ConformanceState::Divergent, true),
            grade(ConformanceState::CheckedConformant, false)
        );
    }

    #[test]
    fn identity_alone_never_decides_a_row() {
        // For each outcome of `identical`, the three states disagree — so a
        // comparator that reported only "identical" would be reporting a
        // value from which the verdict cannot be recovered. That is what
        // "not blanket digest identity" means, made checkable.
        for identical in [true, false] {
            let verdicts = [
                grade(ConformanceState::CheckedConformant, identical),
                grade(ConformanceState::Divergent, identical),
                grade(ConformanceState::Unreviewed, identical),
            ];
            assert_eq!(
                verdicts.len(),
                verdicts
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                "identical={identical}: states must not collapse to one verdict"
            );
        }
    }

    #[test]
    fn absence_of_a_record_is_unreviewed_not_a_dropped_row() {
        assert_eq!(
            ConformanceState::for_row(None),
            ConformanceState::Unreviewed
        );
        assert_eq!(
            ConformanceState::for_row(Some(ConformanceState::CheckedConformant)),
            ConformanceState::CheckedConformant
        );
    }

    #[test]
    fn the_divergent_arms_have_live_rows_cen_g6_and_g6b() {
        // These arms are NOT synthetic-only. CEN-G6 and CEN-G6b are
        // DIVERGENT at `origin/dev` `25e596632` for one shared cause — the
        // ratified surge factor S = 4 against a shipped x50 — which is
        // exactly the DRS-E2 shape: a ratified value the C++ does not
        // implement, so a byte-identical redb reproduces the wrong constant
        // and must FAIL rather than pass.
        //
        // An earlier draft of this test asserted the opposite, that no row
        // was DIVERGENT and the arms could only be reached by fabrication.
        // That came from slicing the register by heading and catching one
        // of its seven sub-tables. The arms are exercisable against real
        // data; this asserts the semantics, and the comparator run over
        // G6/G6b is what will exercise them end to end.
        assert_eq!(
            grade(ConformanceState::Divergent, true),
            Acceptance::Failed(FailureReason::ReproducedKnownDefect)
        );
        assert_eq!(
            grade(ConformanceState::Divergent, false),
            Acceptance::NeedsReviewedDivergence
        );
    }

    #[test]
    fn an_explicit_unreviewed_grades_like_an_absent_one() {
        // CEN-L8 carries an explicit UNREVIEWED token — it failed closed
        // rather than going unexamined. Acceptance must not distinguish it
        // from the by-absence case: neither grants correctness.
        for identical in [true, false] {
            assert_eq!(
                grade(
                    ConformanceState::for_row(Some(ConformanceState::Unreviewed)),
                    identical
                ),
                grade(ConformanceState::for_row(None), identical)
            );
        }
    }

    #[test]
    fn a_divergent_mismatch_awaits_review_until_cited() {
        let graded = grade(ConformanceState::Divergent, false);
        assert_eq!(discharge(graded, None), FinalVerdict::AwaitingReview);
        assert_eq!(ReviewedDivergence::new("CEN-G6", ""), None);
        let evidence = ReviewedDivergence::new("CEN-G6", "CEN-G6 KAT: S=4").expect("non-empty");
        assert_eq!(
            discharge(graded, Some(evidence)),
            FinalVerdict::AcceptedAsCorrected(evidence)
        );
        // The verdict carries the TYPED evidence, so the row it licenses is
        // recoverable downstream rather than lost in an unwrapped string.
        if let FinalVerdict::AcceptedAsCorrected(ev) = discharge(graded, Some(evidence)) {
            assert_eq!(ev.row_id(), "CEN-G6");
        } else {
            panic!("expected AcceptedAsCorrected");
        }
    }

    #[test]
    fn evidence_is_keyed_to_a_row_and_both_halves_are_required() {
        // Shape is gated here; resolution is gated in CI when discharge sites
        // exist. A free citation licenses A divergence; a row-keyed one
        // licenses only the row it names.
        assert_eq!(
            ReviewedDivergence::new("", "CEN-G6 KAT: S=4"),
            None,
            "row_id required"
        );
        assert_eq!(
            ReviewedDivergence::new("CEN-G6", ""),
            None,
            "citation required"
        );
        let a = ReviewedDivergence::new("CEN-G6", "CEN-G6 KAT: S=4").expect("valid");
        let b = ReviewedDivergence::new("CEN-G6b", "CEN-G6 KAT: S=4").expect("valid");
        // Same citation, different row: NOT the same evidence. A caller with
        // two DIVERGENT rows and one reviewed record may not reuse it.
        assert_ne!(a, b);
        assert_eq!(a.row_id(), "CEN-G6");
        assert_eq!(b.row_id(), "CEN-G6b");
    }

    #[test]
    fn evidence_does_not_pardon_a_failure_or_decorate_a_match() {
        let defect = grade(ConformanceState::Divergent, true);
        let evidence = ReviewedDivergence::new("CEN-G6", "should not pardon").expect("non-empty");
        assert_eq!(
            discharge(defect, Some(evidence)),
            FinalVerdict::Failed(FailureReason::ReproducedKnownDefect)
        );
        let ok = grade(ConformanceState::CheckedConformant, true);
        assert_eq!(
            discharge(ok, Some(evidence)),
            FinalVerdict::AcceptedAsCorrect
        );
    }
}
