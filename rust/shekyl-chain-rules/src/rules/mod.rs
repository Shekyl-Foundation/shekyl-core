// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rules themselves, one type per census row, bound to their row by the
//! type system (S-CHAIN-W SCW-18; `CHAIN_RULES_SLICE_1.md` §5).
//!
//! # Why a type per row and not a function per row
//!
//! The registry's `implemented(path)` pin (`census.rs`, G9) proves the path
//! *exists*: `use path as _` refuses a rule that moved or was deleted. It
//! does not prove the path is *this row's* rule — `implemented(rules::
//! header::B2)` under the `B1` entry compiles, and the gate then counts B2's
//! function toward B1's row. A function's signature cannot carry the row;
//! a type can. Every rule is a unit struct implementing [`Rule`] with
//! `const ROW: CenRow`, the registry entry names the **type**, and
//! `census_rows!` emits a `const` assertion that `<T as Rule>::ROW` is the
//! entry's own variant. Row binding is structural, not nominal, and it was
//! decided before the first rule so the migration is one call site rather
//! than 153 (SCW-18).
//!
//! # One signature per rule class — and the class is view-dependence
//!
//! Two block-level shapes, one per stage (`CHAIN_RULES_SLICE_2.md` §4.2,
//! Q1/Q9 as ruled). [`FormRule::check`] is the **stateless** shape: the
//! candidate, the rule set and the clock reading through a
//! [`FormContext`], nothing else — B1, B2, B7 read only those, so they
//! belong here whatever slice added them. [`BlockRule::check`] is the
//! **view-bound** shape: a [`BlockContext`] (the candidate, the rule set, and
//! what `form` established) with the view beside it. A rule that needs a
//! chain fact (the tip, for A2 and B5; the seed block, for D3) reads it from
//! the view, so a new fact is a new `ChainView` method and no rule's
//! signature moves. Stage membership is a *property* — does the rule read
//! the view — not a record of which slice landed it; a stage whose
//! membership was "whatever slice 2 happened to add" would be the accretion
//! pattern with a trait name on it.
//!
//! `form` and `validate` each run their landed **predicate** rows from a
//! list, and [`run_form`] / [`run`] record `R::ROW` themselves: a rule cannot
//! record another row's coverage, and a rule that was not run is not in
//! coverage (G6, G9's runtime half). A **definition** row — one whose
//! "check" is a derivation the verdict carries (CEN-B6; CEN-D4's target,
//! CEN-D2's longhash) — is not in either list: it records its own `ROW` at
//! the derivation site ([`header::B6::identity`]), so a gate that could
//! never fail is never run as one (slice 1 Q5). Those are the writers of
//! coverage, and `RuleCoverage::insert` names them. The per-transaction
//! classes (4.H `tx_form`, 4.I `tx_against`) get their own traits with their
//! slices.
//!
//! # Where a refusal is written
//!
//! At the site that judged, as [`refused`](crate::refused)`(Self::ROW,
//! locus)`. The row is therefore named twice — structurally by `ROW`, and at
//! the arm — and the pin holds the two together: a rule that refuses under
//! another row's id still records its own coverage, and the fixture for the
//! other row fails. `?` inside a rule propagates a **fault** and only a fault
//! (`view.rs`, "Three answers, three positions").

pub(crate) mod difficulty;
pub(crate) mod header;
pub(crate) mod pow;
pub(crate) mod timestamps;
pub(crate) mod topology;

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rule_set::RuleSet;
use crate::rules::timestamps::MtpWindow;
use crate::verdict::Verdict;
use crate::view::ChainView;

/// A consensus rule, bound to the census row it implements.
///
/// Implemented by unit structs; `ROW` is what the registry pin checks
/// (`census.rs`, SCW-18) and what [`run`] records in coverage.
pub(crate) trait Rule {
    /// The census row this type implements.
    const ROW: CenRow;
}

/// The row a rule type is bound to, generic over the registry it belongs
/// to. The `census_rows!` pin reads `<T as Bound<Name>>::ROW`, so the one
/// macro serves both registries: every [`Rule`] is `Bound<CenRow>`; a
/// policy rule (DRS-E5) will be `Bound<PolicyRow>` through its own trait.
pub(crate) trait Bound<R> {
    /// The row.
    const ROW: R;
}

impl<T: Rule> Bound<CenRow> for T {
    const ROW: CenRow = T::ROW;
}

/// What a **stateless** block-level rule may read: the candidate and the
/// rule set. No view, by construction — a rule that needs one is a
/// [`BlockRule`]. The clock `form` reads is not here either: its one
/// consumer (CEN-C1) also reads the connecting height for the genesis
/// exemption, so the comparison is view-bound and the reading travels on
/// the `StructurallyValid` instead.
///
/// A struct rather than positional arguments so the set can grow without
/// moving any rule's signature (rule 26 A1: freeze the signature, replace
/// the body).
pub(crate) struct FormContext<'a> {
    /// The untrusted candidate, exactly as received.
    pub(crate) candidate: &'a Candidate,
    /// The rules the caller claims are in force; `validate` checks the
    /// claim against the committing view.
    pub(crate) rule_set: &'a RuleSet,
}

impl<'a> FormContext<'a> {
    pub(crate) const fn new(candidate: &'a Candidate, rule_set: &'a RuleSet) -> Self {
        Self {
            candidate,
            rule_set,
        }
    }
}

/// A stateless block-level rule: judges the candidate with no view. Runs in
/// `form`, outside the write transaction, in parallel with other blocks.
///
/// No fault position: everything a form rule reads was read before it ran
/// (`form` takes the clock once, up front). `Ok(())` passed;
/// `Err(refused)` refused on `Self::ROW`.
pub(crate) trait FormRule: Rule {
    fn check(cx: &FormContext<'_>) -> Verdict<()>;
}

/// Run one form rule and, if it passed, record its row.
pub(crate) fn run_form<R: FormRule>(
    cx: &FormContext<'_>,
    coverage: &mut RuleCoverage,
) -> Verdict<()> {
    let verdict = R::check(cx);
    if verdict.is_ok() {
        coverage.insert(R::ROW);
    }
    verdict
}

/// What a **view-bound** block-level rule may read besides the view. Built
/// from the [`StructurallyValid`] the stateless stage produced and the
/// definitions `validate` derives before the predicates run; fields grow
/// with the rows that read them (the rule set with 4.D), never ahead of
/// them.
///
/// The view is passed beside it, not inside it, so `V` and its `Fault` stay
/// on the method and the context is one type for every view.
pub(crate) struct BlockContext<'a> {
    /// The untrusted candidate, exactly as received.
    pub(crate) candidate: &'a Candidate,
    /// What `form` established — the clock reading (C1), the seed claim.
    pub(crate) formed: &'a StructurallyValid,
    /// The median-time-past window at the connecting height (C3's
    /// definition); `None` at genesis. Read by C1 (the genesis exemption)
    /// and C2.
    pub(crate) mtp_window: Option<MtpWindow>,
    /// Whether the longhash satisfies the target under the ported
    /// comparison (D1b's definition, evaluated once over D4's target). D1
    /// acts on it; the target itself travels on the verdict, not here.
    pub(crate) pow_meets_target: bool,
}

impl<'a> BlockContext<'a> {
    pub(crate) const fn new(
        formed: &'a StructurallyValid,
        mtp_window: Option<MtpWindow>,
        pow_meets_target: bool,
    ) -> Self {
        Self {
            candidate: formed.candidate(),
            formed,
            mtp_window,
            pow_meets_target,
        }
    }
}

/// A view-bound block-level rule (census 4.A–4.G): judges the candidate
/// against the recorded chain. Runs in `validate`, inside the write
/// transaction that will apply the block.
pub(crate) trait BlockRule: Rule {
    /// `Ok(Ok(()))` passed; `Ok(Err(refused))` refused on `Self::ROW`;
    /// `Err(fault)` the view could not answer. A rule that needs the
    /// recorded chain reads `view` itself — the tip, a parent, a root — so
    /// a new read is a new `ChainView` method, never a new parameter here.
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        view: &V,
    ) -> Result<Verdict<()>, V::Fault>;
}

/// Run one block rule and, if it passed, record its row.
///
/// Records a **predicate** row that ran and passed.
///
/// Definition rows (CEN-B6) are not [`BlockRule`]s — nothing about a
/// candidate can fail them — and record at their derivation site
/// ([`crate::rules::header::B6::identity`]), when the identity is
/// derived. Predicate rows go through this function; a definition row
/// named `implemented(...)` is the function that produces the value.
pub(crate) fn run<'id, R: BlockRule, V: ChainView<'id>>(
    cx: &BlockContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, V::Fault> {
    let verdict = R::check(cx, view)?;
    if verdict.is_ok() {
        coverage.insert(R::ROW);
    }
    Ok(verdict)
}
