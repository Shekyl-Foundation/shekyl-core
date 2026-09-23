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

pub(crate) mod anchors;
pub(crate) mod difficulty;
pub(crate) mod header;
pub(crate) mod miner;
pub(crate) mod pow;
pub use pow::seed_height;
pub(crate) mod timestamps;
pub(crate) mod topology;

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rule_set::RuleSet;
use crate::rules::difficulty::Target;
use crate::rules::timestamps::MtpWindow;
use crate::trust::Trust;
use crate::verdict::Verdict;
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};
use shekyl_types::BlockHeight;

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

/// What a **view-bound** block-level rule may read besides the view: the
/// connect's derived facts, computed once in `validate` before the
/// predicates run.
///
/// The connecting height is the operand almost every view-bound rule
/// needs (genesis exemption, seed height, MTP window, DAA window, B5's
/// root key). It is derived from the tip here, so a rule does not
/// re-read `view.tip()` and C1 does not infer genesis from
/// `mtp_window.is_none()`. The view stays beside the context for
/// per-rule lookups that are not shared (`root_at`, further `block_at`).
pub(crate) struct BlockContext<'a> {
    /// What `form` established — the candidate, the clock reading (C1),
    /// the seed claim, the longhash.
    pub(crate) formed: &'a StructurallyValid,
    /// Height this candidate will occupy. `ZERO` is genesis admission.
    pub(crate) connecting: BlockHeight,
    /// The recorded tip this candidate connects onto; `None` at genesis.
    pub(crate) tip: Option<Tip>,
    /// C3's window. `None` at genesis — the same fact as
    /// `connecting.is_zero()`, not a second genesis signal. C1 reads the
    /// height; C2 reads the window.
    pub(crate) mtp_window: Option<MtpWindow>,
    /// D4's target. D1 compares `formed.pow()` against it.
    pub(crate) target: Target,
    /// What this node takes on the release's word — the anchors (E1 reads
    /// them at anchored heights); from slice 6, the posture the 4.I rows
    /// read.
    pub(crate) trust: &'a Trust,
}

impl<'a> BlockContext<'a> {
    pub(crate) fn new(
        formed: &'a StructurallyValid,
        tip: Option<Tip>,
        mtp_window: Option<MtpWindow>,
        target: Target,
        trust: &'a Trust,
    ) -> Self {
        Self {
            formed,
            connecting: Tip::connecting_height(tip.as_ref()),
            tip,
            mtp_window,
            target,
            trust,
        }
    }

    /// The untrusted candidate, exactly as received.
    pub(crate) const fn candidate(&self) -> &Candidate {
        self.formed.candidate()
    }

    /// Isolated-rule tests that read neither the target nor the anchors.
    /// Production `validate` always passes D4's target and the driver's
    /// `Trust`.
    #[cfg(test)]
    pub(crate) fn for_tests(
        formed: &'a StructurallyValid,
        tip: Option<Tip>,
        mtp_window: Option<MtpWindow>,
    ) -> Self {
        Self::new(
            formed,
            tip,
            mtp_window,
            Target::GENESIS_BLOCK,
            &Trust::UNANCHORED,
        )
    }
}

/// A view-bound block-level rule (census 4.A–4.G): judges the candidate
/// against the recorded chain. Runs in `validate`, inside the write
/// transaction that will apply the block.
pub(crate) trait BlockRule: Rule {
    /// `Ok(Ok(()))` passed; `Ok(Err(refused))` refused on `Self::ROW`;
    /// `Err(fault)` the view could not answer. Shared connect facts (tip,
    /// connecting height, window, target) live on [`BlockContext`]. A rule
    /// that needs a further recorded fact reads `view` itself — a root, a
    /// parent — so a new shared fact is a new context field, and a new
    /// per-rule lookup is a new `ChainView` method.
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

/// The recorded block at `height`, which is below the connecting height
/// and therefore present on a conforming view (a hole is the store's SI-7,
/// reported as its fault before this arm). Shared by every rule that reads
/// a parent-side fact (D4's window and work, F13's accumulator, F20's
/// prefix sums).
pub(crate) fn recorded<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<RecordedBlock, V::Fault> {
    Ok(match view.block_at(height)? {
        AtHeight::Recorded(block) => block,
        AtHeight::AboveTip => unreachable!("heights below the connecting height are recorded"),
    })
}
