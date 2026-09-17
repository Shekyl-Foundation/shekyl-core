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
//! # One signature per rule class
//!
//! [`BlockRule::check`] is the block-level shape: the candidate and the rule
//! set through a [`BlockContext`], and the view beside it. A rule that needs
//! a chain fact (the tip, for A2 and B5) reads it from the view, so a new
//! fact is a new `ChainView` method and no rule's signature moves. `validate`
//! runs the landed **predicate** rows from a list and [`run`] records
//! `R::ROW` itself: a rule cannot record another row's coverage, and a rule
//! that was not run is not in coverage (G6, G9's runtime half). A
//! **definition** row — one whose "check" is a derivation the verdict
//! carries, today only CEN-B6 — is not in that list: it records its own
//! `ROW` at the derivation site ([`header::B6::identity`]), so a gate that
//! could never fail is never run as one (slice 1 Q5). Those are the two
//! writers of coverage, and `RuleCoverage::insert` names both. The
//! per-transaction classes (4.H `tx_form`, 4.I `tx_against`) get their own
//! traits with their slices.
//!
//! # Where a refusal is written
//!
//! At the site that judged, as [`refused`](crate::refused)`(Self::ROW,
//! locus)`. The row is therefore named twice — structurally by `ROW`, and at
//! the arm — and the pin holds the two together: a rule that refuses under
//! another row's id still records its own coverage, and the fixture for the
//! other row fails. `?` inside a rule propagates a **fault** and only a fault
//! (`view.rs`, "Three answers, three positions").

pub(crate) mod header;
pub(crate) mod topology;

use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rule_set::RuleSet;
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

/// What a block-level rule may read besides the view.
///
/// A struct rather than positional arguments so the set can grow without
/// moving any rule's signature (rule 26 A1: freeze the signature, replace
/// the body). The view is passed beside it, not inside it, so `V` and its
/// `Fault` stay on the method and the context is one type for every view.
pub(crate) struct BlockContext<'a> {
    /// The untrusted candidate, exactly as received.
    pub(crate) candidate: &'a Candidate,
    /// The rules in force at the connecting height.
    pub(crate) rule_set: &'a RuleSet,
}

impl<'a> BlockContext<'a> {
    pub(crate) const fn new(candidate: &'a Candidate, rule_set: &'a RuleSet) -> Self {
        Self {
            candidate,
            rule_set,
        }
    }
}

/// A block-level rule (census 4.A–4.G): judges the candidate as a whole.
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
