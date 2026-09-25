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
//! coverage, and `RuleCoverage::insert` names them.
//!
//! The **per-transaction** classes have the same two shapes one level down.
//! A [`TxRule`] (census 4.H) judges one transaction from its bytes alone —
//! a [`TxContext`]: the transaction, which position it occupies
//! ([`TxKind`], derived from the transaction and never declared by the
//! caller), and the rule set — and runs in `tx_form`, which the pool
//! (DRS-E5) shares with `validate`. Each rule states its [`TxScope`]: a
//! row the C++ applies to non-coinbase transactions only is recorded
//! **vacuous** on the coinbase rather than skipped (slice 5 Q2 — CEN-E1's
//! precedent at an unanchored height), so coverage says the row was
//! evaluated at every slot and the pool cannot mis-declare a kind. The
//! 4.I class (`tx_against`, view-bound) arrives with slice 6.
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
pub(crate) mod tx;

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, ViewRead};
use crate::rule_set::RuleSet;
use crate::rules::difficulty::Target;
use crate::rules::timestamps::MtpWindow;
use crate::rules::tx::TxClass;
use crate::trust::Trust;
use crate::verdict::{Locus, TxSlot, Verdict};
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};
use shekyl_types::BlockHeight;
use shekyl_wire::Transaction;

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

/// Which position a transaction occupies, for the rules whose statement
/// names one. **Derived from the slot**, never declared: `TxSlot::Miner` is
/// the coinbase position and every other slot is not. Not derived from the
/// bytes — a sole-`gen` transaction listed in a block, or submitted to the
/// pool on its own, is coinbase-*shaped* and must be refused (CEN-H5) by
/// the rules that are stated for non-coinbase transactions, which a
/// bytes-derived kind would exempt (slice 5 Q2 as amended). The pool holds
/// one slot, [`TxSlot::Lone`](crate::verdict::TxSlot::Lone), so it cannot
/// mis-declare; only `validate` names the miner, for the block's own miner
/// field.
///
/// The principle, since it will recur (slice 5 Q2, ruled 2026-09-23): **a
/// classification that selects which rules apply must come from outside
/// the thing being classified.** Position in a block is a fact about the
/// block; position in the pool is a fact about the pool; `is_coinbase()` is
/// a fact the submitter controls, and an input that selects the rule set it
/// is judged under is a self-exempting input. Same family as `ChainValid`
/// being unforgeable and `held_by_cxx` needing a rejection test rather than
/// a grep: authority sits with something the adversary does not author. The
/// C++ has no such gap only because `ver_non_input_consensus` never sees a
/// coinbase — an accident of call site, not a property of the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxKind {
    /// The block's miner transaction — whatever its bytes; CEN-F1 judges
    /// that they are a sole `Input::Gen`.
    Coinbase,
    /// Everything else — a listed transaction, or a lone one at the pool.
    Listed,
}

impl TxKind {
    /// The kind a slot implies.
    pub(crate) const fn of(slot: TxSlot) -> Self {
        match slot {
            TxSlot::Miner => Self::Coinbase,
            TxSlot::Listed(_) | TxSlot::Lone => Self::Listed,
        }
    }
}

/// Which transactions a [`TxRule`] judges. The C++ runs
/// `ver_non_input_consensus` over the pool supplement only and reaches the
/// coinbase through three block-side calls, so most 4.H rows are stated for
/// non-coinbase transactions and a few for all; the scope is the rule's to
/// state, and [`run_tx`] records an out-of-scope row as **vacuous** rather
/// than skipping it (slice 5 Q2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxScope {
    /// Every transaction, the coinbase included.
    All,
    /// Non-coinbase transactions; vacuous on the coinbase.
    NonCoinbase,
}

impl TxScope {
    /// Whether a rule with this scope judges a transaction of `kind`.
    pub(crate) const fn applies_to(self, kind: TxKind) -> bool {
        match self {
            Self::All => true,
            Self::NonCoinbase => matches!(kind, TxKind::Listed),
        }
    }
}

/// What a **stateless per-transaction** rule may read: the transaction and
/// its kind. No view, by construction — a rule that needs one is a 4.I rule
/// (`tx_against`, slice 6). No rule set either, yet: every 4.H limit is a
/// frozen constant beside its rule (`rules::tx`), the F21 arrangement — a
/// limit joins `RuleSet` when a schedule step can name a different one, and
/// the first such row adds the field. A struct so the set can grow without
/// moving any rule's signature, as [`FormContext`] is.
pub(crate) struct TxContext<'a> {
    /// The transaction, exactly as parsed.
    pub(crate) tx: &'a Transaction,
    /// The slot the transaction occupies — where a refusal points.
    pub(crate) slot: TxSlot,
    /// Derived from `slot`, never declared.
    pub(crate) kind: TxKind,
    /// What kind of transaction the inputs make this — derived once
    /// ([`TxClass::derive`]), judging CEN-H5 and CEN-H6 as it goes, and read
    /// by every rule whose shape depends on it (H14, H20–H22).
    pub(crate) class: TxClass,
}

impl<'a> TxContext<'a> {
    /// Build the context, deriving the class. A refusal here is H5's or
    /// H6's, at `slot`; both rows are recorded in `coverage` when they pass
    /// — at their derivation site, the CEN-B6 arrangement.
    pub(crate) fn derive(
        tx: &'a Transaction,
        slot: TxSlot,
        coverage: &mut RuleCoverage,
    ) -> Verdict<Self> {
        let kind = TxKind::of(slot);
        let class = TxClass::derive(tx, slot, kind, coverage)?;
        Ok(Self {
            tx,
            slot,
            kind,
            class,
        })
    }

    /// Where this transaction's refusals point.
    pub(crate) const fn locus(&self) -> Locus {
        Locus::Tx { slot: self.slot }
    }
}

/// A stateless per-transaction rule (census 4.H): judges one transaction
/// from its bytes alone. Runs in `tx_form`, at block connect for every
/// slot and at pool admission for a lone transaction — one function, two
/// sites, which is the C++'s `ver_non_input_consensus` arrangement kept.
///
/// No fault position: nothing a 4.H rule reads can fail to answer.
/// `Ok(())` passed; `Err(refused)` refused on `Self::ROW` at the context's
/// [`locus`](TxContext::locus) — the slot the caller judged.
pub(crate) trait TxRule: Rule {
    /// Which transactions this rule judges.
    const SCOPE: TxScope;
    fn check(cx: &TxContext<'_>) -> Verdict<()>;
}

/// Run one per-transaction rule and record its row: as passed if it ran and
/// passed, as **vacuous** if the rule's scope excludes this transaction's
/// kind. Both are "the row was evaluated at this slot"; a rule that was not
/// run at all is not in coverage.
pub(crate) fn run_tx<R: TxRule>(cx: &TxContext<'_>, coverage: &mut RuleCoverage) -> Verdict<()> {
    if !R::SCOPE.applies_to(cx.kind) {
        coverage.insert(R::ROW);
        return Ok(());
    }
    let verdict = R::check(cx);
    if verdict.is_ok() {
        coverage.insert(R::ROW);
    }
    verdict
}

/// Run one per-transaction rule whose census row is not yet `implemented`.
///
/// Scope applies, as in [`run_tx`]: an out-of-scope kind is not judged.
/// A pass is not coverage. Recording a half-landed row would claim it.
/// The caller switches to [`run_tx`] in the commit that flips the row.
pub(crate) fn run_tx_unrecorded<R: TxRule>(cx: &TxContext<'_>) -> Verdict<()> {
    if !R::SCOPE.applies_to(cx.kind) {
        return Ok(());
    }
    R::check(cx)
}

/// The recorded block at `height`, which is below the connecting height
/// and therefore present on a conforming view. Shared by every rule that
/// reads a parent-side fact (D4's window and work, F13's accumulator,
/// F20's prefix sums).
///
/// A hole here is the store's SI-7, which a conforming store reports as
/// its own fault before this arm; a view that answers `AboveTip` anyway
/// is [`Corrupt::HoleBelowTip`] — the fault class that halts the writer,
/// not a panic defended by the invariant it would be observing broken
/// (`fault.rs`, the variant's docs).
pub fn recorded<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<RecordedBlock, ViewRead<V::Fault>> {
    match view.block_at(height).map_err(ViewRead::View)? {
        AtHeight::Recorded(block) => Ok(block),
        AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip { at: height })),
    }
}
