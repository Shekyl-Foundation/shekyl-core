// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which rows a verdict actually evaluated.
//!
//! A verdict that says "valid" is only as strong as the rules that ran.
//! [`Coverage`] is the set of census rows a `ChainValid` was judged under,
//! carried with it and persisted beside anything the store writes on its
//! strength (ruling §9.4). Two instantiations, one per census flag —
//! [`RuleCoverage`] over [`CenRow`], [`PolicyCoverage`] over
//! [`PolicyRow`] — and because they are different types, a policy row cannot
//! be counted toward consensus coverage (round-1 ruling Q4): proximity
//! promotion through the instrument does not compile.
//!
//! Only **complete** coverage is parity evidence. A verdict carries the rows
//! that actually ran, and `is_complete_for` is `false` until every row the
//! rule set holds the per-block stages to has landed, so no `ChainValid`
//! minted during the port can be mistaken for parity evidence by anything
//! that checks. The gate prints three readings
//! (`check_chain_rules_coverage.py`): **enforced** `E` is the census's —
//! every consensus row of bucket ≠ 3, fixed by the census and moved by
//! nothing in this crate. **validator-enforced** `E − H` excludes the rows
//! the C++ ingest driver holds until cutover (`RowStatus::HeldByCxx`).
//! **per-block** `E − H − O − B` also excludes rows this crate enforces
//! outside the per-block stages (`RowStatus::EnforcedAt` — CEN-E5 at writer
//! open) and rows that hold by construction (`RowStatus::ByConstruction` —
//! CEN-F2, F8, F19: the type system or the wire's parser, with a falsifier
//! the gate asserts). [`RuleSet::enforced`](crate::RuleSet::enforced) is
//! that per-block reading. Completeness is measured against it. `E` is
//! printed beside it so a hold, an at-open row or a by-construction row
//! reads as a subtraction, never as a smaller denominator.
//! The live figures are the gate's, not this comment's.

use core::fmt;
use core::marker::PhantomData;

use crate::census::{CenRow, PolicyRow, Row, RowStatus};
use crate::rule_set::RuleSet;

/// The rows of one census flag a verdict evaluated.
///
/// A bitset over [`Row::index`]. Four words cover the whole `u8` index
/// space, so `insert` has no out-of-range case and a registry that grew
/// past 256 rows would fail at the `#[repr(u8)]` enum, not here.
///
/// The flag partition is the type parameter. A [`PolicyRow`] is not a
/// question a [`RuleCoverage`] can answer:
///
/// ```compile_fail
/// use shekyl_chain_rules::{PolicyRow, RuleCoverage};
/// let _ = RuleCoverage::EMPTY.contains(PolicyRow::M1);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Coverage<R: Row> {
    words: [u64; 4],
    _rows: PhantomData<R>,
}

/// Consensus coverage: the [`CenRow`]s a `ChainValid` was judged under.
pub type RuleCoverage = Coverage<CenRow>;

/// Policy coverage: the [`PolicyRow`]s an admission decision applied.
/// DRS-E5's; staged with `AdmissionPolicy`.
pub type PolicyCoverage = Coverage<PolicyRow>;

impl<R: Row> Coverage<R> {
    /// No rows evaluated. What every verdict carries until rules land.
    pub const EMPTY: Self = Self {
        words: [0; 4],
        _rows: PhantomData,
    };

    fn slot(row: R) -> (usize, u64) {
        let index = row.index();
        (usize::from(index / 64), 1 << (index % 64))
    }

    /// Whether `row` was evaluated.
    #[must_use]
    pub fn contains(&self, row: R) -> bool {
        let (word, bit) = Self::slot(row);
        self.words[word] & bit != 0
    }

    /// How many rows were evaluated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether no row was evaluated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words == [0; 4]
    }

    /// The evaluated rows in census order — the form the store encodes at
    /// S-CHAIN-W without reaching into the words. Persist [`Row::as_str`],
    /// never [`Row::index`]: `index` is the bitset slot and shifts when the
    /// census inserts a row.
    pub fn iter(&self) -> impl Iterator<Item = R> + '_ {
        R::ALL
            .iter()
            .copied()
            .filter(move |row| self.contains(*row))
    }

    /// Record that `row` was evaluated. Crate-private, with exactly two
    /// writers, one per row kind: [`crate::rules::run`] for a **predicate**
    /// row, after the rule bound to it passed; and a **definition** row's
    /// derivation function, at the site that derived — today
    /// [`crate::rules::header::B6::identity`], the only definition row
    /// landed (slice 1 Q5: B6 is registered as the derivation, not as a
    /// check that always passes). A third writer is a new row kind and a
    /// registry decision, not a convenience. (Slice 1 un-staged this; the
    /// scaffold's `expect(dead_code)` marker went with the first rule, as it
    /// was written to.)
    pub(crate) fn insert(&mut self, row: R) {
        let (word, bit) = Self::slot(row);
        self.words[word] |= bit;
    }

    /// Fold `other` in. Crate-private: `validate` unions the per-tx
    /// coverages into the block's.
    pub(crate) fn union(&mut self, other: &Self) {
        for (mine, theirs) in self.words.iter_mut().zip(other.words) {
            *mine |= theirs;
        }
    }
}

impl Coverage<CenRow> {
    /// `true` iff every one of `rows` is present.
    pub(crate) fn contains_all(&self, rows: impl IntoIterator<Item = CenRow>) -> bool {
        rows.into_iter().all(|row| self.contains(row))
    }

    /// `true` iff every row `rule_set` holds the per-block stages to was
    /// evaluated — `RuleSet::enforced()`, which excludes C++-held rows
    /// (`RowStatus::HeldByCxx`), rows enforced at another site
    /// (`RowStatus::EnforcedAt`) and rows that hold by construction
    /// (`RowStatus::ByConstruction`). See the module docs for the four
    /// readings.
    ///
    /// Empty coverage is never complete — not even against a rule set that
    /// enforces nothing — so a scaffold verdict is never parity evidence.
    #[must_use]
    pub fn is_complete_for(&self, rule_set: &RuleSet) -> bool {
        !self.is_empty() && self.contains_all(rule_set.enforced())
    }

    /// `true` iff every row this rule set enforces **and this crate has
    /// implemented** was evaluated.
    ///
    /// The mint gate during porting. [`Self::is_complete_for`] waits until
    /// every validator-enforced row has landed; this is true as soon as
    /// every *landed* rule actually ran, and was vacuously true while every
    /// entry was `pending` (DRS-D12). A forgotten `validate` call, or a call
    /// that forgets [`Self::insert`], fails it — G9's runtime half.
    #[must_use]
    pub fn covers_landed(&self, rule_set: &RuleSet) -> bool {
        self.contains_all(
            rule_set
                .enforced()
                .filter(|row| row.status() == RowStatus::Implemented),
        )
    }
}

impl<R: Row> fmt::Debug for Coverage<R> {
    // The row list in register form, not the words: `Coverage{CEN-A1, CEN-A2}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Register<R>(R);
        impl<R: Row> fmt::Debug for Register<R> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0.as_str())
            }
        }
        f.write_str("Coverage")?;
        f.debug_set().entries(self.iter().map(Register)).finish()
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod coverage_tests;
