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
//! Only **complete** coverage is parity evidence. `RuleCoverage::EMPTY` —
//! what every verdict carries while zero rules are landed (DRS-D12) — is
//! never complete, so the scaffold's `ChainValid` cannot be mistaken for a
//! judged block by anything that checks.

use core::fmt;
use core::marker::PhantomData;

use crate::census::{CenRow, PolicyRow, Row};
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
    /// S-CHAIN-W (per row, `as_str()` or `index()`) without reaching into
    /// the words.
    pub fn iter(&self) -> impl Iterator<Item = R> + '_ {
        R::ALL
            .iter()
            .copied()
            .filter(move |row| self.contains(*row))
    }

    /// Record that `row` was evaluated. Crate-private: coverage is written
    /// only by the rule that ran.
    // STAGED (rule 23): the writer is the first rule function the porting
    // increments land (DRS-D12; `DAEMON_REDB_STORE.md` §7.5.2 table 3). Zero
    // rules exist in the scaffold, so only the tests call this yet; `expect`
    // turns the marker into a compile error the moment a rule does.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "written by the first landed rule; DRS-D12")
    )]
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
    /// `true` iff every row `rule_set` enforces was evaluated.
    ///
    /// Empty coverage is never complete — not even against a rule set that
    /// enforces nothing — so a scaffold verdict is never parity evidence.
    #[must_use]
    pub fn is_complete_for(&self, rule_set: &RuleSet) -> bool {
        !self.is_empty() && rule_set.enforced().all(|row| self.contains(row))
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
