// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The faults [`validate`](crate::validate) can return that are **not the
//! view's**: a stateless-stage premise that no longer holds against the
//! committing view ([`Stale`]), and view data no conforming store can hold
//! ([`Corrupt`]). Neither is a verdict (`CHAIN_RULES_SLICE_2.md` §8.1 Q8).
//!
//! # Why a fourth kind
//!
//! `form` judges a block with no view: it computes the longhash under a
//! **seed the caller claims** is the block id at the seed height, and under
//! a rule set the caller claims is in force. `validate` then checks both
//! claims against the transaction that will apply the block. A claim that
//! fails is not a refusal of the block — the block is **unproven, not
//! disproven** — and it is not a validator hole or a store capability
//! limit. It means the world moved between the stages (a reorg at least
//! `SEEDHASH_EPOCH_LAG` deep, or a rule-set boundary), and the remedy is to
//! run `form` again. So it has its own type and its own position, beside
//! the view's fault and never inside `InvalidBlock`.
//!
//! # The conversion ban extends here
//!
//! No `From`/`Into` between [`Stale`] (or [`Fault`]) and `InvalidBlock`, a
//! separate arm at every consumer, and `check_store_error_conversion_ban.py`
//! covers the token. A retry arm is *more* tempting to collapse than a store
//! error, not less — "couldn't prove it" reads like "rejected it" at a
//! glance — which is exactly why the gate names it.
//!
//! # The retry is bounded, and the bound has a terminal name
//!
//! Seed mismatch means redo `form`. Under sustained reorg pressure an
//! adversary can make that loop, and an unbounded redo on an
//! attacker-influenced trigger is a DoS primitive. So the count lives in
//! the type: `form` takes a [`FormAttempt`], a `Stale` carries the
//! [`Retry`] the driver is allowed — [`Retry::Again`] with the next attempt,
//! or [`Retry::Exhausted`] with nothing to pass back in. The driver cannot
//! call `form` a fourth time because it has no `FormAttempt` to call it
//! with; the terminal outcome is a named state, not a counter someone
//! forgot to check.

use core::fmt;

use shekyl_types::{BlockHash, BlockHeight};

use crate::rule_set::RuleSet;

/// What `validate` can fail with: the view's own fault, or one of the two
/// kinds this crate defines. Matched arm by arm — `?` on the caller's side
/// propagates the whole enum, never a part of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault<V> {
    /// The view's substrate could not answer. Opaque; the store's own
    /// error for its projection.
    View(V),
    /// A stateless-stage premise no longer holds against the committing
    /// view. Remedy: redo `form`, as the payload allows.
    Stale(Stale),
    /// The view answered with data no conforming store can hold (a store
    /// invariant observed broken from the validator's side). Remedy: the
    /// writer halt — this is an `InvariantViolated` the store did not see
    /// itself, and `connect` treats it as one.
    Corrupt(Corrupt),
}

/// A premise `form` was given that the committing view refutes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stale {
    /// The seed `form` computed the longhash under is not the block id at
    /// the seed height on the chain this block is connecting onto (CEN-D3).
    /// The seed height is at least `SEEDHASH_EPOCH_LAG` blocks below the
    /// connecting height, so this fires only on a reorg that deep between
    /// the two stages.
    Seed {
        /// What the caller claimed.
        claimed: BlockHash,
        /// What the view holds at the seed height.
        expected: BlockHash,
        /// Whether `form` may be run again.
        retry: Retry,
    },
    /// The rule set `form` judged under is not the one in force at the
    /// connecting height. Compared by **value** — a Fakechain `Fixed`
    /// target reuses [`RuleSetId::GENESIS`](crate::RuleSetId::GENESIS), so
    /// the id alone cannot tell `GENESIS` from `fakechain(n)`, or two
    /// different `n`.
    RuleSet {
        /// What `form` was given.
        formed_under: RuleSet,
        /// What `validate` was given.
        in_force: RuleSet,
        /// Whether `form` may be run again.
        retry: Retry,
    },
}

/// View data that violates a store invariant, observed by a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corrupt {
    /// Cumulative difficulty decreased between two recorded heights (SI-10
    /// holds it monotone; overflow of the same fold is SI-8).
    CumulativeDifficultyNotMonotone {
        /// The height whose cumulative difficulty is below its parent's.
        at: BlockHeight,
    },
    /// The parent's cumulative difficulty plus this block's target does not
    /// fit the type.
    CumulativeDifficultyOverflow,
    /// The next-block target derived to zero (CEN-D6). Unreachable over a
    /// conforming view and an issued rule set — the type that carries the
    /// target refuses zero at the mint — and written as a fault so the
    /// refusal has a name if a producer ever appears.
    ZeroTarget,
}

/// The bound on redoing `form` after a [`Stale`] fault.
///
/// A mismatch needs a reorg at least `SEEDHASH_EPOCH_LAG` (64) blocks deep
/// between the two stages; two such reorgs during one block's admission is
/// not an organic condition (rule 75: the rationale for the value). After
/// the last attempt the block is dropped as unproven and the driver does
/// nothing further with it — a fresh relay starts a fresh
/// [`FormAttempt::FIRST`]. The peer that relayed it is not penalised: the
/// block may well be valid.
pub const MAX_FORM_ATTEMPTS: u8 = 3;

/// Which attempt at `form` this is, `1..=MAX_FORM_ATTEMPTS`. The only
/// constructor is [`FIRST`](Self::FIRST); later attempts come from a
/// [`Stale`]'s [`Retry::Again`] and nowhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormAttempt(u8);

impl FormAttempt {
    /// The first attempt — what a driver starts with.
    pub const FIRST: Self = Self(1);

    /// Which attempt this is, for the driver's log line.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0
    }

    /// The attempt after this one, for a fixture that wants to start
    /// mid-sequence without a `Stale` to hand it one.
    #[cfg(test)]
    pub(crate) fn next_for_tests(self) -> Self {
        match self.next() {
            Retry::Again(next) => next,
            Retry::Exhausted => panic!("no attempt after the last"),
        }
    }

    /// The final attempt, for the fixture that checks it is terminal.
    #[cfg(test)]
    pub(crate) const fn last_for_tests() -> Self {
        Self(MAX_FORM_ATTEMPTS)
    }

    /// The attempt after this one, or the terminal state.
    pub(crate) const fn next(self) -> Retry {
        if self.0 < MAX_FORM_ATTEMPTS {
            Retry::Again(Self(self.0 + 1))
        } else {
            Retry::Exhausted
        }
    }
}

/// What a driver may do after a [`Stale`] fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Retry {
    /// Run `form` again with this attempt.
    Again(FormAttempt),
    /// The bound is spent. The block is dropped as unproven; there is no
    /// `FormAttempt` to run `form` with, so the terminal state is enforced
    /// by the type, not by the driver remembering to stop.
    Exhausted,
}

impl fmt::Display for Stale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seed {
                claimed,
                expected,
                retry,
            } => write!(
                f,
                "stale seed: formed under {claimed:?}, the chain holds {expected:?} ({retry})"
            ),
            Self::RuleSet {
                formed_under,
                in_force,
                retry,
            } => write!(
                f,
                "stale rule set: formed under {formed_under:?}, {in_force:?} is in force ({retry})"
            ),
        }
    }
}

impl fmt::Display for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Again(attempt) => write!(f, "retry as attempt {}", attempt.number()),
            Self::Exhausted => f.write_str("retries exhausted; block dropped as unproven"),
        }
    }
}

impl fmt::Display for Corrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CumulativeDifficultyNotMonotone { at } => {
                write!(f, "cumulative difficulty decreases at height {at:?} (SI-8)")
            }
            Self::CumulativeDifficultyOverflow => {
                f.write_str("cumulative difficulty overflows past the parent")
            }
            Self::ZeroTarget => f.write_str("next-block target derived to zero (CEN-D6)"),
        }
    }
}

impl<V: fmt::Display> fmt::Display for Fault<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::View(fault) => write!(f, "view fault: {fault}"),
            Self::Stale(stale) => stale.fmt(f),
            Self::Corrupt(corrupt) => write!(f, "corrupt view: {corrupt}"),
        }
    }
}

impl<V: fmt::Debug + fmt::Display> std::error::Error for Fault<V> {}

#[cfg(test)]
#[path = "fault_tests.rs"]
mod fault_tests;
