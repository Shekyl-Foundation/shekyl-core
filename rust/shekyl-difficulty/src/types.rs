// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transform-shaped difficulty newtypes. They live **here**, not in
//! `shekyl-types`: a difficulty is the output of LWMA-1, not a chain
//! identity (`18-type-placement.mdc`).

use core::fmt;
use core::num::NonZeroU128;

/// A block's **target difficulty** — the value a PoW hash must satisfy
/// (`check_hash`) and the output of [`crate::lwma1_next`].
///
/// **Never zero.** A difficulty is the expected number of hashes per
/// block, and a block costs at least one hash, so one is the least value
/// the quantity has; zero is not a difficulty. LWMA-1 floors its output
/// at [`Self::ONE`] (`DAA_LWMA1.md` §5.3 step 10, Rick 2026-11-07), and
/// the type holds the rest: no path can build a zero target, so the
/// census's CEN-D6 ("a zero next-block difficulty rejects the block") has
/// no runtime arm left.
///
/// Distinct from [`CumulativeDifficulty`]: one is a per-block target,
/// the other is a running sum. Inner field private; convert at the
/// wire edge via [`Self::new`] / [`Self::to_raw`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Difficulty(NonZeroU128);

impl Difficulty {
    /// One: the least difficulty, one expected hash per block. LWMA-1's
    /// floor and the genesis block's own PoW difficulty.
    pub const ONE: Self = match NonZeroU128::new(1) {
        Some(one) => Self(one),
        None => unreachable!(),
    };

    /// The difficulty `raw`, or `None` for zero, which is not one. An
    /// *edge* constructor (wire, constants, tests).
    #[must_use]
    pub const fn new(raw: u128) -> Option<Self> {
        match NonZeroU128::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// The difficulty `raw`, non-zero by its type.
    #[must_use]
    pub const fn from_nonzero(raw: NonZeroU128) -> Self {
        Self(raw)
    }

    /// The value, non-zero.
    #[must_use]
    pub const fn get(self) -> NonZeroU128 {
        self.0
    }

    /// Unwrap to the raw `u128`, never zero. An *edge* accessor.
    #[must_use]
    pub const fn to_raw(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for Difficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Difficulty({})", self.0)
    }
}

impl fmt::Display for Difficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Cumulative difficulty through a block — the running sum of per-block
/// [`Difficulty`] values. Strictly greater cumulative difficulty is the
/// fork-choice arm (`fork_choice`).
///
/// Distinct from [`Difficulty`] so a target cannot be passed where a
/// running sum is expected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CumulativeDifficulty(u128);

impl CumulativeDifficulty {
    /// The zero cumulative (empty chain).
    pub const ZERO: Self = Self(0);

    /// Wrap a raw `u128`. An *edge* constructor.
    #[must_use]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Unwrap to the raw `u128`. An *edge* accessor.
    #[must_use]
    pub const fn to_raw(self) -> u128 {
        self.0
    }
}

impl fmt::Debug for CumulativeDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CumulativeDifficulty({})", self.0)
    }
}

impl fmt::Display for CumulativeDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
