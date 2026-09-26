// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transform-shaped difficulty newtypes. They live **here**, not in
//! `shekyl-types`: a difficulty is the output of LWMA-1, not a chain
//! identity (`18-type-placement.mdc`).

use core::fmt;

/// A block's **target difficulty** — the value a PoW hash must satisfy
/// (`check_hash`) and the output of [`crate::lwma1_next`].
///
/// Distinct from [`CumulativeDifficulty`]: one is a per-block target,
/// the other is a running sum. Inner field private; convert at the FFI
/// / wire edge via [`Self::from_raw`] / [`Self::to_raw`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Difficulty(u128);

impl Difficulty {
    /// The zero difficulty. `check_hash` treats this as always-pass
    /// (inherited C++ genesis/escape behaviour).
    pub const ZERO: Self = Self(0);

    /// Wrap a raw `u128`. An *edge* constructor (FFI, constants, tests).
    #[must_use]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Unwrap to the raw `u128`. An *edge* accessor.
    #[must_use]
    pub const fn to_raw(self) -> u128 {
        self.0
    }

    /// True when this is [`Self::ZERO`].
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
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
