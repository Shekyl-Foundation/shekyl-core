// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fork-choice comparison (C2-R1b-Q1a) — the rule's ONE implementation.
//!
//! Ratified sentence: the best chain is decided at alt admission by
//! **strictly greater cumulative difficulty — equality keeps the
//! incumbent**; an operator-checkpoint match on the alternative chain
//! **forces** the switch regardless of difficulty.
//!
//! The checkpoint arm outranks the difficulty arm deliberately: a
//! checkpoint-forced switch may promote a *lighter* chain, which is also
//! why the C++ switch machinery discards (rather than re-admits) the
//! demoted blocks on that arm — re-admitting the heavier demoted chain
//! would immediately re-trigger a difficulty switch back; the discard is
//! the flip-flop terminator (round doc §4b Q1a).
//!
//! Pure over its operands; the C++ side marshals the two cumulative
//! difficulties as the FFI's `ShekylU128` halves and consumes the verdict
//! (orchestration stays C++ per rule 20).

/// The verdict of one admission-time fork-choice evaluation.
///
/// Discriminants are the FFI wire codes (`difficulty_ffi.rs` re-exports
/// them as `SHEKYL_FORK_CHOICE_*`); keep them stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ForkChoiceVerdict {
    /// The incumbent chain stays: the alternative is not strictly heavier
    /// and no checkpoint forces it. Equality keeps the incumbent.
    KeepCurrent = 0,
    /// Reorganize onto the alternative chain.
    Switch = 1,
}

/// Decide between the incumbent chain and an alternative.
///
/// * `current_cumulative` — cumulative difficulty of the incumbent tip.
/// * `alternative_cumulative` — cumulative difficulty of the alternative
///   tip (the candidate block included).
/// * `checkpoint_match` — the candidate block's id equals an
///   operator-loaded checkpoint at its height (the forced arm).
#[must_use]
pub fn fork_choice(
    current_cumulative: u128,
    alternative_cumulative: u128,
    checkpoint_match: bool,
) -> ForkChoiceVerdict {
    if checkpoint_match {
        return ForkChoiceVerdict::Switch;
    }
    if alternative_cumulative > current_cumulative {
        ForkChoiceVerdict::Switch
    } else {
        ForkChoiceVerdict::KeepCurrent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictly_greater_switches() {
        assert_eq!(fork_choice(10, 11, false), ForkChoiceVerdict::Switch);
    }

    #[test]
    fn equality_keeps_the_incumbent() {
        // The boundary the ruling names: equal weight is NOT a reorg.
        assert_eq!(fork_choice(11, 11, false), ForkChoiceVerdict::KeepCurrent);
    }

    #[test]
    fn lighter_keeps_the_incumbent() {
        assert_eq!(fork_choice(11, 10, false), ForkChoiceVerdict::KeepCurrent);
    }

    #[test]
    fn checkpoint_forces_even_when_lighter() {
        assert_eq!(fork_choice(u128::MAX, 0, true), ForkChoiceVerdict::Switch);
    }

    #[test]
    fn u128_boundary_no_truncation() {
        // Above-u64 halves must participate: a hi-word difference decides.
        let lo_heavy = u128::from(u64::MAX);
        let hi_heavy = 1u128 << 64;
        assert_eq!(
            fork_choice(lo_heavy, hi_heavy, false),
            ForkChoiceVerdict::Switch
        );
        assert_eq!(
            fork_choice(hi_heavy, lo_heavy, false),
            ForkChoiceVerdict::KeepCurrent
        );
    }
}
