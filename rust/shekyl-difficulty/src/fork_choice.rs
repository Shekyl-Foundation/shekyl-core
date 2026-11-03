// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fork-choice comparison (C2-R1b-Q1a) — the rule's ONE implementation.
//!
//! Ratified sentence: the best chain is decided at alt admission by
//! **strictly greater cumulative difficulty — equality keeps the
//! incumbent**. Work is the only input: no coded checkpoint forces a
//! switch, because a checkpoint is a maintainer choosing the chain
//! (S1, design review 2026-11-03). The demoted blocks of a switch are
//! re-admitted as alternative blocks (CEN-K7).
//!
//! Pure over its operands. The Rust switch (`shekyl-chain-ingest`) is
//! the consumer. The C++ alt path and its FFI exports are gone (DEL-009).

/// The verdict of one admission-time fork-choice evaluation.
///
/// Discriminants are the verdict codes the switch matches; keep them
/// stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ForkChoiceVerdict {
    /// The incumbent chain stays: the alternative is not strictly heavier.
    /// Equality keeps the incumbent.
    KeepCurrent = 0,
    /// Reorganize onto the alternative chain: it is strictly heavier. The
    /// demoted blocks re-enter as alternative blocks (CEN-K7).
    Switch = 1,
}

use crate::types::CumulativeDifficulty;

/// Decide between the incumbent chain and an alternative.
///
/// * `current_cumulative` — cumulative difficulty of the incumbent tip.
/// * `alternative_cumulative` — cumulative difficulty of the alternative
///   tip (the candidate block included).
#[must_use]
pub fn fork_choice(
    current_cumulative: CumulativeDifficulty,
    alternative_cumulative: CumulativeDifficulty,
) -> ForkChoiceVerdict {
    if alternative_cumulative > current_cumulative {
        ForkChoiceVerdict::Switch
    } else {
        ForkChoiceVerdict::KeepCurrent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cd(v: u128) -> CumulativeDifficulty {
        CumulativeDifficulty::from_raw(v)
    }

    #[test]
    fn strictly_greater_switches() {
        assert_eq!(
            fork_choice(cd(10), cd(11)),
            ForkChoiceVerdict::Switch
        );
    }

    #[test]
    fn equality_keeps_the_incumbent() {
        // The boundary the ruling names: equal weight is NOT a reorg.
        assert_eq!(
            fork_choice(cd(11), cd(11)),
            ForkChoiceVerdict::KeepCurrent
        );
    }

    #[test]
    fn lighter_keeps_the_incumbent() {
        assert_eq!(
            fork_choice(cd(11), cd(10)),
            ForkChoiceVerdict::KeepCurrent
        );
    }

    #[test]
    fn u128_boundary_no_truncation() {
        // Above-u64 halves must participate: a hi-word difference decides.
        let lo_heavy = cd(u128::from(u64::MAX));
        let hi_heavy = cd(1u128 << 64);
        assert_eq!(
            fork_choice(lo_heavy, hi_heavy),
            ForkChoiceVerdict::Switch
        );
        assert_eq!(
            fork_choice(hi_heavy, lo_heavy),
            ForkChoiceVerdict::KeepCurrent
        );
    }
}
