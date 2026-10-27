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
//! checkpoint-forced switch may promote a *lighter* chain, which is why
//! the switch discards (rather than re-admits) the demoted blocks on that
//! arm — re-admitting the heavier demoted chain would immediately
//! re-trigger a difficulty switch back; the discard is the flip-flop
//! terminator (round doc §4b Q1a, CEN-K7). The verdict says which arm
//! fired ([`ForkChoiceVerdict::ForcedSwitch`], `DRS_E5_POOL_ALT_PRUNE.md`
//! `E5-Q5`), so the switch matches on it rather than re-deriving the
//! checkpoint test the function was already told.
//!
//! Pure over its operands. Two consumers: the Rust switch
//! (`shekyl-chain-ingest`) and, until `DEL-009`, the C++ alt path, which
//! marshals the two cumulative difficulties as the FFI's `ShekylU128`
//! halves.

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
    /// Reorganize onto the alternative chain: it is strictly heavier. The
    /// demoted blocks re-enter as alternative blocks (CEN-K7).
    Switch = 1,
    /// Reorganize onto the alternative chain because a checkpoint names it,
    /// whatever its weight. The demoted blocks are discarded, not
    /// re-admitted (CEN-K7's flip-flop terminator).
    ForcedSwitch = 2,
}

use crate::types::CumulativeDifficulty;

/// Decide between the incumbent chain and an alternative.
///
/// * `current_cumulative` — cumulative difficulty of the incumbent tip.
/// * `alternative_cumulative` — cumulative difficulty of the alternative
///   tip (the candidate block included).
/// * `checkpoint_match` — the candidate block's id equals an
///   operator-loaded checkpoint at its height (the forced arm).
#[must_use]
pub fn fork_choice(
    current_cumulative: CumulativeDifficulty,
    alternative_cumulative: CumulativeDifficulty,
    checkpoint_match: bool,
) -> ForkChoiceVerdict {
    if checkpoint_match {
        return ForkChoiceVerdict::ForcedSwitch;
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

    fn cd(v: u128) -> CumulativeDifficulty {
        CumulativeDifficulty::from_raw(v)
    }

    #[test]
    fn strictly_greater_switches() {
        assert_eq!(
            fork_choice(cd(10), cd(11), false),
            ForkChoiceVerdict::Switch
        );
    }

    #[test]
    fn equality_keeps_the_incumbent() {
        // The boundary the ruling names: equal weight is NOT a reorg.
        assert_eq!(
            fork_choice(cd(11), cd(11), false),
            ForkChoiceVerdict::KeepCurrent
        );
    }

    #[test]
    fn lighter_keeps_the_incumbent() {
        assert_eq!(
            fork_choice(cd(11), cd(10), false),
            ForkChoiceVerdict::KeepCurrent
        );
    }

    #[test]
    fn checkpoint_forces_even_when_lighter() {
        assert_eq!(
            fork_choice(cd(u128::MAX), cd(0), true),
            ForkChoiceVerdict::ForcedSwitch
        );
    }

    #[test]
    fn a_checkpoint_on_a_heavier_chain_is_still_the_forced_arm() {
        // The arm is the checkpoint's, not the weight's: a heavier chain
        // a checkpoint names still discards what it demotes.
        assert_eq!(
            fork_choice(cd(10), cd(11), true),
            ForkChoiceVerdict::ForcedSwitch
        );
    }

    #[test]
    fn u128_boundary_no_truncation() {
        // Above-u64 halves must participate: a hi-word difference decides.
        let lo_heavy = cd(u128::from(u64::MAX));
        let hi_heavy = cd(1u128 << 64);
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
