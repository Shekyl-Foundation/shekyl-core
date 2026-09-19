// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.D, the difficulty half (slice 2; `CHAIN_RULES_SLICE_2.md` §2,
//! §4.3): the next-block target (D4) and the type that carries it (D6).
//! The PoW half — D1, D1b, D2, D3 — is `rules/pow.rs`.
//!
//! # One implementation, adopted
//!
//! The body is `shekyl-difficulty::lwma1_next` (`lwma1.rs:64`), LWMA-1
//! ratified 2026-05-18 and the daemon's one difficulty function through
//! the FFI (`blockchain.cpp:971`–`:1058`). This module assembles the window
//! the way the C++ does — exactly `N + 1` `(timestamp, cumulative
//! difficulty)` pairs ending at the chain tip when the tip is at or past
//! `N`, nothing otherwise (`:1044`–`:1053`) — and calls the one function.
//! No constant, clamp or bias is restated here.
//!
//! # A definition, and the type it mints
//!
//! D4 is not a predicate on the candidate: nothing about a candidate fails
//! "what is the next difficulty". It is a **definition** in B6's shape
//! (slice 1 Q5): derived once per validation at [`D4::target`], recorded
//! there, and carried on the verdict — D1 compares against it, and the
//! store persists the cumulative work it implies (Q5) so `connect` derives
//! `cumulative_difficulty` instead of being handed it.
//!
//! D6 — *"a zero next-block difficulty rejects the block"* — is held **by
//! the type**, not by a predicate (Q4, F4): [`Target`] cannot be built from
//! zero, and the one place a `Difficulty` becomes a `Target` is
//! [`D6::mint`], which records the row and refuses zero as a
//! [`Corrupt::ZeroTarget`] fault. A predicate `target.is_zero()` would
//! have no reachable refusal on the main chain — LWMA-1 floors its output
//! and `GENESIS_DIFFICULTY` is positive — and a gate that cannot fail is
//! the one thing this program has decided it does not ship. The fault arm
//! exists so the refusal has a name if a producer ever appears (slice 9's
//! alt sentinel is the candidate).
//!
//! # The window is the view's
//!
//! `N + 1` point reads of [`ChainView::block_at`] per block. The C++ caches
//! the window on the `Blockchain` object ("ND: Speedup"); this crate does
//! not, deliberately: a windowed read is a reopening with E2's replay
//! number attached, not a pre-provision (rule 21; slice 2 §3).

use core::fmt;
use core::num::NonZeroU128;

use shekyl_difficulty::{lwma1_next, CumulativeDifficulty, Difficulty, Error, N_USIZE};
use shekyl_types::{BlockHeight, Timestamp};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, Fault};
use crate::rule_set::{DifficultyRule, RuleSet};
use crate::rules::Rule;
use crate::view::{AtHeight, ChainView, RecordedBlock};

/// The difficulty a candidate must satisfy, **non-zero by construction**
/// (CEN-D6). Minted by the crate's `D6::mint` from CEN-D4's derivation, or
/// fixed from a `NonZeroU128` on a Fakechain rule set
/// ([`RuleSet::fakechain`](crate::RuleSet::fakechain), CEN-D7); there is
/// no public constructor and no `From<Difficulty>`, so a zero target is
/// unrepresentable where CEN-D1 compares.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target(Difficulty);

impl Target {
    /// The difficulty value, for the comparison (`check_hash`) and the
    /// store's fold.
    #[must_use]
    pub const fn difficulty(self) -> Difficulty {
        self.0
    }

    /// A fixed target for a Fakechain rule set (`RuleSet::fakechain`,
    /// CEN-D7). Non-zero by the argument's type, so the invariant this type
    /// exists for is the caller's type's, not a check.
    pub(crate) const fn fixed(fixed: NonZeroU128) -> Self {
        Self(Difficulty::from_raw(fixed.get()))
    }

    /// The target the C++ forces at height 0 under `--fixed-difficulty`
    /// (`blockchain.cpp:975`: `m_db->height() ? m_fixed_difficulty : 1`).
    const ONE: Self = Self(Difficulty::from_raw(1));
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Target({})", self.0)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// CEN-D6: a zero next-block difficulty rejects the block. Held by the
/// [`Target`] type: this is its one constructor.
pub(crate) struct D6;

impl Rule for D6 {
    const ROW: CenRow = CenRow::D6;
}

impl D6 {
    /// Mint the target from a derived difficulty, recording this row.
    /// Zero is a [`Corrupt::ZeroTarget`] fault — the derivation produced a
    /// value no issued rule set and no conforming view can produce, so it
    /// is not the block's fault and not a verdict.
    pub(crate) fn mint(
        difficulty: Difficulty,
        coverage: &mut RuleCoverage,
    ) -> Result<Target, Corrupt> {
        coverage.insert(Self::ROW);
        if difficulty.is_zero() {
            return Err(Corrupt::ZeroTarget);
        }
        Ok(Target(difficulty))
    }
}

/// CEN-D4: the next-block difficulty is LWMA-1 over the last `N + 1`
/// blocks; below `N` blocks of history the genesis constant applies.
///
/// A definition (module docs): [`D4::target`] derives it once and records
/// the row.
pub(crate) struct D4;

impl Rule for D4 {
    const ROW: CenRow = CenRow::D4;
}

impl D4 {
    /// The target a candidate connecting at `connecting` must satisfy under
    /// `rule_set`, recorded in `coverage` as this row (and D6 at the mint,
    /// D7 at the override consultation).
    ///
    /// `lwma1_next`'s `chain_height` is the **tip's** height — the C++
    /// passes `height − 1` of its block count (`blockchain.cpp:1002`) — so
    /// it is `connecting − 1`, and `0` for genesis admission, where the
    /// function short-circuits to `GENESIS_DIFFICULTY` without reading the
    /// slices.
    pub(crate) fn target<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        rule_set: &RuleSet,
        coverage: &mut RuleCoverage,
    ) -> Result<Target, Fault<V::Fault>> {
        coverage.insert(Self::ROW);
        if let Some(fixed) = D7::fixed_target(rule_set, connecting, coverage) {
            return Ok(fixed);
        }
        let chain_height = BlockHeight::from_raw(connecting.to_raw().saturating_sub(1));
        let window = Self::window(view, chain_height)?;
        let difficulty = match lwma1_next(chain_height, &window.timestamps, &window.work) {
            Ok(difficulty) => difficulty,
            // `window` holds exactly `N + 1` entries whenever the function
            // inspects them, so the count arm has no producer here; the
            // `Window` arm is `alt_window_plan`'s alone (slice 9's).
            Err(Error::InvalidCount | Error::Window) => {
                unreachable!("D4 builds exactly N + 1 entries past N; lwma1_next has no Window arm")
            }
            // Monotonicity was checked as the window was read; the
            // function's own guard is a second belt on the same fact.
            Err(Error::Overflow) => {
                return Err(Fault::Corrupt(Corrupt::CumulativeDifficultyNotMonotone {
                    at: chain_height,
                }));
            }
        };
        D6::mint(difficulty, coverage).map_err(Fault::Corrupt)
    }

    /// The `(timestamp, cumulative difficulty)` window LWMA-1 reads: the
    /// `N + 1` blocks ending at `chain_height`, oldest first, when
    /// `chain_height ≥ N`; empty otherwise (the function does not inspect
    /// it). Cumulative difficulty is checked monotone as it is read (SI-8
    /// observed from this side).
    fn window<'id, V: ChainView<'id>>(
        view: &V,
        chain_height: BlockHeight,
    ) -> Result<Window, Fault<V::Fault>> {
        let n = u64::try_from(N_USIZE).expect("N fits u64");
        let mut window = Window::default();
        if chain_height.to_raw() < n {
            return Ok(window);
        }
        let first = chain_height.to_raw() - n;
        let mut previous: Option<CumulativeDifficulty> = None;
        for h in first..=chain_height.to_raw() {
            let height = BlockHeight::from_raw(h);
            let block = recorded(view, height).map_err(Fault::View)?;
            if previous.is_some_and(|p| block.cumulative_difficulty < p) {
                return Err(Fault::Corrupt(Corrupt::CumulativeDifficultyNotMonotone {
                    at: height,
                }));
            }
            previous = Some(block.cumulative_difficulty);
            window
                .timestamps
                .push(Timestamp::from_raw(block.header.timestamp));
            window.work.push(block.cumulative_difficulty);
        }
        Ok(window)
    }

    /// Cumulative work through a candidate that connects at `connecting`
    /// with `target`: the parent's plus the target (`ZERO` plus the target
    /// at genesis). What the store persists as `block_info.cumulative_
    /// difficulty` (Q5: the validator computes, the store records).
    pub(crate) fn cumulative_after<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        target: Target,
    ) -> Result<CumulativeDifficulty, Fault<V::Fault>> {
        let parent = match connecting.to_raw().checked_sub(1) {
            None => CumulativeDifficulty::ZERO,
            Some(h) => {
                recorded(view, BlockHeight::from_raw(h))
                    .map_err(Fault::View)?
                    .cumulative_difficulty
            }
        };
        parent
            .to_raw()
            .checked_add(target.difficulty().to_raw())
            .map(CumulativeDifficulty::from_raw)
            .ok_or(Fault::Corrupt(Corrupt::CumulativeDifficultyOverflow))
    }
}

/// CEN-D7: `--fixed-difficulty` overrides the DAA on regtest, height 0
/// forced to 1.
///
/// Ported as **data on a Fakechain rule set** (`DifficultyRule::Fixed`,
/// `RuleSet::fakechain`; slice 2 §4.5, arm (d)), not as a flag the validator
/// consults: no override path exists on any nettype other than Fakechain,
/// by type. The row is *evaluated* on every block — is the target
/// overridden here? — and records either way, so coverage is complete under
/// every rule set; under an issued set the answer is always "no".
pub(crate) struct D7;

impl Rule for D7 {
    const ROW: CenRow = CenRow::D7;
}

impl D7 {
    /// The fixed target `rule_set` names, if any, recorded in `coverage` as
    /// this row having been consulted. Height 0 is `1` under a fixed
    /// target, as the C++ has it.
    fn fixed_target(
        rule_set: &RuleSet,
        connecting: BlockHeight,
        coverage: &mut RuleCoverage,
    ) -> Option<Target> {
        coverage.insert(Self::ROW);
        match rule_set.difficulty() {
            DifficultyRule::Lwma1 => None,
            DifficultyRule::Fixed(_) if connecting.is_zero() => Some(Target::ONE),
            DifficultyRule::Fixed(fixed) => Some(fixed),
        }
    }
}

/// The recorded block at `height`, which is below the connecting height
/// and therefore present on a conforming view (a hole is the store's SI-7,
/// reported as its fault before this arm).
fn recorded<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<RecordedBlock, V::Fault> {
    Ok(match view.block_at(height)? {
        AtHeight::Recorded(block) => block,
        AtHeight::AboveTip => unreachable!("heights below the connecting height are recorded"),
    })
}

/// LWMA-1's two input slices, oldest first.
#[derive(Default)]
struct Window {
    timestamps: Vec<Timestamp>,
    work: Vec<CumulativeDifficulty>,
}

#[cfg(test)]
#[path = "difficulty_tests.rs"]
mod difficulty_tests;
