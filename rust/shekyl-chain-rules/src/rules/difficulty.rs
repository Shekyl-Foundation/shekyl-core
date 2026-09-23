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
//! the type**: [`Target`] wraps [`NonZeroU128`], the one `Difficulty` →
//! [`Target`] edge is [`D6::mint`], and every already-valid target
//! (genesis-block `1`, Fakechain `Fixed`) records the row through
//! [`D6::record`] so a Fakechain verdict can mint.
//!
//! **What zero at the mint IS (premise refuted 2026-09-20, DRS-E2 RD-F17).**
//! Slice 2 wrote zero as a corrupt-view fault on the premise that LWMA-1
//! floors its output and no conforming view can derive it. It does not,
//! and one can: the formula's tail is `avg_D · 99·N·(N+1)·T / 200·L` with
//! no floor, and with every solvetime at the `+6T` clamp it is **zero for
//! `avg_D ≤ 6`** (`400 → 66` per maximally slow window, so a conforming chain
//! walks there). The C++ at that point **refuses the block**
//! (`blockchain.cpp:5494`, `CHECK_AND_ASSERT_MES(current_diffic, false, …)`)
//! — which is what the census ratified, and is the parity behaviour. So
//! `D6::mint` yields a **verdict**: zero refuses the block as CEN-D6, never
//! a fault, and never a store-invariant halt (the store's work strictly
//! increased; nothing about the file is corrupt — SI-10 is D4's window walk,
//! not this). That the DAA can drive itself to zero at all — and that a
//! refused block there refuses every successor — is a consensus finding
//! for the DAA's owner, recorded in `FOLLOWUPS.md`; this crate reproduces
//! the ratified behaviour and does not add a floor (rule 71, C2-R8 Q4).
//!
//! # The window is the view's
//!
//! `N + 1` point reads of [`ChainView::block_at`] per block. The C++ caches
//! the window on the `Blockchain` object ("ND: Speedup"); this crate does
//! not, deliberately: a windowed read is a reopening with E2's replay
//! number attached, not a pre-provision (rule 21; slice 2 §3).

use core::fmt;
use core::num::NonZeroU128;

use shekyl_difficulty::{check_hash, lwma1_next, CumulativeDifficulty, Difficulty, Error, N_USIZE};
use shekyl_types::{BlockHeight, PowHash, Timestamp};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, Fault};
use crate::rule_set::{DifficultyRule, RuleSet};
use crate::rules::{recorded, Rule};
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::ChainView;

/// The difficulty a candidate must satisfy, **non-zero by construction**
/// (CEN-D6). The inner type is [`NonZeroU128`]: a zero target cannot be
/// assembled, only refused — `D6::mint` is the one `Difficulty` →
/// [`Target`] edge, and every path that already has a `Target` (genesis
/// block, Fakechain `Fixed`) still records CEN-D6 through
/// [`D6::record`](D6::record) so coverage is complete under every rule
/// set. No public constructor and no `From<Difficulty>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target(NonZeroU128);

impl Target {
    /// One, as a non-zero. Named so block 0's PoW difficulty cannot be
    /// spelled as a raw `1` beside the DAA's genesis constant.
    const ONE: NonZeroU128 = match NonZeroU128::new(1) {
        Some(n) => n,
        None => unreachable!(),
    };

    /// The **genesis block's own** PoW difficulty. Block 0 has no tip, so
    /// the DAA is never consulted for it: its nonce satisfies `check_hash`
    /// at `1` (`shekyl-genesis-tool/src/builder.rs`), and `shekyl-difficulty`
    /// pins `GENESIS_DIFFICULTY > 1` (`consts.rs:94`–`:102`) precisely to
    /// keep the two apart — `GENESIS_DIFFICULTY` is the DAA's short-circuit
    /// for heights `1..N`, not block 0's target. The C++ forces the same
    /// `1` at height 0 under `--fixed-difficulty` (`blockchain.cpp:975`).
    pub(crate) const GENESIS_BLOCK: Self = Self(Self::ONE);

    /// The difficulty value, for the comparison (`check_hash`) and the
    /// store's fold.
    #[must_use]
    pub const fn difficulty(self) -> Difficulty {
        Difficulty::from_raw(self.0.get())
    }

    /// A fixed target for a Fakechain rule set (`RuleSet::fakechain`,
    /// CEN-D7). Non-zero by the argument's type.
    pub(crate) const fn fixed(fixed: NonZeroU128) -> Self {
        Self(fixed)
    }

    /// Whether `pow` satisfies this target under CEN-D1b (`check_hash`:
    /// `hash · difficulty < 2^256`, little-endian). The comparison's one
    /// site; D1b records the definition, D1 acts on the answer.
    #[must_use]
    pub(crate) fn is_satisfied_by(self, pow: PowHash) -> bool {
        check_hash(pow.as_bytes(), self.difficulty())
    }
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
    /// Record this row against an already-valid [`Target`]. Every path
    /// that produces a target for a verdict — LWMA-1, genesis-block `1`,
    /// Fakechain `Fixed` — goes through here, so `covers_landed` cannot
    /// depend on which arm D4 took.
    pub(crate) fn record(target: Target, coverage: &mut RuleCoverage) -> Target {
        coverage.insert(Self::ROW);
        target
    }

    /// The `Difficulty` → [`Target`] edge. Zero **refuses the block** as
    /// CEN-D6 — the census's ratified behaviour and the C++'s
    /// (`blockchain.cpp:5494`). It is a verdict, not a fault: the view is
    /// conforming (module docs), the derivation is honest, and the number
    /// is what the ratified algorithm produced. Records this row either way.
    pub(crate) fn mint(difficulty: Difficulty, coverage: &mut RuleCoverage) -> Verdict<Target> {
        coverage.insert(Self::ROW);
        NonZeroU128::new(difficulty.to_raw())
            .map(Target)
            .ok_or_else(|| InvalidBlock::new(Self::ROW, Locus::Block))
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
    /// it is `connecting − 1`. Its `chain_height = 0` arm is therefore the
    /// target for block **1** given a tip at 0; block 0 itself has no tip,
    /// the DAA is not consulted, and its target is
    /// [`Target::GENESIS_BLOCK`] — `1`, under every rule set.
    pub(crate) fn target<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        rule_set: &RuleSet,
        coverage: &mut RuleCoverage,
    ) -> Result<Verdict<Target>, Fault<V::Fault>> {
        coverage.insert(Self::ROW);
        if let Some(fixed) = D7::fixed_target(rule_set, connecting, coverage) {
            return Ok(Ok(D6::record(fixed, coverage)));
        }
        let Some(chain_height) = connecting.to_raw().checked_sub(1) else {
            return Ok(Ok(D6::record(Target::GENESIS_BLOCK, coverage)));
        };
        let chain_height = BlockHeight::from_raw(chain_height);
        let window = Self::window(view, chain_height)?;
        let difficulty = match lwma1_next(chain_height, &window.timestamps, &window.work) {
            Ok(difficulty) => difficulty,
            // `window` is monotone and, past `N`, exactly `N + 1` long. At
            // the ratified `(N, T)` the formula's `u128` multiplies cannot
            // overflow over such a window (`avg_D ≤ u128::MAX / N`). Count,
            // Window, and Overflow therefore have no producer here: Count
            // and Window are construction bugs; Overflow is the function's
            // SI-8 belt on a decrease the walk already refused. Named as
            // unreachable so a producer panics rather than wearing a more
            // specific `Corrupt` that would lie about which invariant broke.
            Err(Error::InvalidCount | Error::Window | Error::Overflow) => {
                unreachable!(
                    "D4 builds a monotone N+1 window past N; lwma1_next's error arms have no producer here"
                )
            }
        };
        Ok(D6::mint(difficulty, coverage))
    }

    /// The `(timestamp, cumulative difficulty)` window LWMA-1 reads: the
    /// `N + 1` blocks ending at `chain_height`, oldest first, when
    /// `chain_height ≥ N`; empty otherwise (the function does not inspect
    /// it). Cumulative difficulty is checked **strictly increasing** as it
    /// is read (SI-10 observed from this side: equal adjacent work is as
    /// corrupt as a decrease — every target is at least one).
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
            if previous.is_some_and(|p| block.cumulative_difficulty <= p) {
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
            DifficultyRule::Fixed(_) if connecting.is_zero() => Some(Target::GENESIS_BLOCK),
            DifficultyRule::Fixed(fixed) => Some(fixed),
        }
    }
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
