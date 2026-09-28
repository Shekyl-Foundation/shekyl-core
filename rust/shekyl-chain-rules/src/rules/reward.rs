// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.F / 4.G — the paid reward (`CHAIN_RULES_SLICE_7.md` §4, the
//! `judge_emission` definition chain after the medians).
//!
//! One sequence in the shape of `judge_reference`: CEN-G6 yielded the
//! medians and CEN-G6b the block's weight (`rules::block_weight`); here
//! **F14** refuses or **F14b** yields the paid reward, **F16** splits it,
//! **G12** advances the supply — each recorded where it yields. Wave B
//! (F17, F18, G11, G13) extends the sequence in place.
//!
//! - **CEN-F14** — a predicate: a block heavier than **twice the effective
//!   median** is refused at `Locus::Block`; a block at exactly twice it is
//!   accepted and earns a zero subsidy (the inclusive bound, a recorded
//!   divergence from the inherited exclusive one — census F14). The bound
//!   is `2 × M` as a *relationship*, the C++'s
//!   `m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median
//!   * 2` (`blockchain.cpp:6099`); the value follows the zone and the
//!   penalty rulings (`CONSENSUS_C2_R2_WEIGHT_FEES.md`, the zone / surge /
//!   penalty as one control system, `:214–215`), not the other way round.
//! - **CEN-F14b** — a definition: the paid reward,
//!   `shekyl_economics::paid_block_reward` — the release-modulated,
//!   tail-floored emission (F15) with the quadratic penalty applied to the
//!   paid quantity (FL-R12′'s ordering; C2-R2 Q4's curve). **One owner**:
//!   the same function the C++ marshals through `shekyl_block_reward`, so
//!   the refusal and the price come from one call and cannot disagree.
//!   Its `Overflow` arm is a refusal on this row, as the C++'s non-`OK`
//!   status is (`cryptonote_basic_impl.cpp:158`): fail-closed, never a
//!   panic a block can reach.
//! - **CEN-F16** — a definition: the split of the paid reward into the
//!   miner and staker legs (`shekyl_economics::compute_emission_split`,
//!   the one owner, from CEN-F21's epoch). The coinbase may pay only the
//!   miner leg (F18, wave B).
//! - **CEN-G12** — a definition: `already_generated_coins` advances by the
//!   **paid** reward (`blockchain.cpp:5930`, `:5860–5868`),
//!   `shekyl_economics::advance_already_generated`, the one entry point.
//!
//! # Genesis
//!
//! `validate_miner_transaction` returns before `get_block_reward` at height
//! 0 (`blockchain.cpp:1516–1522`): the configured emission stands, F11's
//! observation. So at genesis F14 is recorded as **vacuous** (nothing was
//! bounded — the same evaluated-not-applicable arm `run_tx` records for an
//! out-of-scope row), F14b's paid amount is the coinbase's configured
//! total (F7 already refused an overflowing sum), F16's split is the whole
//! of it to the miner (what G13 will state as G11's height-0 arm), and G12
//! starts the accumulator at it, as the C++'s `add_block` does.
//!
//! # The values ride on the verdict
//!
//! [`PaidEmission`] is carried on `ValidatedBlock` (slice 7 Q5): every
//! field is one the validator had to compute, `connect` records
//! `coins_generated` from it, and the paid reward is F18's and G11's
//! operand. The ingest's composed line for `coins_generated` deletes with
//! this (the `root_after` pattern, DRS-E3).

use shekyl_economics::{
    advance_already_generated, compute_emission_split, paid_block_reward, EmissionError,
    EmissionSplit,
};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rules::block_weight::Weights;
use crate::rules::miner::{economics, Emission, Subsidy, EMISSION_SPLIT_EPOCH};
use crate::rules::Rule;
use crate::verdict::{InvalidBlock, Locus, Verdict};

/// CEN-F14: the block's weight is at most twice the effective median.
pub(crate) struct F14;

impl Rule for F14 {
    const ROW: CenRow = CenRow::F14;
}

/// CEN-F14b: the paid reward — the emission under the weight penalty. A
/// definition row; its overflow arm refuses.
pub(crate) struct F14b;

impl Rule for F14b {
    const ROW: CenRow = CenRow::F14b;
}

/// CEN-F16: the paid reward split into the miner and staker legs. A
/// definition row.
pub(crate) struct F16;

impl Rule for F16 {
    const ROW: CenRow = CenRow::F16;
}

/// CEN-G12: the gross emission through this block — the parent's advanced
/// by the paid reward. A definition row.
pub(crate) struct G12;

impl Rule for G12 {
    const ROW: CenRow = CenRow::G12;
}

/// What the reward chain established for a validated block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidEmission {
    /// The paid (penalised) reward — F14b's value; at genesis the
    /// configured coinbase total (F11).
    pub paid: AtomicUnits,
    /// The miner and staker legs of `paid` (F16). The coinbase may pay
    /// only `miner_emission` plus its fee income (F18, wave B).
    pub split: EmissionSplit,
    /// `already_generated_coins` through this block (G12): the parent's
    /// plus `paid`, saturating as the one owner saturates.
    pub coins_generated: AtomicUnits,
}

/// The reward chain for a candidate connecting at `connecting`, given the
/// emission the 4.F definitions priced (and the parent accumulator they
/// read) and the weights CEN-G6/G6b derived — the paid reward, its split,
/// the advanced supply — recording F14, F14b, F16 and G12 as evaluated.
///
/// Runs after the slot loop (the weight is a judged body's) and before
/// the drain. `Err(refused)` is F14's refusal (a block over twice the
/// median) or F14b's (a price the arithmetic cannot form), both at
/// [`Locus::Block`]; nothing here reads the view, so there is no fault
/// position.
pub(crate) fn judge_emission(
    connecting: BlockHeight,
    emission: &Emission,
    weights: &Weights,
    miner_transaction: &Transaction,
    coverage: &mut RuleCoverage,
) -> Verdict<PaidEmission> {
    let parent_coins_generated = emission.parent_coins_generated();
    let (paid, split) = match emission.subsidy() {
        // Genesis: the configured emission stands, no weight bound is
        // evaluated, and nothing is split — the coinbase pays the
        // configured blob whole and no staker leg exists (module docs;
        // `compute_emission_split` at height 0 would apply the initial
        // share, which the C++ never asks it to). F7 refused an
        // overflowing sum already, so the fold is total here.
        Subsidy::Configured => {
            coverage.insert(F14::ROW);
            coverage.insert(F14b::ROW);
            let paid = miner_transaction
                .prefix
                .outputs
                .iter()
                .fold(0u64, |acc, output| acc.saturating_add(output.amount));
            (
                paid,
                EmissionSplit {
                    miner_emission: paid,
                    staker_emission: 0,
                },
            )
        }
        Subsidy::Derived { .. } => {
            // One call, both answers (the C++'s `shekyl_block_reward`
            // marshal): the weight bound and the price come from the same
            // arithmetic, so the refusal cannot disagree with the value.
            match paid_block_reward(
                weights.medians.effective_median.to_raw(),
                weights.weight.to_raw(),
                parent_coins_generated.to_raw(),
                emission.tx_volume(),
                economics(),
            ) {
                Ok(paid) => {
                    coverage.insert(F14::ROW);
                    coverage.insert(F14b::ROW);
                    (
                        paid,
                        compute_emission_split(
                            paid,
                            connecting.to_raw(),
                            EMISSION_SPLIT_EPOCH.to_raw(),
                        ),
                    )
                }
                Err(EmissionError::BlockTooBig) => {
                    return Err(InvalidBlock::new(F14::ROW, Locus::Block))
                }
                Err(EmissionError::Overflow) => {
                    return Err(InvalidBlock::new(F14b::ROW, Locus::Block))
                }
            }
        }
    };
    coverage.insert(F16::ROW);
    let coins_generated = advance_already_generated(parent_coins_generated.to_raw(), paid);
    coverage.insert(G12::ROW);
    Ok(PaidEmission {
        paid: AtomicUnits::from_raw(paid),
        split,
        coins_generated: AtomicUnits::from_raw(coins_generated),
    })
}

#[cfg(test)]
#[path = "reward_tests.rs"]
mod reward_tests;
