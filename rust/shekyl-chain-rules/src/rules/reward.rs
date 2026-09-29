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
//! **F17** splits the fees, **G11** states what accrues and what burns,
//! **F18** holds the coinbase to the two miner legs, **G12** advances the
//! supply — each recorded where it yields. Wave B (F17, F18, G11, G13;
//! slice 7 §5 row 9) extended the sequence in place on 2026-09-29.
//!
//! - **CEN-F17** — a definition: the fee split,
//!   `shekyl_economics::compute_fee_burn` (the one owner: the zero-fee arm,
//!   the percentage, the D2-escalated share) over the listed bodies' fees
//!   (`Σ ct.fee`, the C++'s `fee_summary` at `blockchain.cpp:5653`), the
//!   volume window (F20), the circulating supply and the frozen-segment
//!   count read at parent state (`rules::miner::BurnOperands`). The
//!   coinbase may pay only `miner_fee_income`. A fee sum the arithmetic
//!   cannot form refuses on this row at `Locus::Block` — unreachable by a
//!   fixture (every fee is bounded by the inputs it is paid from, H18) and
//!   fail-closed where the C++'s `+=` wraps.
//! - **CEN-F18** — a predicate: the coinbase's outputs sum to **exactly**
//!   `miner_emission + miner_fee_income` (`:1551`–`:1560`, both `<` and
//!   `!=`). Refused at `Locus::Tx { slot: Miner }` in both directions: the
//!   evidence is the miner transaction's total against a figure the block
//!   determines, so the miner slot is the locus (slice 7 Q8).
//! - **CEN-G11** — a definition: the staker inflow the store accrues,
//!   `staker_emission + staker_pool_amount`, and the burn it records,
//!   `actually_destroyed` (`:5888`–`:5904`) — verify's exact operands,
//!   because they *are* verify's values (F-B1c). The values ride on the
//!   verdict; the `block_burn` row and the `total_burned` fold read the
//!   burn from there, and the accrual's writer is the store's E4 hook
//!   (`connect.rs` step 9), which reads it from there when it lands.
//! - **CEN-G13** — G11's height-0 arm: genesis has no staker leg and no
//!   accrual; the configured emission is paid whole (F11). Recorded as the
//!   arm at genesis and vacuous above it.
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
//!   miner leg (F18).
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
//! of it to the miner (G13, G11's height-0 arm), F17 and F18 are vacuous
//! (nothing is listed, nothing is owed beyond the configured amount), and
//! G12 starts the accumulator at it, as the C++'s `add_block` does.
//!
//! # The values ride on the verdict
//!
//! [`PaidEmission`] is carried on `ValidatedBlock` (slice 7 Q5): every
//! field is one the composition had to compute. The composition lives in
//! `shekyl-economics` — [`price_emission`] for the derived arm and for the
//! block template, [`configured_emission`] for this crate's genesis arm,
//! where the coinbase sum stands and [`price_emission`] is not called.
//! `connect` records `coins_generated` and the burn from the verdict; the
//! accrual waits on the E4 hook. The ingest's composed lines for
//! `coins_generated` and `burned` deleted with this (the `root_after`
//! pattern, DRS-E3).

use shekyl_economics::{configured_emission, price_emission, EmissionInputs, RewardArithmetic};
use shekyl_types::BlockHeight;
use shekyl_wire::{Ct, Transaction};

use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, ViewRead};
use crate::rules::block_weight::{Medians, Weights};
use crate::rules::miner::{economics, Emission, Subsidy, EMISSION_SPLIT_EPOCH};
use crate::rules::Rule;
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::ChainView;

pub use shekyl_economics::PaidEmission;

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

/// CEN-F17: the fee split — miner income, staker pool, destroyed. A
/// definition row; its overflow arm (a fee sum that does not fit) refuses.
pub(crate) struct F17;

impl Rule for F17 {
    const ROW: CenRow = CenRow::F17;
}

/// CEN-F18: the coinbase pays exactly the miner's emission leg plus the
/// miner's fee income.
pub(crate) struct F18;

impl Rule for F18 {
    const ROW: CenRow = CenRow::F18;
}

/// CEN-G11: the staker inflow to accrue and the burn to record. A
/// definition row; an accrual the arithmetic cannot form refuses.
pub(crate) struct G11;

impl Rule for G11 {
    const ROW: CenRow = CenRow::G11;
}

/// CEN-G13: genesis has no staker leg and no accrual — G11's height-0 arm.
pub(crate) struct G13;

impl Rule for G13 {
    const ROW: CenRow = CenRow::G13;
}

/// The listed bodies' fees, summed — the C++'s `fee_summary`
/// (`blockchain.cpp:5653`, one `get_tx_fee` per listed body, which is
/// `ct_signatures.txnFee` for every version this chain has). A body with a
/// `Null` ct carries no fee (H15 refused it off the coinbase already).
/// `None` when the sum does not fit: F17's refusal.
fn listed_fees(listed: &[Transaction]) -> Option<u64> {
    listed.iter().try_fold(0u64, |sum, tx| match &tx.ct {
        Ct::Fcmp { fee, .. } => sum.checked_add(*fee),
        Ct::Null(_) => Some(sum),
    })
}

/// The coinbase's outputs, summed. `None` when the sum does not fit — F7
/// refused that block before this stage, so the arm is unreachable here
/// and fail-closed rather than saturating.
fn money_in_use(miner_transaction: &Transaction) -> Option<u64> {
    miner_transaction
        .prefix
        .outputs
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.amount))
}

/// Where [`RewardArithmetic`] refuses. Owed overflow is F18 at the miner
/// slot — the coinbase cannot pay a sum that does not exist — and the
/// others are block-level: the weight bound (F14), the paid reward's
/// overflow (F14b), the accrual (G11).
fn arithmetic_refusal(err: RewardArithmetic) -> InvalidBlock {
    let (row, locus) = match err {
        RewardArithmetic::BlockTooBig => (F14::ROW, Locus::Block),
        RewardArithmetic::RewardOverflow => (F14b::ROW, Locus::Block),
        RewardArithmetic::OwedOverflow => (
            F18::ROW,
            Locus::Tx {
                slot: TxSlot::Miner,
            },
        ),
        RewardArithmetic::AccrualOverflow => (G11::ROW, Locus::Block),
    };
    InvalidBlock::new(row, locus)
}

/// The reward chain's definitions for a candidate connecting at
/// `connecting`, given the emission the 4.F definitions priced (and the
/// parent accumulator and burn operands they read), the weights CEN-G6/G6b
/// derived and the listed bodies (their fees) — the paid reward, its
/// split, the fee split, the accrual, the advanced supply — recording F14,
/// F14b, F16, F17, G11, G13 and G12 as evaluated. Everything the block
/// determines *about* the coinbase, without reading the coinbase:
/// [`judge_emission`] adds F18's equality check, and a fixture that must
/// pay what F18 requires reads `owed` off this ([`quote_emission`]).
///
/// The derived arm is [`price_emission`]. Genesis is [`configured_emission`]:
/// the configured coinbase stands, and the kernel is not called. The fee
/// sum is this function's (F17) and stays outside the kernel — a `Null`
/// body contributes nothing here, while the template rejects one outright.
///
/// `Err(refused)` is F14 or F14b at [`Locus::Block`], F17's fee-sum
/// overflow at [`Locus::Block`] (before anything is priced from the fees),
/// F18's owed overflow at `Locus::Tx { slot: Miner }`, or G11's accrual
/// overflow at [`Locus::Block`]. Nothing here reads the view, so there is
/// no fault position. Rows are recorded on the passing path; a refusal
/// carries the row and [`validate`] drops the coverage.
pub(crate) fn price(
    connecting: BlockHeight,
    emission: &Emission,
    weights: &Weights,
    listed: &[Transaction],
    configured: u64,
    coverage: &mut RuleCoverage,
) -> Verdict<PaidEmission> {
    let parent = emission.parent_coins_generated().to_raw();
    let paid = match emission.subsidy() {
        // Genesis: the configured emission stands. No weight bound is
        // evaluated, nothing is split, nothing is listed (F17 vacuous).
        // F7 refused an overflowing sum already, so `configured` is the fold.
        Subsidy::Configured => {
            coverage.insert(F14::ROW);
            coverage.insert(F14b::ROW);
            coverage.insert(F17::ROW);
            configured_emission(configured, parent)
        }
        Subsidy::Derived { burn, .. } => {
            let Some(total_fees) = listed_fees(listed) else {
                return Err(InvalidBlock::new(F17::ROW, Locus::Block));
            };
            let inputs = EmissionInputs {
                height: connecting.to_raw(),
                median_weight: weights.medians.effective_median.to_raw(),
                block_weight: weights.weight.to_raw(),
                already_generated: parent,
                tx_volume: emission.tx_volume(),
                total_fees,
                supply: burn.supply,
                frozen_segments: burn.frozen_segments,
                split_epoch: EMISSION_SPLIT_EPOCH.to_raw(),
                params: economics(),
            };
            match price_emission(&inputs) {
                Ok(priced) => {
                    coverage.insert(F14::ROW);
                    coverage.insert(F14b::ROW);
                    coverage.insert(F17::ROW);
                    priced
                }
                Err(err) => return Err(arithmetic_refusal(err)),
            }
        }
    };
    coverage.insert(F16::ROW);
    coverage.insert(G11::ROW);
    coverage.insert(G13::ROW);
    coverage.insert(G12::ROW);
    Ok(paid)
}

/// The reward chain for `candidate` connecting at `connecting`: [`price`]
/// over its listed bodies, then **F18** — the coinbase's outputs sum to
/// exactly what the block owes it. Recorded vacuous at genesis, where the
/// configured emission stands (`validate_miner_transaction` returns before
/// the check, `blockchain.cpp:1516`).
///
/// Runs after the slot loop (the weight is a judged body's) and before
/// the drain. `Err(refused)` is one of [`price`]'s — F14, F14b, F17 or G11
/// at [`Locus::Block`], or F18's owed overflow at the miner slot — or
/// F18's equality check, also at the miner slot.
pub(crate) fn judge_emission(
    connecting: BlockHeight,
    emission: &Emission,
    weights: &Weights,
    candidate: &Candidate,
    coverage: &mut RuleCoverage,
) -> Verdict<PaidEmission> {
    let miner_transaction = &candidate.block.miner_transaction;
    let refuse_f18 = || {
        InvalidBlock::new(
            F18::ROW,
            Locus::Tx {
                slot: TxSlot::Miner,
            },
        )
    };
    let Some(in_use) = money_in_use(miner_transaction) else {
        return Err(refuse_f18());
    };
    let paid = price(
        connecting,
        emission,
        weights,
        &candidate.transactions,
        in_use,
        coverage,
    )?;
    if matches!(emission.subsidy(), Subsidy::Derived { .. }) && paid.owed.to_raw() != in_use {
        return Err(refuse_f18());
    }
    coverage.insert(F18::ROW);
    Ok(paid)
}

/// [`Emission::derive`] returns [`Fault`] because F20's window is mapped
/// through it. The derivation reads parent state and has no stale premise;
/// [`ViewRead`] is the honest outer error for a caller that is not `validate`.
fn parent_read<VF>(fault: Fault<VF>) -> ViewRead<VF> {
    match fault {
        Fault::View(fault) => ViewRead::View(fault),
        Fault::Corrupt(corrupt) => ViewRead::Corrupt(corrupt),
        Fault::Stale(_) => {
            unreachable!("emission derivation reads parent state and raises no stale premise")
        }
    }
}

/// What the reward chain prices `candidate` at, without rewriting its coinbase.
///
/// [`price`] over a scratch coverage record: the 4.F definitions, the
/// medians, the block's weight, then the composition. The equality half of
/// F18 stays in [`judge_emission`] — a caller asking what the coinbase
/// *should* pay needs `owed` while the amount is still wrong. A coinbase
/// sum that does not fit is F18 at the miner slot, the same refusal
/// [`judge_emission`] raises before it prices.
///
/// # Errors
///
/// [`ViewRead::View`] on a view fault; [`ViewRead::Corrupt`] when a parent
/// read breaks a store invariant (a burned fold above the parent's
/// emission, a hole, a decreasing transaction-count prefix).
pub fn quote_emission<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    candidate: &Candidate,
) -> Result<Verdict<PaidEmission>, ViewRead<V::Fault>> {
    let mut coverage = RuleCoverage::EMPTY;
    let emission = Emission::derive(view, connecting, &mut coverage).map_err(parent_read)?;
    let medians = Medians::derive(view, connecting, &mut coverage)?;
    let weights = Weights::derive(medians, candidate, &mut coverage);
    let Some(configured) = money_in_use(&candidate.block.miner_transaction) else {
        return Ok(Err(InvalidBlock::new(
            F18::ROW,
            Locus::Tx {
                slot: TxSlot::Miner,
            },
        )));
    };
    Ok(price(
        connecting,
        &emission,
        &weights,
        &candidate.transactions,
        configured,
        &mut coverage,
    ))
}

#[cfg(test)]
#[path = "reward_tests.rs"]
mod reward_tests;
