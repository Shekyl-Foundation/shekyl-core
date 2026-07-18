// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D1 projection + drain planning — the drain trust boundary
//! (`ARCHIVAL_FIREWALL_GATE6.md` §12.3, the drain-amount taint-carve).
//!
//! The `P` value-out (drain) path has three stages, each reading the
//! minimum:
//!
//! - **Amount** ([`super::drain_amount::choose_drain_amount`]): `{user
//!   target, cadence, RNG}` + the aggregate scalar (affordability check
//!   only) → a drain amount that is provably not any reward subsum.
//! - **Select** ([`super::drain_select::select_for_drain`]): lineage-blind
//!   coin selection over the stripped `{output_id, amount, spendable_height}`
//!   vector.
//! - **Project** (this module): the single trust boundary. It is the **only**
//!   drain-path site that holds the persisted funding-output records (the
//!   `PScanState.funding_outputs` set the caller loads) and reads their
//!   mint-lineage tag, arrival epoch, and arrival height. It projects those
//!   records into the two operands the guarded stages consume — the aggregate
//!   spendable scalar and the stripped candidate vector — mirroring the
//!   established "orchestrator prepares operands, downstream receives prepared
//!   values" seam (`claim_orchestrator.rs`). The amount and select modules
//!   never name the record or the lineage tag; this module does, and is
//!   deliberately excluded from the F-D1 M1 import-check arm.
//!
//! [`plan_drain`] composes the three stages on an already-loaded record set:
//! the caller (the eventual drain actor/command) loads
//! `PScanState.funding_outputs` exactly as `bond_orchestrator` does and hands
//! the records in; assembling the selected outputs into a signed, broadcast
//! transaction is the downstream follow-on (the claim-assembly analog), not
//! this module. What lands here is the enforced carve: the projection is the
//! only path from records to operands, and the guarded stages are armed
//! against ever reading the decomposition.
//!
//! ## F-D2 (core-side half)
//!
//! The drain's `P`-balance surface is the **aggregate scalar**
//! ([`DrainBalance`]) — never a per-epoch/per-reward decomposition, mirroring
//! the principal `LedgerEngine::balance() -> BalanceSummary` aggregate
//! discipline (`local_ledger.rs`). The planning entry takes a single scalar
//! `target` ([`plan_drain`]), so a UI built on this surface structurally
//! cannot pre-fill or hand in a reward-shaped decomposition: the breakdown
//! never reaches it. The wallet-flow default itself — "never seed a
//! reward-derived amount; offer round-number / random-split" — is a UI
//! affordance against *user-eye* reconstruction (§12.4 coverage boundary) and
//! lands in `shekyl-gui-wallet`; it is **not** part of this PR. F-D2 is not
//! recorded as landed until that flow is built.

use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_types::{BlockHeight, GlobalOutputIndex};
use shekyl_units::AtomicUnits;

use super::drain_amount::{choose_drain_amount, DrainAmountError, DrainRequest};
use super::drain_select::{select_for_drain, DrainCandidate, DrainSelectError};

/// The drain-path `P`-balance surface: a single aggregate spendable scalar
/// (F-D2 core-side). Carries no per-output/per-epoch breakdown by
/// construction — the projection that produces it has already dropped every
/// reward-sequence coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainBalance {
    /// Sum of the provable (mature) `P` funding outputs at the reference
    /// height. A public aggregate, treated like the principal balance
    /// summary.
    pub spendable: AtomicUnits,
}

/// The output of the drain planner: the selected input identities, the drain
/// amount, and the change — all public, none reward-decomposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainPlan {
    /// The amount to move (proven affordable against the aggregate scalar,
    /// never a reward subsum).
    pub amount: AtomicUnits,
    /// The selected outputs' global indices (curve-tree leaf positions the
    /// downstream assembly re-maps to full records for spending).
    pub inputs: Vec<GlobalOutputIndex>,
    /// The sum of the selected inputs' amounts (`>= amount`).
    pub input_total: AtomicUnits,
    /// `input_total - amount`; the change the assembly returns to `P`.
    pub change: AtomicUnits,
}

/// Why the drain planner could not produce a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainError {
    /// The requested target was zero.
    EmptyRequest,
    /// The requested target exceeds the aggregate spendable scalar.
    Unaffordable,
    /// The stripped candidate set could not cover the drain amount. **Not
    /// reachable through [`plan_drain`]**: the amount stage proves `target <=
    /// spendable`, and `spendable` is the sum of the *same* mature candidate
    /// set the select stage draws from, so a passing affordability check
    /// guarantees coverage. This variant exists for the standalone
    /// [`select_for_drain`] contract (a direct caller can hand it an amount
    /// exceeding its candidate sum); [`plan_drain`] maps it for totality only.
    InsufficientSpendable,
    /// Atomic-unit arithmetic overflowed while aggregating or computing
    /// change (structurally unreachable under the supply cap; a corrupt state
    /// otherwise).
    AmountOverflow,
}

impl From<DrainAmountError> for DrainError {
    fn from(e: DrainAmountError) -> Self {
        match e {
            DrainAmountError::Empty => DrainError::EmptyRequest,
            DrainAmountError::Unaffordable => DrainError::Unaffordable,
        }
    }
}

impl From<DrainSelectError> for DrainError {
    fn from(e: DrainSelectError) -> Self {
        match e {
            DrainSelectError::Insufficient => DrainError::InsufficientSpendable,
            DrainSelectError::Overflow => DrainError::AmountOverflow,
        }
    }
}

/// The prepared drain operands: the two projections the guarded stages read.
///
/// Minting this is the projection act — the record vector's `{lineage,
/// epoch, height}` are consumed here and do not survive into the operands.
struct DrainOperands {
    /// Aggregate spendable scalar (amount-stage affordability input; also the
    /// F-D2 balance surface).
    balance: DrainBalance,
    /// Stripped per-output candidates (select-stage input).
    candidates: Vec<DrainCandidate>,
}

/// Project `P`'s persisted funding records into the drain operands: drop
/// `{lineage, epoch, height}`, keep only the provable (mature) subset, and
/// reduce to the aggregate scalar + the stripped candidate vector.
///
/// This is the sole site that reads the funding record's stripped-away
/// fields; the operands it returns carry none of them.
fn project_drain_operands(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
) -> Result<DrainOperands, DrainError> {
    // Mature/provable subset only: a record whose leaf is not yet in the tree
    // at the reference height cannot be spent (no membership path), exactly
    // the `spendable_height <= reference_height` rule the backing/claim paths
    // apply.
    let candidates: Vec<DrainCandidate> = records
        .iter()
        .filter(|r| r.spendable_height <= reference_height)
        .map(|r| DrainCandidate {
            output_id: r.gindex,
            amount: r.amount,
            spendable_height: r.spendable_height,
        })
        .collect();

    let spendable = AtomicUnits::checked_sum(candidates.iter().map(|c| c.amount))
        .ok_or(DrainError::AmountOverflow)?;

    Ok(DrainOperands {
        balance: DrainBalance { spendable },
        candidates,
    })
}

/// F-D2 core-side surface: the aggregate spendable `P` balance at a reference
/// height. Reads the same projection [`plan_drain`] does, and exposes only
/// the scalar — no decomposition reaches the caller.
pub fn drain_balance(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
) -> Result<DrainBalance, DrainError> {
    Ok(project_drain_operands(records, reference_height)?.balance)
}

/// Plan a drain of `target` atomic units out of `P`'s spendable funding
/// outputs at `reference_height`.
///
/// Runs the three F-D1 stages in order — project (this module) → amount
/// ([`choose_drain_amount`], affordability against the aggregate scalar only)
/// → select ([`select_for_drain`], lineage-blind over the stripped vector).
/// `target` is a single scalar (F-D2 core-side contract): the caller cannot
/// hand in a reward decomposition, and the amount the planner returns is
/// provably not any reward subsum.
pub fn plan_drain(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    target: AtomicUnits,
) -> Result<DrainPlan, DrainError> {
    let operands = project_drain_operands(records, reference_height)?;
    let amount = choose_drain_amount(DrainRequest { target }, operands.balance.spendable)?;
    let selection = select_for_drain(&operands.candidates, amount, reference_height)?;
    let change = selection
        .input_total
        .checked_sub(amount.get())
        .ok_or(DrainError::AmountOverflow)?;
    Ok(DrainPlan {
        amount: amount.get(),
        inputs: selection.chosen,
        input_total: selection.input_total,
        change,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::funding_record;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    /// A mature funding record: `funding_record` derives
    /// `spendable_height = height + SPENDABLE_AGE (10)`, so a record minted at
    /// height 90 is provable from height 100 onward.
    fn mature(gindex: u64, amount: u64) -> PFundingOutputRecord {
        funding_record(0, gindex, 90, amount, MintLineageOutput::BondPostChange)
    }

    const REF: u64 = 100;

    #[test]
    fn drain_balance_sums_only_mature_outputs() {
        let mut immature = mature(3, 1_000_000);
        immature.spendable_height = BlockHeight::from_raw(REF + 1);
        let records = [mature(1, 40), mature(2, 60), immature];

        let balance = drain_balance(&records, BlockHeight::from_raw(REF)).expect("projects");

        // 40 + 60; the immature million is excluded from the spendable scalar.
        assert_eq!(balance.spendable, AtomicUnits::from_raw(100));
    }

    #[test]
    fn plan_drain_selects_largest_first_and_returns_change() {
        let records = [mature(1, 30), mature(2, 100), mature(3, 30)];

        let plan = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(90),
        )
        .expect("affordable and coverable");

        // Largest single output (100) covers 90; change is 10.
        assert_eq!(plan.amount, AtomicUnits::from_raw(90));
        assert_eq!(plan.inputs, vec![GlobalOutputIndex::from_raw(2)]);
        assert_eq!(plan.input_total, AtomicUnits::from_raw(100));
        assert_eq!(plan.change, AtomicUnits::from_raw(10));
    }

    #[test]
    fn plan_drain_rejects_zero_target() {
        let records = [mature(1, 100)];
        let err = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(0),
        );
        assert_eq!(err, Err(DrainError::EmptyRequest));
    }

    #[test]
    fn plan_drain_rejects_target_over_spendable_scalar() {
        // Mature spendable is 100; an immature output cannot lift the ceiling.
        let mut immature = mature(2, 1_000);
        immature.spendable_height = BlockHeight::from_raw(REF + 1);
        let records = [mature(1, 100), immature];

        let err = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(101),
        );
        assert_eq!(err, Err(DrainError::Unaffordable));
    }
}
