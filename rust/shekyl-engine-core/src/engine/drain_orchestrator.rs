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
//!   only). The per-output reward vector is never in scope, so core code
//!   cannot *compute* a reward-shaped subsum from it.
//! - **Select** ([`super::drain_select::select_for_drain`]): lineage-blind
//!   coin selection over the stripped `{output_id, amount, spendable_height}`
//!   vector.
//! - **Project** (this module): the single trust boundary. It is the **only**
//!   drain-path site that holds the persisted funding-output records (the
//!   `PScanState.funding_outputs` set the caller loads) — so it is the only
//!   site *permitted to observe* their mint-lineage tag, arrival epoch, and
//!   arrival height, and it drops all three by projecting only `{output_id,
//!   amount, spendable_height}`. It reduces the records into the two operands
//!   the guarded stages consume — the aggregate spendable scalar and the
//!   stripped candidate vector — mirroring the established "orchestrator
//!   prepares operands, downstream receives prepared values" seam
//!   (`claim_orchestrator.rs`). The amount and select modules never name the
//!   record or the lineage tag; this module does, and is deliberately
//!   excluded from the F-D1 M1 import-check arm.
//!
//! [`plan_drain`] composes the three stages on an already-loaded record set:
//! the caller (the eventual drain actor/command) loads
//! `PScanState.funding_outputs` exactly as `bond_orchestrator` does and hands
//! the records in; assembling the selected outputs into a signed, broadcast
//! transaction is the downstream follow-on (the claim-assembly analog), not
//! this module. What lands here is the enforced carve: the projection is the
//! only path from records to the *guarded stages'* operands (the amount scalar
//! and the stripped candidate vector), and those stages are armed against ever
//! reading the decomposition. The aggregate balance read ([`drain_balance`]) is
//! a lineage-blind scalar sum that observes the same carve without building the
//! candidate vector.
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

use std::collections::BTreeSet;

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
/// amount, and the change — none reward-decomposed.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for DrainPlan {
    /// Redacted: `inputs` is the set of leaf positions `P` is about to drain
    /// together — a slice of `P`'s spend set, which the firewall keeps
    /// unenumerable, same discipline as the stripped candidates it came from.
    /// The aggregate scalars (`amount`, `input_total`, `change`) are public and
    /// render.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainPlan")
            .field("amount", &self.amount)
            .field("inputs", &"<redacted spend-set>")
            .field("input_total", &self.input_total)
            .field("change", &self.change)
            .finish()
    }
}

/// Why the drain planner could not produce a plan.
///
/// Public API (returned by [`plan_drain`] / [`drain_balance`]), so it carries
/// `Display` + `std::error::Error` via `thiserror` — the same discipline as the
/// other public engine errors (`PScanStartError`) — to compose with `?` and
/// surface a human-readable reason up through a UI/logging boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrainError {
    /// The requested target was zero.
    #[error("the requested drain amount is zero")]
    EmptyRequest,
    /// The requested target exceeds the aggregate spendable scalar.
    #[error("the requested drain amount exceeds the spendable balance")]
    Unaffordable,
    /// The stripped candidate set could not cover the drain amount. **Not
    /// reachable through [`plan_drain`]**: the amount stage proves `target <=
    /// spendable`, and `spendable` is the sum of the *same* mature candidate
    /// set the select stage draws from, so a passing affordability check
    /// guarantees coverage. This variant exists for the standalone
    /// [`select_for_drain`] contract (a direct caller can hand it an amount
    /// exceeding its candidate sum); [`plan_drain`] maps it for totality only.
    #[error("the spendable outputs cannot cover the drain amount")]
    InsufficientSpendable,
    /// Atomic-unit arithmetic overflowed while aggregating or computing
    /// change (structurally unreachable under the supply cap; a corrupt state
    /// otherwise).
    #[error("atomic-unit arithmetic overflowed while planning the drain")]
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

/// The maturity predicate the projection and the balance surface share: a
/// record is provable (spendable) once its leaf is in the curve tree at the
/// reference height — the `spendable_height <= reference_height` rule the
/// backing/claim paths apply (a record whose leaf is not yet in the tree has no
/// membership path and cannot be spent). Reads only `spendable_height`, a
/// maturity axis and never a reward-sequence coordinate, so applying it outside
/// the projection discloses nothing the aggregate scalar doesn't already.
fn is_mature(record: &PFundingOutputRecord, reference_height: BlockHeight) -> bool {
    record.spendable_height <= reference_height
}

/// Project `P`'s persisted funding records into the drain operands: drop
/// `{lineage, epoch, height}`, keep only the provable (mature) **and
/// unreserved** subset, and reduce to the aggregate scalar + the stripped
/// candidate vector.
///
/// `reserved` is the gindex union already committed to in-flight bond posts /
/// claims / drains (`PendingPostBlock::reserved_gindexes`). Excluding it here —
/// the *same* carve [`drain_balance`] applies — keeps both operands consistent:
/// the spendable scalar the amount stage checks affordability against, and the
/// candidate set [`select_for_drain`] draws from, are one net set. That is what
/// makes the totals reconcile (a plan can never be sized against funds a live tx
/// already holds) and structurally bars the selector from choosing a reserved
/// output — a double-spend of an in-flight input. A gindex is a public
/// curve-tree leaf position, so the filter stays lineage-blind.
///
/// This is the sole site that reads the funding record's stripped-away
/// fields; the operands it returns carry none of them.
fn project_drain_operands(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainOperands, DrainError> {
    let candidates: Vec<DrainCandidate> = records
        .iter()
        .filter(|r| is_mature(r, reference_height) && !reserved.contains(&r.gindex))
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
/// height. Exposes only the scalar — no decomposition reaches the caller.
///
/// "Spendable" is **mature ∧ unreserved** — the codebase's standing definition
/// of a persona's usable `P` funding (`bond_assembly`'s sweep sums the
/// *unreserved* mature records, and `InsufficientFunding.available` is their
/// sum). `reserved` is the union of gindexes already committed to in-flight
/// bond posts / claims / drains (`PendingPostBlock::reserved_gindexes`); an
/// output a live tx holds cannot also be drained, so counting it would
/// over-report "drainable". A gindex is a public curve-tree leaf position, so
/// the filter stays lineage-blind — never a reward-sequence coordinate.
///
/// A balance read needs only the aggregate, so it sums the eligible amounts
/// directly rather than routing through [`project_drain_operands`], which
/// materialises the stripped candidate vector the *select* stage consumes — a
/// heap allocation a poll-frequency query has no use for. It observes the same
/// carve: only `amount`, gated by the shared [`is_mature`] predicate.
pub fn drain_balance(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainBalance, DrainError> {
    let spendable = AtomicUnits::checked_sum(
        records
            .iter()
            .filter(|r| is_mature(r, reference_height) && !reserved.contains(&r.gindex))
            .map(|r| r.amount),
    )
    .ok_or(DrainError::AmountOverflow)?;
    Ok(DrainBalance { spendable })
}

/// Plan a drain of `target` atomic units out of `P`'s spendable funding
/// outputs at `reference_height`.
///
/// Runs the three F-D1 stages in order — project (this module; mature ∧
/// unreserved) → amount ([`choose_drain_amount`], affordability against the
/// aggregate scalar only) → select ([`select_for_drain`], lineage-blind over the
/// stripped vector). `reserved` (the in-flight gindex union) is excluded at the
/// projection, so the spendable scalar, the affordability check, and the
/// selectable candidates are one consistent net set — a drain can neither be
/// planned against nor select an output an in-flight tx already holds, and its
/// figure reconciles with the [`drain_balance`] read.
///
/// `target` is a single scalar (F-D2 core-side contract): the caller cannot
/// hand in a reward decomposition, and the per-output reward vector never
/// reaches the amount stage — so core code cannot *compute* a reward-shaped
/// amount. Steering the returned value away from a subsum is the F-D2 UI
/// default (round-number / random-split), not built here.
pub fn plan_drain(
    records: &[PFundingOutputRecord],
    reference_height: BlockHeight,
    target: AtomicUnits,
    reserved: &BTreeSet<GlobalOutputIndex>,
) -> Result<DrainPlan, DrainError> {
    let operands = project_drain_operands(records, reference_height, reserved)?;
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

        let balance = drain_balance(&records, BlockHeight::from_raw(REF), &BTreeSet::new())
            .expect("projects");

        // 40 + 60; the immature million is excluded from the spendable scalar.
        assert_eq!(balance.spendable, AtomicUnits::from_raw(100));
    }

    #[test]
    fn drain_balance_excludes_reserved_outputs() {
        // gindex 2 is committed to an in-flight bond post / claim / drain, so it
        // is not drainable — it must not count toward the spendable scalar even
        // though it is mature ("spendable = unreserved mature").
        let records = [mature(1, 40), mature(2, 60), mature(3, 5)];
        let reserved = BTreeSet::from([GlobalOutputIndex::from_raw(2)]);

        let balance =
            drain_balance(&records, BlockHeight::from_raw(REF), &reserved).expect("projects");

        // 40 + 5; the reserved 60 is excluded.
        assert_eq!(balance.spendable, AtomicUnits::from_raw(45));
    }

    #[test]
    fn plan_drain_selects_largest_first_and_returns_change() {
        let records = [mature(1, 30), mature(2, 100), mature(3, 30)];

        let plan = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(90),
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
        );
        assert_eq!(err, Err(DrainError::Unaffordable));
    }

    #[test]
    fn plan_drain_never_plans_against_or_selects_a_reserved_output() {
        // The big output (gindex 2, 100) is committed to an in-flight tx. The
        // plan must (a) size affordability against the unreserved total only —
        // 30 + 30 = 60, so a target of 90 is Unaffordable — and (b) never select
        // the reserved output. Both operands must be net, or the read total and
        // the drainable total disagree and the selector could double-spend an
        // in-flight input.
        let records = [mature(1, 30), mature(2, 100), mature(3, 30)];
        let reserved = BTreeSet::from([GlobalOutputIndex::from_raw(2)]);

        // (a) affordability is against the net scalar (60), not the gross (160).
        let err = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(90),
            &reserved,
        );
        assert_eq!(err, Err(DrainError::Unaffordable));

        // (b) an affordable target draws only from the unreserved candidates.
        let plan = plan_drain(
            &records,
            BlockHeight::from_raw(REF),
            AtomicUnits::from_raw(50),
            &reserved,
        )
        .expect("50 <= 60 net spendable");
        assert!(
            !plan.inputs.contains(&GlobalOutputIndex::from_raw(2)),
            "selector chose a reserved (in-flight) output: {:?}",
            plan.inputs
        );
    }
}
