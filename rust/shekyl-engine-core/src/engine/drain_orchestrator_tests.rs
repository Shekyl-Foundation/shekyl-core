// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for `drain_orchestrator`, in a `#[path]` sibling so the
//! production source stays under the engine-decomposition ratchet's
//! `NEW_FILE_CAP` (the pattern the crate's other `*_tests.rs` siblings
//! follow). Both files are scanned by the ratchet; this one is well under
//! the cap on its own.

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

/// This bites against the remainder being summed over the projection's
/// mature-only candidates: a pass that empties
/// the mature subset while an IMMATURE payout still sits on the slot
/// must report that payout as remainder — never `0`, which the CLI
/// renders as "collection complete" while the immature output holds the
/// funded retirement gate with nothing telling the caller to return.
/// Another slot's record must not leak into the figure. It does NOT
/// cover the wire rendering (the facade's).
#[test]
fn sweep_remainder_counts_the_immature_residue_never_zero() {
    use super::super::stake_engine::PSlot;

    let mut immature = mature(3, 1_000_000);
    immature.spendable_height = BlockHeight::from_raw(REF + 1);
    let mut other_slot = mature(9, 777);
    other_slot.p_slot = PSlot::from_raw(1);
    // The pass swept the two mature records (40 + 60).
    let records = [mature(1, 40), mature(2, 60), immature, other_slot];

    let remainder = sweep_slot_remainder(&records, PSlot::from_raw(0), AtomicUnits::from_raw(100))
        .expect("sums are small");
    assert_eq!(
        remainder,
        AtomicUnits::from_raw(1_000_000),
        "the immature payout IS the remainder; a zero here forges completion"
    );

    // Completion is exactly the whole slot swept — the genuine zero.
    let remainder = sweep_slot_remainder(
        &[mature(1, 40), mature(2, 60)],
        PSlot::from_raw(0),
        AtomicUnits::from_raw(100),
    )
    .expect("sums are small");
    assert_eq!(remainder, AtomicUnits::ZERO);
}

#[test]
fn drain_balance_sums_only_mature_outputs() {
    let mut immature = mature(3, 1_000_000);
    immature.spendable_height = BlockHeight::from_raw(REF + 1);
    let records = [mature(1, 40), mature(2, 60), immature];

    let balance =
        drain_balance(&records, BlockHeight::from_raw(REF), &BTreeSet::new()).expect("projects");

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

    let balance = drain_balance(&records, BlockHeight::from_raw(REF), &reserved).expect("projects");

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
fn scoped_records_keeps_own_slot_and_drops_reserved() {
    use shekyl_types::PSlot;

    let s = |slot: u32, g: u64| funding_record(slot, g, 90, 100, MintLineageOutput::BondPostChange);
    // slot 0: g1 (keep), g2 (reserved → drop), g4 (keep); slot 1: g3 (foreign → drop).
    let records = [s(0, 1), s(0, 2), s(1, 3), s(0, 4)];
    let reserved: BTreeSet<GlobalOutputIndex> =
        [GlobalOutputIndex::from_raw(2)].into_iter().collect();

    let kept = scoped_records(
        &SpentRecordsDurablyPruned::for_test(),
        &records,
        PSlot::from_raw(0),
        &reserved,
    );
    let gindexes: Vec<u64> = kept.iter().map(|r| r.gindex.to_raw()).collect();
    assert_eq!(
        gindexes,
        vec![1, 4],
        "keep slot-0 unreserved records; drop the reserved g2 and the foreign-slot g3"
    );
}

#[test]
fn exit_reserve_maps_liveness_to_the_floor() {
    // A live persona holds the pinned reserve; a retired one holds nothing.
    assert_eq!(exit_reserve_atomic(false), EXIT_FEE_RESERVE_ATOMIC);
    assert_eq!(exit_reserve_atomic(true), 0);
}

#[test]
fn live_drain_must_leave_the_reserve() {
    let r = EXIT_FEE_RESERVE_ATOMIC;
    // Pool exactly one payment above the reserve: `payment + fee == r`
    // clears (leaves the reserve on the nose); one atomic more breaches.
    let pool = 2 * r;
    assert!(
        enforce_exit_reserve(pool, r, false).is_ok(),
        "target that leaves exactly the reserve is allowed"
    );
    assert!(
        matches!(
            enforce_exit_reserve(pool, r + 1, false),
            Err(DrainOrchestrationError::ReserveBreached)
        ),
        "one atomic into the reserve is refused"
    );
}

#[test]
fn live_drain_below_reserve_pool_is_wholly_undrainable() {
    // A pool that cannot even cover the reserve leaves nothing drainable:
    // every positive target breaches (the `checked_sub` underflow arm).
    assert!(matches!(
        enforce_exit_reserve(EXIT_FEE_RESERVE_ATOMIC - 1, 1, false),
        Err(DrainOrchestrationError::ReserveBreached)
    ));
}

#[test]
fn live_unaffordable_target_defers_to_the_planner_not_the_reserve() {
    // A live target that exceeds the WHOLE pool is plain unaffordability,
    // not a reserve breach: the reserve gate must pass it through so the
    // planner surfaces `Unaffordable` (the actionable "too large" error),
    // rather than masking it as `ReserveBreached` (Copilot r3626008352).
    let pool = 2 * EXIT_FEE_RESERVE_ATOMIC;
    assert!(
        enforce_exit_reserve(pool, pool + 1, false).is_ok(),
        "a target over the whole pool defers to the planner's Unaffordable"
    );
    // The planner is then the arm that actually rejects it.
    let r = mature(1, pool);
    let err = plan_drain(
        std::slice::from_ref(&r),
        BlockHeight::from_raw(REF),
        AtomicUnits::from_raw(pool + 1),
        &BTreeSet::new(),
    );
    assert_eq!(err, Err(DrainError::Unaffordable));
}

#[test]
fn retired_sweep_ignores_the_reserve() {
    // A retired persona reserves nothing: a drain-all to the last atomic is
    // allowed, and the guard defers unaffordability entirely to the planner.
    let pool = EXIT_FEE_RESERVE_ATOMIC; // below the live floor, irrelevant here
    assert!(
        enforce_exit_reserve(pool, pool, true).is_ok(),
        "retired sweep of the whole pool clears the reserve gate"
    );
    // Even an over-balance target passes *this* gate (retired ⇒ no-op); the
    // planner's `Unaffordable` is the arm that catches it downstream.
    assert!(enforce_exit_reserve(pool, pool + 1, true).is_ok());
}

/// Composition + firewall pins (`wire.rs`-tripwire style; the test module
/// is split off so the needles cannot self-match):
///
/// 1. the drain pipeline is a **free function** over [`DrainCtx`], not an
///    `Engine` method — no `self_arc`, no `Arc<RwLock<Self>>` (the
///    `ENGINE_COMPOSITION_DECOMPOSITION.md` discipline the engine-side
///    entry delegates through);
/// 2. the **body of `orchestrate_drain`** (not the file — `plan_drain` is
///    still defined here as the public planner, so grepping the file for
///    it is vacuous) routes the payment arm through the F-D1 amount+select
///    half ([`plan_from_operands`]) and the sweep arm through
///    [`select_for_sweep`], never the bond sweep (`sweep_funding_outputs`),
///    which would bypass the §12.3 drain-amount taint-carve.
///
/// Named edits that make this red: delete the `plan_from_operands(` call
/// from the payment arm; delete the `select_for_sweep(` call from the
/// sweep arm; add a `sweep_funding_outputs(` call in the body.
#[test]
fn orchestrate_drain_is_a_free_function_over_the_fd1_carve() {
    let (src, _tests) = include_str!("drain_orchestrator.rs")
        .split_once("\n#[cfg(test)]")
        .expect("drain_orchestrator.rs has a #[cfg(test)] section to exclude from the scan");

    let free_fn = concat!("pub(crate) async fn orchestrate", "_drain(");
    assert!(
        src.contains(free_fn),
        "the drain pipeline must be a free function over DrainCtx"
    );
    assert!(
        !src.contains("self_arc"),
        "orchestrate_drain must not be an Engine method (no self_arc)"
    );
    assert!(
        !src.contains("Arc<RwLock"),
        "orchestrate_drain must not hold the Engine lock"
    );

    let body: String = src
        .split_once(free_fn)
        .expect("orchestrate_drain must exist to pin its body")
        .1
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n");

    let payment_planner = concat!("plan_from", "_operands(");
    assert!(
        body.contains(payment_planner),
        "the payment arm must route through the F-D1 amount+select half \
         (plan_from_operands) — grepping the file for plan_drain is vacuous \
         because this module still defines that wrapper"
    );
    let sweep_select = concat!("select_for", "_sweep(");
    assert!(
        body.contains(sweep_select),
        "the sweep arm must route through select_for_sweep"
    );
    let bond_sweep = concat!("sweep", "_funding_outputs(");
    assert!(
        !body.contains(bond_sweep),
        "the drain must not select via the bond sweep (it bypasses the §12.3 carve)"
    );
}
