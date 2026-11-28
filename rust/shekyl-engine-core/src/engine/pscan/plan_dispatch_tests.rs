// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The plan half of the dispatch driver's tests (BD-Q2, BD-Q3).
//!
//! A child of the driver's suite so the due, the endings and the drain
//! stay next to each other. The scripted signer and the post fixtures
//! stay with the driver.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_engine_state::pending_post_block::OutcomeKind;
use shekyl_engine_state::{PendingPostBlock, PendingPostState};
use shekyl_types::{BlockCount, ChainCount, PCanonicalId, PSlot};
use tokio_util::sync::CancellationToken;

use super::{
    accepted, driver_with_posts, persona, post, test_config, test_lock, tick, DispatchDriver,
    DispatchTick, MemStore, PlanAttempt, PlanEnding, PlanWait, ScriptedBroadcast, ScriptedSigner,
    TestDriver, TickEvidence, TickOutcome, Verdict,
};
use crate::engine::bond_plan::FundingPlace;

// -- gate 1: due-check boundaries ----------------------------------------

/// The plan's due is boundary-exact on the count clock (BD-Q2: `a + 1 + s`
/// with `a` the funding's anchor): nothing is signed at `due − 1`, it is
/// signed and sent at `due`, and a late first tick (`due + k`) still signs
/// and sends it, with no re-draw (elapsed time counts).
#[tokio::test]
async fn due_check_boundaries() {
    let due = 1_721 + 10;
    let (mut driver, _store, broadcast, _signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 10)], vec![accepted()]);
    tick_funded(&mut driver, due - 1, &one_output(), &BTreeSet::new()).await;
    assert!(broadcast.sent().is_empty(), "tip = due − 1 must not fire");
    tick_funded(&mut driver, due, &one_output(), &BTreeSet::new()).await;
    assert_eq!(broadcast.sent().len(), 1, "tip = due fires");

    let (mut late_driver, _s, late_broadcast, _late_signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 10)], vec![accepted()]);
    tick_funded(&mut late_driver, due + 160, &one_output(), &BTreeSet::new()).await;
    assert_eq!(
        late_broadcast.sent().len(),
        1,
        "tip = due + k fires (lateness only adds delay, never a re-draw)"
    );
}

// -- gate 2: one-per-tick + deterministic ordering ------------------------

/// A catch-up backlog (every plan overdue on one tick) signs and sends
/// exactly one post per tick, lowest due first; ties break by persona id.
#[tokio::test]
async fn one_per_tick_and_deterministic_ordering() {
    // due: A=1751 (draw 30), B=C=D=1741 (draw 20).
    let plans = vec![
        a_plan(0xAA, 1, 30),
        a_plan(0xBB, 2, 20),
        a_plan(0xCC, 3, 20),
        a_plan(0xDD, 4, 20),
    ];
    let (mut driver, _store, broadcast, _signer) =
        driver_with_plans(plans, (0..4).map(|_| accepted()).collect());
    let funding: BTreeMap<_, _> = [(1, 0xAA), (2, 0xBB), (3, 0xCC), (4, 0xDD)]
        .into_iter()
        .map(|(g, slot)| {
            (
                shekyl_types::GlobalOutputIndex::from_raw(g),
                place(slot, 1_000),
            )
        })
        .collect();

    // Every plan overdue at once: the downtime catch-up shape (§3.2).
    for _ in 0..4 {
        tick_funded(&mut driver, 1_800, &funding, &BTreeSet::new()).await;
    }
    let sent: Vec<PCanonicalId> = broadcast.sent().iter().map(|(p, _)| *p).collect();
    assert_eq!(
        sent,
        vec![persona(0xBB), persona(0xCC), persona(0xDD), persona(0xAA)],
        "order: lowest due first (B/C/D at 1741 before A at 1751); the tie breaks by \
         persona id"
    );
    assert_eq!(broadcast.sent().len(), 4, "strictly one per tick");
}

// -- BD-Q3: signing at due, and how a plan ends (ruled 2026-11-26) -------------

/// The funding place of one output at `height` for `slot`: ordinary
/// maturity, spendable ten blocks on.
fn place(slot: u8, height: u64) -> FundingPlace {
    FundingPlace {
        p_slot: PSlot::from_raw(u32::from(slot)),
        height: shekyl_types::BlockHeight::from_raw(height),
        spendable_height: shekyl_types::BlockHeight::from_raw(height + 10),
    }
}

fn a_plan(persona_byte: u8, gindex: u64, draw: u64) -> shekyl_engine_state::PendingBondPlan {
    shekyl_engine_state::PendingBondPlan {
        p_slot: PSlot::from_raw(u32::from(persona_byte)),
        persona: persona(persona_byte),
        posture: shekyl_engine_state::PlannedPosture::SupportCompleteTree,
        draw: BlockCount::from_raw(draw),
        requested_at: ChainCount::from_raw(1_000),
        funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(gindex)],
        funded_through: shekyl_types::BlockHeight::from_raw(1_000),
        wait: None,
    }
}

/// A driver over a block holding `plans`, with a scripted signer.
fn driver_with_plans(
    plans: Vec<shekyl_engine_state::PendingBondPlan>,
    outcomes: Vec<Verdict>,
) -> (
    TestDriver,
    std::sync::Arc<MemStore>,
    std::sync::Arc<ScriptedBroadcast>,
    std::sync::Arc<ScriptedSigner>,
) {
    let store = std::sync::Arc::new(MemStore::default());
    let mut block = PendingPostBlock::empty();
    for plan in plans {
        let g = block.generation();
        assert_eq!(
            block.seal_plan(plan, g),
            shekyl_engine_state::pending_post_block::SealAdmission::Admit
        );
    }
    *store.block.lock().expect("mem store") = Some(block);
    let broadcast = std::sync::Arc::new(ScriptedBroadcast::scripted(outcomes));
    let signer = std::sync::Arc::new(ScriptedSigner::over(store.clone()));
    let driver = DispatchDriver::new(
        store.clone(),
        broadcast.clone(),
        signer.clone(),
        test_config(),
        test_lock(),
    );
    (driver, store, broadcast, signer)
}

/// A tick with the funding places the scan holds (their outputs are the live
/// set) and the personas it has retired.
async fn tick_funded(
    driver: &mut TestDriver,
    tip: u64,
    funding: &BTreeMap<shekyl_types::GlobalOutputIndex, FundingPlace>,
    retired: &BTreeSet<PCanonicalId>,
) -> TickOutcome {
    let live: BTreeSet<shekyl_types::GlobalOutputIndex> = funding.keys().copied().collect();
    driver
        .on_tick(
            ChainCount::from_raw(tip),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &live,
                scanned_through: Some(shekyl_types::BlockHeight::from_raw(tip - 1)),
                funding,
                retired,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick")
}

fn block_of(store: &MemStore) -> PendingPostBlock {
    store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("a seeded block")
}

/// One funding output at height 1 000 for slot 0xA1, gindex 1. Its anchor is
/// the scan horizon, `1 000 + 720` (BD-Q2), so a plan drawing `s` is due at
/// count `1 721 + s`.
fn one_output() -> BTreeMap<shekyl_types::GlobalOutputIndex, FundingPlace> {
    BTreeMap::from([(
        shekyl_types::GlobalOutputIndex::from_raw(1),
        place(0xA1, 1_000),
    )])
}

/// The FOLLOWUPS falsifier, on the driver: a plan is not signed before its
/// due block, and at its due block it is signed and sent in the same tick,
/// at reference age 6 from the claimed tip.
#[tokio::test]
async fn a_plan_signed_at_its_due_block_is_sent_at_reference_age_six() {
    let (mut driver, store, broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 37)], vec![]);
    let funding = one_output();
    let due = 1_721 + 37;

    tick_funded(&mut driver, due - 1, &funding, &BTreeSet::new()).await;
    assert!(
        signer.signed().is_empty(),
        "not signed before its due block"
    );
    assert!(broadcast.sent().is_empty());

    tick_funded(&mut driver, due, &funding, &BTreeSet::new()).await;
    assert_eq!(signer.signed(), vec![persona(0xA1)]);
    assert_eq!(
        broadcast.sent().len(),
        1,
        "sent in the tick it was signed in"
    );
    let block = block_of(&store);
    let post = &block.posts()[0];
    let claimed_tip = due - 1;
    assert_eq!(
        post.reference_height.to_raw(),
        claimed_tip - 6,
        "reference age 6"
    );
    assert!(matches!(post.state, PendingPostState::Dispatched { .. }));
}

/// A plan blocked past the draw window by a fee above its funding signs and
/// is sent when the fee falls; the window bounds when a post comes due, not
/// when it lands. Its reason is kept while it waits.
///
/// **Scripted, not live:** the signer's answers are scripted
/// (`ScriptedSigner`). A regtest chain cannot hold a fee above a plan's
/// funding without a fee lever in production, which is ruled out, so this
/// runs the real driver against scripted waits. The mapping from a real
/// funding shortfall to [`PlanWait::FeeAboveFunding`] is
/// `bond_due_tests.rs`.
#[tokio::test]
async fn a_plan_blocked_past_the_window_by_the_fee_signs_when_the_fee_falls() {
    let (mut driver, store, broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 600)], vec![]);
    let funding = one_output();
    let due = 1_721 + 600;
    signer.script.lock().expect("script").extend([
        PlanAttempt::Wait(PlanWait::FeeAboveFunding),
        PlanAttempt::Wait(PlanWait::FeeAboveFunding),
    ]);
    tick_funded(&mut driver, due, &funding, &BTreeSet::new()).await;
    tick_funded(&mut driver, due + 200, &funding, &BTreeSet::new()).await;
    assert_eq!(
        block_of(&store).plans()[0].wait,
        Some(PlanWait::FeeAboveFunding),
        "the reason is shown while it waits"
    );
    assert!(broadcast.sent().is_empty());

    let late = due + 400;
    assert!(late > 1_720 + crate::engine::stake_timing::DEFAULT_ENTRY_GAP.as_blocks());
    tick_funded(&mut driver, late, &funding, &BTreeSet::new()).await;
    assert_eq!(
        broadcast.sent().len(),
        1,
        "signed and sent once the fee fell"
    );
    assert!(block_of(&store).plans().is_empty());
}

/// A plan still blocked for a limited reason when its maximum wait passes
/// ends with its own outcome; a temporary reason never ends it.
///
/// **Scripted, not live:** the signer's answers are scripted
/// (`ScriptedSigner`). A regtest chain cannot hold a fee above a plan's
/// funding without a fee lever in production, which is ruled out, so this
/// runs the real driver against scripted waits. The mapping from a real
/// funding shortfall to [`PlanWait::FeeAboveFunding`] is
/// `bond_due_tests.rs`.
#[tokio::test]
async fn a_plan_at_its_maximum_ends_waited_out_and_a_temporary_wait_never_does() {
    let (mut driver, store, broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 0)], vec![]);
    let funding = one_output();
    let due = 1_721;
    let at_max = due + crate::engine::bond_plan::PLAN_MAX_WAIT.to_raw();
    signer.script.lock().expect("script").extend([
        PlanAttempt::Wait(PlanWait::NodeUnreachable),
        PlanAttempt::Wait(PlanWait::FeeAboveFunding),
    ]);
    tick_funded(&mut driver, at_max, &funding, &BTreeSet::new()).await;
    assert_eq!(
        block_of(&store).plans().len(),
        1,
        "a temporary wait has no limit"
    );

    tick_funded(&mut driver, at_max + 1, &funding, &BTreeSet::new()).await;
    let block = block_of(&store);
    assert!(block.plans().is_empty());
    assert_eq!(block.ended_plans()[0].ending, PlanEnding::WaitedOut);
    assert_eq!(
        signer.ended(),
        vec![PSlot::from_raw(0xA1)],
        "deactivated at once"
    );
    assert_eq!(
        block.outcomes().last().map(|o| o.outcome),
        Some(OutcomeKind::WaitedOut)
    );
    assert!(broadcast.sent().is_empty(), "nothing was sent");
}

/// A withdrawn plan: its reservation is released, one drain to the
/// principal is sent, and once the persona holds nothing its slot is handed
/// to the scan task to retire; the record goes once the retirement is
/// durable.
#[tokio::test]
async fn a_withdrawn_plan_is_drained_once_and_its_persona_retired() {
    let (mut driver, store, _broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 37)], vec![]);
    {
        let mut guard = store.block.lock().expect("mem store");
        let block = guard.as_mut().expect("seeded");
        assert!(matches!(
            block.withdraw_plan(&persona(0xA1), shekyl_types::BlockHeight::from_raw(1_100)),
            shekyl_engine_state::Withdrawal::Withdrawn(_)
        ));
        assert!(
            block.reserved_gindexes().is_empty(),
            "the reservation is released"
        );
    }
    let funding = one_output();
    let out = tick_funded(&mut driver, 1_200, &funding, &BTreeSet::new()).await;
    assert_eq!(
        signer.drains(),
        vec![(PSlot::from_raw(0xA1), persona(0xA1))]
    );
    assert_eq!(
        signer.ended(),
        vec![PSlot::from_raw(0xA1)],
        "deactivated from the ended row"
    );
    assert!(out.retire.is_empty(), "still funded");
    assert!(
        signer.signed().is_empty(),
        "a withdrawn plan is never signed"
    );

    // The drain confirmed: the persona holds nothing, so it is retired.
    let out = tick_funded(&mut driver, 1_300, &BTreeMap::new(), &BTreeSet::new()).await;
    assert_eq!(
        signer.ended(),
        vec![PSlot::from_raw(0xA1), PSlot::from_raw(0xA1)],
        "an ended plan is deactivated again on the next tick"
    );
    assert_eq!(signer.drains().len(), 1, "one drain");
    assert_eq!(out.retire.len(), 1);
    assert_eq!(out.retire[0].persona(), persona(0xA1));

    let retired = BTreeSet::from([persona(0xA1)]);
    tick_funded(&mut driver, 1_301, &BTreeMap::new(), &retired).await;
    assert!(block_of(&store).ended_plans().is_empty());
    assert_eq!(
        signer.retired(),
        vec![PSlot::from_raw(0xA1)],
        "its slot leaves the live staking record"
    );
}

/// A crash between the ending's save and the drain's send: the next open's
/// driver reads the ended plan and sends the drain.
#[tokio::test]
async fn a_crash_after_the_ending_sends_the_drain_on_the_next_open() {
    let (_first, store, _broadcast, _signer) = driver_with_plans(vec![a_plan(0xA1, 1, 0)], vec![]);
    {
        let mut guard = store.block.lock().expect("mem store");
        let block = guard.as_mut().expect("seeded");
        assert!(block
            .end_plan(
                &persona(0xA1),
                PlanEnding::WaitedOut,
                shekyl_types::BlockHeight::from_raw(2_400),
            )
            .is_some());
    }
    // Reopen: a fresh driver over the same seal.
    let signer = std::sync::Arc::new(ScriptedSigner::over(store.clone()));
    let mut reopened = DispatchDriver::new(
        store.clone(),
        std::sync::Arc::new(ScriptedBroadcast::scripted(vec![])),
        signer.clone(),
        test_config(),
        test_lock(),
    );
    tick_funded(&mut reopened, 2_401, &one_output(), &BTreeSet::new()).await;
    assert_eq!(
        signer.drains(),
        vec![(PSlot::from_raw(0xA1), persona(0xA1))]
    );
}

/// A plan whose reserved funding left the live set was spent by another
/// transaction: it ends at once, unsigned.
#[tokio::test]
async fn a_plan_whose_funding_was_spent_elsewhere_ends_at_once() {
    let (mut driver, store, broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 0)], vec![]);
    let other = BTreeMap::from([(
        shekyl_types::GlobalOutputIndex::from_raw(9),
        place(0xA1, 1_000),
    )]);
    tick_funded(&mut driver, 5_000, &other, &BTreeSet::new()).await;
    let block = block_of(&store);
    assert!(block.plans().is_empty());
    assert_eq!(block.ended_plans()[0].ending, PlanEnding::SpentElsewhere);
    assert_eq!(
        signer.ended(),
        vec![PSlot::from_raw(0xA1)],
        "deactivated at once"
    );
    assert!(signer.signed().is_empty() && broadcast.sent().is_empty());
}

/// One transaction per tick: an owed drain waits for a tick that sends no
/// post, so two personas never leave together.
#[tokio::test]
async fn an_owed_drain_never_leaves_in_the_same_tick_as_a_post() {
    let (mut driver, store, broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 0), a_plan(0xB2, 2, 0)], vec![]);
    let mut funding = one_output();
    funding.insert(
        shekyl_types::GlobalOutputIndex::from_raw(2),
        place(0xB2, 1_000),
    );
    {
        let mut guard = store.block.lock().expect("mem store");
        assert!(matches!(
            guard
                .as_mut()
                .expect("seeded")
                .withdraw_plan(&persona(0xB2), shekyl_types::BlockHeight::from_raw(1_100)),
            shekyl_engine_state::Withdrawal::Withdrawn(_)
        ));
    }
    tick_funded(&mut driver, 1_721, &funding, &BTreeSet::new()).await;
    assert_eq!(broadcast.sent().len(), 1, "the due post went");
    assert!(signer.drains().is_empty(), "the drain waited");
    tick_funded(&mut driver, 1_722, &funding, &BTreeSet::new()).await;
    assert_eq!(
        signer.drains().len(),
        1,
        "the drain went on a tick with no post"
    );
}

/// BD-Q3 Rule 1: a post signed but never sent (its send did not happen
/// before the wallet closed) is signed again at the canonical reference
/// before its first send, never sent at an older age.
#[tokio::test]
async fn a_post_never_sent_is_re_signed_before_its_first_send() {
    let (mut driver, store, broadcast) =
        driver_with_posts(vec![post(0xA1, 1_000, 0, &[1])], vec![]);
    // Ten blocks after it was signed (below REBUILD_AT).
    tick(&mut driver, 1_010).await;
    assert_eq!(broadcast.sent().len(), 1);
    let block = block_of(&store);
    assert_eq!(block.posts()[0].reference_height.to_raw(), 1_009 - 6);
}

/// Absence from a scan that has not covered the funding's block is not a
/// spend: after a rescan the live set is empty until the scan reaches it, and
/// a plan must neither end nor its persona retire on that.
#[tokio::test]
async fn absence_before_the_scan_covers_the_funding_is_not_a_spend() {
    let (mut driver, store, _broadcast, signer) =
        driver_with_plans(vec![a_plan(0xA1, 1, 0)], vec![]);
    let live = BTreeSet::new();
    let funding = BTreeMap::new();
    let retired = BTreeSet::new();
    let out = driver
        .on_tick(
            ChainCount::from_raw(5_000),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &live,
                // A fresh scan, short of the funding block at 1 000.
                scanned_through: Some(shekyl_types::BlockHeight::from_raw(400)),
                funding: &funding,
                retired: &retired,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");
    assert_eq!(block_of(&store).plans().len(), 1, "the plan stands");
    assert!(out.retire.is_empty() && signer.ended().is_empty());
}
