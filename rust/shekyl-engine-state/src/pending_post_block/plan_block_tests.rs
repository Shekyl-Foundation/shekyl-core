// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The plan record's transitions: sealing, signing, endings, and the stage
//! a persona's stake is in. Lives beside `plan.rs`.

use std::collections::BTreeSet;

use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot};

use super::super::{
    OutcomeKind, PendingBondPost, PendingDrain, PendingPostBlock, PendingPostState, SealAdmission,
};
use super::{
    PendingBondPlan, PlanEnding, PlanWait, PlannedPosture, SignAdmission, StakeStage, Withdrawal,
};

/// The reference every test post is built at.
const TEST_REFERENCE: BlockHeight = BlockHeight::from_raw(5_000);

fn post(persona_byte: u8, gindexes: &[u64]) -> PendingBondPost {
    PendingBondPost {
        wait: None,
        p_slot: PSlot::from_raw(0),
        persona: PCanonicalId::from_bytes([persona_byte; 32]),
        tx_bytes: vec![0xAB; 16],
        posture: PlannedPosture::SupportCompleteTree,
        due: ChainCount::from_raw(1_000),
        funded_through: BlockHeight::from_raw(1_000),
        funding_gindexes: gindexes
            .iter()
            .copied()
            .map(GlobalOutputIndex::from_raw)
            .collect(),
        state: PendingPostState::Pending,
        reference_height: TEST_REFERENCE,
        terminal: None,
    }
}

fn drain(persona_byte: u8, funding_gindexes: &[u64]) -> PendingDrain {
    PendingDrain {
        persona: PCanonicalId::from_bytes([persona_byte; 32]),
        tx_bytes: vec![0xDE; 16],
        funding_gindexes: funding_gindexes
            .iter()
            .copied()
            .map(GlobalOutputIndex::from_raw)
            .collect(),
        state: PendingPostState::Pending,
        reference_height: TEST_REFERENCE,
        terminal: None,
    }
}

// ---- BD-Q3: the plan, its signing, and how it ends (v15) ----

fn plan(persona_byte: u8, gindexes: &[u64]) -> PendingBondPlan {
    PendingBondPlan {
        p_slot: PSlot::from_raw(u32::from(persona_byte)),
        persona: PCanonicalId::from_bytes([persona_byte; 32]),
        posture: PlannedPosture::SupportCompleteTree,
        draw: BlockCount::from_raw(37),
        requested_at: ChainCount::from_raw(1_000),
        funding_gindexes: gindexes
            .iter()
            .copied()
            .map(GlobalOutputIndex::from_raw)
            .collect(),
        funded_through: BlockHeight::from_raw(1_000),
        wait: None,
    }
}

fn planned(plans: &[PendingBondPlan]) -> PendingPostBlock {
    let mut block = PendingPostBlock::empty();
    for p in plans {
        let g = block.generation();
        assert_eq!(block.seal_plan(p.clone(), g), SealAdmission::Admit);
    }
    block
}

const AT: BlockHeight = BlockHeight::from_raw(2_000);

/// A plan reserves its funding from the request, and its persona holds a
/// stake in flight: a second plan or post for it refuses as live.
#[test]
fn a_plan_reserves_its_funding_and_is_its_personas_one_stake() {
    let mut block = planned(&[plan(0xA1, &[1, 2])]);
    assert_eq!(
        block.reserved_gindexes(),
        [1, 2]
            .into_iter()
            .map(GlobalOutputIndex::from_raw)
            .collect()
    );
    assert!(!block.plans().is_empty() || !block.posts().is_empty());
    let g = block.generation();
    assert_eq!(
        block.seal_plan(plan(0xA1, &[3]), g),
        SealAdmission::PersonaLive
    );
    assert_eq!(
        block.seal_post(post(0xA1, &[3]), g),
        SealAdmission::PersonaLive
    );
    assert_eq!(
        block.seal_plan(plan(0xA2, &[2]), g),
        SealAdmission::InputRaced
    );
}

/// Signing replaces the plan with the post in one mutation: the plan's
/// own reservation does not count against its post, and nothing is
/// released, so the generation does not move.
#[test]
fn signing_replaces_the_plan_and_moves_no_generation() {
    let mut block = planned(&[plan(0xA1, &[1, 2])]);
    let g = block.generation();
    let signed = post(0xA1, &[1, 2]);
    assert_eq!(block.sign_plan(signed.clone(), g), SignAdmission::Signed);
    assert!(block.plans().is_empty());
    assert_eq!(block.posts(), std::slice::from_ref(&signed));
    assert_eq!(block.generation(), g);
}

/// A plan withdrawn while its post was proved wins: the signed bytes are
/// refused, and the ending stands.
#[test]
fn a_withdrawal_during_signing_wins() {
    let mut block = planned(&[plan(0xA1, &[1])]);
    let g = block.generation();
    assert!(matches!(
        block.withdraw_plan(&PCanonicalId::from_bytes([0xA1; 32]), AT),
        Withdrawal::Withdrawn(_)
    ));
    assert_eq!(
        block.sign_plan(post(0xA1, &[1]), g),
        SignAdmission::PlanGone
    );
    assert!(block.posts().is_empty());
    assert_eq!(block.ended_plans().len(), 1);
}

/// A post's inputs taken by another record refuse the signing; a
/// release since the read refuses it as stale.
#[test]
fn signing_rechecks_other_reservations_and_the_generation() {
    let mut block = planned(&[plan(0xA1, &[1]), plan(0xA2, &[2])]);
    let g = block.generation();
    assert_eq!(
        block.sign_plan(post(0xA1, &[2]), g),
        SignAdmission::InputRaced
    );
    assert!(block
        .end_plan(
            &PCanonicalId::from_bytes([0xA2; 32]),
            PlanEnding::Withdrawn,
            AT,
        )
        .is_some());
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Stale);
}

/// BD-Q3 Rule 1: a post never sent may be signed again; once a submit
/// was attempted it never is.
#[test]
fn a_sent_post_is_never_re_signed() {
    let mut block = planned(&[plan(0xA1, &[1])]);
    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Signed);
    let fresh = PendingBondPost {
        wait: None,
        reference_height: BlockHeight::from_raw(5_010),
        ..post(0xA1, &[1])
    };
    assert_eq!(block.resign_post(fresh.clone(), g), SignAdmission::Signed);
    let persona = PCanonicalId::from_bytes([0xA1; 32]);
    assert!(block
        .mark_dispatched(&persona, ChainCount::from_raw(5_020))
        .is_some());
    assert_eq!(block.resign_post(fresh, g), SignAdmission::AlreadySent);
}

/// A signed post refuses withdrawal (ruled 2026-11-26).
#[test]
fn a_signed_post_refuses_withdrawal() {
    let mut block = planned(&[plan(0xA1, &[1])]);
    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Signed);
    assert_eq!(
        block.withdraw_plan(&PCanonicalId::from_bytes([0xA1; 32]), AT),
        Withdrawal::AlreadySigned
    );
    assert_eq!(block.posts().len(), 1, "the post stays");
}

/// Every ending of a plan writes its own outcome, releases the
/// reservation, and leaves an ended plan whose drain is owed; nothing was
/// sent. A sent post never ends here.
#[test]
fn every_plan_ending_writes_its_own_outcome_and_owes_a_drain() {
    for (ending, outcome) in [
        (PlanEnding::SpentElsewhere, OutcomeKind::SpentElsewhere),
        (PlanEnding::Withdrawn, OutcomeKind::Withdrawn),
        (PlanEnding::Unbondable, OutcomeKind::Unbondable),
        (PlanEnding::WaitedOut, OutcomeKind::WaitedOut),
    ] {
        let mut block = planned(&[plan(0xA1, &[1])]);
        let persona = PCanonicalId::from_bytes([0xA1; 32]);
        let g = block.generation();
        let ended = block.end_plan(&persona, ending, AT).expect("the plan ends");
        assert_eq!(ended.ending, ending);
        assert!(block.plans().is_empty() && block.reserved_gindexes().is_empty());
        assert!(block.has_ended_plan_for(&persona));
        assert_eq!(block.generation(), g + 1, "a released reservation moves it");
        let written = block.outcomes().last().expect("an outcome");
        assert_eq!((written.outcome, written.sent), (outcome, false));
        assert!(block.end_plan(&persona, ending, AT).is_none(), "idempotent");
    }
    let mut block = planned(&[plan(0xA1, &[1])]);
    let persona = PCanonicalId::from_bytes([0xA1; 32]);
    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Signed);
    assert!(block
        .mark_dispatched(&persona, ChainCount::from_raw(5_020))
        .is_some());
    assert!(
        block
            .end_plan(&persona, PlanEnding::WaitedOut, AT)
            .is_none(),
        "a sent post ends at its end date"
    );
}

/// An ended plan stays until its persona holds no live funding and no
/// live drain, then until its retirement is durable; its slot stays
/// derivable throughout.
#[test]
fn an_ended_plan_is_retired_only_after_its_drain_and_dropped_after_retirement() {
    let mut block = planned(&[plan(0xA1, &[1])]);
    let persona = PCanonicalId::from_bytes([0xA1; 32]);
    let slot = PSlot::from_raw(0xA1);
    assert!(matches!(
        block.withdraw_plan(&persona, AT),
        Withdrawal::Withdrawn(_)
    ));
    assert!(block.stake_slots().contains(&slot));
    let funded: BTreeSet<PSlot> = [slot].into_iter().collect();
    let covered = Some(BlockHeight::from_raw(1_000));
    assert_eq!(
        block
            .drained_plans(&BTreeSet::new(), Some(BlockHeight::from_raw(999)))
            .count(),
        0,
        "absence from a scan short of the funding block is not a spend"
    );
    assert_eq!(
        block.drained_plans(&funded, covered).count(),
        0,
        "still funded"
    );
    let g = block.generation();
    assert_eq!(
        block.seal_drain(drain(0xA1, &[1]), ChainCount::from_raw(2_001), g),
        SealAdmission::Admit
    );
    assert_eq!(
        block.drained_plans(&BTreeSet::new(), covered).count(),
        0,
        "a live drain is not done"
    );
    assert!(block.remove_drain(&persona).is_some());
    assert_eq!(block.drained_plans(&BTreeSet::new(), covered).count(), 1);
    assert!(block.drop_retired_plans(&BTreeSet::new()).is_empty());
    let retired: BTreeSet<PCanonicalId> = [persona].into_iter().collect();
    assert_eq!(block.drop_retired_plans(&retired).len(), 1);
    assert!(block.stake_slots().is_empty());
}

/// A blocked attempt's reason is stored on the row that is waiting, and
/// only when it changes. A sent post is not waiting.
#[test]
fn a_sign_wait_is_written_on_the_row_that_is_waiting() {
    let mut block = planned(&[plan(0xA1, &[1])]);
    let persona = PCanonicalId::from_bytes([0xA1; 32]);
    assert!(block.set_sign_wait(&persona, Some(PlanWait::FeeAboveFunding)));
    assert!(!block.set_sign_wait(&persona, Some(PlanWait::FeeAboveFunding)));
    assert_eq!(block.plans()[0].wait, Some(PlanWait::FeeAboveFunding));
    assert!(PlanWait::FeeAboveFunding.is_limited());
    assert!(!PlanWait::NodeUnreachable.is_limited());

    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Signed);
    assert!(block.set_sign_wait(&persona, Some(PlanWait::NodeNotLocal)));
    assert_eq!(block.posts()[0].wait, Some(PlanWait::NodeNotLocal));
    assert!(block
        .mark_dispatched(&persona, ChainCount::from_raw(5_020))
        .is_some());
    assert!(
        !block.set_sign_wait(&persona, Some(PlanWait::FeeAboveFunding)),
        "a sent post is not waiting to be signed"
    );
    assert_eq!(
        block.posts()[0].wait,
        Some(PlanWait::NodeNotLocal),
        "the writer leaves a sent post unchanged"
    );
}

/// A v16 block round-trips with a plan, a post and an ended plan.
#[test]
fn a_v16_block_round_trips_every_stake_stage() {
    let mut block = planned(&[plan(0xA1, &[1]), plan(0xA2, &[2]), plan(0xA3, &[3])]);
    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA2, &[2]), g), SignAdmission::Signed);
    assert!(matches!(
        block.withdraw_plan(&PCanonicalId::from_bytes([0xA3; 32]), AT),
        Withdrawal::Withdrawn(_)
    ));
    let bytes = block.to_postcard_bytes().expect("encode");
    let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
    assert_eq!(back, block);
    assert_eq!(back.version(), 16);
}

/// One scan names the stage. A plan, a post never sent, a sent post, and an
/// ended plan are four arms, and only the first two are waiting.
#[test]
fn a_persona_stake_is_one_stage() {
    let persona = PCanonicalId::from_bytes([0xA1; 32]);
    let mut block = planned(&[plan(0xA1, &[1])]);
    assert!(matches!(
        block.stake_stage(&persona),
        Some(StakeStage::Plan(_))
    ));
    assert!(matches!(
        block.waiting_stakes().next(),
        Some(super::WaitingStake::Plan(_))
    ));

    let g = block.generation();
    assert_eq!(block.sign_plan(post(0xA1, &[1]), g), SignAdmission::Signed);
    assert!(matches!(
        block.stake_stage(&persona),
        Some(StakeStage::Unsent(_))
    ));

    assert!(block
        .mark_dispatched(&persona, ChainCount::from_raw(5_020))
        .is_some());
    assert!(matches!(
        block.stake_stage(&persona),
        Some(StakeStage::Sent(_))
    ));
    assert!(block.waiting_stakes().next().is_none());

    // A sent post does not end here; the ended stage is a plan's ending.
    let mut ended = planned(&[plan(0xA2, &[2])]);
    let other = PCanonicalId::from_bytes([0xA2; 32]);
    assert!(ended.end_plan(&other, PlanEnding::Withdrawn, AT).is_some());
    assert!(matches!(
        ended.stake_stage(&other),
        Some(StakeStage::Ended(_))
    ));
    assert!(ended.waiting_stakes().next().is_none());
}
