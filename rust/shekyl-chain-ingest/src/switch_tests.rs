// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The switch through the production stack (DRS-E5 a5;
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.3): two drivers mine the same prefix and
//! then different branches; one driver's blocks arrive at the other as
//! alternatives. A switch is correct when nothing is left over — the store
//! that switched equals the store that connected the winning branch
//! directly, digest for digest.

use shekyl_difficulty::ForkChoiceVerdict;
use shekyl_types::{BlockHash, BlockHeight};

use crate::connector::{Offered, PlanMismatchReason, RunFault, Switched};
use crate::scenario::{FreeHash, Mined, Scenario};

/// A driver over a fresh store with `prefix` empty blocks.
async fn with_prefix(name: &str, prefix: u64) -> Scenario<FreeHash> {
    let mut s = Scenario::open(name);
    s.mine(prefix).await;
    s
}

/// Offer every block of `branch`; every offer but the last must be held,
/// and the last must name a switch. Returns that plan.
async fn offer_branch(x: &Scenario<FreeHash>, branch: &[Mined]) -> crate::SwitchPlan {
    let (last, held) = branch.split_last().expect("a branch");
    for mined in held {
        match x.offer(mined).await.expect("offer") {
            Offered::Held { height } => assert_eq!(height, mined.height),
            other => panic!("block {:?} not held: {other:?}", mined.height),
        }
    }
    match x.offer(last).await.expect("offer") {
        Offered::SwitchDue(plan) => plan,
        other => panic!("the heavier tip did not name a switch: {other:?}"),
    }
}

const PREFIX: u64 = 5;

#[tokio::test]
async fn a_heavier_branch_switches_and_equals_the_branch_connected_directly() {
    let mut x = with_prefix("switch-direct-x", PREFIX).await;
    let mut y = with_prefix("switch-direct-y", PREFIX).await;
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    assert_ne!(
        a[0].hash, b[0].hash,
        "the branches differ from the first block"
    );

    // Equal work keeps the incumbent (K6): B's third block ties A's tip.
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.verdict, ForkChoiceVerdict::Switch);
    assert_eq!(plan.root.height, BlockHeight::from_raw(PREFIX - 1));
    assert_eq!(plan.demoted.len(), 3);
    assert_eq!(plan.promoted.len(), 4);

    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert!(
        done.demoted_kept,
        "a difficulty switch keeps the demoted chain (K7)"
    );
    assert_eq!(
        done.demoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        a.iter().map(|m| m.hash).collect::<Vec<_>>()
    );
    assert_eq!(
        done.promoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        b.iter().map(|m| m.hash).collect::<Vec<_>>()
    );

    // Nothing left over: the store that switched is the store that
    // connected B directly, and its alt table is exactly A.
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    assert_same_chain(&x, &y, &a.iter().collect::<Vec<_>>(), "A → B equals B").await;

    // The demoted blocks are alt rows now (K7), and the promoted rows are
    // gone: three held, B's four removed.
    assert_eq!(x.alt_blocks_held().await.expect("al6"), 3);
    // Offering one again finds it held.
    assert!(matches!(
        x.offer(&a[0]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn switching_back_restores_the_chain_that_never_switched() {
    let mut x = with_prefix("switch-back-x", PREFIX).await;
    let mut y = with_prefix("switch-back-y", PREFIX).await;
    let mut z = with_prefix("switch-back-z", PREFIX).await;
    let a = x.mine(3).await;
    let a_again = z.mine(3).await;
    assert_eq!(
        a.iter().map(|m| m.hash).collect::<Vec<_>>(),
        a_again.iter().map(|m| m.hash).collect::<Vec<_>>(),
        "the driver is deterministic: z re-mines x's branch"
    );
    let a_ext = z.mine(2).await;
    y.idle();
    let b = y.mine(4).await;

    let plan = offer_branch(&x, &b).await;
    assert!(matches!(
        x.reorganize(&plan).await.expect("switch"),
        Switched::Done(_)
    ));
    // A, extended past B, arrives: its first three blocks are held from the
    // demotion, the extension ties then wins.
    let plan = offer_branch(&x, &a_ext).await;
    assert_eq!(
        plan.promoted.len(),
        5,
        "A's three demoted rows and its two new blocks"
    );
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch back") else {
        panic!("the switch back did not land");
    };
    assert_eq!(done.demoted.len(), 4, "B's four blocks");
    assert_eq!(x.digest().await.expect("d"), z.digest().await.expect("d"));
    x.close().await;
    y.close().await;
    z.close().await;
}

#[tokio::test]
async fn an_orphan_is_unlinked_and_an_extension_is_not_an_alternative() {
    let mut x = with_prefix("switch-arms-x", PREFIX).await;
    let mut y = with_prefix("switch-arms-y", PREFIX).await;
    y.idle();
    let b = y.mine(2).await;
    // b[1]'s parent is b[0], which x has never seen.
    match x.offer(&b[1]).await.expect("offer") {
        Offered::Unlinked { at } => assert_eq!(at, b[0].hash),
        other => panic!("an orphan was not unlinked: {other:?}"),
    }
    // A block on x's own tip is an extension: a driver defect, the writer
    // stays up.
    let mut w = with_prefix("switch-arms-w", PREFIX).await;
    let ext = w.mine(1).await;
    assert!(matches!(
        x.offer(&ext[0]).await,
        Err(RunFault::NotAlternative { .. })
    ));
    assert!(x.mine(1).await.len() == 1, "the writer is up");
    x.close().await;
    y.close().await;
    w.close().await;
}

#[tokio::test]
async fn a_promoted_block_that_fails_validate_rolls_back_and_removes_its_suffix() {
    let mut x = with_prefix("switch-refused-x", PREFIX).await;
    let mut y = with_prefix("switch-refused-y", PREFIX).await;
    x.mine(2).await;
    y.idle();
    let mut b = y.mine(3).await;
    // B's tip commits to a tree root its chain does not hold: the cheap
    // tier reads no chain state and admits it; promotion's `validate`
    // (CEN-B5) refuses it.
    let tip = b.last_mut().expect("tip");
    tip.template.block.header.curve_tree_root = shekyl_types::CurveTreeRoot::from_bytes([0x42; 32]);
    tip.hash = tip.template.block.hash();
    let before = x.digest().await.expect("d");

    let plan = offer_branch(&x, &b).await;
    match x.reorganize(&plan).await.expect("switch") {
        Switched::Refused {
            hash,
            refused,
            removed,
            ..
        } => {
            assert_eq!(hash, b[2].hash);
            assert_eq!(
                refused.rule,
                shekyl_chain_rules::CenRow::B5,
                "promotion's root check refused it"
            );
            assert_eq!(
                removed,
                vec![b[2].hash],
                "the refused block and nothing below it"
            );
        }
        other => panic!("the refusal did not roll back: {other:?}"),
    }
    assert_eq!(
        x.digest().await.expect("d"),
        before,
        "the main chain is the pre-switch chain"
    );
    // The suffix below the refused block is still held.
    assert!(matches!(
        x.offer(&b[0]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    x.close().await;
    y.close().await;
}

/// A trust whose one anchor pins `mined` at its height — a fixture table
/// (no regtest run is anchored), leaked for the `'static` the release
/// tables have.
fn anchoring(mined: &Mined) -> shekyl_chain_rules::Trust {
    let pins: &'static [shekyl_chain_rules::Anchor] =
        Box::leak(Box::new([shekyl_chain_rules::Anchor {
            height: mined.height,
            hash: mined.hash,
        }]));
    shekyl_chain_rules::Trust::full(shekyl_chain_rules::ReleaseAnchors::for_tests(None, pins))
}

#[tokio::test]
async fn a_checkpoint_forced_switch_discards_the_demoted_chain() {
    let mut x = with_prefix("switch-forced-x", PREFIX).await;
    let mut y = with_prefix("switch-forced-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    // A release pins B's first block above x's tip (K6's checkpoint arm).
    // Above the tip it is no floor yet (CEN-E2), so the branch is offered.
    x.connector()
        .ask(crate::connector::AnchorForTests(anchoring(&b[3])))
        .await
        .expect("anchor");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.verdict, ForkChoiceVerdict::ForcedSwitch);
    assert!(
        plan.demoted.is_empty(),
        "ForcedSwitch discards the demoted chain and does not read it"
    );
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the forced switch did not land");
    };
    assert!(!done.demoted_kept, "the checkpoint arm discards (K7)");
    assert_eq!(done.demoted.len(), 3);
    assert_eq!(
        x.alt_blocks_held().await.expect("al6"),
        0,
        "nothing re-entered"
    );
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    // Both alt tables empty: x discarded what it demoted, y never had any.
    assert_same_chain(&x, &y, &[], "a forced switch equals B connected directly").await;
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_demoted_block_the_tier_refuses_halts_the_writer_si27() {
    let mut x = with_prefix("switch-si27-x", PREFIX).await;
    let mut y = with_prefix("switch-si27-y", PREFIX).await;
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let plan = offer_branch(&x, &b).await;
    // Witnesses the halt's wiring, not a production path: between the plan
    // and the switch the fixture swaps in an anchor table the recorded
    // chain fails (A's second block under another hash), so the demotion's
    // tier refuses A's first block. Production cannot reach this — a
    // release's anchors are admitted at open (CEN-E5) and checked at offer
    // under the same tip (ruling 2, the SI-27 register row; the test
    // `a_new_release_anchor_refuses_the_pending_alternative_at_offer_and_si27_never_fires`).
    // It stands in for the one case SI-27 is for: a store whose recorded
    // chain fails its own rules.
    let mut wrong = a[1].clone();
    wrong.hash = BlockHash::from_bytes([0xEE; 32]);
    x.connector()
        .ask(crate::connector::AnchorForTests(anchoring(&wrong)))
        .await
        .expect("anchor");
    let err = x.reorganize(&plan).await.expect_err("SI-27 halts");
    let want = shekyl_chain_store::store::StoreInvariant::DemotedBlockRefused {
        height: a[0].height,
    };
    assert!(
        matches!(&err, RunFault::Store(shekyl_chain_store::store::StoreError::InvariantViolated(row)) if *row == want),
        "{err:?}"
    );
    // The writer is over.
    assert!(matches!(x.facts().await, Err(RunFault::Over(_))));
    x.close().await;
    y.close().await;
}

// ---------------------------------------------------------------------------
// a6 — the three refusals distinguished, §4's boundary and floor fixtures,
// and the self-differential (`E5-Q9` re-ruled 2026-10-15).
// ---------------------------------------------------------------------------

/// The one table two stores holding the same chain legitimately differ
/// on: each holds the alternative blocks it switched away from. Never
/// excluded — [`assert_same_chain`] asserts it exactly.
const ALT_TABLE: &str = "alt_blocks";

/// The alt blocks' listed bodies, keyed as [`ALT_TABLE`] is: excluded from
/// the byte comparison with it, and asserted to hold exactly its keys.
const ALT_BODIES_TABLE: &str = "alt_block_bodies";

/// The tables other than the alt table whose rows differ between `x` and
/// `y`, every one compared at the byte level (`TableRows`).
async fn differing_tables(x: &Scenario<FreeHash>, y: &Scenario<FreeHash>) -> Vec<&'static str> {
    let a = x.table_rows().await.expect("rows");
    let b = y.table_rows().await.expect("rows");
    let names: std::collections::BTreeSet<&'static str> =
        a.keys().chain(b.keys()).copied().collect();
    names
        .into_iter()
        .filter(|name| *name != ALT_TABLE && *name != ALT_BODIES_TABLE)
        .filter(|name| a.get(name) != b.get(name))
        .collect()
}

/// The blocks a store's alt table holds, by hash, decoded from its rows.
async fn alt_hashes(s: &Scenario<FreeHash>) -> std::collections::BTreeSet<BlockHash> {
    use shekyl_chain_store::codec::{AltBlock, Canonical};
    s.table_rows()
        .await
        .expect("rows")
        .get(ALT_TABLE)
        .map(|rows| {
            rows.iter()
                .map(|(_, value)| AltBlock::decode(value).expect("decodes").block().hash())
                .collect()
        })
        .unwrap_or_default()
}

/// `switched` holds the chain `direct` connected directly: every table but
/// the alt table byte-equal, and the alt table exactly — `switched` holds
/// `kept` (the blocks it demoted and kept), `direct` holds nothing.
async fn assert_same_chain(
    switched: &Scenario<FreeHash>,
    direct: &Scenario<FreeHash>,
    kept: &[&Mined],
    why: &str,
) {
    assert_eq!(
        differing_tables(switched, direct).await,
        Vec::<&str>::new(),
        "{why}"
    );
    assert_eq!(
        alt_hashes(switched).await,
        kept.iter().map(|m| m.hash).collect(),
        "{why}: the switched store's alt table is exactly the demoted blocks it kept"
    );
    assert!(
        alt_hashes(direct).await.is_empty(),
        "{why}: the directly connected store holds no alternative block"
    );
    for store in [switched, direct] {
        let rows = store.table_rows().await.expect("rows");
        let keys = |name| {
            rows.get(name)
                .map(|rows| rows.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        assert_eq!(
            keys(ALT_BODIES_TABLE),
            keys(ALT_TABLE),
            "{why}: every alt row has its bodies, and no bodies outlive a row"
        );
    }
}

/// The levered schedule `scenario_shard` runs: a 20-block epoch and a reorg
/// cap of 10, so the cap and the undo floor are reachable in a test.
fn levered() -> crate::schedule::ChainRules {
    crate::scenario_shard::levered_rules()
}

const LEVERED_CAP: u64 = crate::scenario_shard::REORG_CAP_BLOCKS;

#[tokio::test]
async fn a_switch_popping_exactly_the_cap_lands_and_one_more_is_refused_locally() {
    // Tip 29; a fork rooted at 19 pops ten (the cap), one rooted at 18
    // pops eleven. The refusal is the cap's, before any pop and before any
    // RandomX, never a verdict: the block stays stored, the chain is
    // untouched.
    let mut x = Scenario::open_under("switch-cap-x", FreeHash, levered());
    x.mine(30).await;
    let mut at_cap = Scenario::open_under("switch-cap-y", FreeHash, levered());
    at_cap.mine(20).await;
    at_cap.idle();
    let b = at_cap.mine(LEVERED_CAP + 1).await;
    let plan = offer_branch(&x, &b).await;
    assert_eq!(
        plan.demoted.len(),
        usize::try_from(LEVERED_CAP).expect("small")
    );
    assert!(matches!(
        x.reorganize(&plan).await.expect("switch"),
        Switched::Done(_)
    ));

    let mut over = Scenario::open_under("switch-cap-z", FreeHash, levered());
    let mut x2 = Scenario::open_under("switch-cap-x2", FreeHash, levered());
    x2.mine(30).await;
    over.mine(19).await;
    over.idle();
    let b = over.mine(LEVERED_CAP + 2).await;
    let before = x2.digest().await.expect("d");
    let (last, held) = b.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x2.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    match x2.offer(last).await.expect("offer") {
        Offered::BeyondCap(beyond) => {
            assert_eq!(beyond.depth.to_raw(), LEVERED_CAP + 1);
            assert_eq!(beyond.cap.to_raw(), LEVERED_CAP);
        }
        other => panic!("one past the cap was not refused locally: {other:?}"),
    }
    assert_eq!(x2.digest().await.expect("d"), before, "nothing popped");
    assert_eq!(
        x2.alt_blocks_held().await.expect("al6"),
        LEVERED_CAP + 2,
        "the refused-for-depth block stays stored"
    );
    for s in [x, at_cap, over, x2] {
        s.close().await;
    }
}

#[tokio::test]
async fn a_pop_below_the_undo_floor_is_a_local_fail_stop_not_a_verdict() {
    // §4's floor fixture. The retention prune at the epoch-2 boundary
    // keeps the journal from `40 − 10`; a rewind lowers the tip to 35
    // without moving the floor, so a fork inside the cap (rooted at 28,
    // seven pops) reaches below the journal at height 29. The cap check
    // passes; the floor refuses — two operands, two refusals (`E5-Q6`).
    let mut x = Scenario::open_under("switch-floor-x", FreeHash, levered());
    x.mine(50).await;
    x.rewind_to(BlockHeight::from_raw(35))
        .await
        .expect("rewind");
    let mut y = Scenario::open_under("switch-floor-y", FreeHash, levered());
    y.mine(29).await;
    y.idle();
    let b = y.mine(8).await;
    let before = x.digest().await.expect("d");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.demoted.len(), 7, "inside the cap");
    let held_before = x.alt_blocks_held().await.expect("alt held before");
    match x.reorganize(&plan).await.expect("switch") {
        Switched::BelowFloor { tip, floor } => {
            assert!(tip < floor, "the pop that met the floor");
            assert!(
                floor > plan.root.height.to_raw(),
                "the floor is above the fork point"
            );
        }
        other => panic!("the floor did not refuse locally: {other:?}"),
    }
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");
    // The heavier chain this node could not follow stays stored: the
    // refusal is local and moves nothing, the alt table included.
    // Supersedes the alt-store half of the C++ core test
    // `gen_reorg_watermark_refused_switch` (`expected_alt_count`).
    assert_eq!(
        x.alt_blocks_held().await.expect("alt held after"),
        held_before,
        "the refused branch's blocks stay in the alt store"
    );
    assert!(
        held_before >= u64::try_from(b.len()).expect("fits"),
        "the offered branch is held as alternatives: {held_before} < {}",
        b.len()
    );
    assert_eq!(x.mine(1).await.len(), 1, "a local refusal is not a halt");
    x.close().await;
    y.close().await;
}

/// `pop_blocks`' bound (DX-Q3, Q7; the landed defect was a store fault
/// that stopped ingest): a count whose lowest block is below the undo
/// floor is refused before any pop, as a reply; one whose lowest block is
/// the floor pops; and the writer stays up either way.
#[tokio::test]
async fn pop_blocks_below_the_undo_floor_is_refused_before_any_pop() {
    use crate::connector::{PopBlocks, Rewound};
    let mut x = Scenario::open_under("pop-floor-x", FreeHash, levered());
    x.mine(50).await;
    let pop = |count| x.connector().ask(PopBlocks { count });
    let Rewound::Refused { tip, floor } = pop(50).await.expect("a reply") else {
        panic!("popping genesis is refused");
    };
    assert_eq!(tip.to_raw(), 49);
    assert!(floor.to_raw() > 1, "the prune moved the floor: {floor:?}");
    let before = x.digest().await.expect("d");
    let below = tip.to_raw() - (floor.to_raw() - 2);
    assert_eq!(
        pop(below).await.expect("a reply, not a fault"),
        Rewound::Refused { tip, floor },
        "the lowest block popped would be {}",
        floor.to_raw() - 1
    );
    assert_eq!(x.digest().await.expect("d"), before, "nothing popped");
    let at = tip.to_raw() - (floor.to_raw() - 1);
    let popped = pop(at).await.expect("it pops");
    assert_eq!(popped.popped(), at, "down to the floor's parent");
    x.idle();
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
}

/// The spending height: block 0's coinbase has matured for it.
const AT: u64 = crate::test_support::FIRST_SPEND_HEIGHT + 1;

/// The spend self-differential, and the planted rows that witness it.
#[path = "switch_differential_tests.rs"]
mod switch_differential_tests;

/// A promotion `form` refuses, and the header ledger after a switch.
#[path = "switch_promotion_tests.rs"]
mod switch_promotion_tests;

#[tokio::test]
async fn a_recorded_block_offered_as_an_alternative_is_already_held() {
    // Relayed twice: a block on x's own chain below the tip arrives as if
    // it were an alternative. It is held already — never stored as an alt
    // row as well, where a later switch demoting it would meet its own row.
    let mut x = with_prefix("switch-recorded-x", PREFIX).await;
    let own = x.mine(3).await;
    assert!(matches!(
        x.offer(&own[1]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    assert_eq!(x.alt_blocks_held().await.expect("al6"), 0);
    x.close().await;
}

#[tokio::test]
async fn a_stale_or_mismatched_plan_is_a_driver_defect_and_the_writer_stays_up() {
    let mut x = with_prefix("switch-plan-x", PREFIX).await;
    let mut y = with_prefix("switch-plan-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let plan = offer_branch(&x, &b).await;
    let before = x.digest().await.expect("d");

    // The promoted blocks are not the alternative chain's entries.
    let mut short = plan.clone();
    short.promoted.pop();
    assert!(matches!(
        x.reorganize(&short).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::PromotedLength,
        })
    ));
    // A demoted block formed with a witness its height row does not hold
    // (CEN-K5b's demoted direction).
    let mut witnessed = plan.clone();
    witnessed.demoted[0].candidate.attestation_witness =
        Some(shekyl_types::archival::AttestationWitness::new(vec![0x5E; 8]).expect("non-empty"));
    assert!(matches!(
        x.reorganize(&witnessed).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::DemotedChain,
        })
    ));
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");

    // The tip moves between the plan and the switch: the plan is stale.
    x.mine(1).await;
    assert!(matches!(
        x.reorganize(&plan).await,
        Err(RunFault::StalePlan { .. })
    ));
    assert_eq!(x.mine(1).await.len(), 1, "a driver defect is not a halt");
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_plan_naming_a_recorded_block_as_its_alternative_tip_is_a_mismatch_not_a_crash() {
    // A driver defect a malformed plan carries: its alternative tip is a
    // block the recorded chain holds, so the alternative chain has no
    // entries. The actor replies; it does not panic, and stays up.
    let mut x = with_prefix("switch-empty-plan-x", PREFIX).await;
    let mut y = with_prefix("switch-empty-plan-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let mut plan = offer_branch(&x, &b).await;
    plan.alt_tip = x
        .hash_at(BlockHeight::from_raw(PREFIX))
        .await
        .expect("read")
        .expect("recorded");
    plan.promoted.clear();
    assert!(matches!(
        x.reorganize(&plan).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::AlternativeTipRecorded,
        })
    ));
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
    y.close().await;
}

/// A fixture anchor table pinning each `(height, hash)`, leaked for the
/// `'static` a release table has.
fn release(pins: &[(BlockHeight, BlockHash)]) -> shekyl_chain_rules::ReleaseAnchors {
    let anchors: Vec<shekyl_chain_rules::Anchor> = pins
        .iter()
        .map(|&(height, hash)| shekyl_chain_rules::Anchor { height, hash })
        .collect();
    shekyl_chain_rules::ReleaseAnchors::for_tests(None, Box::leak(anchors.into_boxed_slice()))
}

/// Open the store at `path` under `anchors` the way a release opens it
/// (`ChainStore::with_release`, CEN-E5 at open), and close it.
fn admit_release(
    path: &std::path::Path,
    anchors: &shekyl_chain_rules::ReleaseAnchors,
) -> Result<(), shekyl_chain_store::store::StoreError> {
    let horizons = shekyl_chain_store::store::Horizons::under(
        &crate::scenario::RULES.in_force(BlockHeight::from_raw(0)),
    )
    .expect("the scenario's rule set is a store schedule");
    shekyl_chain_store::store::ChainStore::with_release(
        path,
        shekyl_chain_store::apply_policy::ApplyPolicy::default(),
        horizons,
        anchors,
    )
    .map(drop)
}

#[tokio::test]
async fn a_new_release_anchor_refuses_the_pending_alternative_at_offer_and_si27_never_fires() {
    // Ruling 2 (2026-10-15): an anchor table cannot reach SI-27. Two
    // mechanisms stand between them, and this test runs both.
    let mut x = with_prefix("switch-si27-anchor-x", PREFIX).await;
    let mut y = with_prefix("switch-si27-anchor-y", PREFIX).await;
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    // B is pending: held as alternative blocks, its fork point below A.
    for mined in &b[..3] {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    // (1) At open: a release whose anchor contradicts the recorded chain
    // does not open the store (CEN-E5, `StoreCannot::ReleasePin`) ...
    let contradicting = release(&[(a[1].height, BlockHash::from_bytes([0xEE; 32]))]);
    // ... and one that agrees with it does. Its anchor sits above B's fork
    // point.
    let agreeing = release(&[(a[1].height, a[1].hash)]);
    let mut refused_at_open = None;
    x.reopen(|path| {
        refused_at_open = Some(admit_release(path, &contradicting));
        admit_release(path, &agreeing).expect("an agreeing release opens the store");
    })
    .await;
    assert!(
        matches!(
            refused_at_open,
            Some(Err(shekyl_chain_store::store::StoreError::Cannot(
                shekyl_chain_store::store::StoreCannot::ReleasePin(_)
            )))
        ),
        "{refused_at_open:?}"
    );
    x.connector()
        .ask(crate::connector::AnchorForTests(
            shekyl_chain_rules::Trust::full(agreeing),
        ))
        .await
        .expect("anchor");
    // (2) At offer, under that tip: B's heavier block forks below the new
    // floor, so CEN-E2 refuses it there — no plan exists, so no switch
    // ever judges a demoted block under the new table.
    match x.offer(&b[3]).await.expect("offer") {
        Offered::Refused(refused) => {
            assert_eq!(refused.rule, shekyl_chain_rules::CenRow::E2);
        }
        other => panic!("the pending alternative was not refused at offer: {other:?}"),
    }
    // The writer is up: no SI-27, no halt.
    assert_eq!(x.mine(1).await.len(), 1, "the writer stays up");
    x.close().await;
    y.close().await;
}

/// A longhash probe: every call is counted, and every target is satisfied
/// (the free hash), so a test can see how many times a step asked RandomX.
#[derive(Clone)]
struct CountingPow(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl CountingPow {
    fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    fn calls(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl shekyl_chain_rules::Substrate for CountingPow {
    type Fault = std::convert::Infallible;
    type Held = ();

    fn local_clock(&self) -> Result<shekyl_types::Timestamp, Self::Fault> {
        Ok(crate::scenario::CLOCK_START)
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<shekyl_types::PowHash, Self::Fault> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(shekyl_types::PowHash::from_bytes([0; 32]))
    }
}

/// Two drivers under the levered set (cap 10): `x` holds 30 blocks and the
/// probe, `y` mines the 11-block branch rooted at 19 that pops exactly the
/// cap. Returns `x`, its probe, `y` and the branch, offered up to the plan.
async fn at_the_cap_with_a_probe(
    name: &str,
) -> (
    Scenario<CountingPow>,
    CountingPow,
    Scenario<CountingPow>,
    crate::SwitchPlan,
) {
    let probe = CountingPow::new();
    let mut x = Scenario::open_under(&format!("{name}-x"), probe.clone(), levered());
    let mut y = Scenario::open_under(&format!("{name}-y"), CountingPow::new(), levered());
    x.mine(30).await;
    y.mine(20).await;
    y.idle();
    let b = y.mine(LEVERED_CAP + 1).await;
    let (last, held) = b.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    let Offered::SwitchDue(plan) = x.offer(last).await.expect("offer") else {
        panic!("the heavier tip did not name a switch");
    };
    (x, probe, y, plan)
}

#[tokio::test]
async fn a_switch_at_the_cap_calls_randomx_zero_times() {
    // Ruling 3 (2026-10-15): every block the switch re-judges was hashed
    // when this node first judged it — the demoted ones at connect, the
    // promoted ones at arrival — and the plan carries those records. The
    // switch's forming asks RandomX nothing.
    let (mut x, probe, y, plan) = at_the_cap_with_a_probe("switch-recall").await;
    assert_eq!(
        plan.demoted.len(),
        usize::try_from(LEVERED_CAP).expect("small")
    );
    let before = probe.calls();
    let switched = x.reorganize(&plan).await.expect("switch");
    assert!(matches!(switched, Switched::Done(_)), "{switched:?}");
    assert_eq!(
        probe.calls() - before,
        0,
        "N + M = {} blocks re-formed through their recorded PoW",
        plan.demoted.len() + plan.promoted.len()
    );
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_seed_claim_that_differs_from_the_recorded_one_recomputes() {
    // The record is keyed by (identity, seed): a claim under another seed
    // is not the recorded computation, so it goes to RandomX — once — and
    // then to CEN-D3, which refuses the claim as it would without a record.
    let (mut x, probe, y, mut plan) = at_the_cap_with_a_probe("switch-recall-seed").await;
    plan.promoted[0].at.seed = BlockHash::from_bytes([0x5D; 32]);
    let before = probe.calls();
    let out = x.reorganize(&plan).await;
    assert_eq!(
        probe.calls() - before,
        1,
        "only the mismatched claim recomputes"
    );
    assert!(matches!(out, Err(RunFault::StaleSeed { .. })), "{out:?}");
    x.close().await;
    y.close().await;
}

/// The third claim during a switch (2026-10-16, `CHAIN_RULES_CRATE.md`
/// §4.6): a promoted block's spend is verified in `form` against the
/// plan's header chain, and `validate` compares the claim with the chain
/// inside the closure. A claim the chain refutes — the reference at
/// another height, or no claim where the chain holds the reference in
/// the window — is `RunFault::StaleReference`, a driver defect: never a
/// verdict, never a second verify, the transaction rolled back and the
/// writer up. A stale target claim is the same class. A claim with the
/// wrong **root** never reaches the comparison: the root is the
/// verifier's input, so the proof fails against it and `form` refuses the
/// spend on CEN-I15 — the claim cannot widen what the chain accepts. The
/// honest plan then lands. That refusal is observed through `form`
/// directly. It is not [`crate::RefusePromotion`]: a false claim must not
/// delete a chain the honest claim accepts.
#[tokio::test]
async fn a_reference_or_target_claim_the_switch_cannot_make_is_a_driver_defect() {
    let mut x = Scenario::open("switch-stale-claim-x");
    let mut y = Scenario::open("switch-stale-claim-y");
    x.mine(AT).await;
    let prefix = y.mine(AT).await;
    let a = x.mine(1).await;
    y.idle();
    // B's first block lists a spend referencing a block below the fork
    // point — inside the plan's header window.
    let spend = shekyl_harness_spender::Spender::over(&prefix).spend_coinbase(
        y.wallet(),
        BlockHeight::from_raw(0),
        BlockHeight::from_raw(AT),
        crate::test_support::Family::Main.fee(),
    );
    let mut b = vec![y
        .mine_listing(vec![spend])
        .await
        .unwrap_or_else(|o| panic!("the spend connects: {o}"))];
    b.extend(y.mine(1).await);
    let reference = *b[0]
        .candidate()
        .proof_references()
        .iter()
        .next()
        .expect("the spend names a reference");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.demoted.len(), 1);
    let position = plan
        .headers
        .iter()
        .position(|h| h.hash == reference)
        .expect("the plan's header chain holds the reference");
    assert!(
        plan.headers[position].height < plan.promoted[0].at.height,
        "the reference is below the block that spends it"
    );
    let before = x.digest().await.expect("digest");

    // Another root for the reference: the proof fails against it in
    // `form` — CEN-I15 at the spend, the claim's own refusal, before any
    // closure. Through `form` directly, as the driver would see it.
    let mut wrong_root = plan.clone();
    let wrong = shekyl_types::CurveTreeRoot::from_bytes([0xd1; 32]);
    assert_ne!(wrong_root.headers[position].root, wrong);
    wrong_root.headers[position].root = wrong;
    {
        let at = &plan.promoted[0].at;
        let candidate = b[0].candidate();
        let claims = wrong_root.references_for(at, &candidate);
        assert_eq!(claims.get(&reference).map(|c| c.root), Some(wrong));
        let verdict = shekyl_chain_rules::form(
            candidate,
            &crate::scenario::RULES.in_force(at.height),
            &FreeHash,
            at.seed,
            at.target,
            &claims,
            shekyl_chain_rules::FormAttempt::FIRST,
        )
        .expect("the free substrate does not fault");
        match verdict {
            Err(refused) => {
                assert_eq!(refused.rule, shekyl_chain_rules::CenRow::I15);
                assert_eq!(
                    refused.locus,
                    shekyl_chain_rules::Locus::Tx {
                        slot: shekyl_chain_rules::TxSlot::Listed(0)
                    }
                );
            }
            Ok(_) => panic!("a proof verified against a root it was not built over"),
        }
    }

    // The reference at another height, its root right: the proof verifies
    // in `form` and the comparison inside the closure refutes the height,
    // with both claims named.
    let mut wrong_height = plan.clone();
    let shifted = BlockHeight::from_raw(plan.headers[position].height.to_raw() + 1);
    assert!(shifted < plan.promoted[0].at.height);
    wrong_height.headers[position].height = shifted;
    match x.reorganize(&wrong_height).await {
        Err(RunFault::StaleReference {
            height,
            slot,
            reference: named,
            claims,
            ..
        }) => {
            assert_eq!(height, b[0].height);
            assert_eq!(slot, shekyl_chain_rules::TxSlot::Listed(0));
            assert_eq!(named, reference);
            assert_eq!(claims.claimed.map(|c| c.height), Some(shifted));
            assert_eq!(claims.expected.root, plan.headers[position].root);
            assert_eq!(claims.expected.height, plan.headers[position].height);
        }
        other => panic!("expected StaleReference, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // No claim at all for a reference the chain holds in the window.
    let mut unclaimed = plan.clone();
    unclaimed.headers.remove(position);
    match x.reorganize(&unclaimed).await {
        Err(RunFault::StaleReference { claims, .. }) => {
            assert_eq!(claims.claimed, None);
            assert_eq!(claims.expected.root, plan.headers[position].root);
        }
        other => panic!("expected StaleReference, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // A target claim the stitched headers do not derive.
    let mut wrong_target = plan.clone();
    let claimed = plan.promoted[0].at.target;
    let other = shekyl_chain_rules::Target::for_tests(
        core::num::NonZeroU128::new(claimed.difficulty().to_raw().saturating_mul(2).max(2))
            .expect("non-zero"),
    );
    assert_ne!(other, claimed);
    wrong_target.promoted[0].at.target = other;
    match x.reorganize(&wrong_target).await {
        Err(RunFault::StaleTarget {
            height,
            claimed: was,
            expected,
            ..
        }) => {
            assert_eq!(height, b[0].height);
            assert_eq!(was, other);
            assert_eq!(expected, claimed);
        }
        other => panic!("expected StaleTarget, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // The writer is up and the honest plan lands.
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the honest switch did not land");
    };
    assert_eq!(done.promoted.len(), 2);
    assert_same_chain(&x, &y, &a.iter().collect::<Vec<_>>(), "A → B equals B").await;
    x.close().await;
    y.close().await;
}
