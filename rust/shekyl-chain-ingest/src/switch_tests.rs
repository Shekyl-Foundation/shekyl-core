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

use std::collections::HashMap;

use shekyl_difficulty::ForkChoiceVerdict;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Transaction;

use crate::connector::{Offered, RunFault, Switched};
use crate::scenario::{FreeHash, Mined, Scenario};

/// The listed bodies of `branches`' blocks, by hash — what the pool will
/// hold for the switch from PR-b on.
fn bodies<'a>(
    branches: impl IntoIterator<Item = &'a Mined>,
) -> HashMap<BlockHash, Vec<Transaction>> {
    branches
        .into_iter()
        .map(|m| (m.hash, m.template.transactions.clone()))
        .collect()
}

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

    let Switched::Done(done) = x.reorganize(&plan, &bodies(&b)).await.expect("switch") else {
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
    // connected B directly.
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));

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
        x.reorganize(&plan, &bodies(&b)).await.expect("switch"),
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
    let Switched::Done(done) = x
        .reorganize(&plan, &bodies(a.iter().chain(&a_ext)))
        .await
        .expect("switch back")
    else {
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
    match x.reorganize(&plan, &bodies(&b)).await.expect("switch") {
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
    let Switched::Done(done) = x.reorganize(&plan, &bodies(&b)).await.expect("switch") else {
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
    // Between the plan and the switch, a release anchors A's second block
    // under another hash: the recorded chain now fails its own tier (the
    // anchor floors every fork rooted below it), and the switch's demotion
    // judges A's first block against it.
    let mut wrong = a[1].clone();
    wrong.hash = BlockHash::from_bytes([0xEE; 32]);
    x.connector()
        .ask(crate::connector::AnchorForTests(anchoring(&wrong)))
        .await
        .expect("anchor");
    let err = x
        .reorganize(&plan, &bodies(&b))
        .await
        .expect_err("SI-27 halts");
    let want = shekyl_chain_store::store::StoreInvariant::DemotedBlockRefused {
        height: a[0].height.to_raw(),
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
