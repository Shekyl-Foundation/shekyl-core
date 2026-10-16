// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A promotion `form` refuses under the plan's own claims
//! (`DRS_E5_POOL_ALT_PRUNE.md` §2.3). The proofs ran off the actor, so the
//! writer never opens the switch: the main chain stays, and the failing
//! alternative suffix is removed.
//!
//! The broken block cannot be mined. `mine_listing` forms with reference
//! claims, so the membership proof is refused before it connects, and an
//! offer re-forms a connected block. The block is assembled on its own
//! chain — empty claims, so the cheap tier can hold it — and a heavier
//! child is assembled on top of it without connecting either. Anchoring
//! the broken block at the recorded tip would be CEN-E2, not a switch.
//!
//! The other test is the driver's header ledger after a switch that lands.
//! It still held the losing branch, and a later claim reloads only heights
//! it lacks, so a spend whose reference and whose target window sit on the
//! promoted chain connects only once those headers have been dropped.

use std::collections::HashMap;

use shekyl_chain_rules::{CenRow, Locus, TxSlot, REFERENCE_BLOCK_MIN_AGE};
use shekyl_harness_spender::Spender;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::{Ct, Transaction};

use crate::connector::{Offered, Switched};
use crate::scenario::{Mined, Scenario};
use crate::test_support::Family;

use super::{bodies, offer_branch, AT};

#[tokio::test]
async fn a_promotion_form_refusal_removes_the_alt_suffix_and_does_not_pop() {
    let mut x = Scenario::open("switch-form-i15-x");
    let mut y = Scenario::open("switch-form-i15-y");
    x.mine(AT).await;
    let prefix = y.mine(AT).await;
    // One incumbent block: the alternative of two is strictly heavier.
    let incumbent = x.mine(1).await;
    let before = x.digest().await.expect("digest");
    let facts = y.facts().await.expect("facts");
    assert_eq!(facts.connecting, BlockHeight::from_raw(AT));

    // Signed after the flip, so the refusal is the proof (CEN-I15) and not
    // the signature over it (CEN-I18). Empty claims skip the proof, which
    // is why the offer holds the block.
    let spend = shekyl_harness_spender::Spender::over(&prefix)
        .spend_coinbase_posting_breaking_membership_proof(
            y.wallet(),
            BlockHeight::from_raw(0),
            facts.connecting,
            Family::Main.fee(),
            None,
        );
    let broken = y
        .assemble_unconnected(&facts, &[spend])
        .await
        .unwrap_or_else(|outcome| panic!("empty claims form the broken proof: {outcome}"));
    // The child is priced from the prefix's facts with its parent set to
    // the unconnected block. The cheap tier judges the header ladder and
    // the target claim, not the curve root or the emission, and the child
    // makes the alternative heavier than the one incumbent block.
    let mut child_facts = facts;
    child_facts.connecting = facts
        .connecting
        .checked_add(BlockCount::ONE)
        .expect("a successor height");
    child_facts.previous = broken.hash;
    let child = y
        .assemble_unconnected(&child_facts, &[])
        .await
        .unwrap_or_else(|outcome| panic!("the heavier child forms: {outcome}"));

    match x.offer_unconnected(&broken).await.expect("offer") {
        Offered::Held { height } => assert_eq!(height, broken.height),
        other => panic!("equal work was not held: {other:?}"),
    }
    let plan = match x.offer_unconnected(&child).await.expect("offer") {
        Offered::SwitchDue(plan) => plan,
        other => panic!("the heavier child did not name a switch: {other:?}"),
    };
    assert_eq!(plan.demoted.len(), 1, "the one incumbent block");
    assert_eq!(plan.promoted.len(), 2, "the broken block and its child");

    let listed: HashMap<BlockHash, Vec<Transaction>> =
        HashMap::from([(broken.hash, broken.candidate.transactions.clone())]);
    match x.reorganize(&plan, &listed).await.expect("form refusal") {
        Switched::Refused {
            at,
            hash,
            refused,
            removed,
        } => {
            assert_eq!(at, broken.height);
            assert_eq!(hash, broken.hash);
            assert_eq!(refused.rule, CenRow::I15);
            assert_eq!(
                refused.locus,
                Locus::Tx {
                    slot: TxSlot::Listed(0)
                }
            );
            assert_eq!(removed, vec![broken.hash, child.hash]);
        }
        other => panic!("the promotion was not refused: {other:?}"),
    }
    assert_eq!(
        x.digest().await.expect("digest"),
        before,
        "the main chain was not popped"
    );
    assert_eq!(
        x.hash_at(incumbent[0].height).await.expect("tip"),
        Some(incumbent[0].hash),
        "the incumbent block is still the tip"
    );
    assert_eq!(x.alt_blocks_held().await.expect("al6"), 0);
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_switch_drops_the_losing_branch_from_the_target_ledger() {
    // The newest reference a block may name is `connecting − MIN_AGE`
    // below it. The losing branch is that deep, so the height the spend
    // names was cached as the incumbent's header and now belongs to the
    // chain the switch promoted.
    let min_age = REFERENCE_BLOCK_MIN_AGE.to_raw();
    let mut x = Scenario::open("switch-ledger-x");
    let mut y = Scenario::open("switch-ledger-y");
    x.mine(AT).await;
    let prefix = y.mine(AT).await;
    x.mine(min_age).await;
    y.idle();
    let won = y.mine(min_age + 1).await;
    let plan = offer_branch(&x, &won).await;
    let Switched::Done(_) = x.reorganize(&plan, &bodies(&won)).await.expect("switch") else {
        panic!("the switch did not land");
    };

    let connecting = BlockHeight::from_raw(AT + min_age + 1);
    assert_eq!(won[1].height, BlockHeight::from_raw(AT + 1));
    let mut chain: Vec<Mined> = prefix;
    chain.extend(won.iter().cloned());
    let spend = Spender::over(&chain).spend_coinbase(
        x.wallet(),
        BlockHeight::from_raw(0),
        connecting,
        Family::Main.fee(),
    );
    let reference = match &spend.ct {
        Ct::Fcmp {
            reference_block, ..
        } => *reference_block,
        Ct::Null(_) => panic!("a spend names a reference"),
    };
    assert_eq!(
        reference, won[1].hash,
        "the spend references a block the switch promoted"
    );
    let landed = x
        .mine_listing(vec![spend])
        .await
        .unwrap_or_else(|outcome| panic!("the spend connects on the switched chain: {outcome}"));
    assert_eq!(landed.height, connecting);
    x.close().await;
    y.close().await;
}
