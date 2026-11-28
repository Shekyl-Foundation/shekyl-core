// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stake-refusal and due-reference tests for the bond orchestrator.
//!
//! Split from `bond_orchestrator_tests.rs` when that file crossed 1000 lines.

use super::*;
use shekyl_curve_tree::BlockHash;
use shekyl_types::BlockHeight;

/// An owed drain refuses a new stake with its own reason, not as a stake in
/// flight (`ARCHIVAL_BOND_POST_DELAY.md` §3.6, ruled 2026-11-27). A plan
/// still refuses as in flight, and so does a plan beside an ended one.
/// Red edit: answer an ended plan with `BondInFlight`.
#[test]
fn an_owed_drain_refuses_a_new_stake_with_its_own_reason() {
    use shekyl_engine_state::{PendingBondPlan, PendingPostBlock, PlanEnding, PlannedPosture};
    use shekyl_types::{BlockCount, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot};

    let plan = |byte: u8| PendingBondPlan {
        p_slot: PSlot::from_raw(u32::from(byte)),
        persona: PCanonicalId::from_bytes([byte; 32]),
        posture: PlannedPosture::SupportCompleteTree,
        draw: BlockCount::from_raw(20),
        requested_at: ChainCount::from_raw(1_000),
        funding_gindexes: vec![GlobalOutputIndex::from_raw(u64::from(byte))],
        funded_through: BlockHeight::from_raw(1_000),
        wait: None,
    };
    let seal = |block: &mut PendingPostBlock, byte: u8| {
        let g = block.generation();
        assert_eq!(
            block.seal_plan(plan(byte), g),
            shekyl_engine_state::pending_post_block::SealAdmission::Admit
        );
    };
    let refusal = |block: &PendingPostBlock| super::in_flight_refusal(block).map(|e| e.to_string());

    let mut block = PendingPostBlock::empty();
    assert_eq!(refusal(&block), None, "nothing in flight, nothing owed");

    seal(&mut block, 1);
    assert!(matches!(
        super::in_flight_refusal(&block),
        Some(FirstStakeError::BondInFlight)
    ));

    let ended = block.end_plan(
        &PCanonicalId::from_bytes([1; 32]),
        PlanEnding::Withdrawn,
        BlockHeight::from_raw(1_010),
    );
    assert!(ended.is_some(), "the plan ended");
    assert!(matches!(
        super::in_flight_refusal(&block),
        Some(FirstStakeError::EndedStakeReturning)
    ));

    seal(&mut block, 2);
    assert!(
        matches!(
            super::in_flight_refusal(&block),
            Some(FirstStakeError::BondInFlight)
        ),
        "a stake in flight is the first reason"
    );
}

/// A due post is signed at the canonical reference for the daemon-claimed
/// tip, and the wallet needs only to have reached that block: a wallet whose
/// tree is one block behind the claimed tip still signs (BD-Q3). Anchoring
/// from the wallet's own tip instead put the reference one block too old
/// whenever the driver ticked before the wallet took in the newest block,
/// and the sign waited on every such tick.
/// Red edit: answer `reference_block_at` from the wallet's ingested tip.
#[tokio::test(flavor = "current_thread")]
async fn a_due_reference_is_the_named_one_while_the_wallet_has_reached_it() {
    use super::{anchored_reference_block, reference_block_at};
    use crate::engine::curve_tree_actor::CurveTreeHandle;
    use shekyl_curve_tree::reference::select_reference_height;
    use shekyl_curve_tree::CurveTreeClient;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let client = CurveTreeClient::open(dir.path().join("curve_tree.redb")).expect("open tree");
    let tree = CurveTreeHandle::spawn(client);
    let ingested = 40u64;
    for h in 0..=ingested {
        tree.ingest(BlockHeight::from_raw(h), std::sync::Arc::new(Vec::new()))
            .await
            .expect("empty-leaf ingest advances the cursor");
    }
    let hash = |h: BlockHeight| {
        Some(BlockHash::from_bytes(
            [u8::try_from(h.to_raw()).unwrap_or(0); 32],
        ))
    };

    // The claimed tip is one block past the wallet's: its canonical
    // reference is one block newer than the wallet's own anchor.
    let wallet_tip = BlockHeight::from_raw(ingested);
    let claimed_tip = BlockHeight::from_raw(ingested + 1);
    let canonical = select_reference_height(claimed_tip).expect("a long enough chain");
    let from_wallet = anchored_reference_block(&tree, wallet_tip, hash)
        .await
        .expect("the wallet's own anchor");
    assert_eq!(from_wallet.height.to_raw() + 1, canonical.to_raw());

    let named = reference_block_at(&tree, canonical, hash)
        .await
        .expect("a reference the wallet has reached is used as named");
    assert_eq!(named.height, canonical);

    // A reference the wallet's tree has not reached refuses as resyncing.
    let ahead = BlockHeight::from_raw(ingested + 1);
    assert!(matches!(
        reference_block_at(&tree, ahead, hash).await,
        Err(BondAssemblyError::ReferenceResyncing { .. })
    ));
}
