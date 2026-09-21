// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E fixtures (`CHAIN_RULES_SLICE_3.md` §5). CEN-E5 is judged over
//! a recorded chain, not a candidate: the negative fixture is a chain whose
//! block at an anchored height is not the anchor.

use super::*;
use crate::anchors::{Anchor, Remedy};
use crate::harness::fixture::{recorded, root};
use crate::harness::{infallible, FaultingView, MockChain};
use shekyl_types::BlockHash;

/// A five-block chain (heights 0–4), timestamps 100–104.
fn five_blocks() -> MockChain {
    (0..5u64).fold(MockChain::default(), |chain, i| {
        chain.push(recorded(100 + i), root(u8::try_from(i).expect("small")))
    })
}

/// The identity the fixture chain recorded at `height`.
fn hash_at(chain: &MockChain, height: u64) -> BlockHash {
    chain.with_view(
        |view| match infallible(view.block_at(BlockHeight::from_raw(height))) {
            AtHeight::Recorded(block) => block.hash,
            AtHeight::AboveTip => panic!("fixture chain has a block at {height}"),
        },
    )
}

const OTHER: BlockHash = BlockHash::from_bytes([0xEE; 32]);

fn conflict(chain: &MockChain, anchors: &ReleaseAnchors) -> Option<AnchorConflict> {
    chain.with_view(|view| infallible(anchors.conflict_with(&view)))
}

/// The refusal fixture the registry names: a recorded block at an anchored
/// height that is not the anchor is the conflict, and it names both hashes.
#[test]
fn a_recorded_block_that_is_not_the_anchor_is_the_conflict() {
    let chain = five_blocks();
    let anchors = ReleaseAnchors::for_tests(Box::leak(Box::new([Anchor {
        height: BlockHeight::from_raw(3),
        hash: OTHER,
    }])));
    assert_eq!(
        conflict(&chain, &anchors),
        Some(AnchorConflict {
            height: BlockHeight::from_raw(3),
            expected: OTHER,
            recorded: Some(hash_at(&chain, 3)),
        })
    );
}

/// A chain that carries the anchor agrees — at height 3 and at genesis.
#[test]
fn a_chain_that_carries_its_anchors_has_no_conflict() {
    let chain = five_blocks();
    let anchors = ReleaseAnchors::for_tests(Box::leak(Box::new([
        Anchor {
            height: BlockHeight::from_raw(0),
            hash: hash_at(&chain, 0),
        },
        Anchor {
            height: BlockHeight::from_raw(3),
            hash: hash_at(&chain, 3),
        },
    ])));
    assert_eq!(conflict(&chain, &anchors), None);
}

/// An anchor above the tip is not yet checkable: skipped, not a conflict
/// (the C++ `continue`s past `pt.first >= blockchain_height`).
#[test]
fn an_anchor_above_the_tip_is_not_yet_checkable() {
    let chain = five_blocks();
    let anchors = ReleaseAnchors::for_tests(Box::leak(Box::new([Anchor {
        height: BlockHeight::from_raw(9),
        hash: OTHER,
    }])));
    assert_eq!(conflict(&chain, &anchors), None);
}

/// The first conflict in height order is reported, not the last.
#[test]
fn the_first_conflict_in_height_order_is_reported() {
    let chain = five_blocks();
    let anchors = ReleaseAnchors::for_tests(Box::leak(Box::new([
        Anchor {
            height: BlockHeight::from_raw(1),
            hash: OTHER,
        },
        Anchor {
            height: BlockHeight::from_raw(4),
            hash: OTHER,
        },
    ])));
    assert_eq!(
        conflict(&chain, &anchors).map(|c| c.height),
        Some(BlockHeight::from_raw(1))
    );
}

/// An empty file contradicts nothing, and an empty table contradicts
/// nothing — what every node is today.
#[test]
fn an_empty_chain_or_an_empty_table_has_no_conflict() {
    let anchors = ReleaseAnchors::for_tests(Box::leak(Box::new([Anchor {
        height: BlockHeight::from_raw(0),
        hash: OTHER,
    }])));
    assert_eq!(conflict(&MockChain::default(), &anchors), None);
    assert_eq!(conflict(&five_blocks(), &ReleaseAnchors::EMPTY), None);
}

/// A view that cannot answer is a fault, not a conflict and not agreement.
#[test]
fn a_faulting_view_is_a_fault_not_a_verdict() {
    let view = FaultingView::default();
    assert!(ReleaseAnchors::EMPTY.conflict_with(&view).is_err());
}

/// The remedy is C2-R1b clause (3): refuse at genesis; otherwise pop to two
/// blocks before the conflict, floored at 1 (heights 1 and 2 both roll back
/// to 1, never to a saturated 0).
#[test]
fn the_remedy_refuses_at_genesis_and_pops_to_two_before_floored_at_one() {
    let at = |height: u64| AnchorConflict {
        height: BlockHeight::from_raw(height),
        expected: OTHER,
        recorded: None,
    };
    assert_eq!(at(0).remedy(), Remedy::RefuseToRun);
    assert_eq!(at(1).remedy(), Remedy::PopTo(BlockHeight::from_raw(1)));
    assert_eq!(at(2).remedy(), Remedy::PopTo(BlockHeight::from_raw(1)));
    assert_eq!(at(3).remedy(), Remedy::PopTo(BlockHeight::from_raw(1)));
    assert_eq!(at(4).remedy(), Remedy::PopTo(BlockHeight::from_raw(2)));
    assert_eq!(at(1000).remedy(), Remedy::PopTo(BlockHeight::from_raw(998)));
}

/// The rollback arithmetic alone, at the floor boundary.
#[test]
fn rollback_target_is_two_before_floored_at_one() {
    for (conflict, target) in [
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 2),
        (5, 3),
        (u64::MAX, u64::MAX - 2),
    ] {
        assert_eq!(
            rollback_target(BlockHeight::from_raw(conflict)),
            BlockHeight::from_raw(target),
            "conflict at {conflict}"
        );
    }
}
