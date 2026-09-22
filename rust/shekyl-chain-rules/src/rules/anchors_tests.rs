// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E fixtures (`CHAIN_RULES_SLICE_3.md` §5). CEN-E5 is judged over
//! a recorded chain, not a candidate: the negative fixture is a chain whose
//! block at an anchored height is not the anchor.

use super::*;
use crate::anchors::Anchor;
use crate::harness::fixture::{candidate_on, recorded, root};
use crate::harness::{assert_refused, formed_on, infallible, judged, FaultingView, MockChain};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::validate;
use shekyl_types::BlockHash;

// ---- CEN-E1: the anchor's equality, per block, through `validate` -------

/// A one-entry table anchoring `height` at `hash`.
fn anchoring(height: u64, hash: BlockHash) -> ReleaseAnchors {
    ReleaseAnchors::for_tests(Box::leak(Box::new([Anchor {
        height: BlockHeight::from_raw(height),
        hash,
    }])))
}

/// Refusal fixture: a valid candidate connecting at an anchored height whose
/// identity is not the anchor is refused on E1, at the block.
#[test]
fn a_block_at_an_anchored_height_that_is_not_the_anchor_is_refused() {
    let chain = five_blocks();
    // Anchor the connecting height (5) at a hash the candidate cannot have.
    let trust = Trust::full(anchoring(5, OTHER));
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        let verdict = judged(validate(formed, &view, &RuleSet::GENESIS, &trust));
        assert_refused(verdict, CenRow::E1, Locus::Block);
    });
}

/// A candidate whose identity *is* the anchor passes, and E1 is in the
/// coverage — the row ran.
#[test]
fn a_block_that_is_the_anchor_passes_with_e1_recorded() {
    let chain = five_blocks();
    let candidate = candidate_on(&chain, Vec::new());
    let identity = candidate.block.hash();
    let trust = Trust::full(anchoring(5, identity));
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate);
        let valid = judged(validate(formed, &view, &RuleSet::GENESIS, &trust))
            .expect("the anchored block is the anchor");
        assert_eq!(valid.block().hash(), identity);
        assert!(valid.coverage().contains(CenRow::E1));
    });
}

/// At an unanchored height — every height today — E1 is vacuously
/// satisfied and still recorded as evaluated: the coverage says the row
/// ran, which the C++ never records.
#[test]
fn an_unanchored_height_passes_vacuously_and_is_recorded() {
    let chain = five_blocks();
    for trust in [Trust::UNANCHORED, Trust::full(anchoring(3, OTHER))] {
        chain.with_view(|view| {
            let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
            let valid = judged(validate(formed, &view, &RuleSet::GENESIS, &trust))
                .expect("no anchor at the connecting height");
            assert!(valid.coverage().contains(CenRow::E1));
        });
    }
}

/// E1 at genesis: an anchor at height 0 judges the genesis candidate.
#[test]
fn a_genesis_anchor_judges_the_genesis_candidate() {
    let chain = MockChain::default();
    let wrong = Trust::full(anchoring(0, OTHER));
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        assert_refused(
            judged(validate(formed, &view, &RuleSet::GENESIS, &wrong)),
            CenRow::E1,
            Locus::Block,
        );
    });
}

// ---- CEN-E5: the binary's anchors agree with the file, at open ---------

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

/// The remedy is C2-R1b clause (3), as a chain count. Genesis refuses.
/// Every other conflict pops until this many blocks remain: the count whose
/// tip is the conflict and the two blocks before it, or genesis alone when
/// the chain is shorter than that. A conflict at height 1 leaves genesis,
/// so the conflicting block is removed.
#[test]
fn the_remedy_refuses_at_genesis_and_pops_to_a_chain_count() {
    let at = |height: u64| AnchorConflict {
        height: BlockHeight::from_raw(height),
        expected: OTHER,
        recorded: None,
    };
    assert_eq!(at(0).remedy(), Remedy::RefuseToRun);
    // conflict ordinal, stop count, tip that count leaves
    for (conflict, count, tip) in [
        (1, 1, 0),
        (2, 1, 0),
        (3, 1, 0),
        (4, 2, 1),
        (5, 3, 2),
        (1000, 998, 997),
        (u64::MAX, u64::MAX - 2, u64::MAX - 3),
    ] {
        let Remedy::PopTo(got) = at(conflict).remedy() else {
            panic!("conflict at {conflict} pops");
        };
        assert_eq!(got, ChainCount::from_raw(count), "count at {conflict}");
        assert_eq!(
            got.tip(),
            Some(BlockHeight::from_raw(tip)),
            "tip at {conflict}"
        );
        assert_eq!(
            rollback_count(BlockHeight::from_raw(conflict)),
            got,
            "remedy and rollback_count agree at {conflict}"
        );
    }
}
