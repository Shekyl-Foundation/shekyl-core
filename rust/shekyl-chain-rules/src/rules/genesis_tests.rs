// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E fixtures (`CHAIN_RULES_SLICE_3.md` §5): the genesis pin, per
//! block (CEN-E1) and at open (CEN-E5). CEN-E5 is judged over a recorded
//! chain, not a candidate: the negative fixture is a chain whose block 0
//! is not the pinned genesis.

use super::*;
use crate::harness::fixture::{candidate_on, recorded, root};
use crate::harness::{assert_refused, formed_on, infallible, judged, FaultingView, MockChain};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::validate;
use shekyl_types::BlockHash;

// ---- CEN-E1: the genesis pin's equality, per block, through `validate` --

/// A table pinning genesis at `hash`: a public network's shape.
fn pinning_genesis(hash: BlockHash) -> GenesisPin {
    GenesisPin::for_tests(Some(hash))
}

/// E1 at genesis: the pin judges the height-0 candidate by equality, and a
/// foreign genesis is refused on E1, at the block.
#[test]
fn the_genesis_pin_judges_the_genesis_candidate() {
    let chain = MockChain::default();
    let wrong = Trust::full(pinning_genesis(OTHER));
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        assert_refused(
            judged(validate(formed, &view, &RuleSet::GENESIS, &wrong)),
            CenRow::E1,
            Locus::Block,
        );
    });
}

/// A genesis candidate that *is* the pin passes, and E1 is in the coverage:
/// the row ran.
#[test]
fn the_pinned_genesis_passes_with_e1_recorded() {
    let chain = MockChain::default();
    let candidate = candidate_on(&chain, Vec::new());
    let identity = candidate.block.hash();
    let trust = Trust::full(pinning_genesis(identity));
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate);
        let valid = judged(validate(formed, &view, &RuleSet::GENESIS, &trust))
            .expect("the genesis candidate is the pin");
        assert_eq!(valid.block().hash(), identity);
        assert!(valid.coverage().contains(CenRow::E1));
    });
}

/// Above genesis nothing is pinned: E1 is vacuously satisfied and still
/// recorded as evaluated, under a pinned genesis or none.
#[test]
fn a_height_above_genesis_passes_vacuously_and_is_recorded() {
    let chain = five_blocks();
    for trust in [Trust::UNPINNED, Trust::full(pinning_genesis(OTHER))] {
        chain.with_view(|view| {
            let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
            let valid = judged(validate(formed, &view, &RuleSet::GENESIS, &trust))
                .expect("nothing is pinned above genesis");
            assert!(valid.coverage().contains(CenRow::E1));
        });
    }
}

// ---- CEN-E5: the file's genesis is the pinned one, at open -------------

/// A five-block chain (heights 0–4), timestamps 100–104.
fn five_blocks() -> MockChain {
    (0..5u64).fold(MockChain::default(), |chain, i| {
        chain.push(recorded(100 + i), root(u8::try_from(i).expect("small")))
    })
}

/// The identity the fixture chain recorded at `height`.
fn hash_at(chain: &MockChain, height: BlockHeight) -> BlockHash {
    chain.with_view(|view| match infallible(view.header_at(height)) {
        AtHeight::Recorded(record) => record.hash,
        AtHeight::AboveTip => panic!("fixture chain has a block at {height}"),
    })
}

const OTHER: BlockHash = BlockHash::from_bytes([0xEE; 32]);

fn conflict(chain: &MockChain, anchors: &GenesisPin) -> Option<GenesisConflict> {
    chain.with_view(|view| infallible(anchors.conflict_with(&view)))
}

/// The refusal fixture the registry names: a file whose genesis is not the
/// pinned one is the conflict at height 0 — another network's file, or a
/// remint — and it names both hashes. F11's "as configured" half at open
/// (slice 4 Q3).
#[test]
fn a_foreign_genesis_is_the_conflict_at_height_zero() {
    let chain = five_blocks();
    assert_eq!(
        conflict(&chain, &pinning_genesis(OTHER)),
        Some(GenesisConflict {
            height: BlockHeight::ZERO,
            expected: OTHER,
            recorded: Some(hash_at(&chain, BlockHeight::ZERO)),
        })
    );
}

/// A chain that carries the pinned genesis agrees.
#[test]
fn a_chain_that_carries_its_genesis_has_no_conflict() {
    let chain = five_blocks();
    assert_eq!(
        conflict(&chain, &pinning_genesis(hash_at(&chain, BlockHeight::ZERO))),
        None
    );
}

/// An empty file contradicts nothing — not even a genesis pin — and an
/// empty table contradicts nothing.
#[test]
fn an_empty_chain_or_an_empty_table_has_no_conflict() {
    assert_eq!(
        conflict(&MockChain::default(), &pinning_genesis(OTHER)),
        None
    );
    assert_eq!(conflict(&five_blocks(), &GenesisPin::NONE), None);
}

/// `conflict_with` is the view face of `conflict_over`. A second walk
/// would let the store's open and the view's open disagree.
#[test]
fn conflict_with_is_the_view_face_of_the_one_walk() {
    let chain = five_blocks();
    let anchors = pinning_genesis(OTHER);
    chain.with_view(|view| {
        let via_view = infallible(anchors.conflict_with(&view));
        let tip = infallible(view.tip());
        let via_walk = infallible(anchors.conflict_over(tip, |height| {
            Ok(match view.header_at(height)? {
                AtHeight::Recorded(record) => Some(record.hash),
                AtHeight::AboveTip => None,
            })
        }));
        assert_eq!(via_view, via_walk);
        assert!(via_walk.is_some(), "a foreign genesis is a conflict");
    });
}

/// A view that cannot answer is a fault, not a conflict and not agreement.
#[test]
fn a_faulting_view_is_a_fault_not_a_verdict() {
    let view = FaultingView::default();
    assert!(GenesisPin::NONE.conflict_with(&view).is_err());
}
