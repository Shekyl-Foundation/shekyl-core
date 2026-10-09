// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's own subject.
//!
//! A harness with nothing to test passes vacuously; the probe below is a
//! *labelled* rule — not an implementation of CEN-J1, whose registry entry
//! stays `pending` past slice 8, which scoped the serve-credit successor
//! rows out (`CHAIN_RULES_SLICE_8.md` §1.2). (It wore the CEN-C1 label
//! until slice 2 landed that row, the CEN-E1 label until slice 3 did, the
//! CEN-F1 label until slice 4 did, and the CEN-G1 label until slice 7
//! commit 7 did; the probe moves ahead of the port so it never names a
//! landed rule.) Shaped
//! exactly
//! like the rules the porting increments
//! will write, so the mock, the fault channel and the two assertions are
//! each shown to bite before the first real rule leans on them. The
//! `should_panic` cases are what make this file's green mean something.

use super::fixture::{candidate, candidate_on, recorded, root, spendable_chain};
use super::*;
use crate::census::CenRow;
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::validate;
use crate::verdict::{refused, Locus, TxSlot, Verdict};

/// The probe: reads the view (so a fault must travel), then refuses on a
/// zero timestamp under the CEN-J1 label.
fn probe_cen_j1<'id, V: ChainView<'id>>(
    candidate: &Candidate,
    view: &V,
) -> Result<Verdict<()>, V::Fault> {
    let _genesis = view.block_at(BlockHeight::ZERO)?;
    if candidate.block.header.timestamp == 0 {
        return refused(CenRow::J1, Locus::Block);
    }
    Ok(Ok(()))
}

fn with_timestamp(timestamp: u64) -> Candidate {
    let mut candidate = candidate(Vec::new());
    candidate.block.header.timestamp = timestamp;
    candidate
}

fn one_block() -> MockChain {
    MockChain::default().push(recorded(1_000), root(0xaa))
}

// --- the mock chain -------------------------------------------------------

#[test]
fn an_empty_chain_has_no_tip_and_every_height_is_above_it() {
    let chain = MockChain::default();
    assert_eq!(chain.tip(), None);
    chain.with_view(|view| {
        assert_eq!(infallible(view.tip()), None);
        // Height 0 has no block, but it has a tree state — the empty tree —
        // exactly as the store answers (`root_at(0)` is `EMPTY` there too).
        assert_eq!(
            infallible(view.root_at(BlockHeight::ZERO)),
            AtHeight::Recorded(CurveTreeRoot::EMPTY)
        );
        for height in [0, 1, u64::MAX] {
            let height = BlockHeight::from_raw(height);
            assert_eq!(infallible(view.block_at(height)), AtHeight::AboveTip);
        }
        for height in [1, 2, u64::MAX] {
            assert_eq!(
                infallible(view.root_at(BlockHeight::from_raw(height))),
                AtHeight::AboveTip
            );
        }
    });
}

#[test]
fn push_records_densely_from_zero_and_reads_back_by_height() {
    let chain = MockChain::default()
        .push(recorded(1_000), root(0xa0))
        .push(recorded(1_060), root(0xa1))
        .push(recorded(1_120), root(0xa2));
    let tip = chain.tip().expect("three blocks recorded");
    assert_eq!(tip.height, BlockHeight::from_raw(2));
    assert_eq!(
        tip.hash,
        recorded(1_120).hash,
        "the tip's identity is the last block's"
    );
    assert_eq!(Tip::connecting_height(Some(&tip)), BlockHeight::from_raw(3));
    assert_eq!(Tip::connecting_height(None), BlockHeight::ZERO);
    chain.with_view(|view| assert_eq!(infallible(view.tip()), Some(tip)));
    chain.with_view(|view| {
        for (height, stamp) in (0u64..).zip([1_000, 1_060, 1_120]) {
            let height = BlockHeight::from_raw(height);
            let block = infallible(view.block_at(height));
            assert_eq!(block, AtHeight::Recorded(recorded(stamp)));
        }
        // Roots are keyed one height after the block they were pushed with
        // (SCW-19): the state *at* h is what h − 1 left. Height 0 is the
        // empty tree; tip + 1 is recorded; tip + 2 is not.
        assert_eq!(
            infallible(view.root_at(BlockHeight::ZERO)),
            AtHeight::Recorded(CurveTreeRoot::EMPTY)
        );
        for (height, byte) in (1u64..).zip([0xa0, 0xa1, 0xa2]) {
            assert_eq!(
                infallible(view.root_at(BlockHeight::from_raw(height))),
                AtHeight::Recorded(root(byte)),
                "root_at({height}) is the root pushed with block {}",
                height - 1
            );
        }
        // One past the tip: no block, but a recorded root (CEN-B5's read).
        assert_eq!(
            infallible(view.block_at(BlockHeight::from_raw(3))),
            AtHeight::AboveTip
        );
        assert_eq!(
            infallible(view.root_at(BlockHeight::from_raw(3))),
            AtHeight::Recorded(root(0xa2))
        );
        assert_eq!(
            infallible(view.root_at(BlockHeight::from_raw(4))),
            AtHeight::AboveTip
        );
        assert_eq!(
            infallible(view.root_at(BlockHeight::from_raw(u64::MAX))),
            AtHeight::AboveTip
        );
    });
}

/// The tree is told, never derived: a count pushed with its root is what
/// `leaf_count_at` and `depth_at` answer at that height, a plain `push`
/// carries the count before it forward (no outputs, no growth), and the
/// frontier of a planted tree is one `grow` refuses — the mock holds no
/// chunks, and says so in the type rather than with an empty frontier
/// under a non-zero count.
#[test]
fn the_tree_travels_with_the_root_it_was_pushed_with() {
    use crate::tree_growth::{grow, FrontierFault, GrowFault};
    use shekyl_fcmp::tree::layer_count_for_leaves;

    // Three leaves: one layer-0 chunk under a single root layer.
    let planted = 3;
    let chain = MockChain::default()
        .push(recorded(1_000), root(0xa0))
        .push_tree(recorded(1_060), root(0xa1), planted)
        .push(recorded(1_120), root(0xa2));
    chain.with_view(|view| {
        // Heights 0 and 1: the empty tree, as a chain built by `push` has.
        for height in [0, 1] {
            let height = BlockHeight::from_raw(height);
            assert_eq!(
                infallible(view.leaf_count_at(height)),
                AtHeight::Recorded(0)
            );
            assert_eq!(infallible(view.depth_at(height)), AtHeight::Recorded(0));
        }
        // Height 2: the planted tree, keyed as its root is (SCW-19).
        assert_eq!(
            infallible(view.root_at(BlockHeight::from_raw(2))),
            AtHeight::Recorded(root(0xa1))
        );
        assert_eq!(
            infallible(view.leaf_count_at(BlockHeight::from_raw(2))),
            AtHeight::Recorded(planted)
        );
        assert_eq!(
            infallible(view.depth_at(BlockHeight::from_raw(2))),
            AtHeight::Recorded(layer_count_for_leaves(planted) - 1)
        );
        // Height 3: `push` after a plant grows nothing — the count carries.
        assert_eq!(
            infallible(view.leaf_count_at(BlockHeight::from_raw(3))),
            AtHeight::Recorded(planted)
        );
        assert_eq!(
            infallible(view.leaf_count_at(BlockHeight::from_raw(4))),
            AtHeight::AboveTip
        );
        // The frontier names the planted count and no chunks; a grow over
        // it is the view failing to describe its tree, not a root.
        let frontier = infallible(view.tree_frontier());
        assert_eq!(frontier.leaf_count, planted);
        assert_eq!(
            grow(
                &frontier,
                &[shekyl_types::TreeLeaf::from_bytes(
                    [0; shekyl_types::TreeLeaf::LEN]
                )]
            ),
            Err(GrowFault::Frontier(FrontierFault::Shape {
                layers: 0,
                expected: layer_count_for_leaves(planted),
            }))
        );
    });
    // A chain that planted nothing has the empty frontier, as before.
    one_block().with_view(|view| {
        assert_eq!(infallible(view.tree_frontier()), TreeFrontier::EMPTY);
    });
}

#[test]
fn key_images_are_a_set() {
    let spent = KeyImage::from_bytes([0x5e; 32]);
    let fresh = KeyImage::from_bytes([0x0f; 32]);
    let chain = MockChain::default().with_key_image(spent);
    chain.with_view(|view| {
        assert!(infallible(view.has_key_image(&spent)));
        assert!(!infallible(view.has_key_image(&fresh)));
    });
}

/// The candidate is coinbase-only: the one well-formed block a `MockChain`
/// can hold, since a fixture spend is refused at CEN-I13 on any view
/// (slice 6 row 6; `fixture_sanity_tests`).
#[test]
fn the_mock_view_validates_a_candidate_with_a_brand_of_its_own() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let valid = judged(validate(
            formed_on(&chain, candidate_on(&chain, Vec::new())),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("a candidate built on the chain's tip satisfies every landed rule");
        assert_eq!(valid.rule_set_id(), RuleSet::GENESIS.id());
        // The landed block rules ran; the probe is not among them.
        assert!(!valid.coverage().contains(CenRow::J1));
    });
}

// --- the probe against the harness ---------------------------------------

#[test]
fn probe_harness_fires_on_the_named_row() {
    one_block().with_view(|view| {
        assert_refused(
            infallible(probe_cen_j1(&with_timestamp(0), &view)),
            CenRow::J1,
            Locus::Block,
        );
        boundary_pair(1, 0, CenRow::J1, Locus::Block, |timestamp| {
            infallible(probe_cen_j1(&with_timestamp(timestamp), &view))
        });
    });
}

#[test]
fn probe_passes_a_good_candidate() {
    one_block().with_view(|view| {
        assert_eq!(
            infallible(probe_cen_j1(&with_timestamp(1_000), &view)),
            Ok(())
        );
    });
}

#[test]
#[should_panic(expected = "expected CEN-E2 at block, but CEN-J1 refused at block")]
fn probe_harness_bites_wrong_row() {
    one_block().with_view(|view| {
        assert_refused(
            infallible(probe_cen_j1(&with_timestamp(0), &view)),
            CenRow::E2,
            Locus::Block,
        );
    });
}

#[test]
#[should_panic(expected = "expected CEN-J1 at block, but the candidate passed")]
fn probe_harness_bites_ok() {
    one_block().with_view(|view| {
        assert_refused(
            infallible(probe_cen_j1(&with_timestamp(1_000), &view)),
            CenRow::J1,
            Locus::Block,
        );
    });
}

#[test]
#[should_panic(expected = "the last acceptable value was refused: CEN-J1 refused at block")]
fn probe_boundary_bites_inverted_pair() {
    one_block().with_view(|view| {
        boundary_pair(0, 1, CenRow::J1, Locus::Block, |timestamp| {
            infallible(probe_cen_j1(&with_timestamp(timestamp), &view))
        });
    });
}

#[test]
#[should_panic(expected = "expected CEN-J1 at miner tx, but CEN-J1 refused at block")]
fn probe_harness_bites_wrong_locus() {
    one_block().with_view(|view| {
        assert_refused(
            infallible(probe_cen_j1(&with_timestamp(0), &view)),
            CenRow::J1,
            Locus::Tx {
                slot: TxSlot::Miner,
            },
        );
    });
}

#[test]
fn every_faulting_view_method_faults() {
    let view = FaultingView::default();
    let image = KeyImage::from_bytes([0; 32]);
    assert_eq!(view.has_key_image(&image), Err(Faulted));
    assert_eq!(view.block_at(BlockHeight::ZERO), Err(Faulted));
    assert_eq!(view.root_at(BlockHeight::ZERO), Err(Faulted));
}

#[test]
fn probe_propagates_a_fault_and_never_reaches_a_verdict() {
    let faulting = FaultingView::default();
    // Both the candidate the probe would refuse and the one it would pass
    // come back as the fault: the substrate failed before any judgement.
    assert_eq!(probe_cen_j1(&with_timestamp(0), &faulting), Err(Faulted));
    assert_eq!(
        probe_cen_j1(&with_timestamp(1_000), &faulting),
        Err(Faulted)
    );
}
