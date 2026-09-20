// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

#[test]
fn the_three_block_counts_are_three_different_numbers() {
    // The opening brief conflated these. Pinning them together is what stops a
    // later edit re-merging them silently.
    assert_eq!(W, 730);
    assert_eq!(REPLAY_WINDOW_BLOCKS, 725);
    assert_eq!(HELD_BUFFER_BLOCKS, 790);
    const { assert!(REPLAY_WINDOW_BLOCKS < W) };
    const { assert!(HELD_BUFFER_BLOCKS > W) };
    assert_eq!(HELD_BUFFER_BLOCKS - W, COINBASE_LOCK_WINDOW as u64);
}

#[test]
fn depth_ladder_matches_the_production_capacity_function() {
    // The ladder is derived from `outputs_per_node`, so this asserts the
    // derivation's *shape*: one more leaf than a layer's capacity forces the
    // next layer.
    assert_eq!(min_leaves_for_depth(1), None);
    assert_eq!(min_leaves_for_depth(2), Some(1));
    for depth in 3u8..=6 {
        let min = min_leaves_for_depth(depth).expect("depth >= 2 has a floor");
        assert_eq!(min, outputs_per_node(depth - 2) as u64 + 1);
        let shallower = min_leaves_for_depth(depth - 1).expect("depth >= 2 has a floor");
        assert!(min > shallower, "the ladder must be strictly increasing");
    }
}

#[test]
fn depth_six_is_out_of_reach_for_a_dense_rig_corpus() {
    // The finding that forced the sparse-path design: a dense depth-6 tree does
    // not fit the 8 GB rig with room to work. If a width change ever made it
    // fit, the sparse arm would become optional -- and this test is where that
    // news arrives.
    let leaves = min_leaves_for_depth(6).expect("depth 6 has a floor");
    let leaf_scalar_bytes = leaves * SCALARS_PER_LEAF_BYTES;
    assert!(
        leaf_scalar_bytes > 2_000_000_000,
        "expected a multi-gigabyte dense depth-6 corpus, got {leaf_scalar_bytes} B"
    );
}

const SCALARS_PER_LEAF_BYTES: u64 = 4 * 32;

#[test]
fn the_weight_ceiling_is_the_landed_clamp_not_a_json_constant() {
    // 2 x max(S x zone, zone) = 2 x 4 x 300_000.
    assert_eq!(sustained_block_weight_ceiling(), 2_400_000);
}

#[test]
fn the_densest_shape_is_within_the_mempool_limit() {
    for depth in 2u8..=6 {
        let shape = densest_leaf_shape(depth);
        assert!(
            shape.weight <= shekyl_wire::transaction::TX_WEIGHT_LIMIT,
            "depth {depth}: a shape the mempool refuses cannot appear in a worst-case block"
        );
        assert!(shape.outputs >= 1 && shape.inputs >= 1);
    }
}

#[test]
fn the_leaf_rate_falls_as_the_tree_deepens() {
    // The monotonicity the doc comment claims -- asserted, not asserted-in-prose.
    // A deeper tree means a larger proof, a heavier tx, and fewer of them.
    let shallow = worst_case_leaves_per_block(2).leaves_per_block;
    let deep = worst_case_leaves_per_block(6).leaves_per_block;
    assert!(
        shallow >= deep,
        "leaf rate must not increase with depth: {shallow} at depth 2, {deep} at depth 6"
    );
}

#[test]
fn the_window_is_the_rate_times_the_replay_window() {
    let rate = worst_case_leaves_per_block(6);
    assert_eq!(
        worst_case_window_leaves(6),
        rate.leaves_per_block * REPLAY_WINDOW_BLOCKS
    );
}

// ── The control-depth validator ─────────────────────────────────────────────
//
// The sparse-path argument is flatness of the sparse/dense ratio across
// ADJACENT rungs. A set that cannot express that must be refused before it is
// used as licensing evidence, not labelled afterwards.

#[test]
fn a_repeated_rung_is_refused_because_it_is_one_rung() {
    let err = validate_control_depths(&[4, 4]).expect_err("a repeated depth is one rung");
    assert!(err.contains("distinct"), "{err}");
}

#[test]
fn a_gap_is_refused_because_it_shows_no_flatness_across_what_it_skips() {
    let err = validate_control_depths(&[4, 6]).expect_err("4 and 6 are not adjacent");
    assert!(err.contains("adjacent"), "{err}");
}

#[test]
fn a_depth_below_the_ladder_floor_is_refused() {
    // The Selene leaf layer is never itself the root, so depth 2 is the floor.
    let err = validate_control_depths(&[1, 2]).expect_err("depth 1 is not a tree shape");
    assert!(err.contains("floor"), "{err}");
    assert_eq!(min_leaves_for_depth(1), None);
}

#[test]
fn an_empty_control_set_is_refused() {
    assert!(validate_control_depths(&[]).is_err());
}

#[test]
fn adjacent_distinct_rungs_are_accepted_in_either_order() {
    // Order is the operator's; adjacency is the property.
    assert!(validate_control_depths(&[4, 5]).is_ok());
    assert!(validate_control_depths(&[5, 4]).is_ok());
    assert!(validate_control_depths(&[4]).is_ok());
}
