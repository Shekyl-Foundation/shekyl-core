// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Plumbing tests for the verify-edge fixture.
//!
//! **What is deliberately not here: the recompute contrast.** One complete
//! segment is `leaves_per_segment()` = 25 992 leaves, and a `root_at_count`
//! over it is a real curve computation — a unit test that built one would be
//! the slowest thing in the workspace and would still only reproduce what the
//! binary asserts at run time anyway. The contrast is the **binary's** runtime
//! red-bite: it records `mixed_path_confirmed` from the frozen-versus-unfrozen
//! ratio and fails the run when the control does not freeze every complete
//! segment. These tests cover the arithmetic and the state assertions that
//! contrast rests on, so a break in *those* is caught in CI rather than on the
//! rig.

use shekyl_curve_tree::LeafStore;

use crate::corpus::{leaves_per_block_at, nominal_block_weight, GRADED_TREE_DEPTH};
use crate::verifyedge::{build_population, frozen_count};

/// Leaf bytes that decode as scalars, so a recompute would be valid.
fn leaves() -> Vec<[u8; 128]> {
    crate::fixture::build_corpus(64, 3)
        .chunk
        .iter()
        .filter_map(|c| c.scalars())
        .map(|sc| {
            let mut b = [0u8; 128];
            for (i, s) in sc.iter().enumerate() {
                b[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            b
        })
        .collect()
}

#[test]
fn population_matches_the_derived_rate() {
    let store = LeafStore::open_ephemeral().unwrap();
    let rate = leaves_per_block_at(GRADED_TREE_DEPTH, nominal_block_weight());
    let bytes = leaves();
    let n = bytes.len() as u64;
    let pop = build_population(&store, 3, &rate, &|p| bytes[(p % n) as usize]).unwrap();

    // The scale the per-call cost is reported against must be the derived one,
    // not whatever the loop happened to write.
    assert_eq!(pop.leaves, 3 * rate.leaves_per_block);
    assert_eq!(pop.blocks, 3);
    assert_eq!(
        pop.complete_segments * pop.leaves_per_segment + pop.tail_leaves,
        pop.leaves,
        "the segment split must account for every leaf"
    );
}

#[test]
fn a_fresh_population_has_no_frozen_segments() {
    // The measurement's whole premise: inside the burial window nothing is
    // frozen, and nothing in the append path freezes it. If this ever fails,
    // the unfrozen phase is measuring a cost that is not there.
    let store = LeafStore::open_ephemeral().unwrap();
    let rate = leaves_per_block_at(GRADED_TREE_DEPTH, nominal_block_weight());
    let bytes = leaves();
    let n = bytes.len() as u64;
    let pop = build_population(&store, 2, &rate, &|p| bytes[(p % n) as usize]).unwrap();

    assert_eq!(frozen_count(&store, pop.complete_segments).unwrap(), 0);
}

#[test]
fn a_population_below_one_segment_has_no_recompute_to_measure() {
    // The binary refuses this case rather than reporting a cheap number. The
    // arithmetic that refusal reads is here: under `E` leaves, every leaf is
    // tail and no segment is complete.
    let store = LeafStore::open_ephemeral().unwrap();
    let rate = leaves_per_block_at(GRADED_TREE_DEPTH, nominal_block_weight());
    let bytes = leaves();
    let n = bytes.len() as u64;
    let pop = build_population(&store, 1, &rate, &|p| bytes[(p % n) as usize]).unwrap();

    assert!(pop.leaves < pop.leaves_per_segment, "one block is under E");
    assert_eq!(pop.complete_segments, 0);
    assert_eq!(pop.tail_leaves, pop.leaves);
}
