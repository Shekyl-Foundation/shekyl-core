// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the path-assembly cost instrument.
//!
//! The grader is exercised with synthetic durations, so both halves of the
//! pre-registered criterion are shown able to fire **before** capture exists.
//! A criterion only ever tested on passing input is a criterion that has not
//! been tested.
//!
//! The rig itself is driven at a deliberately small population: it proves the
//! ingest path, the rule-47 assertions and the assembly call, none of which
//! depend on scale. The graded populations are the bin's job, not a test's.

use std::time::Duration;

use super::*;

/// Population small enough for a test, large enough for two owned outputs to
/// land in different layer-0 chunks.
const TEST_LEAVES: u64 = 200;
/// Leaves per block in the rig tests.
const TEST_LEAVES_PER_BLOCK: u64 = 20;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn plan_derives_four_arms_from_the_ladder() {
    let arms = plan();
    assert_eq!(arms.len(), 4, "the plan is four arms");
    assert_eq!(arms[0].role, ArmRole::RungBelow);
    assert_eq!(arms[1].role, ArmRole::RungFloor);
    assert_eq!(arms[2].role, ArmRole::GradedTop);
    assert_eq!(arms[3].role, ArmRole::InputCap);
}

#[test]
fn the_cross_rung_pair_is_adjacent_in_n_and_one_layer_apart() {
    let arms = plan();
    let below = arms[0].population;
    let floor = arms[1].population;
    assert_eq!(
        below.leaf_count + 1,
        floor.leaf_count,
        "the cross-rung pair must differ by one leaf, so any cost difference \
         is the layer and not the population"
    );
    assert_eq!(
        below.depth + 1,
        floor.depth,
        "the cross-rung pair must differ by exactly one layer"
    );
}

#[test]
fn the_same_rung_pair_shares_a_depth_and_separates_enough_to_discriminate() {
    let arms = plan();
    let floor = arms[1].population;
    let top = arms[2].population;
    assert_eq!(
        floor.depth, top.depth,
        "the same-rung pair must share a depth, or it tests the wrong half"
    );
    // A same-rung pair only discriminates if `n` really grows across it: a
    // slope in `n` has to be large enough to clear the noise bound. Pinned so
    // a width change that collapsed the separation fails here rather than
    // quietly producing a powerless comparison.
    let separation = top.leaf_count as f64 / floor.leaf_count as f64;
    assert!(
        separation >= 1.5,
        "same-rung separation is {separation:.3}x; below 1.5x the pair cannot \
         tell a slope from noise"
    );
}

#[test]
fn the_input_cap_arm_holds_the_population_and_raises_only_k() {
    let arms = plan();
    assert_eq!(arms[3].population, arms[2].population);
    assert_eq!(arms[2].owned_inputs, CANONICAL_OWNED_INPUTS);
    assert_eq!(arms[3].owned_inputs, MAX_INPUTS);
}

#[test]
fn a_populations_depth_comes_from_the_production_arithmetic() {
    let p = Population::at(TEST_LEAVES);
    assert_eq!(p.depth, layer_count_for_leaves(TEST_LEAVES));
}

#[test]
fn owned_positions_land_in_distinct_chunks() {
    let positions = owned_positions(TEST_LEAVES, 2);
    assert_eq!(positions.len(), 2);
    let chunks: Vec<u64> = positions
        .iter()
        .map(|p| p / SELENE_CHUNK_WIDTH as u64)
        .collect();
    assert_ne!(
        chunks[0], chunks[1],
        "two owned outputs in one chunk would hide a reused leaf position"
    );
}

#[test]
fn the_cross_rung_ratio_is_one_more_layers_work() {
    assert!((expected_cross_rung_ratio(4, 5) - 1.25).abs() < f64::EPSILON);
    assert!((expected_cross_rung_ratio(5, 6) - 1.2).abs() < 1e-12);
}

#[test]
fn a_flat_assembler_passes_both_halves() {
    let grade = grade(
        FlatnessCriterion::default(),
        (ms(100), ms(100)),
        (ms(100), ms(125)),
        (4, 5),
    );
    assert_eq!(grade, FlatnessGrade::Flat);
}

#[test]
fn a_same_rung_slope_fires() {
    let grade = grade(
        FlatnessCriterion::default(),
        (ms(100), ms(150)),
        (ms(100), ms(125)),
        (4, 5),
    );
    match grade {
        FlatnessGrade::SameRungSlope { spread_pct, .. } => {
            assert!((spread_pct - 50.0).abs() < 1e-9, "spread was {spread_pct}");
        }
        other => panic!("a 50% same-rung spread must fire; got {other:?}"),
    }
}

#[test]
fn a_cross_rung_overstep_fires() {
    let grade = grade(
        FlatnessCriterion::default(),
        (ms(100), ms(100)),
        (ms(100), ms(200)),
        (4, 5),
    );
    match grade {
        FlatnessGrade::CrossRungOverstep {
            ratio, expected, ..
        } => {
            assert!((ratio - 2.0).abs() < 1e-9);
            assert!((expected - 1.25).abs() < f64::EPSILON);
        }
        other => panic!("doubling across one layer must fire; got {other:?}"),
    }
}

#[test]
fn a_cross_rung_step_flatter_than_predicted_passes() {
    // Cheaper than one layer's work is not a failure: the criterion bounds
    // the overstep, not the direction.
    let grade = grade(
        FlatnessCriterion::default(),
        (ms(100), ms(100)),
        (ms(100), ms(100)),
        (4, 5),
    );
    assert_eq!(grade, FlatnessGrade::Flat);
}

#[test]
fn the_same_rung_half_is_judged_before_the_cross_rung_half() {
    // Both halves failing reports the same-rung one, so a verdict names one
    // pair rather than the first that happened to be computed.
    let grade = grade(
        FlatnessCriterion::default(),
        (ms(100), ms(150)),
        (ms(100), ms(200)),
        (4, 5),
    );
    assert!(matches!(grade, FlatnessGrade::SameRungSlope { .. }));
}

#[test]
fn spread_is_symmetric_in_its_arguments() {
    let a = spread_pct(ms(100), ms(150));
    let b = spread_pct(ms(150), ms(100));
    assert!((a - b).abs() < f64::EPSILON, "{a} != {b}");
}

#[test]
fn the_rig_assembles_one_path_per_owned_input() {
    let arm = Arm {
        role: ArmRole::GradedTop,
        population: Population::at(TEST_LEAVES),
        owned_inputs: CANONICAL_OWNED_INPUTS,
    };
    let rig = AssembleRig::new(arm, TEST_LEAVES_PER_BLOCK, None);
    assert_eq!(rig.owned_inputs(), CANONICAL_OWNED_INPUTS);
    assert_eq!(rig.assemble_once(), CANONICAL_OWNED_INPUTS);
}

#[test]
fn the_rig_is_repeatable_across_calls() {
    // The timed call must not consume or mutate the rig: a series of samples
    // has to measure the same work every time.
    let arm = Arm {
        role: ArmRole::GradedTop,
        population: Population::at(TEST_LEAVES),
        owned_inputs: CANONICAL_OWNED_INPUTS,
    };
    let rig = AssembleRig::new(arm, TEST_LEAVES_PER_BLOCK, None);
    assert_eq!(rig.assemble_once(), CANONICAL_OWNED_INPUTS);
    assert_eq!(rig.assemble_once(), CANONICAL_OWNED_INPUTS);
}

#[test]
fn the_reference_height_is_one_past_the_last_leafs_maturity() {
    let last = BlockHeight::from_raw(100);
    let reference = reference_height_for(last);
    let maturity = maturity_height(last, false, TargetKind::TaggedKey).expect("tagged key matures");
    assert_eq!(reference.to_raw(), maturity.to_raw() + 1);
}

#[test]
fn the_windows_tree_depth_does_not_depend_on_the_rate_model() {
    // Two axes, conflated once already: `LEAF_RATE_MODEL_DEPTH` prices a
    // path's proof weight (and so a block's leaf rate); a tree's depth comes
    // from its leaf count. Across every plausible model depth the window is
    // one and the same tree depth, so a reader cannot take the model's 6 for
    // the tree's. If this ever fails, the leaf rate has become depth-sensitive
    // enough to move a rung and the plan's populations must be re-derived.
    let depths: Vec<u8> = (3..=7u8)
        .map(|model| layer_count_for_leaves(worst_case_window_leaves(model)))
        .collect();
    assert!(
        depths.windows(2).all(|w| w[0] == w[1]),
        "the window's tree depth tracked the rate model's depth: {depths:?}"
    );
}

#[test]
fn the_graded_arms_depth_comes_from_the_population_not_the_rate_model() {
    let arms = plan();
    let top = arms[2].population;
    assert_eq!(
        top.depth,
        layer_count_for_leaves(top.leaf_count),
        "the graded arm's depth must be read from its leaf count"
    );
}
