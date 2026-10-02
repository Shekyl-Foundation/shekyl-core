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
//! depend on scale. The window and shape populations are the bin's job, not
//! a test's.

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
fn the_window_plan_derives_four_arms_from_the_ladder() {
    let arms = plan_at_replay_window();
    assert_eq!(arms.len(), 4, "the plan is four arms");
    assert_eq!(arms[0].role, ArmRole::RungBelow);
    assert_eq!(arms[1].role, ArmRole::RungFloor);
    assert_eq!(arms[2].role, ArmRole::RungTop);
    assert_eq!(arms[3].role, ArmRole::InputCap);
}

#[test]
fn the_cross_rung_pair_is_adjacent_in_n_and_one_layer_apart() {
    let arms = plan_at_replay_window();
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
    let arms = plan_at_replay_window();
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
        separation >= SAME_RUNG_SEPARATION,
        "same-rung separation is {separation:.3}x; below {SAME_RUNG_SEPARATION}x the pair \
         cannot tell a slope from noise"
    );
}

#[test]
fn the_input_cap_arm_holds_the_population_and_raises_only_k() {
    let arms = plan_at_replay_window();
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
    // The cross-rung half is a ceiling. A ratio of 1.0 against an expected
    // 1.25 passes, and that pass is not evidence the step matched the model.
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
        role: ArmRole::RungTop,
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
        role: ArmRole::RungTop,
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
fn an_arms_depth_comes_from_its_population_not_the_rate_model() {
    let arms = plan_at_replay_window();
    let top = arms[2].population;
    assert_eq!(
        top.depth,
        layer_count_for_leaves(top.leaf_count),
        "an arm's depth must be read from its leaf count"
    );
}

#[test]
fn a_shape_rung_carries_the_same_four_roles_as_the_window_rung() {
    let shape = plan_at_depth(4);
    let window = plan_at_replay_window();
    let roles: Vec<ArmRole> = shape.iter().map(|a| a.role).collect();
    let window_roles: Vec<ArmRole> = window.iter().map(|a| a.role).collect();
    assert_eq!(
        roles, window_roles,
        "a shape run must exercise the same comparisons, or it establishes a \
         different claim than the one it is standing in for"
    );
}

#[test]
fn a_shape_rung_is_cheaper_than_the_window_one_but_separates_as_much() {
    let shape = plan_at_depth(4);
    let window = plan_at_replay_window();
    assert!(
        shape[2].population.leaf_count < window[2].population.leaf_count,
        "a shape rung that is not cheaper buys nothing"
    );
    let separation = shape[2].population.leaf_count as f64 / shape[1].population.leaf_count as f64;
    assert!(
        separation >= SAME_RUNG_SEPARATION,
        "shape separation {separation:.3}x is below {SAME_RUNG_SEPARATION}x"
    );
    assert_eq!(
        shape[0].population.depth + 1,
        shape[1].population.depth,
        "the shape rung must still straddle a boundary"
    );
}

#[test]
fn the_replay_window_never_reaches_the_rate_models_depth() {
    // The window is not the chain, and `assemble.rs`'s docstring reached for
    // the window's figure ("765 600 at the graded worst case") to describe a
    // population that is not windowed at all. Pinned as a set relation rather
    // than as two numbers: the window's leaf count sits BELOW the floor of the
    // rung the rate model is parameterised at, so the two can never be read as
    // one reading of one quantity.
    let window = worst_case_window_leaves(LEAF_RATE_MODEL_DEPTH);
    let model_rung_floor = min_leaves_for_depth(LEAF_RATE_MODEL_DEPTH)
        .expect("the rate model's depth has a rung floor");
    assert!(
        window < model_rung_floor,
        "the replay window ({window} leaves) has reached the rate model's rung \
         ({model_rung_floor}); the window and the chain are no longer trivially \
         distinguishable and every figure derived from either needs re-reading"
    );
}

#[test]
fn no_plan_here_claims_to_be_the_graded_one() {
    // Rule 22's named blocker, kept honest by a test: assembly's cost grows
    // without bound in chain length, so a graded population is a ruling about
    // chain age and not something this module may derive. If a `plan` function
    // ever appears that is neither the window's nor a shape rung's, this test
    // is where the claim has to be justified.
    let window = plan_at_replay_window();
    let shape = plan_at_depth(4);
    assert!(
        shape[2].population.leaf_count < window[2].population.leaf_count,
        "the shape rung must sit below the window rung"
    );
    assert!(
        window[2].population.leaf_count
            < min_leaves_for_depth(LEAF_RATE_MODEL_DEPTH).expect("rate model rung floor"),
        "the window plan must stay below the rate model's rung, or it has quietly \
         become a claim about the chain"
    );
}

// ── Withholding, direction, and the plan's identity ─────────────────────────

/// A flat-looking run on a moving board must not report `Flat`.
#[test]
fn a_contaminated_run_is_withheld_even_when_it_looks_flat() {
    let reading = read_flatness(
        FlatnessCriterion::default(),
        false,
        true,
        (ms(100), ms(100)),
        (ms(100), ms(125)),
        (4, 5),
    );
    assert_eq!(
        reading.outcome,
        FlatnessOutcome::Withheld(GradeWithheld::BoardNotQuiet),
        "a non-quiet board cannot support the claim a grade makes"
    );
    // The numbers stay. Withholding the judgment is not withholding the data,
    // and the ratio is the one the grade would have used.
    assert!((reading.cross_rung_ratio - 1.25).abs() < 1e-9);
    assert!((reading.cross_rung_expected - 1.25).abs() < 1e-12);
}

/// An unconverged series is not yet a cost, so it cannot be graded either.
#[test]
fn an_unconverged_series_is_withheld() {
    let reading = read_flatness(
        FlatnessCriterion::default(),
        true,
        false,
        (ms(100), ms(100)),
        (ms(100), ms(125)),
        (4, 5),
    );
    assert_eq!(
        reading.outcome,
        FlatnessOutcome::Withheld(GradeWithheld::SeriesUnconverged)
    );
}

/// The board is named ahead of convergence: it is the stronger
/// disqualification, and a board that moved makes convergence meaningless.
#[test]
fn both_faults_report_the_board() {
    let reading = read_flatness(
        FlatnessCriterion::default(),
        false,
        false,
        (ms(100), ms(100)),
        (ms(100), ms(125)),
        (4, 5),
    );
    assert_eq!(
        reading.outcome,
        FlatnessOutcome::Withheld(GradeWithheld::BoardNotQuiet)
    );
}

/// A quiet, converged run is graded — otherwise withholding would be
/// unconditional and the gate could not pass.
#[test]
fn a_quiet_converged_run_is_graded() {
    let reading = read_flatness(
        FlatnessCriterion::default(),
        true,
        true,
        (ms(100), ms(100)),
        (ms(100), ms(125)),
        (4, 5),
    );
    assert_eq!(
        reading.outcome,
        FlatnessOutcome::Graded(FlatnessGrade::Flat)
    );
    assert!(reading.same_rung_spread_pct.abs() < 1e-9);
    assert!((reading.cross_rung_ratio - 1.25).abs() < 1e-9);
}

/// A cheaper `MAX_INPUTS` arm reads as cheaper, not as a cost.
///
/// This is the discarded first run's actual shape — `k = 8` came in below
/// `k = 2` — and the absolute spread reported it as a 70 % cost.
#[test]
fn a_cheaper_input_cap_arm_reports_a_negative_change() {
    let change = signed_change_pct(ms(6081), ms(3575));
    assert!(
        change < 0.0,
        "a cheaper arm must read negative; got {change:.1} %"
    );
    // The absolute spread cannot tell the two directions apart, which is why
    // it is the wrong instrument for this field.
    assert!(spread_pct(ms(6081), ms(3575)) > 0.0);
    assert!(signed_change_pct(ms(3575), ms(6081)) > 0.0);
}

/// The published ratio is the ratio the grade used, zero guard included.
///
/// A raw `deep / shallow` on a zero shallow arm is `NaN`. The reading and
/// the grade both go through the guard, so they agree on infinity and the
/// record cannot publish a ratio the criterion did not judge.
#[test]
fn the_recorded_ratio_is_the_ratio_the_grade_judged() {
    let same = (ms(100), ms(100));
    let cross = (Duration::ZERO, ms(100));
    let depths = (4, 5);
    let reading = read_flatness(
        FlatnessCriterion::default(),
        true,
        true,
        same,
        cross,
        depths,
    );
    let judged = grade(FlatnessCriterion::default(), same, cross, depths);
    assert!(reading.cross_rung_ratio.is_infinite());
    match (reading.outcome, judged) {
        (
            FlatnessOutcome::Graded(FlatnessGrade::CrossRungOverstep {
                ratio, expected, ..
            }),
            FlatnessGrade::CrossRungOverstep {
                ratio: judged_ratio,
                expected: judged_expected,
                ..
            },
        ) => {
            assert_eq!(reading.cross_rung_ratio, ratio);
            assert_eq!(ratio, judged_ratio);
            assert_eq!(reading.cross_rung_expected, expected);
            assert_eq!(expected, judged_expected);
        }
        other => panic!("a zero shallow arm must overstep, and both doors must agree: {other:?}"),
    }
}

/// The plan's label comes from the type, so the replay window is never
/// announced as a graded figure.
#[test]
fn the_replay_window_plan_is_not_labelled_graded() {
    assert_eq!(PlanKind::ReplayWindow.label(), "REPLAY WINDOW");
    assert_eq!(PlanKind::Shape { depth: 4 }.label(), "SHAPE");
    for kind in [PlanKind::ReplayWindow, PlanKind::Shape { depth: 4 }] {
        assert!(
            !kind.label().contains("GRADED"),
            "no plan here is the graded one, so no label may say so"
        );
        assert!(
            !kind.note().is_empty(),
            "every plan must say what its figures mean"
        );
    }
}
