// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 5 — the path-assembly cost instrument.
//!
//! Times [`CurveTreeClient::assemble_paths`] on a store-backed client at
//! several leaf populations, with the owned-output count held fixed. Capture
//! is unbuilt. This is the instrument it will be graded with, written before
//! capture exists. The argument, the chain-versus-window finding, and the
//! pre-registered criterion are `CT6_PROVING_STATE.md` §11.
//!
//! ## The two halves
//!
//! [`FlatnessCriterion`] pre-registers both. [`read_flatness`] is the only
//! function that applies them, and the record stores that one value.
//!
//! - **Within one depth rung**, cost is constant within
//!   [`SAME_RUNG_TOLERANCE_PCT`] however much `n` grows.
//! - **Across a rung boundary**, the deeper arm costs no more than one
//!   layer's work, within the same tolerance. A cheaper step still passes.
//!   That pass is an upper bound. It is not evidence the step matched
//!   [`expected_cross_rung_ratio`]. The model treats every layer as the same
//!   cost, and increment 6 re-derives it before a passing capture is graded.
//!
//! [`plan_at_replay_window`] is one day of chain. [`plan_at_depth`] is a
//! cheaper rung, for the shape. The same-rung pair on the shape plan sits
//! [`SAME_RUNG_SEPARATION`] apart; the window plan's separation is whatever
//! the ladder produces, and it must clear that floor. The cross-rung pair
//! differs by one leaf. Neither plan is the graded assembly population.
//! That population is blocked on a ruled chain age.
//!
//! ## What a run does not establish
//!
//! The rig takes its reference root from [`CurveTreeClient::root_and_depth_at`],
//! so the integrity gate is green by construction. Root agreement is graded
//! in `shekyl-curve-tree`'s `client::ct6_oracle`. This rig asserts its own
//! subject: the client drained the population it was fed, and reports the
//! depth that count implies.

use std::time::Duration;

use shekyl_curve_tree::recon::{maturity_height, PQC_LEAF_ENTRY_BYTES, PQC_LEAF_POINT_BYTES};
use shekyl_curve_tree::{
    AssembleInput, BlockHash, BlockHeight, BlockLeaves, CommitmentBytes, CurveTreeClient, Gindex,
    OneTimePubkey, RawOutput, ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::{key_image_generator, layer_count_for_leaves, SELENE_CHUNK_WIDTH};
use shekyl_fcmp::MAX_INPUTS;

use crate::corpus::{min_leaves_for_depth, worst_case_window_leaves};
use crate::timing::DEFAULT_TOLERANCE_PCT;

/// Tree depth the worst-case leaf **rate** is modelled at.
///
/// Re-exported from its owner rather than restated: this is the depth
/// [`worst_case_window_leaves`] prices a path's proof weight at, which fixes
/// how many leaf-producing transactions a block holds.
///
/// ## Three different depths, and they are not interchangeable
///
/// - The **rate model's** depth, this constant: 6, what a path's proof weight
///   is priced at.
/// - The **replay window's** depth: the window that rate produces holds
///   765 600 leaves, which is a depth-**5** tree. It is depth 5 at every model
///   depth from 3 to 7, because the leaf rate moves only 4.5 % across them
///   (765 600 … 800 400) while a rung needs 38×.
///   `the_windows_tree_depth_does_not_depend_on_the_rate_model` pins that.
/// - The **chain's** depth, which is what the curve tree actually is. At
///   760 320 leaves/day the chain crosses `min_leaves_for_depth(6)` =
///   17 778 529 after about 23 days, so [`GRADED_TREE_DEPTH`]'s stated band is
///   satisfied in weeks. Its judgment is sound; it simply is not a statement
///   about the window.
///
/// The window is not the chain, and for path assembly the chain is what
/// counts — see the module header. This module therefore never reads a depth
/// from any of the three: [`Population::depth`] comes from the population's
/// own leaf count, and the rig asserts the client agrees with it. A rung is a
/// property of `n`, and attributing a cost to the wrong rung is evidence for
/// the wrong half of the claim.
pub use crate::corpus::GRADED_TREE_DEPTH as LEAF_RATE_MODEL_DEPTH;

/// Owned outputs a canonical spend holds. The fixed term in "flat in chain
/// size **at a fixed owned-output count**".
pub const CANONICAL_OWNED_INPUTS: usize = 2;

/// A leaf population and the depth its tree reaches — one reading, never two.
///
/// The pair travels together for the same reason `ct6_oracle`'s `TierReading`
/// carries root and depth as one value: a depth taken from a different leaf
/// count agrees with nothing, and a cost attributed to the wrong rung is
/// evidence for the wrong half of the claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Population {
    /// Drained leaves in the tree.
    pub leaf_count: u64,
    /// Depth that leaf count implies, from the production arithmetic.
    pub depth: u8,
}

impl Population {
    /// The population at `leaf_count`, with its depth derived rather than
    /// stated.
    #[must_use]
    pub fn at(leaf_count: u64) -> Self {
        Self {
            leaf_count,
            depth: layer_count_for_leaves(leaf_count),
        }
    }
}

/// Which half of the flatness claim an arm supplies evidence for.
///
/// The roles are a family, not a list: [`Self::RungFloor`] pairs with
/// [`Self::RungTop`] across `n` at one depth, and with [`Self::RungBelow`]
/// across depth at one `n`. Each arm belongs to exactly one pair per axis, so
/// neither comparison borrows a point chosen for the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArmRole {
    /// The largest population one rung shallower: [`ArmRole::RungFloor`]'s
    /// leaf count minus one. Adjacent in `n`, one layer shallower.
    RungBelow,
    /// The fewest leaves that reach [`Self::RungTop`]'s depth.
    RungFloor,
    /// The rung's upper population, at [`CANONICAL_OWNED_INPUTS`].
    ///
    /// In [`plan_at_replay_window`] this is one day of chain. In
    /// [`plan_at_depth`] it is [`SAME_RUNG_SEPARATION`] above the floor.
    /// Either way it is the arm the floor is compared against across `n`.
    /// It is also the board-control subject: the run builds it last and times
    /// it twice, back to back, with no other rig resident.
    RungTop,
    /// [`ArmRole::RungTop`]'s population at [`MAX_INPUTS`], so the record shows
    /// the `k` term beside `n` rather than asserting it is small (`#842`'s
    /// `n + k`).
    InputCap,
}

impl ArmRole {
    /// Stable record key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RungBelow => "rung_below",
            Self::RungFloor => "rung_floor",
            Self::RungTop => "rung_top",
            Self::InputCap => "input_cap",
        }
    }
}

/// One population measured at one owned-output count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Arm {
    /// Which comparison this arm serves.
    pub role: ArmRole,
    /// Leaves and depth.
    pub population: Population,
    /// Owned outputs assembled per call — the term held fixed across `n`.
    pub owned_inputs: usize,
}

/// Least separation in `n` a same-rung pair needs to tell a slope from noise.
///
/// Below this the pair is powerless: today's cost is linear in `n`, so a
/// same-rung comparison can only see a slope that clears
/// [`SAME_RUNG_TOLERANCE_PCT`], and `1.5×` in `n` puts a linear term at `50 %`
/// — five times the bound. [`plan_at_replay_window`]'s separation is whatever
/// the ladder produces, and it is checked against this floor rather than set
/// by it. [`plan_at_depth`] builds its top at this multiple, rounded up.
///
/// This is the *display* form. Leaf counts are derived and compared through
/// [`separated_leaves`], the exact integer form, so no plan arithmetic goes
/// through a float; the const-assert below pins the two to one value.
pub const SAME_RUNG_SEPARATION: f64 = 1.5;

/// [`SAME_RUNG_SEPARATION`] as an exact ratio `(numerator, denominator)`.
const SAME_RUNG_SEPARATION_RATIO: (u32, u32) = (3, 2);

const _: () = assert!(
    SAME_RUNG_SEPARATION * (SAME_RUNG_SEPARATION_RATIO.1 as f64)
        == SAME_RUNG_SEPARATION_RATIO.0 as f64,
    "SAME_RUNG_SEPARATION and SAME_RUNG_SEPARATION_RATIO name one value"
);

/// The fewest leaves that sit [`SAME_RUNG_SEPARATION`] above `floor_leaves`:
/// `ceil(floor × 3 / 2)`, in integers.
///
/// Rounded **up**, not truncated: the separation is a floor, and truncating
/// `floor × 1.5` lands just under it (25 993 → 38 989, a ratio of 1.49998),
/// so a plan built on it would construct a pair that fails its own bound.
/// Integer arithmetic keeps this exact at any leaf count; a float round-trip
/// is exact only below `2^53`.
///
/// # Panics
///
/// If `floor_leaves × 3` overflows `u64` — no rung is that wide.
#[must_use]
pub fn separated_leaves(floor_leaves: u64) -> u64 {
    let (numerator, denominator) = SAME_RUNG_SEPARATION_RATIO;
    floor_leaves
        .checked_mul(u64::from(numerator))
        .expect("a rung floor times the separation ratio fits in u64")
        .div_ceil(u64::from(denominator))
}

/// Whether `depth`'s rung floor is a real leaf count rather than a wrapped one.
///
/// [`shekyl_fcmp::tree::outputs_per_node`] documents its own overflow as "a
/// const-eval or **debug** panic, not a silent wrap", on the stated grounds
/// that "`j` names a layer of the tree, whose depth is single digits". In a
/// **release** build — which is how this harness runs — the `usize` product
/// wraps with no panic, so a deep `--rung` yields a plausible-looking but
/// wrong population and the run measures nothing meaningful. That is worse
/// than a crash, because the record would look valid.
///
/// [`min_leaves_for_depth`] carries that domain: it recomputes the product
/// with `checked_mul` and answers `None` where it would not fit — the same
/// answer it already gives for a depth below the ladder. So this is a reading
/// of that one `Option`, not a second ceiling; no bound is restated here,
/// which is how a harness and a consensus-frozen domain drift apart.
#[must_use]
pub fn rung_floor_is_representable(depth: u8) -> bool {
    min_leaves_for_depth(depth).is_some()
}

/// The arms at one replay window's worth of leaves — **not** the graded
/// assembly population.
///
/// 725 blocks is about one day of chain at a 120 s target. Assembly's `n` is
/// not windowed (module header), so this plan measures a one-day-old chain and
/// nothing more. It is kept because it is the population every *neighbouring*
/// figure in this harness is expressed in, which makes it the right arm to
/// compare a spend-edge record against — and because naming it honestly is
/// what stops the window's figure being read as the graded one.
///
/// **The graded assembly population is blocked on a ruled chain age** (rule
/// 22's named blocker): the cost grows without bound in chain length, so
/// "worst case" is a policy choice about how old a chain the wallet must still
/// spend on, not something this module can derive. Until that is ruled, no
/// plan here is the graded plan, and `AssembleEdgeRecord::plan` says so.
///
/// Every population comes from a function that owns it:
/// [`worst_case_window_leaves`] for the window's top, and
/// [`min_leaves_for_depth`] for the rung floor — which is itself derived from
/// `outputs_per_node`, the capacity function the widths live in. Nothing here
/// restates a leaf count, so a width change moves the whole plan.
///
/// # Panics
///
/// If the window top's depth has no rung floor, or if the window does not
/// clear [`SAME_RUNG_SEPARATION`] above it — either means the ladder changed
/// shape under the plan, which must stop a run rather than silently leave it
/// with a comparison that cannot discriminate.
#[must_use]
pub fn plan_at_replay_window() -> Vec<Arm> {
    let top = Population::at(worst_case_window_leaves(LEAF_RATE_MODEL_DEPTH));
    let floor_leaves =
        min_leaves_for_depth(top.depth).expect("the replay-window top sits on a rung with a floor");
    assert!(
        top.leaf_count >= separated_leaves(floor_leaves),
        "the replay window ({} leaves) is less than {SAME_RUNG_SEPARATION}x its rung floor \
         ({floor_leaves}); the same-rung pair could not tell a slope from noise",
        top.leaf_count
    );
    arms_for(top, floor_leaves)
}

/// The same four roles on `depth`'s rung, for establishing the shape at a
/// population that fits in a coffee break.
///
/// The claim is about *shape*, and shape is a property of a rung, not of any
/// one rung in particular: a cost constant across one rung, and no dearer
/// than one layer at its boundary, is the same evidence wherever it is measured.
/// What does **not** travel is the absolute figure.
///
/// # Panics
///
/// If `depth` has no rung floor, or if its rung is too narrow to hold a
/// [`SAME_RUNG_SEPARATION`] pair.
#[must_use]
pub fn plan_at_depth(depth: u8) -> Vec<Arm> {
    let floor_leaves =
        min_leaves_for_depth(depth).unwrap_or_else(|| panic!("depth {depth} has no rung floor"));
    let top = Population::at(separated_leaves(floor_leaves));
    assert_eq!(
        top.depth, depth,
        "depth {depth}'s rung is narrower than {SAME_RUNG_SEPARATION}x, so a same-rung pair \
         does not fit inside it"
    );
    arms_for(top, floor_leaves)
}

/// Assemble the four roles around one rung.
fn arms_for(top: Population, floor_leaves: u64) -> Vec<Arm> {
    let floor = Population::at(floor_leaves);
    assert_eq!(
        floor.depth, top.depth,
        "the rung floor must share the rung top's depth; the ladder and \
         layer_count_for_leaves disagree"
    );
    let below = Population::at(
        floor_leaves
            .checked_sub(1)
            .expect("a rung floor above depth 2 has a predecessor"),
    );
    assert_eq!(
        below.depth + 1,
        top.depth,
        "one leaf below the rung floor must be exactly one layer shallower"
    );

    vec![
        Arm {
            role: ArmRole::RungBelow,
            population: below,
            owned_inputs: CANONICAL_OWNED_INPUTS,
        },
        Arm {
            role: ArmRole::RungFloor,
            population: floor,
            owned_inputs: CANONICAL_OWNED_INPUTS,
        },
        Arm {
            role: ArmRole::RungTop,
            population: top,
            owned_inputs: CANONICAL_OWNED_INPUTS,
        },
        Arm {
            role: ArmRole::InputCap,
            population: top,
            owned_inputs: MAX_INPUTS,
        },
    ]
}

/// Which plan a run measured.
///
/// Typed rather than a string, because the console header read the record's
/// prose with `starts_with("SHAPE")` and printed `GRADED` for everything else
/// — including the replay-window plan, which the record says in the same breath
/// is **not** the graded assembly population. A label a reader could copy as
/// the ruled figure must not be derived by sniffing the text that disclaims it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub enum PlanKind {
    /// [`plan_at_replay_window`]: 725 blocks, about one day of chain.
    ReplayWindow,
    /// [`plan_at_depth`]: a shallower rung, measured for shape only.
    Shape {
        /// The rung's depth.
        depth: u8,
    },
}

impl PlanKind {
    /// Short label for a console header.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ReplayWindow => "REPLAY WINDOW",
            Self::Shape { .. } => "SHAPE",
        }
    }

    /// What the plan's figures do and do not mean, for the record.
    #[must_use]
    pub fn note(self) -> &'static str {
        match self {
            Self::ReplayWindow => {
                "REPLAY WINDOW — 725 blocks, about one day of chain. NOT the graded assembly \
                 population: assembly's n is the whole chain, so a graded figure is a ruling \
                 about chain age rather than a measurement. These seconds are a one-day-old \
                 chain's."
            }
            Self::Shape { .. } => {
                "SHAPE — a rung chosen to run in minutes. Flatness across the rung and the \
                 one-layer step at its boundary travel; the absolute seconds do NOT."
            }
        }
    }
}

/// Bound on a same-rung spread, in percent.
///
/// Two arms are compared through medians that each converged to within
/// [`DEFAULT_TOLERANCE_PCT`] of their own steady state, so the pair can differ
/// by that much on each side before the workload has said anything. The bound
/// is therefore twice the convergence tolerance — derived from the number the
/// harness already judges a series by, not a fresh threshold with its own
/// provenance.
pub const SAME_RUNG_TOLERANCE_PCT: f64 = 2.0 * DEFAULT_TOLERANCE_PCT;

/// Capture's pass criterion, fixed before capture exists.
///
/// Pre-registered in the commit that builds the instrument, so "flattened" is
/// judged against a shape written down in advance rather than one first seen
/// after capture runs. Both bounds are percentages of the smaller arm.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
pub struct FlatnessCriterion {
    /// Largest same-rung spread that still reads as flat.
    pub same_rung_tolerance_pct: f64,
    /// Largest excess of the measured cross-rung ratio over
    /// [`expected_cross_rung_ratio`], in percent of that expectation, that
    /// still passes. A ratio below the expectation is inside the bound:
    /// the half is a ceiling, not a target.
    pub cross_rung_tolerance_pct: f64,
}

impl Default for FlatnessCriterion {
    fn default() -> Self {
        Self {
            same_rung_tolerance_pct: SAME_RUNG_TOLERANCE_PCT,
            cross_rung_tolerance_pct: SAME_RUNG_TOLERANCE_PCT,
        }
    }
}

/// Cost ratio a flat assembler pays for one more layer.
///
/// Post-capture, assembling a path walks the path's layers, so depth
/// `deep_depth` costs `deep_depth / shallow_depth` of depth `shallow_depth`.
/// Derived from the depths the populations actually reached, never stated.
///
/// ## A uniform-layer model, and where it stops being one
///
/// This treats every layer as costing the same, and they do not: a Selene
/// node hashes [`SELENE_CHUNK_WIDTH`] = 38 children, a Helios node
/// [`shekyl_fcmp::tree::HELIOS_CHUNK_WIDTH`] = 18, and the layers alternate. The added layer is
/// one or the other, so the true ratio is
/// `(walked + added) / walked` in *chunk work*, not in layer count.
///
/// The approximation is the right shape for "flat, or tracking `n`", where
/// the two hypotheses differ by orders of magnitude and a 2× error in one
/// layer's share changes nothing.
///
/// ## The grade uses this number as a ceiling
///
/// [`read_flatness`] fails the cross-rung half only when the measured ratio
/// exceeds this value by more than
/// [`FlatnessCriterion::cross_rung_tolerance_pct`]. A smaller ratio passes.
/// The pass means the deep arm was no dearer than one layer. It does not
/// mean the step matched. A `Flat` cross-rung half is therefore not evidence
/// that a capture walked the added layer.
///
/// Increment 6 must widen the bound explicitly or derive the expectation
/// from [`shekyl_fcmp::tree::chunk_width`] of the layer actually added before
/// it grades a passing capture. This paragraph is that blocker (rule 22).
///
/// # Panics
///
/// If `shallow_depth` is `0`: depth 0 is not a tree, and a zero divisor
/// would hand [`read_flatness`] an infinite expectation that grades nothing.
#[must_use]
pub fn expected_cross_rung_ratio(shallow_depth: u8, deep_depth: u8) -> f64 {
    assert!(
        shallow_depth > 0,
        "depth 0 is not a tree; the cross-rung ratio has no shallow arm"
    );
    f64::from(deep_depth) / f64::from(shallow_depth)
}

/// How a measured pair read against [`FlatnessCriterion`].
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
pub enum FlatnessGrade {
    /// Both halves inside their bounds.
    Flat,
    /// Two arms on one rung disagreed: cost still tracks `n`.
    SameRungSlope {
        /// Measured spread, in percent of the smaller arm.
        spread_pct: f64,
        /// Bound it exceeded.
        tolerance_pct: f64,
    },
    /// The rung boundary cost more than one layer's work.
    CrossRungOverstep {
        /// Measured ratio across the boundary.
        ratio: f64,
        /// Ratio one layer's work predicts.
        expected: f64,
        /// Bound the excess exceeded.
        tolerance_pct: f64,
    },
}

/// The criterion's reading, or why the run cannot support one.
///
/// A grade is only meaningful from a run whose numbers are the workload's.
/// [`LoadControl`](crate::report::LoadControl) already says a non-quiet run
/// "cannot claim its figure is a property of the work rather than of the
/// machine" — which is exactly the claim a grade makes — and the spend edge
/// withholds its verdict in that state. Emitting a `FlatnessGrade`
/// unconditionally would let a contaminated run report **`Flat`**, the one
/// reading capture is trying to earn.
///
/// # Why this is not [`Verdict`](crate::report::Verdict)
///
/// `Verdict` answers *did the measured figure meet its budget on the pinned
/// rig*; its `Ungraded` means "measured somewhere else". This answers *does
/// the cost track `n`*, and withholds for contamination rather than for
/// provenance. Two questions with different inputs, so two types; collapsing
/// them would overload `Ungraded` with a second meaning.
///
/// The raw series stay in the record either way — withholding the reading is
/// not withholding the data.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
pub enum FlatnessOutcome {
    /// The board stayed quiet and every contributing series converged.
    Graded(FlatnessGrade),
    /// No reading. The reason is part of the value (rule 82).
    Withheld(GradeWithheld),
}

/// Why a reading was withheld.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub enum GradeWithheld {
    /// The board moved across the run: the control re-timed identical work
    /// and disagreed with the first timing by more than the bound, so the
    /// numbers describe the machine.
    BoardNotQuiet,
    /// A contributing series never settled, so its median is not yet a cost.
    SeriesUnconverged,
}

/// The numbers [`read_flatness`] judged, and whether they may be read as a grade.
///
/// One value. The record stores this struct, so the published ratio is the
/// ratio the criterion used — including the zero-arm guard — rather than a
/// second division beside it.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
pub struct FlatnessReading {
    /// Absolute spread of the same-rung pair, in percent of the smaller arm.
    pub same_rung_spread_pct: f64,
    /// `deep / shallow` across the rung boundary. Infinite when the shallow
    /// arm is zero.
    pub cross_rung_ratio: f64,
    /// [`expected_cross_rung_ratio`] at the depths those costs were measured at.
    pub cross_rung_expected: f64,
    /// The judgment, or why it was withheld. The three numbers above are
    /// present either way: withholding the judgment is not withholding the data.
    pub outcome: FlatnessOutcome,
}

/// The spread and the ratio a judgment is taken over. Private so a caller
/// cannot grade one pair of numbers and publish another.
#[derive(Clone, Copy)]
struct PairNumbers {
    same_rung_spread_pct: f64,
    cross_rung_ratio: f64,
    cross_rung_expected: f64,
}

fn pair_numbers(
    same_rung: (Duration, Duration),
    cross_rung: (Duration, Duration),
    cross_rung_depths: (u8, u8),
) -> PairNumbers {
    PairNumbers {
        same_rung_spread_pct: spread_pct(same_rung.0, same_rung.1),
        cross_rung_ratio: ratio(cross_rung.0, cross_rung.1),
        cross_rung_expected: expected_cross_rung_ratio(cross_rung_depths.0, cross_rung_depths.1),
    }
}

/// Apply [`FlatnessCriterion`] to one run.
///
/// `same_rung` is `(smaller_n, larger_n)`, the two costs at one depth.
/// `cross_rung` is `(shallow_arm, deep_arm)`, the two costs one layer apart.
/// `cross_rung_depths` is `(shallow, deep)` for that pair.
///
/// The numbers are always filled. The outcome is withheld, board first, when
/// the run cannot support a grade: a moving board is the stronger
/// disqualification, and naming convergence for a run that was never quiet
/// would point at the wrong remedy. A withheld outcome carries no
/// [`FlatnessGrade`]. A contaminated run must not be able to say `Flat`.
#[must_use]
pub fn read_flatness(
    criterion: FlatnessCriterion,
    board_quiet: bool,
    every_series_converged: bool,
    same_rung: (Duration, Duration),
    cross_rung: (Duration, Duration),
    cross_rung_depths: (u8, u8),
) -> FlatnessReading {
    let numbers = pair_numbers(same_rung, cross_rung, cross_rung_depths);
    let outcome = if !board_quiet {
        FlatnessOutcome::Withheld(GradeWithheld::BoardNotQuiet)
    } else if !every_series_converged {
        FlatnessOutcome::Withheld(GradeWithheld::SeriesUnconverged)
    } else {
        FlatnessOutcome::Graded(judge(criterion, numbers))
    };
    FlatnessReading {
        same_rung_spread_pct: numbers.same_rung_spread_pct,
        cross_rung_ratio: numbers.cross_rung_ratio,
        cross_rung_expected: numbers.cross_rung_expected,
        outcome,
    }
}

/// Same-rung spread first, then the cross-rung ceiling.
///
/// The first failure is the grade, so a verdict names one pair. The
/// cross-rung half fails only when [`PairNumbers::cross_rung_ratio`] exceeds
/// [`PairNumbers::cross_rung_expected`] by more than the tolerance.
fn judge(criterion: FlatnessCriterion, numbers: PairNumbers) -> FlatnessGrade {
    if numbers.same_rung_spread_pct > criterion.same_rung_tolerance_pct {
        return FlatnessGrade::SameRungSlope {
            spread_pct: numbers.same_rung_spread_pct,
            tolerance_pct: criterion.same_rung_tolerance_pct,
        };
    }

    let overstep_pct = (numbers.cross_rung_ratio - numbers.cross_rung_expected)
        / numbers.cross_rung_expected
        * 100.0;
    if overstep_pct > criterion.cross_rung_tolerance_pct {
        return FlatnessGrade::CrossRungOverstep {
            ratio: numbers.cross_rung_ratio,
            expected: numbers.cross_rung_expected,
            tolerance_pct: criterion.cross_rung_tolerance_pct,
        };
    }

    FlatnessGrade::Flat
}

/// [`judge`] on a fresh [`pair_numbers`]. Tests use this to show each half
/// can fire. Production goes through [`read_flatness`], which judges the
/// numbers it returns.
#[cfg(test)]
fn grade(
    criterion: FlatnessCriterion,
    same_rung: (Duration, Duration),
    cross_rung: (Duration, Duration),
    cross_rung_depths: (u8, u8),
) -> FlatnessGrade {
    judge(
        criterion,
        pair_numbers(same_rung, cross_rung, cross_rung_depths),
    )
}

/// Absolute spread between two costs, as a percentage of the smaller.
#[must_use]
pub fn spread_pct(a: Duration, b: Duration) -> f64 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let lo = lo.as_secs_f64();
    if lo <= 0.0 {
        return f64::INFINITY;
    }
    (hi.as_secs_f64() - lo) / lo * 100.0
}

/// Signed percentage change from `from` to `to`.
///
/// Distinct from [`spread_pct`], which is absolute and therefore says
/// "70 % cost" for an arm that was 70 % *cheaper*. Direction is the whole
/// point for the `k` arm: a cheaper `MAX_INPUTS` arm is evidence that the `k`
/// term is lost in the noise of `n`, and reporting it as a cost inverts that
/// reading. The discarded first run was exactly this case.
#[must_use]
pub fn signed_change_pct(from: Duration, to: Duration) -> f64 {
    let from = from.as_secs_f64();
    if from <= 0.0 {
        return f64::INFINITY;
    }
    (to.as_secs_f64() - from) / from * 100.0
}

/// `deep / shallow`, as a ratio.
#[must_use]
fn ratio(shallow: Duration, deep: Duration) -> f64 {
    let shallow = shallow.as_secs_f64();
    if shallow <= 0.0 {
        return f64::INFINITY;
    }
    deep.as_secs_f64() / shallow
}

/// One `0x07` leaf entry: a commitment point, then an opaque record.
///
/// Only the leading point is the leaf's fourth-scalar source (`PL-D3`), so the
/// record is filled with the tag byte and carries nothing the leaf reads.
fn leaf_entry(cm: &[u8; 32]) -> [u8; PQC_LEAF_ENTRY_BYTES] {
    let mut entry = [0x07u8; PQC_LEAF_ENTRY_BYTES];
    entry[..PQC_LEAF_POINT_BYTES].copy_from_slice(cm);
    entry
}

/// A valid, torsion-free curve point derived from `seed`, through the crate's
/// own point primitive.
fn point_from_seed(seed: u64) -> [u8; 32] {
    let mut material = [0u8; 32];
    material[..8].copy_from_slice(&seed.to_le_bytes());
    key_image_generator(&material)
}

/// Public material for one output.
#[derive(Clone, Copy)]
struct LeafMaterial {
    output_key: OneTimePubkey,
    commitment: CommitmentBytes,
    cm: [u8; 32],
}

impl LeafMaterial {
    /// Distinct material, derived from `seed`.
    fn derived(seed: u64) -> Self {
        Self {
            output_key: OneTimePubkey::from_bytes(point_from_seed(seed)),
            commitment: CommitmentBytes::from_bytes(point_from_seed(seed ^ COMMITMENT_SEED_MASK)),
            cm: point_from_seed(seed ^ CM_SEED_MASK),
        }
    }

    fn raw(&self) -> RawOutput {
        RawOutput {
            output_key: self.output_key,
            commitment: Some(self.commitment),
            target: TargetKind::TaggedKey,
        }
    }
}

/// Domain separators keeping one seed's three points apart. Distinct bit
/// patterns rather than `seed + 1` / `seed + 2`, so adjacent outputs' points
/// cannot collide with each other's.
const COMMITMENT_SEED_MASK: u64 = 0x5555_5555_5555_5555;
/// Separator for the `0x07` commitment point. See [`COMMITMENT_SEED_MASK`].
const CM_SEED_MASK: u64 = 0xAAAA_AAAA_AAAA_AAAA;

/// Seed for the filler every non-owned output shares. See
/// [`AssembleRig::new`] for why one point is enough.
const FILLER_SEED: u64 = 1;

/// A live, store-backed client holding one population, and the inputs to
/// assemble against it.
pub struct AssembleRig {
    /// Kept so the database file outlives the rig.
    _dir: tempfile::TempDir,
    client: CurveTreeClient,
    reference: ReferenceBlock,
    inputs: Vec<AssembleInput>,
    arm: Arm,
}

impl AssembleRig {
    /// Build a client holding `arm.population` drained leaves, and the
    /// `arm.owned_inputs` inputs to assemble at the reference height.
    ///
    /// ## Why one filler point serves every non-owned output
    ///
    /// Hashing a curve point costs the same whatever the point is — the
    /// primitives are constant-time by construction — so a population built
    /// from one repeated filler measures exactly the work a population of
    /// distinct leaves measures. The outputs that must be distinct are the
    /// **owned** ones, because `assemble_paths` checks the `(output_key,
    /// commitment)` it resolved against the one the caller asked for, and a
    /// shared filler would make that check pass for any `gindex`. Those are
    /// derived per output, so [`shekyl_curve_tree::ClientError::IdentityMismatch`]
    /// can still fire.
    ///
    /// ## Owned outputs straddle leaf chunks
    ///
    /// They are spread by whole chunk strides, so no two share a layer-0
    /// chunk. Inputs inside one chunk would hide a reused leaf position, which
    /// is the hazard increment 3 introduced by hoisting the reconstruction out
    /// of the per-input loop.
    ///
    /// # Panics
    ///
    /// If the store cannot be created, if ingest fails, or if the client's
    /// drained count or depth disagrees with the population this rig fed — a
    /// rig that measured a population it did not build would report a cost for
    /// the wrong point on the curve (rule 47).
    #[must_use]
    pub fn new(arm: Arm, leaves_per_block: u64, store_dir: Option<&std::path::Path>) -> Self {
        assert!(leaves_per_block > 0, "a block must carry at least one leaf");
        assert!(
            arm.owned_inputs > 0 && arm.owned_inputs <= MAX_INPUTS,
            "owned inputs must be in 1..={MAX_INPUTS}; got {}",
            arm.owned_inputs
        );
        assert!(
            arm.population.leaf_count >= leaves_per_block,
            "population {} is smaller than one block's {leaves_per_block} leaves",
            arm.population.leaf_count
        );

        let dir = match store_dir {
            Some(parent) => tempfile::tempdir_in(parent).expect("scratch dir for the client"),
            None => tempfile::tempdir().expect("scratch dir for the client"),
        };
        let mut client = CurveTreeClient::open(dir.path().join("assemble.curvetree"))
            .expect("fresh client store");

        // Owned positions, spread by whole chunk strides across the
        // population so each lands in a distinct layer-0 chunk.
        let owned = owned_positions(arm.population.leaf_count, arm.owned_inputs);
        let owned_material: Vec<(u64, LeafMaterial)> = owned
            .iter()
            .map(|&pos| (pos, LeafMaterial::derived(OWNED_SEED_BASE + pos)))
            .collect();

        let filler = LeafMaterial::derived(FILLER_SEED);

        // Feed the population. Every output is a non-miner `TaggedKey`, so
        // every leaf matures on one schedule and the drained count at the
        // reference height is exactly what was fed.
        let mut next_gindex = 0_u64;
        let mut height_raw = 0_u64;
        while next_gindex < arm.population.leaf_count {
            let remaining = arm.population.leaf_count - next_gindex;
            let this_block = remaining.min(leaves_per_block);
            let span = usize::try_from(this_block).expect("block leaf count fits usize");

            let materials: Vec<LeafMaterial> = (0..span)
                .map(|i| {
                    let gindex = next_gindex + u64::try_from(i).expect("block index fits u64");
                    owned_material
                        .iter()
                        .find(|(pos, _)| *pos == gindex)
                        .map_or(filler, |(_, m)| *m)
                })
                .collect();
            let raws: Vec<RawOutput> = materials.iter().map(LeafMaterial::raw).collect();
            let blob: Vec<u8> = materials.iter().flat_map(|m| leaf_entry(&m.cm)).collect();

            let txs = [TxLeafInputs {
                is_miner: false,
                leaf_entry_blob: Some(&blob),
                outputs: &raws,
            }];
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight::from_raw(height_raw),
                    txs: &txs,
                })
                .expect("ingest of a conforming block");

            next_gindex += this_block;
            height_raw = height_raw.checked_add(1).expect("chain height fits u64");
        }

        // `height_raw` is now one past the last block that carried leaves.
        let last_carrying = height_raw
            .checked_sub(1)
            .expect("at least one block carried leaves");
        let reference_height = reference_height_for(BlockHeight::from_raw(last_carrying));

        // Empty blocks up to the reference height, so the client's tip covers
        // it and every fed leaf has matured.
        while height_raw <= reference_height.to_raw() {
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight::from_raw(height_raw),
                    txs: &[TxLeafInputs {
                        is_miner: false,
                        leaf_entry_blob: None,
                        outputs: &[],
                    }],
                })
                .expect("ingest of an empty block");
            height_raw = height_raw.checked_add(1).expect("chain height fits u64");
        }

        // Rule 47: this rig's subject is the population it fed. Assert the
        // client drained exactly that, and that the depth it reports is the
        // depth that count implies — the two readings the cost is attributed
        // to.
        let drained = client.drained_leaf_count(reference_height);
        assert_eq!(
            u64::try_from(drained).expect("drained count fits u64"),
            arm.population.leaf_count,
            "client drained {drained} leaves at {reference_height:?}; the rig fed {}",
            arm.population.leaf_count
        );
        let (root, depth) = client
            .root_and_depth_at(reference_height)
            .expect("root and depth at a height this rig just ingested");
        assert_eq!(
            depth, arm.population.depth,
            "client reports depth {depth} for {} leaves; layer_count_for_leaves says {}",
            arm.population.leaf_count, arm.population.depth
        );

        let inputs = owned_material
            .iter()
            .map(|(pos, m)| AssembleInput {
                gindex: Gindex::from_raw(*pos),
                output_key: m.output_key,
                commitment: m.commitment,
            })
            .collect();

        Self {
            _dir: dir,
            client,
            reference: ReferenceBlock {
                height: reference_height,
                curve_tree_root: root,
                block_hash: BlockHash::from_bytes([7u8; 32]),
            },
            inputs,
            arm,
        }
    }

    /// Assemble every input's path once — the call the wallet pays per spend.
    ///
    /// Timed whole, gate included. The integrity gate is store-backed and adds
    /// no term in `n`, but carving it out would make the rig report a cost the
    /// wallet never pays.
    ///
    /// # Panics
    ///
    /// On any assembly error. A rig that swallowed one would report the cost
    /// of not doing the work.
    pub fn assemble_once(&self) -> usize {
        let paths = self
            .client
            .assemble_paths(&self.inputs, &self.reference)
            .expect("assembly against a reference this rig built");
        paths.len()
    }

    /// The arm this rig measures.
    #[must_use]
    pub fn arm(&self) -> Arm {
        self.arm
    }

    /// Inputs assembled per call — the `k` in `n + k`.
    #[must_use]
    pub fn owned_inputs(&self) -> usize {
        self.inputs.len()
    }
}

/// Seeds for owned outputs, kept clear of [`FILLER_SEED`].
const OWNED_SEED_BASE: u64 = 1 << 32;

/// Leaf positions for `count` owned outputs, spread by whole layer-0 chunk
/// strides so no two share a chunk.
fn owned_positions(leaf_count: u64, count: usize) -> Vec<u64> {
    let chunks = leaf_count.div_ceil(SELENE_CHUNK_WIDTH as u64).max(1);
    let wanted = u64::try_from(count).expect("owned count fits u64");
    assert!(
        chunks >= wanted,
        "population of {leaf_count} leaves holds {chunks} chunks; {count} owned outputs \
         cannot each take their own"
    );
    let stride = chunks / wanted;
    (0..wanted)
        .map(|i| {
            let chunk = i * stride;
            (chunk * SELENE_CHUNK_WIDTH as u64).min(leaf_count - 1)
        })
        .collect()
}

/// Reference height at which every leaf created through `last_carrying` has
/// drained.
///
/// Maturity comes from [`maturity_height`] — the production per-target
/// arithmetic — rather than restating the spendable age, and the root at `h`
/// drains through `h - 1`, so the reference is one past the last maturity.
fn reference_height_for(last_carrying: BlockHeight) -> BlockHeight {
    let maturity = maturity_height(last_carrying, false, TargetKind::TaggedKey)
        .expect("a tagged-key output has a maturity");
    BlockHeight::from_raw(
        maturity
            .to_raw()
            .checked_add(1)
            .expect("reference height fits u64"),
    )
}

#[cfg(test)]
#[path = "assembleedge_tests.rs"]
mod tests;
