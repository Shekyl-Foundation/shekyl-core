// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 5 — the path-assembly cost instrument.
//!
//! This module times [`CurveTreeClient::assemble_paths`] against a real,
//! store-backed client at several leaf populations with the owned-output count
//! held fixed. It is the instrument capture is graded with, written **before**
//! capture exists, so the criterion cannot be fitted to the curve it is meant
//! to judge.
//!
//! ## What it measures, and why nothing did before
//!
//! The spend-edge rig ([`crate::fixture`]) proves against *synthesized* paths:
//! it hands [`crate::fixture::prove_only`] a [`crate::fixture::Path`] it built
//! itself, so `assemble_paths` is never called and its cost has never been
//! measured. That is the gap this module closes. Path assembly today rebuilds
//! every layer from every drained leaf:
//!
//! ```text
//! let stream = assemble_leaf_stream(&self.entries, cutoff);
//! let layers = build_layers(&stream);
//! ```
//!
//! — `n` work for `k <= MAX_INPUTS` paths. Increment 3 hoisted that out of the
//! per-input loop, taking `k · n` to `n + k`; the `n` remains.
//!
//! ## `n` is the chain, not a window
//!
//! `CurveTreeClient::entries` is append-only — `extend` on ingest, replaced
//! wholesale only by a rollback's rebuild, and never `retain`ed, `drain`ed or
//! `truncate`d. `rebuild_from_store` reloads the **whole** drained set, and a
//! resume from a store whose frozen segments were pruned is refused outright
//! (`ClientError::ResumeFromPrunedStore`, F5) rather than resumed from a
//! partial one. So every drained leaf since genesis is in memory, and
//! `assemble_paths` rebuilds every layer over all of them for every spend.
//!
//! This matters because every *neighbouring* figure in this harness is
//! windowed, and `assemble.rs`'s own docstring reaches for one of them —
//! "765 600 at the graded worst case" is `worst_case_window_leaves`, the
//! 725-block replay window, which is about **one day** of chain at a 120 s
//! target. Assembly is not bounded by that window. At 760 320 leaves/day and
//! the ~102 µs/leaf this instrument measures:
//!
//! | assembly population | `n` | cost per spend |
//! | --- | --- | --- |
//! | replay window, ~1 day of chain | 765 600 | ~78 s |
//! | depth-6 floor, ~23 days | 17 778 529 | ~30 min |
//! | one year of chain | 277 516 800 | ~7.9 h |
//!
//! An O(chain) spend cost fails the mission's third commitment — the system
//! must outlast the team — whatever today's budget says, which is the whole
//! argument for capture. It also means "worst case" cannot be derived here:
//! it is a ruling about how old a chain the wallet must still spend on. See
//! [`plan_at_replay_window`].
//!
//! ## The claim, stated so it can fail
//!
//! Capture's claim is that assembly becomes **flat in chain size at a fixed
//! owned-output count**. Flat does not mean constant: a path of depth `d + 1`
//! does one more layer's chunk work than a path of depth `d`. So the claim has
//! two halves, and [`FlatnessCriterion`] pre-registers both:
//!
//! - **Within one depth rung**, cost is constant within noise however much `n`
//!   grows. This is the half that fails today.
//! - **Across a rung boundary**, cost steps by one layer's work and no more.
//!
//! [`plan`] chooses populations so both halves are observable: two arms share a
//! rung at a `1.6×` separation in `n`, and two more straddle a rung boundary at
//! a separation of **one leaf**, which isolates the layer step from the
//! population term entirely.
//!
//! ## What this instrument does not establish
//!
//! `assemble_paths` gates on `root_at(reference.height) == reference.curve_tree_root`
//! before doing any work. This rig takes the reference root from the client's own
//! [`CurveTreeClient::root_and_depth_at`], so **the gate's verdict is green by
//! construction** — the rig measures what the gate costs, never whether it is
//! right. That the store tier reproduces an independently built root is graded
//! in-crate by the CT-6 height-keyed C1 oracle (`shekyl-curve-tree`'s
//! `client::ct6_oracle`, increments 2 and 4), against a replay oracle this crate
//! cannot reach: `CurveTreeClient::entries` is `pub(crate)`, `store::ops` is
//! private, and the oracle itself is `#[cfg(test)]`. Widening any of those to
//! re-derive the check here would publish a second root mechanism a production
//! caller could gate against, which `assemble.rs` rules out by design ("no
//! replay-oracle fallback"). The rig instead asserts what it *can* establish
//! independently, which is its own subject (rule 47): that the population it
//! fed is the population the client drained, and that the depth the client
//! reports is the depth that population's leaf count implies.

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
    /// The fewest leaves that reach the graded top's depth.
    RungFloor,
    /// The rung's upper population, at [`CANONICAL_OWNED_INPUTS`]. In [`plan`]
    /// this is the graded worst case; in [`plan_at_depth`] it is
    /// [`SAME_RUNG_SEPARATION`] above the floor. Either way it is the arm the
    /// floor is compared against across `n`.
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
/// — five times the bound. The graded rung's natural separation is checked
/// against this rather than set by it.
pub const SAME_RUNG_SEPARATION: f64 = 1.5;

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
/// [`worst_case_window_leaves`] for the graded top, and
/// [`min_leaves_for_depth`] for the rung floor — which is itself derived from
/// `outputs_per_node`, the capacity function the widths live in. Nothing here
/// restates a leaf count, so a width change moves the whole plan.
///
/// # Panics
///
/// If the graded top's depth has no rung floor, or if the window does not
/// clear [`SAME_RUNG_SEPARATION`] above it — either means the ladder changed
/// shape under the plan, which must stop a run rather than silently leave it
/// with a comparison that cannot discriminate.
#[must_use]
pub fn plan_at_replay_window() -> Vec<Arm> {
    let top = Population::at(worst_case_window_leaves(LEAF_RATE_MODEL_DEPTH));
    let floor_leaves =
        min_leaves_for_depth(top.depth).expect("the graded worst case sits on a rung with a floor");
    assert!(
        top.leaf_count as f64 >= floor_leaves as f64 * SAME_RUNG_SEPARATION,
        "the replay window ({} leaves) is less than {SAME_RUNG_SEPARATION}x its rung floor          ({floor_leaves}); the same-rung pair could not tell a slope from noise",
        top.leaf_count
    );
    arms_for(top, floor_leaves)
}

/// The same four roles on `depth`'s rung, for establishing the shape at a
/// population that fits in a coffee break.
///
/// The claim is about *shape*, and shape is a property of a rung, not of the
/// graded rung in particular: a cost constant across one rung and stepping by
/// one layer at its boundary is the same evidence wherever it is measured.
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
    // Rounded UP, not truncated: the separation is a floor, and truncating
    // `floor x 1.5` lands just under it (25 993 -> 38 989, a ratio of
    // 1.49998), so the plan would construct a pair that fails its own bound.
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    let top_leaves = (floor_leaves as f64 * SAME_RUNG_SEPARATION).ceil() as u64;
    let top = Population::at(top_leaves);
    assert_eq!(
        top.depth, depth,
        "depth {depth}'s rung is narrower than {SAME_RUNG_SEPARATION}x, so a same-rung pair          does not fit inside it"
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
    /// Largest cross-rung overstep beyond one layer's work that still passes.
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
#[must_use]
pub fn expected_cross_rung_ratio(shallow_depth: u8, deep_depth: u8) -> f64 {
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

/// Grade a measured plan: the same-rung pair, then the cross-rung pair.
///
/// `same_rung` is `(shallower_n_cost, larger_n_cost)` at one depth;
/// `cross_rung` is `(shallow_depth_cost, deep_depth_cost)` at adjacent `n`,
/// with the depths those costs were measured at.
///
/// Returns the first failure, so a verdict names one pair.
#[must_use]
pub fn grade(
    criterion: FlatnessCriterion,
    same_rung: (Duration, Duration),
    cross_rung: (Duration, Duration),
    cross_rung_depths: (u8, u8),
) -> FlatnessGrade {
    let spread_pct = spread_pct(same_rung.0, same_rung.1);
    if spread_pct > criterion.same_rung_tolerance_pct {
        return FlatnessGrade::SameRungSlope {
            spread_pct,
            tolerance_pct: criterion.same_rung_tolerance_pct,
        };
    }

    let expected = expected_cross_rung_ratio(cross_rung_depths.0, cross_rung_depths.1);
    let ratio = ratio(cross_rung.0, cross_rung.1);
    let overstep_pct = (ratio - expected) / expected * 100.0;
    if overstep_pct > criterion.cross_rung_tolerance_pct {
        return FlatnessGrade::CrossRungOverstep {
            ratio,
            expected,
            tolerance_pct: criterion.cross_rung_tolerance_pct,
        };
    }

    FlatnessGrade::Flat
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
