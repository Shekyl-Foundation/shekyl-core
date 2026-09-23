// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verify edge: what `root_at_count` costs on a store whose complete
//! segments are **not yet frozen**.
//!
//! # Why a third measurement exists
//!
//! `WALLET_SIDE_STORE.md` §6.3.4's two timed rows grade the two *human-facing*
//! edges — the wait at spend time (row 2) and the wait at wallet open (row 3).
//! Neither touches the cost `CT-6`'s F3(a) priced, because that one is paid
//! **per block, during refresh, with nobody waiting on it**:
//! [`CurveTreeClient::root_at`]'s own doc calls itself *"the §3.3 verify hot
//! path"*, and `merge.rs:661` calls `verify_root` inside the per-block ingest
//! loop as the CT-5b lying-daemon defence.
//!
//! F3(a): freeze requires 730-block burial, so the reference window lies
//! entirely inside the unfrozen zone, and every `root_at_count` call
//! recomputes `R_k` over each complete-but-unfrozen segment — about 29 of them
//! at the worst-case leaf rate. **This module measures that, and nothing
//! grades it**, which is the point: a design (`CT-6` increment 4's snapshot
//! tier) whose cost axis has no baseline cannot be re-graded against one
//! later.
//!
//! # This measurement carries no threshold, and that is deliberate
//!
//! `CT-6 Q4` is **PENDING AS DERIVATION** — its budget is pre-registered but
//! its field is owed a re-point, and in any case Q4 grades the *amortized*
//! form's advance. This is the **naive** cost the amortized form would
//! replace. So the record reports [`VerifyEdgeRecord::grading`] as prose and
//! emits **no `Verdict`**: reusing [`crate::report::Verdict::Ungraded`] — whose
//! meaning is *"measured off the pinned rig"* — for *"no ruled threshold
//! exists"* would be one value standing in for two meanings, which is the
//! defect `SCHEMA_VERSION` 2 was bumped to correct.
//!
//! The cadence ratio is reported **informationally**: per-call seconds against
//! the block target, so a reader sees the duty cycle without a budget being
//! implied.
//!
//! # How the record knows which branch it timed
//!
//! `root_at_count` has two paths — the mixed composition it is written for,
//! and a `full_build_root` fallback over *every* leaf when the tail is too
//! short to promote to layer `j`. Timing the fallback and reporting it as the
//! recompute cost would be the narrower-question instrument, so the run
//! discriminates them **behaviourally** rather than by restating the store's
//! internal decomposition: the fallback ignores frozen sub-roots entirely, so
//! **if freezing the population collapses the time, the mixed path was the one
//! that ran**. That same contrast is the red-bite — a measurement that does
//! not move when the recompute is removed was never measuring the recompute.
//!
//! [`CurveTreeClient::root_at`]: shekyl_curve_tree::CurveTreeClient::root_at

use shekyl_curve_tree::{
    BlockHeight, CommitmentBytes, Gindex, LeafEntry, LeafStore, OneTimePubkey, OutputIdentity,
    TargetKind,
};

use crate::corpus::LeafRate;
use crate::timing::Series;

/// Leaves written per `append_drained` call while building the population.
///
/// One block's worth would make the write pattern realistic and the build
/// unusably slow at 730 blocks; one batch would make it fast and unlike
/// anything production does. This is a build-time constant with no bearing on
/// the measured quantity — `root_at_count` reads a finished store — so it is
/// chosen for build throughput and named rather than inlined.
const APPEND_BATCH: usize = 4_096;

/// A leaf whose bytes are deterministic in its position.
///
/// The leaf's *content* is irrelevant to this measurement — `recompute_segment_r_k`
/// costs the same whatever the scalars are — but it must be **valid**, or the
/// recompute errors instead of costing anything. [`crate::fixture::build_corpus`]
/// already owns that construction, so this consumes it rather than minting a
/// second leaf shape.
fn entry(pos: u64, leaf: [u8; 128], height: u64) -> LeafEntry {
    LeafEntry {
        gindex: Gindex::from_raw(pos),
        maturity: BlockHeight::from_raw(height),
        creation_height: BlockHeight::from_raw(height),
        leaf,
        // The identity is not read by `root_at_count` — the recompute consumes
        // leaf scalars — so it is filled with a well-formed constant rather
        // than varied per position. Varying it would cost build time and
        // change nothing measured.
        identity: OutputIdentity {
            output_key: OneTimePubkey::from_bytes([1u8; 32]),
            commitment: Some(CommitmentBytes::from_bytes([2u8; 32])),
            cm: [3u8; 32],
            target: TargetKind::TaggedKey,
        },
    }
}

/// What the population was built to be, recorded so a reader can see the scale
/// the per-call cost belongs to.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Population {
    /// Blocks of leaves written — `W`, the burial window.
    pub blocks: u64,
    /// The density this population was built at, with every term behind it.
    pub leaf_rate: LeafRate,
    /// Leaves actually written.
    pub leaves: u64,
    /// Complete segments in the population — the recompute count per call.
    pub complete_segments: u64,
    /// Leaves in the incomplete tail.
    pub tail_leaves: u64,
    /// Segment size `E`, from its one owner.
    pub leaves_per_segment: u64,
}

/// Build a store holding `blocks` blocks of leaves at `rate`, **unfrozen**.
///
/// Freezing is caller-driven (`LeafStore::maybe_freeze_segments`) and nothing
/// in the append path calls it, so "unfrozen" needs no arranging — but it is
/// *asserted* rather than assumed, because a population that froze by accident
/// makes every number here cheap and meaningless (rule 47).
///
/// # Errors
///
/// Propagates any store error from the append path.
pub fn build_population(
    store: &LeafStore,
    blocks: u64,
    rate: &LeafRate,
    leaf_bytes: &dyn Fn(u64) -> [u8; 128],
) -> Result<Population, shekyl_curve_tree::StoreError> {
    let leaves = blocks * rate.leaves_per_block;
    let mut batch: Vec<LeafEntry> = Vec::with_capacity(APPEND_BATCH);
    let mut pos = 0u64;
    while pos < leaves {
        batch.clear();
        let end = (pos + APPEND_BATCH as u64).min(leaves);
        for p in pos..end {
            // Height rises with position so the drain heights a freeze would
            // read are monotonic, as they are in production.
            batch.push(entry(p, leaf_bytes(p), p / rate.leaves_per_block));
        }
        // `append_block_deltas` is the **production** ingest path;
        // `append_drained` is a `#[cfg(test)]` wrapper and not reachable here,
        // which is the right constraint: a baseline taken through a test-only
        // door would not describe what refresh actually does.
        //
        // The tip trails the written height, so no segment is ever
        // burial-eligible during the build even if something consulted it.
        store.append_block_deltas(
            &batch,
            &[],
            &[],
            BlockHeight::from_raw(end / rate.leaves_per_block),
        )?;
        pos = end;
    }
    let e = shekyl_curve_tree::leaves_per_segment() as u64;
    Ok(Population {
        blocks,
        leaf_rate: *rate,
        leaves,
        complete_segments: leaves / e,
        tail_leaves: leaves % e,
        leaves_per_segment: e,
    })
}

/// Count frozen segments by asking for each one, so the assertion reads the
/// same table the hot path reads.
///
/// # Errors
///
/// Propagates any store error.
pub fn frozen_count(
    store: &LeafStore,
    complete: u64,
) -> Result<u64, shekyl_curve_tree::StoreError> {
    let mut n = 0;
    for k in 0..complete {
        let id = shekyl_curve_tree::SegmentId(u32::try_from(k).expect("segment key fits u32"));
        if store.frozen_segment(id)?.is_some() {
            n += 1;
        }
    }
    Ok(n)
}

/// One timed `root_at_count` phase.
///
/// Returns the series and the root, so the caller can assert the two phases
/// agree: freezing must change **how** the root is reached, never **what** it
/// is. A control that moved the answer would not be a control.
pub fn time_root_at(
    store: &LeafStore,
    leaf_count: u64,
    warmup: usize,
    tolerance_pct: f64,
    max_wall_s: f64,
) -> (Series, [u8; 32]) {
    let mut last = [0u8; 32];
    let series = crate::timing::sustained_within(warmup, tolerance_pct, max_wall_s, || {
        last = store
            .root_at_count(leaf_count)
            .expect("root_at_count on a population this run just built");
    });
    (series, last)
}

#[cfg(test)]
#[path = "verifyedge_tests.rs"]
mod tests;
