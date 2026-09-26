// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 2 — the height-keyed C1 oracle, and the Q2 examiner
//! increment 4 grades.
//!
//! The oracle cutoff is `height - 1`, written at the call. The leaf stream
//! and the root are [`assemble_leaf_stream`] and [`root_from_scalars`], the
//! pair the store's count-keyed oracle is already pinned to. The height
//! axis adds the mapping onto that leaf count.
//!
//! [`examine_tier_readings`] is Q2: across the examined heights the two
//! tiers are total, and identical where both answer. A [`TierReading`]
//! carries the root and the depth together, because C3 pins both to one
//! leaf count. [`TierCoverage::OutsideSpan`] is the only way to say a tier
//! does not cover a height — a tier that failed to answer has no variant
//! here, so the caller handles that error before building a
//! [`HeightAnswers`]. Increment 4 builds those answers from the segment
//! tier and the snapshot tier; this function does not change.

use super::tests::{coinbase_raw, ingest_outputs_at};
use super::{BlockLeaves, CurveTreeClient, TxLeafInputs};
use crate::recon::{assemble_leaf_stream, drained_sorted, root_from_scalars};
use crate::types::{AssembleInput, BlockHeight, CurveTreeRoot, LeafEntry, ReferenceBlock};
use crate::ClientError;
use shekyl_consensus::COINBASE_LOCK_WINDOW;
use shekyl_fcmp::tree::{
    layer_count_for_leaves, HELIOS_CHUNK_WIDTH, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};
use shekyl_types::BlockCount;

/// Output counts by creation height, cycling. The zeros are the off-by-one
/// that moves no leaves.
const OUTPUTS_PER_BLOCK: [usize; 12] = [1, 3, 0, 2, 5, 0, 1, 4, 2, 0, 3, 1];

/// Schedule cycles ingested past the coinbase lock, so the drained window
/// contains every slot of [`OUTPUTS_PER_BLOCK`], including a zero.
const SCHEDULE_CYCLES_PAST_LOCK: u64 = 2;

/// Root and depth one tier reports at a height it covers.
///
/// The two fields are one reading. Agreement that compared the root alone
/// would accept a depth taken from a different leaf count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct TierReading {
    root: CurveTreeRoot,
    depth: u8,
}

/// Whether a tier covers one height.
///
/// `OutsideSpan` is not a failure. A store error, a poisoned client, or a
/// height past the ingested tip never becomes this value — those stay
/// `Result`s at the caller, which has no `OutsideSpan` arm to hide them in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TierCoverage {
    /// The tier covers the height and reported this reading.
    Covers(TierReading),
    /// The tier's span does not include the height.
    OutsideSpan,
}

/// One examined height, as the segment tier and the snapshot tier answered it.
#[derive(Clone, Copy, Debug)]
struct HeightAnswers {
    height: BlockHeight,
    segment: TierCoverage,
    snapshot: TierCoverage,
}

/// The two ways Q2's invariant fails. They stay distinct because the fixes
/// are different: a hole in the union, or two answers that disagree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TierFault {
    /// Neither tier covers `height`.
    Uncovered { height: BlockHeight },
    /// Both tiers cover `height` and their readings differ.
    Disagree { height: BlockHeight },
}

/// Inclusive run of heights.
#[derive(Clone, Copy, Debug)]
struct HeightSpan {
    first: BlockHeight,
    last: BlockHeight,
}

impl HeightSpan {
    fn inclusive(first: BlockHeight, last: BlockHeight) -> Self {
        assert!(first <= last, "height span {first}..={last} is inverted");
        Self { first, last }
    }

    fn covers(self, height: BlockHeight) -> bool {
        self.first <= height && height <= self.last
    }

    fn heights(self) -> impl Iterator<Item = BlockHeight> {
        let exclusive_end = self
            .last
            .checked_add(BlockCount::ONE)
            .expect("height span has a successor");
        self.first.ordinals_until(exclusive_end)
    }
}

/// A tier that answers [`Self::reading`] on [`Self::span`], with at most
/// one height replaced. Increment 4 stops using this and passes the real
/// tiers' readings to [`examine_tier_readings`]; the examiner stays.
#[derive(Clone, Copy, Debug)]
struct InjectedTier {
    span: HeightSpan,
    reading: TierReading,
    replaced_at: Option<(BlockHeight, TierReading)>,
}

impl InjectedTier {
    fn uniform(span: HeightSpan, reading: TierReading) -> Self {
        Self {
            span,
            reading,
            replaced_at: None,
        }
    }

    fn coverage(self, height: BlockHeight) -> TierCoverage {
        if !self.span.covers(height) {
            return TierCoverage::OutsideSpan;
        }
        match self.replaced_at {
            Some((at, reading)) if at == height => TierCoverage::Covers(reading),
            _ => TierCoverage::Covers(self.reading),
        }
    }
}

/// Q2. Returns the first fault, so a failing test names one height.
///
/// Overlap — both [`TierCoverage::Covers`] and equal — is agreement.
/// One tier covering a height the other does not is agreement too: the
/// union is what has to be total.
fn examine_tier_readings(rows: impl IntoIterator<Item = HeightAnswers>) -> Result<(), TierFault> {
    for row in rows {
        match (row.segment, row.snapshot) {
            (TierCoverage::OutsideSpan, TierCoverage::OutsideSpan) => {
                return Err(TierFault::Uncovered { height: row.height });
            }
            (TierCoverage::Covers(segment), TierCoverage::Covers(snapshot)) => {
                if segment != snapshot {
                    return Err(TierFault::Disagree { height: row.height });
                }
            }
            (TierCoverage::Covers(_), TierCoverage::OutsideSpan)
            | (TierCoverage::OutsideSpan, TierCoverage::Covers(_)) => {}
        }
    }
    Ok(())
}

/// How far the examined window extends past the two spans.
#[derive(Clone, Copy, Debug)]
enum ExaminedWindow {
    /// `frozen.first` through `snapshot.last` — the union, when the spans overlap.
    Union,
    /// The union plus the one height after the snapshot span.
    OneHolePastUnion,
}

struct TierLayout {
    frozen: HeightSpan,
    snapshot: HeightSpan,
    examined: HeightSpan,
}

struct RegionCensus {
    frozen_only: usize,
    snapshot_only: usize,
    both: usize,
    neither: usize,
}

impl TierLayout {
    fn census(&self) -> RegionCensus {
        let mut census = RegionCensus {
            frozen_only: 0,
            snapshot_only: 0,
            both: 0,
            neither: 0,
        };
        for height in self.examined.heights() {
            match (self.frozen.covers(height), self.snapshot.covers(height)) {
                (true, false) => census.frozen_only += 1,
                (false, true) => census.snapshot_only += 1,
                (true, true) => census.both += 1,
                (false, false) => census.neither += 1,
            }
        }
        census
    }

    fn answers(&self, segment: InjectedTier, snapshot: InjectedTier) -> Vec<HeightAnswers> {
        self.examined
            .heights()
            .map(|height| HeightAnswers {
                height,
                segment: segment.coverage(height),
                snapshot: snapshot.coverage(height),
            })
            .collect()
    }
}

/// Minimum spans that have a frozen-only height, an overlap, and a
/// snapshot-only height. Built from [`BlockHeight::ZERO`] and
/// [`BlockCount::ONE`] so the shape is that minimum and nothing else.
fn overlapping_layout(window: ExaminedWindow) -> TierLayout {
    let one = BlockCount::ONE;
    let frozen = HeightSpan::inclusive(BlockHeight::ZERO, BlockHeight::ZERO + one + one);
    let snapshot_first = BlockHeight::ZERO + one;
    let snapshot = HeightSpan::inclusive(snapshot_first, snapshot_first + one + one);
    let last = match window {
        ExaminedWindow::Union => snapshot.last,
        ExaminedWindow::OneHolePastUnion => snapshot.last + one,
    };
    let layout = TierLayout {
        frozen,
        snapshot,
        examined: HeightSpan::inclusive(frozen.first, last),
    };
    let census = layout.census();
    assert!(census.frozen_only > 0, "fixture has no frozen-only height");
    assert!(
        census.snapshot_only > 0,
        "fixture has no snapshot-only height"
    );
    assert!(census.both > 0, "fixture overlap is empty");
    match window {
        ExaminedWindow::Union => {
            assert_eq!(census.neither, 0, "union window has a hole");
        }
        ExaminedWindow::OneHolePastUnion => {
            assert_eq!(
                census.neither, 1,
                "hole window should uncover exactly one height"
            );
        }
    }
    layout
}

fn first_overlap(layout: &TierLayout) -> BlockHeight {
    layout
        .examined
        .heights()
        .find(|height| layout.frozen.covers(*height) && layout.snapshot.covers(*height))
        .expect("layout overlap is empty")
}

/// Leaf count where the tree gains a layer: `SELENE_CHUNK_WIDTH` leaves
/// per leaf-layer node, `HELIOS_CHUNK_WIDTH` of those nodes.
fn layer_step_leaf_count() -> u64 {
    let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("Selene chunk width fits u64");
    let helios = u64::try_from(HELIOS_CHUNK_WIDTH).expect("Helios chunk width fits u64");
    selene
        .checked_mul(helios)
        .expect("layer-step leaf count fits u64")
}

/// Depth on each side of [`layer_step_leaf_count`]. The pair differs, which
/// is what makes a depth taken from `n + 1` visible.
fn stepped_depths() -> (u8, u8) {
    let step = layer_step_leaf_count();
    let at_step = layer_count_for_leaves(step);
    let past_step = layer_count_for_leaves(step + 1);
    assert_ne!(
        at_step, past_step,
        "layer_count_for_leaves is flat at n={step}"
    );
    (at_step, past_step)
}

fn root_distinct_from_empty() -> CurveTreeRoot {
    let mut bytes = CurveTreeRoot::EMPTY.to_bytes();
    bytes[0] ^= 0x01;
    CurveTreeRoot::from_bytes(bytes)
}

fn agreed_reading() -> TierReading {
    TierReading {
        root: CurveTreeRoot::EMPTY,
        depth: stepped_depths().0,
    }
}

/// Root and leaf count of the leaves drained through `cutoff`.
///
/// `cutoff` is the caller's. This does not read [`CurveTreeClient::drained_through`].
/// The consensus anchor the assembler gates against, taken from the client so
/// the gate passes for a correct reference and the test is about assembly.
fn reference_at(client: &CurveTreeClient, height: BlockHeight) -> ReferenceBlock {
    ReferenceBlock {
        height,
        curve_tree_root: client.root_at(height).expect("fixture root reads"),
        block_hash: crate::types::BlockHash::from_bytes([7u8; 32]),
    }
}

fn oracle_at(entries: &[LeafEntry], cutoff: BlockHeight) -> (CurveTreeRoot, u64) {
    let scalars = assemble_leaf_stream(entries, cutoff);
    assert!(
        scalars.len().is_multiple_of(SCALARS_PER_LEAF),
        "assembled leaf stream is not a whole number of leaves"
    );
    let leaf_count = u64::try_from(scalars.len() / SCALARS_PER_LEAF).expect("leaf count fits u64");
    let root = CurveTreeRoot::from_bytes(root_from_scalars(&scalars));
    (root, leaf_count)
}

fn lock_count() -> BlockCount {
    BlockCount::from_raw(u64::try_from(COINBASE_LOCK_WINDOW).expect("coinbase lock fits u64"))
}

fn varying_tip() -> BlockHeight {
    let cycle = u64::try_from(OUTPUTS_PER_BLOCK.len()).expect("schedule length fits u64");
    let past_lock = cycle
        .checked_mul(SCHEDULE_CYCLES_PAST_LOCK)
        .expect("schedule cycles fit u64");
    BlockHeight::ZERO + lock_count() + BlockCount::from_raw(past_lock)
}

/// Reference height at which the coinbase created in the last counted block
/// has drained. Maturity is creation plus the lock; the root at `h` drains
/// through `h - 1`.
fn tip_when_last_creation_drains(creations: usize) -> BlockHeight {
    let last_index = creations.checked_sub(1).expect("at least one creation");
    let created_at =
        BlockHeight::from_raw(u64::try_from(last_index).expect("creation index fits u64"));
    created_at + lock_count() + BlockCount::ONE
}

fn scheduled_outputs(height: BlockHeight) -> usize {
    let cycle = u64::try_from(OUTPUTS_PER_BLOCK.len()).expect("schedule length fits u64");
    let slot = usize::try_from(height.to_raw() % cycle).expect("schedule slot fits usize");
    OUTPUTS_PER_BLOCK[slot]
}

fn outputs_of(counts: &[usize]) -> impl Fn(BlockHeight) -> usize + '_ {
    move |height| {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| counts.get(index).copied())
            .unwrap_or(0)
    }
}

fn ingest_through(
    client: &mut CurveTreeClient,
    tip: BlockHeight,
    outputs_at: impl Fn(BlockHeight) -> usize,
) {
    let end = tip
        .checked_add(BlockCount::ONE)
        .expect("ingested tip has a successor");
    for height in BlockHeight::ZERO.ordinals_until(end) {
        let n = outputs_at(height);
        if n == 0 {
            let txs: Vec<TxLeafInputs<'_>> = Vec::new();
            client
                .ingest_block(BlockLeaves { height, txs: &txs })
                .unwrap();
        } else {
            let outs = vec![coinbase_raw(); n];
            ingest_outputs_at(client, height.to_raw(), &outs);
        }
    }
}

/// Wide blocks of one Selene chunk, a remainder that lands on the layer
/// step, and one more leaf so the next count is past the step.
fn counts_landing_on_layer_step() -> Vec<usize> {
    let boundary = usize::try_from(layer_step_leaf_count()).expect("layer step fits usize");
    let wide = SELENE_CHUNK_WIDTH;
    assert!(boundary > wide, "layer step is past one Selene chunk");
    let wide_blocks = (boundary - 1) / wide;
    let remainder = boundary - wide_blocks * wide;
    assert!(
        remainder > 0,
        "remainder must be the block that lands on the step"
    );
    let mut counts = vec![wide; wide_blocks];
    counts.push(remainder);
    counts.push(1);
    let total: usize = counts.iter().copied().sum();
    assert_eq!(
        total,
        boundary + 1,
        "counts must sum to the step plus one leaf"
    );
    counts
}

/// Assert the client at `height` against the oracle at `height - 1`.
///
/// `height` is at least 1. The cutoff is that predecessor, not
/// [`CurveTreeClient::drained_through`].
fn assert_pinned(client: &CurveTreeClient, height: BlockHeight) -> (CurveTreeRoot, u64) {
    let cutoff = height - BlockCount::ONE;
    let (want_root, want_n) = oracle_at(&client.entries, cutoff);
    let (got_root, got_depth) = client
        .root_and_depth_at(height)
        .unwrap_or_else(|err| panic!("height {height}: {err:?}"));
    let got_n = u64::try_from(client.drained_leaf_count(height)).expect("drained count fits u64");
    assert_eq!(got_n, want_n, "height {height}: drained count");
    assert_eq!(
        got_root, want_root,
        "height {height}: root over n={want_n} drained through {cutoff}"
    );
    assert_eq!(
        got_depth,
        layer_count_for_leaves(want_n),
        "height {height}: depth is not pinned to n={want_n}"
    );
    (want_root, want_n)
}

#[test]
fn height_keyed_read_matches_oracle_at_every_height() {
    let tip = varying_tip();
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, scheduled_outputs);

    // The first coinbase drains at lock + 1. The sweep starts at 1 so the
    // empty-tree side of the 0 → 1 depth step is asserted.
    let first_drained = BlockHeight::ZERO + lock_count() + BlockCount::ONE;
    assert!(
        first_drained <= tip,
        "fixture never reaches a drained height"
    );

    let mut empty = 0usize;
    let mut with_leaves = 0usize;
    let mut shift_changes_root = 0usize;
    let mut shift_same_root = 0usize;
    let end = tip
        .checked_add(BlockCount::ONE)
        .expect("ingested tip has a successor");
    for height in (BlockHeight::ZERO + BlockCount::ONE).ordinals_until(end) {
        let (want_root, want_n) = assert_pinned(&client, height);
        if want_n == 0 {
            empty += 1;
        } else {
            with_leaves += 1;
        }

        let cutoff = height - BlockCount::ONE;
        let (shifted_root, shifted_n) = oracle_at(&client.entries, cutoff + BlockCount::ONE);
        if want_root == shifted_root {
            assert_eq!(
                want_n, shifted_n,
                "height {height}: equal roots hid a leaf-count change"
            );
            // Count this as witnessing the invisible case **only where leaves
            // exist**. Before the first drain both cutoffs see the empty tree,
            // so equal roots there are guaranteed by the fixture's start and
            // say nothing about a zero-output block inside the drained window —
            // which is the only thing the assertion below claims.
            if want_n > 0 {
                shift_same_root += 1;
            }
        } else {
            shift_changes_root += 1;
        }
    }

    assert!(empty > 0, "no empty-tree height was asserted");
    assert!(with_leaves > 0, "no drained height was asserted");
    assert!(
        shift_changes_root > 0,
        "a one-block cutoff shift changed no root; a wrong cutoff would not fail this test"
    );
    assert!(
        shift_same_root > 0,
        "a one-block cutoff shift changed every root at a height that had leaves; the \
         fixture has no zero-output block inside the drained window, so the case where a \
         wrong cutoff is invisible in the count went untested"
    );
}

#[test]
fn depth_is_pinned_where_layer_count_steps() {
    stepped_depths();
    let step = layer_step_leaf_count();
    let counts = counts_landing_on_layer_step();
    let tip = tip_when_last_creation_drains(counts.len());
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, outputs_of(&counts));

    let mut saw_step = false;
    let mut saw_past_step = false;
    let end = tip
        .checked_add(BlockCount::ONE)
        .expect("ingested tip has a successor");
    for height in (BlockHeight::ZERO + BlockCount::ONE).ordinals_until(end) {
        let (_, want_n) = oracle_at(&client.entries, height - BlockCount::ONE);
        if want_n != step && want_n != step + 1 {
            continue;
        }
        let (_, pinned) = assert_pinned(&client, height);
        if pinned == step {
            saw_step = true;
        } else {
            saw_past_step = true;
        }
    }

    assert!(
        saw_step,
        "n={step} was never the drained count; the layer step was not landed on"
    );
    assert!(
        saw_past_step,
        "n={} was never the drained count; the far side of the layer step was not landed on",
        step + 1
    );
}

fn disagree_at(flipped: TierReading) -> (BlockHeight, Result<(), TierFault>) {
    let layout = overlapping_layout(ExaminedWindow::Union);
    let overlap = first_overlap(&layout);
    let agreed = agreed_reading();
    let segment = InjectedTier::uniform(layout.frozen, agreed);
    let snapshot = InjectedTier {
        span: layout.snapshot,
        reading: agreed,
        replaced_at: Some((overlap, flipped)),
    };
    let result = examine_tier_readings(layout.answers(segment, snapshot));
    (overlap, result)
}

#[test]
fn agreeing_overlap_is_total() {
    let layout = overlapping_layout(ExaminedWindow::Union);
    let agreed = agreed_reading();
    let segment = InjectedTier::uniform(layout.frozen, agreed);
    let snapshot = InjectedTier::uniform(layout.snapshot, agreed);
    assert_eq!(
        examine_tier_readings(layout.answers(segment, snapshot)),
        Ok(())
    );
}

#[test]
fn root_disagreement_is_named() {
    let agreed = agreed_reading();
    let flipped = TierReading {
        root: root_distinct_from_empty(),
        depth: agreed.depth,
    };
    assert_ne!(agreed.root, flipped.root);
    assert_eq!(agreed.depth, flipped.depth);
    let (overlap, result) = disagree_at(flipped);
    assert_eq!(result, Err(TierFault::Disagree { height: overlap }));
}

#[test]
fn depth_disagreement_is_named() {
    let agreed = agreed_reading();
    let flipped = TierReading {
        root: agreed.root,
        depth: stepped_depths().1,
    };
    assert_eq!(agreed.root, flipped.root);
    assert_ne!(agreed.depth, flipped.depth);
    let (overlap, result) = disagree_at(flipped);
    assert_eq!(result, Err(TierFault::Disagree { height: overlap }));
}

#[test]
fn height_outside_both_spans_is_uncovered() {
    let layout = overlapping_layout(ExaminedWindow::OneHolePastUnion);
    let hole = layout.examined.last;
    assert!(!layout.frozen.covers(hole));
    assert!(!layout.snapshot.covers(hole));
    let agreed = agreed_reading();
    let segment = InjectedTier::uniform(layout.frozen, agreed);
    let snapshot = InjectedTier::uniform(layout.snapshot, agreed);
    assert_eq!(
        examine_tier_readings(layout.answers(segment, snapshot)),
        Err(TierFault::Uncovered { height: hole })
    );
}

// ---------------------------------------------------------------------------
// CT-6 increment 3 — per-transaction reconstruction reuse (closeout row (a))
// ---------------------------------------------------------------------------

/// Two inputs whose leaves sit in **different layer-0 chunks**.
///
/// The hazard this increment introduces is shared state leaking across inputs:
/// the drained leaves and their layers are now built once for the batch, so a
/// value that should be per-input — `leaf_pos`, and everything derived from it
/// — could be computed once and reused. Inputs inside one chunk would hide
/// that, because their `leaf_chunk` is the same slice either way. These two
/// straddle a chunk boundary, so a reused position changes the answer.
fn two_inputs_in_different_chunks(
    client: &CurveTreeClient,
    cutoff: BlockHeight,
) -> (Vec<AssembleInput>, usize, usize) {
    let drained = drained_sorted(&client.entries, cutoff);
    let first = 0usize;
    let second = SELENE_CHUNK_WIDTH;
    assert!(
        drained.len() > second,
        "fixture holds {} drained leaves; need more than {second} so the two \
         inputs land in different layer-0 chunks",
        drained.len()
    );
    assert_ne!(
        first / SELENE_CHUNK_WIDTH,
        second / SELENE_CHUNK_WIDTH,
        "the two positions must be in different chunks or a reused leaf_pos is invisible"
    );
    let inputs = [first, second]
        .into_iter()
        .map(|pos| {
            let e = &drained[pos];
            AssembleInput {
                gindex: e.gindex,
                output_key: e.identity.output_key,
                commitment: e
                    .identity
                    .commitment
                    .expect("a drained leaf carries a commitment"),
            }
        })
        .collect();
    (inputs, first, second)
}

/// The batch assembles a **distinct** path per input.
///
/// This is the red-bite for increment 3: computing `leaf_pos` once and reusing
/// it across the batch would make both paths identical, and this assertion is
/// what notices. It is not an equivalence test against `assemble_path` —
/// that method now delegates to the batch, so comparing them would compare a
/// function to itself.
#[test]
fn batched_assembly_keeps_each_input_its_own_path() {
    let tip = varying_tip();
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, scheduled_outputs);

    let height = tip;
    let cutoff = height - BlockCount::ONE;
    let (inputs, first, second) = two_inputs_in_different_chunks(&client, cutoff);
    let reference = reference_at(&client, height);

    let paths = client
        .assemble_paths(&inputs, &reference)
        .expect("batch assembles");

    assert_eq!(paths.len(), inputs.len(), "one path per input");
    assert_ne!(
        paths[0].leaf_chunk, paths[1].leaf_chunk,
        "positions {first} and {second} are in different layer-0 chunks, so their \
         leaf chunks must differ; equal chunks mean a per-input value was computed \
         once and reused across the batch"
    );
    // **The branches above layer 0 are deliberately not asserted to differ.**
    // Two leaves in different layer-0 chunks may share every parent above
    // them: at this fixture's depth the walk divides `leaf_node_idx` by
    // `HELIOS_CHUNK_WIDTH`, so chunks 0 and 1 both resolve to node 0 and the
    // branch is legitimately identical. Asserting otherwise would fail on
    // correct code — which is how this assertion was first written, and what
    // running it caught. `leaf_chunk` is the discriminator here because
    // `leaf_pos` is what selects it, so a reused position changes it and
    // nothing else needs to.
}

/// The integrity gate runs **once, before any input work**, and a mismatch
/// yields no paths rather than a partial batch.
#[test]
fn a_root_mismatch_refuses_the_whole_batch() {
    let tip = varying_tip();
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, scheduled_outputs);

    let height = tip;
    let cutoff = height - BlockCount::ONE;
    let (inputs, _, _) = two_inputs_in_different_chunks(&client, cutoff);

    let mut reference = reference_at(&client, height);
    let mut wrong = reference.curve_tree_root.to_bytes();
    wrong[0] ^= 0x01;
    reference.curve_tree_root = CurveTreeRoot::from_bytes(wrong);

    let err = client
        .assemble_paths(&inputs, &reference)
        .expect_err("a wrong reference root must refuse the batch");
    assert!(
        matches!(err, ClientError::RootMismatch { .. }),
        "expected RootMismatch, got {err:?}"
    );
}
