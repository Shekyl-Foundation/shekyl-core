// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 4 — the real segment tier and the snapshot ring, graded
//! by the examiner in the parent module.
//!
//! [`super::examine_tier_readings`], [`super::TierReading`],
//! [`super::TierCoverage`], [`super::TierFault`] and [`super::HeightSpan`]
//! are unchanged. What follows replaces the injected tiers as the *source*
//! of the answers: the segment tier is the landed CT-1 composition and the
//! snapshot tier is the ring.

use super::super::tests::{coinbase_raw, ingest_outputs_at};
use super::super::{BlockLeaves, CurveTreeClient, TxLeafInputs};
use super::{
    examine_tier_readings, ingest_through, layer_step_leaf_count, lock_count, outputs_of,
    scheduled_outputs, stepped_depths, tip_when_last_creation_drains, varying_tip, HeightAnswers,
    HeightSpan, RegionCensus, TierCoverage, TierFault, TierReading,
};
use crate::frontier::Frontier;
use crate::segment::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;
use crate::types::BlockHeight;
use crate::ClientError;
use shekyl_types::BlockCount;

/// How the segment tier is offered to the examiner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SegmentTier {
    /// The landed `root_at_count` path, which answers every ingested
    /// height. This is the pass that can produce `Disagree`.
    OverTheWholeChain,
    /// No height at all — the state a fixture with nothing frozen is
    /// actually in. This is the only pass in which a hole in the ring can
    /// reach `Uncovered`; with the segment tier answering, the store masks
    /// every hole.
    CoversNothing,
}

/// Build the examiner's rows from the two real tiers.
///
/// Neither tier is read through [`CurveTreeClient::root_and_depth_at`]. That
/// is the dispatcher — it picks one tier and returns it, so feeding it to
/// both columns would compare the picked tier to itself and agree by
/// construction.
fn real_answers(
    client: &CurveTreeClient,
    examined: HeightSpan,
    segment_tier: SegmentTier,
) -> Vec<HeightAnswers> {
    examined
        .heights()
        .map(|height| {
            let segment = match segment_tier {
                SegmentTier::OverTheWholeChain => {
                    let (root, depth) = client
                        .segment_tier_reading(height)
                        .unwrap_or_else(|err| panic!("segment tier at {height}: {err:?}"));
                    TierCoverage::Covers(TierReading { root, depth })
                }
                SegmentTier::CoversNothing => TierCoverage::OutsideSpan,
            };
            let snapshot = client
                .snapshot_tier_reading(height)
                .unwrap_or_else(|err| panic!("snapshot tier at {height}: {err:?}"))
                .map_or(TierCoverage::OutsideSpan, |(root, depth)| {
                    TierCoverage::Covers(TierReading { root, depth })
                });
            HeightAnswers {
                height,
                segment,
                snapshot,
            }
        })
        .collect()
}

fn census_of(rows: &[HeightAnswers]) -> RegionCensus {
    let mut census = RegionCensus {
        frozen_only: 0,
        snapshot_only: 0,
        both: 0,
        neither: 0,
    };
    for row in rows {
        match (row.segment, row.snapshot) {
            (TierCoverage::Covers(_), TierCoverage::OutsideSpan) => census.frozen_only += 1,
            (TierCoverage::OutsideSpan, TierCoverage::Covers(_)) => census.snapshot_only += 1,
            (TierCoverage::Covers(_), TierCoverage::Covers(_)) => census.both += 1,
            (TierCoverage::OutsideSpan, TierCoverage::OutsideSpan) => census.neither += 1,
        }
    }
    census
}

/// Every height from genesis to the ingested tip.
fn examined_chain(client: &CurveTreeClient) -> HeightSpan {
    HeightSpan::inclusive(
        BlockHeight::ZERO,
        client.ingested_tip_height().expect("fixture ingested"),
    )
}

/// A client over the varying-output schedule, tall enough that the drained
/// window holds every slot of [`super::OUTPUTS_PER_BLOCK`].
fn varying_client() -> (CurveTreeClient, BlockHeight) {
    let tip = varying_tip();
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, scheduled_outputs);
    (client, tip)
}

/// A valid frontier over `n` leaves whose content differs from the fixture's,
/// so its root differs while its leaf count does not.
///
/// The count has to match or the C3 check refuses the row before the root is
/// ever consulted — and then the test would be observing the count check, not
/// the read it claims to observe.
fn foreign_frontier(n: u64) -> Frontier {
    let mut f = Frontier::new();
    for i in 0..n {
        let mut leaf = [0u8; 128];
        for (s, slot) in leaf.chunks_exact_mut(32).enumerate() {
            let index = u64::try_from(s).expect("scalar index fits u64");
            slot[..8].copy_from_slice(
                &i.wrapping_mul(0x0005_DEEC_E66D)
                    .wrapping_add(index)
                    .to_le_bytes(),
            );
            slot[9] = 0x11;
        }
        f.push_leaf(&leaf).expect("foreign advance");
    }
    f
}

#[test]
fn the_two_real_tiers_agree_at_every_ingested_height() {
    let (client, tip) = varying_client();
    let examined = examined_chain(&client);
    let rows = real_answers(&client, examined, SegmentTier::OverTheWholeChain);

    // Rule 47: the pass asserts its own subject. If the ring covered
    // nothing, every row would be segment-only, `examine_tier_readings`
    // would return `Ok(())`, and the green would mean nothing at all.
    let census = census_of(&rows);
    assert_eq!(
        census.both,
        usize::try_from(tip.to_raw() + 1).expect("height count fits usize"),
        "the ring answered {} of {} ingested heights; an overlap census of zero would \
         make this pass green with nothing compared",
        census.both,
        tip.to_raw() + 1
    );
    assert_eq!(census.neither, 0, "a height neither tier answered");

    assert_eq!(examine_tier_readings(rows), Ok(()));
}

#[test]
fn the_ring_alone_is_total_over_the_ingested_chain() {
    let (client, _) = varying_client();
    // The segment tier is offered as covering nothing, which is what it
    // actually covers here: the freeze gate needs
    // `SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` of burial
    // and this fixture is nowhere near it. Asserting the cursor rather than
    // assuming it is the difference between a claim and a fixture fact.
    assert_eq!(
        client.next_freeze_seg().expect("freeze cursor reads"),
        0,
        "a segment froze in this fixture, so `CoversNothing` no longer describes the segment column"
    );
    let rows = real_answers(&client, examined_chain(&client), SegmentTier::CoversNothing);
    let census = census_of(&rows);
    assert_eq!(census.frozen_only, 0, "the segment tier answered a height");
    assert!(census.snapshot_only > 0, "the ring answered no height");
    assert_eq!(examine_tier_readings(rows), Ok(()));
}

#[test]
fn a_hole_in_the_ring_is_uncovered_where_nothing_is_frozen() {
    let (client, tip) = varying_client();
    let hole = tip - BlockCount::ONE;
    client
        .test_set_snapshot(hole, None)
        .expect("ring row removed");

    // With the segment tier answering, the store masks the hole — which is
    // why the totality pass is a separate pass and not a stricter assertion
    // on the agreement one.
    let masked = real_answers(
        &client,
        examined_chain(&client),
        SegmentTier::OverTheWholeChain,
    );
    assert_eq!(examine_tier_readings(masked), Ok(()));

    let rows = real_answers(&client, examined_chain(&client), SegmentTier::CoversNothing);
    assert_eq!(
        examine_tier_readings(rows),
        Err(TierFault::Uncovered { height: hole })
    );
}

#[test]
fn a_ring_row_that_disagrees_is_named_by_the_examiner() {
    let (client, tip) = varying_client();
    let at = tip - BlockCount::ONE;
    let n = u64::try_from(client.drained_leaf_count(at)).expect("count fits u64");
    assert!(n > 0, "the disagreement height must hold leaves");
    client
        .test_set_snapshot(at, Some(&foreign_frontier(n)))
        .expect("ring row replaced");

    let rows = real_answers(
        &client,
        examined_chain(&client),
        SegmentTier::OverTheWholeChain,
    );
    assert_eq!(
        examine_tier_readings(rows),
        Err(TierFault::Disagree { height: at }),
        "a ring row built over different leaves did not reach the examiner as a disagreement"
    );
}

#[test]
fn the_dispatcher_answers_an_in_horizon_height_from_the_ring() {
    let (client, tip) = varying_client();
    let at = tip - BlockCount::ONE;
    let n = u64::try_from(client.drained_leaf_count(at)).expect("count fits u64");
    assert!(n > 0, "the probed height must hold leaves");
    let (segment_root, segment_depth) = client.segment_tier_reading(at).expect("segment tier");

    client
        .test_set_snapshot(at, Some(&foreign_frontier(n)))
        .expect("ring row replaced");
    let (served_root, served_depth) = client.root_and_depth_at(at).expect("dispatcher answers");

    assert_ne!(
        served_root, segment_root,
        "the dispatcher returned the segment tier's root at an in-horizon height; the ring \
         can be captured and never read, and every other test here would still be green"
    );
    // The depth is a function of the leaf count, which the replacement kept,
    // so it must NOT move. A depth that changed here would mean the read
    // took its two halves from two different places.
    assert_eq!(served_depth, segment_depth, "depth moved with the root");
}

#[test]
fn a_ring_row_over_the_wrong_leaf_count_is_refused_not_served() {
    let (client, tip) = varying_client();
    let at = tip - BlockCount::ONE;
    let n = u64::try_from(client.drained_leaf_count(at)).expect("count fits u64");
    assert!(
        n > 1,
        "the probed height needs a smaller valid count below it"
    );
    client
        .test_set_snapshot(at, Some(&foreign_frontier(n - 1)))
        .expect("ring row replaced");

    let err = client
        .root_and_depth_at(at)
        .expect_err("a snapshot over the wrong count must be refused");
    assert!(
        matches!(
            err,
            ClientError::SnapshotLeafCountMismatch {
                height,
                snapshot,
                expected,
            } if height == at && snapshot == n - 1 && expected == n
        ),
        "expected SnapshotLeafCountMismatch, got {err:?}"
    );
}

#[test]
fn the_ring_covers_every_legal_reorgs_fork_and_nothing_deeper() {
    // The one test that runs at the real constant. The horizon IS
    // `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`; shrinking it for the test would
    // grade a ring of a different size than the one that ships.
    let horizon = BlockCount::from_raw(SEGMENT_FREEZE_REORG_MARGIN_BLOCKS);
    // The tip has to clear the horizon by more than the coinbase lock, or
    // the deepest fork's drain cutoff predates the first maturity and the
    // rewind half of this test would run over an empty tree — a pass that
    // asserts nothing about restoring a frontier.
    let tip = BlockHeight::ZERO + horizon + lock_count() + BlockCount::from_raw(2);
    let mut client = CurveTreeClient::new();
    ingest_through(&mut client, tip, scheduled_outputs);

    // **The expected span comes from what a reorg is, not from the eviction's
    // own bound.** A reorg of depth `horizon` replaces that many blocks, so
    // its fork height is `tip - horizon` — the block the replaced ones build
    // on — and `rollback_to_fork` restores from the row AT the fork. Reading
    // the expectation off the delete's bound instead would assert the
    // implementation back at itself and accept the half-open run that drops
    // exactly the deepest legal rewind.
    let deepest_fork = tip - horizon;
    let (first, last) = client
        .snapshot_span()
        .expect("span reads")
        .expect("the ring holds rows");
    assert_eq!(last, tip, "the ring does not reach the tip");
    assert_eq!(
        first, deepest_fork,
        "the ring's lowest height is not the deepest legal reorg's fork"
    );

    let too_deep = deepest_fork - BlockCount::ONE;
    assert!(
        client
            .snapshot_tier_reading(too_deep)
            .expect("ring read")
            .is_none(),
        "height {too_deep} is one below the deepest legal fork and the ring still answers it"
    );
    assert!(
        client
            .snapshot_tier_reading(deepest_fork)
            .expect("ring read")
            .is_some(),
        "the deepest legal fork is not covered, so the deepest legal rewind would refold \
         the whole drained prefix"
    );

    // Falling out of the ring changes who answers, never what is answered.
    assert_eq!(
        client.root_and_depth_at(too_deep).expect("dispatcher"),
        client.segment_tier_reading(too_deep).expect("segment tier"),
        "an evicted height's answer moved"
    );
    // **What is NOT asserted here, and whose it is.** A rollback to
    // `too_deep` — deeper than any legal reorg — succeeds today, slowly, by
    // folding the whole drained prefix. C7's refusal is increment 5's, and
    // building it here would put a consensus-facing refusal in the increment
    // that only has to answer heights. The seam is: this is where it goes.

    // And the deepest legal rewind really does restore from that row: the
    // same discriminator the in-horizon rollback test uses, at the boundary
    // the span assertions above are about.
    let n_at_fork = u64::try_from(client.drained_leaf_count(deepest_fork)).expect("count fits u64");
    assert!(n_at_fork > 0, "the deepest fork must hold leaves");
    client
        .test_set_snapshot(deepest_fork, Some(&foreign_frontier(n_at_fork)))
        .expect("ring row replaced");
    client
        .rollback_to_fork(deepest_fork)
        .expect("deepest rollback");
    assert_eq!(
        client.live_frontier_leaf_count(),
        n_at_fork,
        "the restored frontier is over the wrong leaf count"
    );
    assert_ne!(
        client.root_and_depth_at(deepest_fork).expect("dispatcher"),
        client
            .segment_tier_reading(deepest_fork)
            .expect("segment tier"),
        "the deepest legal rewind did not read the fork height's snapshot"
    );
}

#[test]
fn an_in_horizon_rollback_restores_the_fork_heights_snapshot() {
    let (mut client, tip) = varying_client();
    let fork = tip - BlockCount::ONE - BlockCount::ONE;
    let n_at_fork = u64::try_from(client.drained_leaf_count(fork)).expect("count fits u64");
    assert!(n_at_fork > 0, "the fork height must hold leaves");

    // The discriminator. A correct restore and a correct fold produce the
    // same frontier, so the only way to see WHICH one ran is to make the
    // ring's row at the fork differ from what a fold would produce, and then
    // ask what the next block was built on.
    client
        .test_set_snapshot(fork, Some(&foreign_frontier(n_at_fork)))
        .expect("ring row replaced");
    client.rollback_to_fork(fork).expect("rollback");
    assert_eq!(
        client.ingested_tip_height(),
        Some(fork),
        "rollback did not move the tip"
    );
    let (_, ring_last) = client
        .snapshot_span()
        .expect("span reads")
        .expect("the ring still holds rows");
    assert_eq!(
        ring_last, fork,
        "the ring still answers a height above the fork; those rows describe a tree the \
         rollback removed"
    );
    assert_eq!(
        client.live_frontier_leaf_count(),
        n_at_fork,
        "the restored frontier is over the wrong leaf count"
    );

    let next = fork + BlockCount::ONE;
    let outs = vec![coinbase_raw(); scheduled_outputs(next)];
    if outs.is_empty() {
        let txs: Vec<TxLeafInputs<'_>> = Vec::new();
        client
            .ingest_block(BlockLeaves {
                height: next,
                txs: &txs,
            })
            .expect("replay forward");
    } else {
        ingest_outputs_at(&mut client, next.to_raw(), &outs);
    }

    let (replayed, _) = client.root_and_depth_at(next).expect("replayed read");
    let (recomputed, _) = client.segment_tier_reading(next).expect("segment tier");
    assert_ne!(
        replayed, recomputed,
        "the block replayed after the rollback was built on a frontier the ring did not \
         supply; the restore folded the whole drained prefix instead of reading the fork \
         height's snapshot, and the one-block rewind bound does not hold"
    );
}

#[test]
fn a_rollback_and_replay_reproduces_the_uninterrupted_chain() {
    let (mut rolled, tip) = varying_client();
    let fork = tip - BlockCount::ONE - BlockCount::ONE;
    rolled.rollback_to_fork(fork).expect("rollback");
    let mut height = fork + BlockCount::ONE;
    while height <= tip {
        let outs = vec![coinbase_raw(); scheduled_outputs(height)];
        if outs.is_empty() {
            let txs: Vec<TxLeafInputs<'_>> = Vec::new();
            rolled
                .ingest_block(BlockLeaves { height, txs: &txs })
                .expect("replay forward");
        } else {
            ingest_outputs_at(&mut rolled, height.to_raw(), &outs);
        }
        height = height + BlockCount::ONE;
    }

    let (straight, _) = varying_client();
    for h in examined_chain(&straight).heights() {
        assert_eq!(
            rolled.root_and_depth_at(h).expect("rolled read"),
            straight.root_and_depth_at(h).expect("straight read"),
            "height {h} differs after a rollback and replay"
        );
    }
}

#[test]
fn the_snapshot_tiers_depth_comes_from_the_snapshots_own_count() {
    // The one axis the examiner cannot separate on real data. On the
    // production read C3 forces the snapshot's count and the client's to be
    // equal, so a depth taken from the wrong one is invisible there. The
    // tier reader has no such check — it is what the examiner consumes — so
    // the weld is asserted against directly, at a count on the far side of a
    // layer step from the fixture's.
    let (client, tip) = varying_client();
    let at = tip - BlockCount::ONE;
    let (_, fixture_depth) = client.segment_tier_reading(at).expect("segment tier");

    let (at_step, past_step) = stepped_depths();
    assert_ne!(at_step, past_step, "the fixture spans no layer step");
    assert_ne!(
        fixture_depth, past_step,
        "the fixture's own depth is already the one this test would read on a weld"
    );
    let stepped = layer_step_leaf_count() + 1;
    client
        .test_set_snapshot(at, Some(&foreign_frontier(stepped)))
        .expect("ring row replaced");

    let (_, depth) = client
        .snapshot_tier_reading(at)
        .expect("ring read")
        .expect("the ring covers this height");
    assert_eq!(
        depth, past_step,
        "the snapshot tier reported depth {depth} for a snapshot over {stepped} leaves; \
         it took the depth from the client's leaf count, which welds this tier to the \
         segment tier on the one axis C3 pins"
    );
}

/// A persistent client over a short coinbase chain, for the resume paths.
///
/// Short on purpose: every block is a real redb commit, and what these tests
/// are about is which limb `rebuild_from_store` takes, not chain length.
fn persistent_client(path: &std::path::Path) -> (CurveTreeClient, BlockHeight) {
    let counts = vec![2usize, 1, 3];
    let tip = tip_when_last_creation_drains(counts.len());
    let mut client = CurveTreeClient::open(path).expect("store opens");
    ingest_through(&mut client, tip, outputs_of(&counts));
    (client, tip)
}

/// With no ring row at the tip, resume **folds** — and lands on the same
/// frontier the ring would have supplied.
///
/// This is the limb a store written before the ring existed takes, and it is
/// the one with no other test: the rollback bite proves the ring branch runs,
/// which says nothing about what happens when there is nothing to read.
#[test]
fn resume_folds_the_drained_prefix_when_the_ring_has_no_row_at_the_tip() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("resume_fold.curvetree");
    let (expected_reading, expected_n, tip) = {
        let (client, tip) = persistent_client(&path);
        let reading = client.root_and_depth_at(tip).expect("read before resume");
        let n = client.live_frontier_leaf_count();
        assert!(n > 0, "the fixture drained no leaves");
        client
            .test_set_snapshot(tip, None)
            .expect("ring row removed");
        (reading, n, tip)
    };

    let mut resumed = CurveTreeClient::open(&path).expect("resume");
    assert_eq!(
        resumed.live_frontier_leaf_count(),
        expected_n,
        "the folded frontier is over the wrong leaf count"
    );
    // The row is gone, so this height now answers from the segment tier --
    // which is exactly the fall-through, and it must answer the same thing.
    assert_eq!(
        resumed.root_and_depth_at(tip).expect("read after resume"),
        expected_reading,
        "the fall-through answer moved"
    );

    // The real claim: the NEXT block is built on the folded frontier, so its
    // captured snapshot has to agree with the composition over the same
    // leaves. A frontier folded in the wrong order or short by a leaf shows
    // up here and nowhere earlier.
    let next = tip + BlockCount::ONE;
    let txs: Vec<TxLeafInputs<'_>> = Vec::new();
    resumed
        .ingest_block(BlockLeaves {
            height: next,
            txs: &txs,
        })
        .expect("ingest after resume");
    assert!(
        resumed
            .snapshot_tier_reading(next)
            .expect("ring read")
            .is_some(),
        "the block after a folded resume captured no snapshot"
    );
    assert_eq!(
        resumed.root_and_depth_at(next).expect("dispatcher"),
        resumed.segment_tier_reading(next).expect("segment tier"),
        "the snapshot captured after a folded resume disagrees with the composition"
    );
}

/// A ring row at the tip whose leaf count is not the store's is **refused**
/// at resume, not quietly re-folded.
///
/// The two are written in one transaction from a frontier already checked
/// against the drain index, so a disagreement is corruption; C8's answer is
/// refuse-and-resync, and a silent re-fold would repair the symptom and hide
/// the cause.
#[test]
fn resume_refuses_a_ring_row_that_disagrees_with_the_store() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("resume_refuse.curvetree");
    let stored = {
        let (client, tip) = persistent_client(&path);
        let n = client.live_frontier_leaf_count();
        assert!(n > 1, "the fixture needs a smaller valid count below it");
        client
            .test_set_snapshot(tip, Some(&foreign_frontier(n - 1)))
            .expect("ring row replaced");
        n
    };

    let err = CurveTreeClient::open(&path).expect_err("resume must refuse");
    assert!(
        matches!(
            err,
            ClientError::SnapshotLeafCountMismatch {
                snapshot, expected, ..
            } if snapshot == stored - 1 && expected == stored
        ),
        "expected SnapshotLeafCountMismatch, got {err:?}"
    );
}
