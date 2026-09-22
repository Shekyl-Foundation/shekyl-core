// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-CURVE (`DRS_E1_SCURVE.md` §3): the three curve-tree reads on
//! `ReadSnapshot`.
//!
//! No writer for `curve_tree_meta` / `curve_tree_leaves` exists yet (the
//! grow path is DRS-E3's), so every planted state is written raw — the
//! shape a file the grow path produced will have — and every fault is
//! planted raw as well, then asserted on a fresh snapshot: the reads
//! classify what is *in the file*, and a read never arms the halt.

use shekyl_chain_rules::AtHeight;
use shekyl_types::{BlockHeight, CurveTreeRoot, TreeLeaf, TreePosition};

use super::connect_fixtures::{connect_chain, root_at_height};
use super::error::{CellFault, LeafDensity, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{Canonical, CurveTreeState, LeafCount, TreeDepth};
use crate::schema::{CURVE_TREE_LEAVES, CURVE_TREE_META};

fn pos(raw: u64) -> TreePosition {
    TreePosition::from_raw(raw)
}

fn leaf(fill: u8) -> TreeLeaf {
    TreeLeaf::from_bytes([fill; TreeLeaf::LEN])
}

/// A grown summary: depth 2, `count` leaves, `root` as given.
fn grown(root: CurveTreeRoot, count: u64) -> CurveTreeState {
    CurveTreeState {
        root,
        depth: TreeDepth::from_raw(2),
        leaf_count: LeafCount::from_raw(count),
    }
}

/// Three blocks from genesis. The live root is [`live_root_after_three`].
fn connect_three(path: &std::path::Path) {
    let store = ChainStore::create(path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
}

/// `curve_tree_roots[tip + 1]` after [`connect_three`]: tip is 2, so key 3,
/// the root the connect of block 2 wrote.
fn live_root_after_three() -> CurveTreeRoot {
    root_at_height(3)
}

/// Write `state` over the seal's summary and leaves at `0..leaf_count`.
/// Rows already past that count are left where they are.
fn plant_summary(path: &std::path::Path, state: CurveTreeState) {
    let count = state.leaf_count.to_raw();
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut meta = txn.open_table(CURVE_TREE_META).expect("t");
        meta.insert((), state.encoded().as_encoded())
            .expect("insert");
        let mut leaves = txn.open_table(CURVE_TREE_LEAVES).expect("t");
        for p in 0..count {
            let fill = u8::try_from(p).expect("small trees in tests");
            leaves
                .insert(p, leaf(fill).encoded().as_encoded())
                .expect("insert");
        }
    }
    txn.commit().expect("commit");
}

fn is_length(err: &StoreError, count: u64, rows: u64) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::LeavesNotDense {
            observed: LeafDensity::Length { count: c, rows: r }
        }) if *c == count && *r == rows
    )
}

fn is_hole(err: &StoreError, position: u64) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::LeavesNotDense {
            observed: LeafDensity::Hole { position: p }
        }) if *p == position
    )
}

fn is_root_diverged(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::SummaryRootDiverged)
    )
}

// ---------------------------------------------------------------------------
// C1 — the summary
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_store_reads_the_empty_tree_as_a_row_not_a_default() {
    let path = tmp("curve-c1-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.curve_tree().expect("summary"), CurveTreeState::EMPTY);
    // And the empty range inside an empty tree is an answer, not an absence.
    assert_eq!(
        snap.leaves(pos(0)..pos(0)).expect("walk"),
        AtIndex::Recorded(Vec::new())
    );
    cleanup(&path);
}

#[test]
fn an_ungrown_chain_keeps_the_seal_summary_while_the_live_root_moves() {
    let path = tmp("curve-c1-ungrown");
    connect_three(&path);
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.curve_tree().expect("summary"), CurveTreeState::EMPTY);
    assert_eq!(
        snap.root_at(BlockHeight::from_raw(3)).expect("live"),
        AtHeight::Recorded(live_root_after_three()),
        "connect recorded a live root the summary does not claim"
    );
    cleanup(&path);
}

#[test]
fn the_summary_is_the_planted_row_when_its_root_is_the_live_root() {
    let path = tmp("curve-c1-grown");
    connect_three(&path);
    let planted = grown(live_root_after_three(), 3);
    plant_summary(&path, planted);
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let state = snap.curve_tree().expect("summary");
    assert_eq!(state, planted);
    assert_eq!(state.depth.fcmp_layers(), 3, "depth 2 ⇒ three proof layers");
    assert_eq!(state.leaf_count.next_position(), pos(3));
    cleanup(&path);
}

#[test]
fn a_grown_summary_whose_root_is_not_the_live_root_is_si12() {
    let path = tmp("curve-c1-root");
    connect_three(&path);
    plant_summary(&path, grown(CurveTreeRoot::from_bytes([0x11; 32]), 3));
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap.curve_tree().expect_err("roots disagree");
    assert!(is_root_diverged(&err), "{err}");
    assert_eq!(StoreInvariant::SummaryRootDiverged.row(), 12);
    cleanup(&path);
}

#[test]
fn a_grown_summary_on_an_empty_chain_is_si12() {
    let path = tmp("curve-c1-root-empty-chain");
    ChainStore::create(&path, EPOCH).expect("create");
    // Count 0, so the length belt would agree; the root is what fails.
    plant_summary(&path, grown(CurveTreeRoot::from_bytes([0xc1; 32]), 0));
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .curve_tree()
        .expect_err("no tip, so the live root is EMPTY");
    assert!(is_root_diverged(&err), "{err}");
    cleanup(&path);
}

#[test]
fn a_missing_summary_row_is_si7_absent_never_the_empty_tree() {
    let path = tmp("curve-c1-absent");
    ChainStore::create(&path, EPOCH).expect("create");
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut meta = txn.open_table(CURVE_TREE_META).expect("t");
            assert!(
                meta.remove(()).expect("remove").is_some(),
                "the seal wrote it"
            );
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap.curve_tree().expect_err("no row, no default");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "curve_tree_meta",
                fault: CellFault::Absent
            })
        ),
        "{err}"
    );
    // The leaf walk bounds itself on the same row and refuses the same way.
    let err = snap
        .leaves(pos(0)..pos(0))
        .expect_err("no bound to walk under");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "curve_tree_meta",
                ..
            })
        ),
        "{err}"
    );
    cleanup(&path);
}

#[test]
fn a_count_that_is_not_the_leaf_tables_length_is_si11_length() {
    let path = tmp("curve-c1-count");
    connect_three(&path);
    plant_summary(&path, grown(live_root_after_three(), 3));
    {
        // Drop the last leaf; the summary still claims three.
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut leaves = txn.open_table(CURVE_TREE_LEAVES).expect("t");
            assert!(leaves.remove(2).expect("remove").is_some());
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap.curve_tree().expect_err("count and rows disagree");
    assert!(is_length(&err, 3, 2), "{err}");
    // The walk names the missing position. The length belt does not.
    let err = snap.leaves(pos(0)..pos(3)).expect_err("a hole at 2");
    assert!(is_hole(&err, 2), "{err}");
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// C2 — root_at, the store's public read of the view's body
// ---------------------------------------------------------------------------

#[test]
fn root_at_on_an_empty_chain_is_the_empty_tree_at_zero_and_above_tip_after() {
    let path = tmp("curve-c2-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.root_at(BlockHeight::ZERO).expect("read"),
        AtHeight::Recorded(CurveTreeRoot::EMPTY)
    );
    assert_eq!(
        snap.root_at(BlockHeight::from_raw(1)).expect("read"),
        AtHeight::AboveTip
    );
    cleanup(&path);
}

#[test]
fn root_at_reads_key_h_through_the_live_root_and_refuses_above_it() {
    let path = tmp("curve-c2-chain");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // Rows 1..=tip + 1 are what the connects wrote: the state going into
    // each height, and `tip + 1` the live root.
    for h in 0..=3u64 {
        assert_eq!(
            snap.root_at(BlockHeight::from_raw(h)).expect("read"),
            AtHeight::Recorded(root_at_height(h)),
            "height {h}"
        );
    }
    assert_eq!(
        snap.root_at(BlockHeight::from_raw(4)).expect("read"),
        AtHeight::AboveTip
    );
    // The snapshot's read and the batch view's are one body: same answer.
    let via_view: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for h in 0..=4u64 {
            assert_eq!(
                shekyl_chain_rules::ChainView::root_at(&view, BlockHeight::from_raw(h))?,
                snap.root_at(BlockHeight::from_raw(h))?,
                "height {h}"
            );
        }
        Ok(())
    });
    assert_eq!(via_view, Ok(()));
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// C3 — leaves
// ---------------------------------------------------------------------------

#[test]
fn leaves_walks_a_range_in_position_order_and_refuses_past_the_count() {
    let path = tmp("curve-c3-walk");
    connect_three(&path);
    plant_summary(&path, grown(live_root_after_three(), 3));
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.leaves(pos(0)..pos(3)).expect("walk"),
        AtIndex::Recorded(vec![leaf(0), leaf(1), leaf(2)])
    );
    assert_eq!(
        snap.leaves(pos(1)..pos(2)).expect("walk"),
        AtIndex::Recorded(vec![leaf(1)])
    );
    // The end is the count: the whole range is inside the tree.
    assert_eq!(
        snap.leaves(pos(2)..pos(3)).expect("walk"),
        AtIndex::Recorded(vec![leaf(2)])
    );
    // One past the count refuses the whole range — no partial answer.
    assert_eq!(
        snap.leaves(pos(2)..pos(4)).expect("walk"),
        AtIndex::BeyondCount
    );
    assert_eq!(
        snap.leaves(pos(7)..pos(9)).expect("walk"),
        AtIndex::BeyondCount
    );
    // Empty and inverted ranges inside the count are empty answers.
    assert_eq!(
        snap.leaves(pos(1)..pos(1)).expect("walk"),
        AtIndex::Recorded(Vec::new())
    );
    assert_eq!(
        snap.leaves(pos(2)..pos(1)).expect("walk"),
        AtIndex::Recorded(Vec::new())
    );
    cleanup(&path);
}

#[test]
fn a_hole_inside_the_count_is_si11_at_the_first_missing_position() {
    let path = tmp("curve-c3-hole");
    connect_three(&path);
    plant_summary(&path, grown(live_root_after_three(), 4));
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut leaves = txn.open_table(CURVE_TREE_LEAVES).expect("t");
            assert!(leaves.remove(1).expect("remove").is_some());
            // Keep the length honest so only the walk can see the hole.
            leaves
                .insert(9, leaf(0x99).encoded().as_encoded())
                .expect("insert");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.curve_tree().expect("length still matches").leaf_count,
        LeafCount::from_raw(4)
    );
    let err = snap.leaves(pos(0)..pos(3)).expect_err("hole at 1");
    assert!(is_hole(&err, 1), "{err}");
    // A range that starts past the hole is fine; the belt is per read.
    assert_eq!(
        snap.leaves(pos(2)..pos(4)).expect("walk"),
        AtIndex::Recorded(vec![leaf(2), leaf(3)])
    );
    // A read never arms the halt.
    assert!(matches!(
        snap.tip().expect("tip").connect,
        super::halt::ConnectState::Live
    ));
    cleanup(&path);
}
