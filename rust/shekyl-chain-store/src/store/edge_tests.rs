// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SI-5 (`edge.rs`): after a run of pops the tree's right edge is what its
//! stored children rebuild to. A clean run passes; a wrong leaf under the
//! edge, which no pop restores, halts at the leaf chunk; a leaf scalar that
//! is not on its curve names `curve_tree_leaves`; a summary and recorded
//! root moved together — SI-12 holds, the tree does not — halts on the
//! root arm.

use shekyl_chain_rules::RuleSet;
use shekyl_types::{BlockHeight, CurveTreeRoot, TreeLeaf};

use super::connect_fixtures::{connect_chain, spend, spendable_prefix, Listed};
use super::error::{EdgeFault, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use redb::ReadableTable;

use crate::codec::{Canonical, CurveTreeState};
use crate::schema::{CURVE_TREE_LEAVES, CURVE_TREE_META, CURVE_TREE_ROOTS};

/// The unlock window: from height `W` on, every connect drains one
/// coinbase, so the chain below has leaves to trim.
const W: u64 = RuleSet::GENESIS.mined_money_unlock_window().to_raw();
/// Heights `0..=TIP`: a spendable prefix with one spend, then enough empty
/// blocks that the last few connects each drained a leaf.
const TIP: u64 = W + 8;
/// Pops in the run under test: each removes one drained leaf.
const POPS: u64 = 3;

fn listing() -> Vec<Vec<Listed>> {
    let mut listed = spendable_prefix(vec![vec![spend()]]);
    listed.resize_with(usize::try_from(TIP + 1).expect("small"), Vec::new);
    listed
}

fn chain(name: &str) -> (std::path::PathBuf, ChainStore) {
    let path = tmp(name);
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &listing());
    (path, store)
}

fn summary(store: &ChainStore) -> CurveTreeState {
    store
        .begin_read()
        .expect("read")
        .curve_tree()
        .expect("summary")
}

#[test]
fn a_run_of_pops_leaves_a_right_edge_its_children_rebuild_to() {
    let (path, store) = chain("edge-clean");
    let before = summary(&store);
    assert!(before.leaf_count.to_raw() > POPS, "the run trims leaves");
    let out: Result<usize, TestErr> = store.write(|batch| Ok(batch.pop_many(POPS)?.len()));
    assert_eq!(out, Ok(usize::try_from(POPS).expect("small")));
    let after = summary(&store);
    assert!(
        after.leaf_count < before.leaf_count,
        "the pops trimmed the tree"
    );
    let snap = store.begin_read().expect("read");
    let live = snap
        .root_at(BlockHeight::from_raw(TIP - POPS + 1))
        .expect("root");
    assert_eq!(live, AtHeight::Recorded(after.root));
    assert!(store.connect_state().is_live());
    drop(snap);
    drop(store);
    cleanup(&path);
}

#[test]
fn popping_nothing_reads_nothing_and_succeeds() {
    let (path, store) = chain("edge-zero");
    let out: Result<usize, TestErr> = store.write(|batch| Ok(batch.pop_many(0)?.len()));
    assert_eq!(out, Ok(0));
    drop(store);
    cleanup(&path);
}

/// Rewrite the leaf at `position` under the store's back (a raw redb
/// transaction, as the read tests plant rows). `edit` decides the bytes:
/// a still-canonical scalar diverges the chunk; a non-element is not on
/// the curve.
fn rewrite_leaf(
    path: &std::path::Path,
    position: u64,
    edit: impl FnOnce(&mut [u8; TreeLeaf::LEN]),
) {
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut leaves = txn.open_table(CURVE_TREE_LEAVES).expect("t");
        let held: TreeLeaf = leaves
            .get(position)
            .expect("get")
            .expect("a leaf below the count")
            .value()
            .decode()
            .expect("decodes");
        let mut bytes = *held.as_bytes();
        edit(&mut bytes);
        leaves
            .insert(position, TreeLeaf::from_bytes(bytes).encoded().as_encoded())
            .expect("plant");
    }
    txn.commit().expect("commit");
}

#[test]
fn a_wrong_leaf_under_the_edge_halts_the_pop_run_at_the_leaf_chunk() {
    let (path, store) = chain("edge-leaf");
    drop(store);
    // Position 0 sits in the leaf layer's last (and only) chunk and below
    // anything the pops trim: no undo row restores it.
    // The low byte of the first scalar: still canonical, not the leaf.
    rewrite_leaf(&path, 0, |bytes| bytes[0] ^= 1);
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let out: Result<usize, TestErr> = store.write(|batch| Ok(batch.pop_many(POPS)?.len()));
    let want = StoreInvariant::RightEdgeDiverged {
        observed: EdgeFault::Chunk { layer: 0 },
    };
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(TIP - POPS + 1),
            row: want,
        },
        "SI-5 halts at the height the last pop worked at"
    );
    // Nothing landed: the tip is where it was.
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded;
    assert_eq!(tip.map(|t| t.height.to_raw()), Some(TIP));
    drop(store);
    cleanup(&path);
}

#[test]
fn an_off_curve_leaf_on_the_edge_names_the_leaves_table() {
    let (path, store) = chain("edge-off-curve-leaf");
    drop(store);
    // Not a field element: the rebuild refuses it before it can diverge.
    rewrite_leaf(&path, 0, |bytes| bytes.fill(0xFF));
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let out: Result<usize, TestErr> = store.write(|batch| Ok(batch.pop_many(POPS)?.len()));
    let want = StoreInvariant::CellCorrupt {
        key: "curve_tree_leaves",
        fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
            codec: "tree_leaf",
            reason: "a leaf scalar on the tree's right edge is not on its curve",
        }),
    };
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(TIP - POPS + 1),
            row: want,
        },
        "SI-5 halts at the height the last pop worked at"
    );
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded;
    assert_eq!(tip.map(|t| t.height.to_raw()), Some(TIP));
    drop(store);
    cleanup(&path);
}

#[test]
fn a_summary_and_live_root_moved_together_fail_the_root_arm() {
    // SI-12 compares the summary's root with `curve_tree_roots[tip + 1]`;
    // move both to the same wrong value and only the tree can tell. A pop
    // would restore the summary from its pre-image, so the belt is run
    // directly over the planted tip.
    let (path, store) = chain("edge-root");
    drop(store);
    let wrong = CurveTreeRoot::from_bytes([0x5a; 32]);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut meta = txn.open_table(CURVE_TREE_META).expect("t");
            let mut state: CurveTreeState = meta
                .get(())
                .expect("get")
                .expect("summary")
                .value()
                .decode()
                .expect("decodes");
            state.root = wrong;
            meta.insert((), state.encoded().as_encoded())
                .expect("plant");
            txn.open_table(CURVE_TREE_ROOTS)
                .expect("t")
                .insert(TIP + 1, wrong.encoded().as_encoded())
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.check_right_edge()?));
    let want = StoreInvariant::RightEdgeDiverged {
        observed: EdgeFault::Root,
    };
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));
    drop(store);
    cleanup(&path);
}
