// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The snapshot view answers every read the batch view answers, over the
//! same committed chain — the reads are one body, and this holds the two
//! projections of it to each other (the conformance suite's chain, so a
//! disagreement here and one there are about the same blocks).

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{AtHeight, ChainView, HeaderView};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, KeyImage, PCanonicalId};

use super::super::conformance_tests::twin_chains;
use super::super::store_tests::{cleanup, TestErr};
use super::SnapshotView;

/// Every read the validator makes, at every probed height, rendered for
/// comparison. The two views' faults are both `StoreError`, so a fault is
/// rendered as well — a view that faulted where the other answered fails.
fn every_read<'id, V: ChainView<'id>>(view: &V, hashes: &[BlockHash]) -> Vec<String>
where
    V::Fault: core::fmt::Debug,
{
    let mut out = vec![format!("tip {:?}", view.tip())];
    for h in 0..8u64 {
        let h = BlockHeight::from_raw(h);
        out.push(format!("header_at {h:?} {:?}", view.header_at(h)));
        out.push(format!("block_at {h:?} {:?}", view.block_at(h)));
        out.push(format!("root_at {h:?} {:?}", view.root_at(h)));
        out.push(format!("leaf_count_at {h:?} {:?}", view.leaf_count_at(h)));
        out.push(format!("depth_at {h:?} {:?}", view.depth_at(h)));
        out.push(format!("outputs_at {h:?} {:?}", view.outputs_at(h)));
        out.push(format!(
            "median_at {h:?} {:?}",
            view.long_term_effective_median_at(h)
        ));
        out.push(format!("burned_through {h:?} {:?}", view.burned_through(h)));
        for width in [0, 3, 100] {
            out.push(format!(
                "weights_window {h:?} {width} {:?}",
                view.weights_window(h, BlockCount::from_raw(width))
            ));
        }
    }
    for hash in hashes {
        out.push(format!("height_of {:?}", view.height_of(hash)));
    }
    out.push(format!("tree_frontier {:?}", view.tree_frontier()));
    out.push(format!("total_burned {:?}", view.total_burned()));
    out.push(format!(
        "has_key_image {:?}",
        view.has_key_image(&KeyImage::from_bytes([0x5a; 32]))
    ));
    out.push(format!(
        "bond_record {:?}",
        view.bond_record(&PCanonicalId::from_bytes([0x5a; 32]))
    ));
    out.push(format!("bond_records {:?}", view.bond_records()));
    out.push(format!(
        "last_settled_slash_epoch {:?}",
        view.last_settled_slash_epoch()
    ));
    out
}

#[test]
fn the_snapshot_view_answers_every_read_as_the_batch_view_does() {
    let (store, path, _mock, blocks) = twin_chains(5);
    let hashes: Vec<BlockHash> = blocks
        .iter()
        .map(|b| b.block.hash())
        .chain(core::iter::once(fixture::UNRECORDED_REFERENCE))
        .collect();
    let batch: Result<Vec<String>, TestErr> =
        store.write(|batch| Ok(every_read(&batch.chain_view(), &hashes)));
    let batch = batch.expect("batch reads");
    let snapshot = store.begin_read().expect("snapshot");
    let snap = every_read(&SnapshotView::new(&snapshot), &hashes);
    assert_eq!(snap, batch);
    // The fixture is not trivially empty: five recorded headers, and the
    // root above the tip is absent on both.
    assert!(matches!(
        SnapshotView::new(&snapshot).header_at(BlockHeight::from_raw(4)),
        Ok(AtHeight::Recorded(_))
    ));
    assert!(matches!(
        SnapshotView::new(&snapshot).root_at(BlockHeight::from_raw(6)),
        Ok(AtHeight::AboveTip)
    ));
    drop(snapshot);
    drop(store);
    cleanup(&path);
}
