// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`SnapshotView`] reads what [`BatchView`](super::view::BatchView) reads.
//!
//! The two share every body; the one thing that differs is the fault
//! policy. So the test is a conformance test over a real chain — one
//! connected through `form` → `validate` → `connect`, listing real spends
//! — that asks both views every height-keyed read at every height (and one
//! past the tip), plus the chain-wide reads, and holds the answers equal.

use shekyl_chain_rules::{AtHeight, ChainView, HeaderView};
use shekyl_types::{BlockCount, BlockHeight, KeyImage};

use super::connect_fixtures::{connect_chain, Listed, FIRST_SPEND_HEIGHT};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

/// Every [`ChainView`] read the facts and the rules' derivations make,
/// answered by both views over one committed chain.
#[test]
fn a_snapshot_view_reads_what_a_batch_view_reads_at_every_height() {
    let path = tmp("snapshot-view-conformance");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Coinbase-only blocks, then three blocks each listing a real spend.
    let mut listed: Vec<Vec<Listed>> =
        vec![Vec::new(); usize::try_from(FIRST_SPEND_HEIGHT).expect("small")];
    for _ in 0..3 {
        listed.push(vec![Listed::Spend { fee: 1_000 }]);
    }
    let grown = connect_chain(&store, &listed);
    let tip = u64::try_from(listed.len()).expect("small") - 1;
    let spent: Vec<KeyImage> = (FIRST_SPEND_HEIGHT..=tip)
        .flat_map(|h| grown.images_at(BlockHeight::from_raw(h)).to_vec())
        .map(KeyImage::from_bytes)
        .collect();
    assert_eq!(spent.len(), 3, "the fixture spent three coinbases");

    let snap = store.begin_read().expect("read");
    let snapshot = SnapshotView::new(&snap);
    let out: Result<(), TestErr> = store.write(|batch| {
        let batch_view = batch.chain_view();
        assert_eq!(snapshot.tip()?, batch_view.tip()?, "tip");
        assert_eq!(
            snapshot.tip()?.map(|t| t.height.to_raw()),
            Some(tip),
            "the snapshot names the committed tip"
        );
        for raw in 0..=tip + 1 {
            let h = BlockHeight::from_raw(raw);
            assert_eq!(
                snapshot.header_at(h)?,
                batch_view.header_at(h)?,
                "header_at({raw})"
            );
            assert_eq!(
                snapshot.block_at(h)?,
                batch_view.block_at(h)?,
                "block_at({raw})"
            );
            assert_eq!(
                snapshot.root_at(h)?,
                batch_view.root_at(h)?,
                "root_at({raw})"
            );
            assert_eq!(
                snapshot.leaf_count_at(h)?,
                batch_view.leaf_count_at(h)?,
                "leaf_count_at({raw})"
            );
            assert_eq!(
                snapshot.outputs_at(h)?,
                batch_view.outputs_at(h)?,
                "outputs_at({raw})"
            );
            assert_eq!(
                snapshot.weights_window(h, BlockCount::from_raw(100))?,
                batch_view.weights_window(h, BlockCount::from_raw(100))?,
                "weights_window({raw})"
            );
            assert_eq!(
                snapshot.long_term_effective_median_at(h)?,
                batch_view.long_term_effective_median_at(h)?,
                "long_term_effective_median_at({raw})"
            );
            assert_eq!(
                snapshot.burned_through(h)?,
                batch_view.burned_through(h)?,
                "burned_through({raw})"
            );
            if let AtHeight::Recorded(block) = snapshot.block_at(h)? {
                assert_eq!(
                    snapshot.height_of(&block.header.hash)?,
                    Some(h),
                    "height_of(block {raw})"
                );
            }
        }
        assert_eq!(
            snapshot.tree_frontier()?,
            batch_view.tree_frontier()?,
            "frontier"
        );
        assert_eq!(
            snapshot.total_burned()?,
            batch_view.total_burned()?,
            "total_burned"
        );
        for image in &spent {
            assert!(snapshot.has_key_image(image)?, "a spent image is held");
            assert_eq!(
                snapshot.has_key_image(image)?,
                batch_view.has_key_image(image)?
            );
        }
        assert!(
            !snapshot.has_key_image(&KeyImage::from_bytes([0x5a; 32]))?,
            "an image nobody spent is not held"
        );
        assert_eq!(
            snapshot.bond_records()?,
            batch_view.bond_records()?,
            "bond_records"
        );
        assert_eq!(
            snapshot.last_settled_slash_epoch()?,
            batch_view.last_settled_slash_epoch()?,
            "last_settled_slash_epoch"
        );
        Ok(())
    });
    out.expect("both views read the committed chain");
    drop(snap);
    drop(store);
    cleanup(&path);
}
