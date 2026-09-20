// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-OUT-KI snapshot tests: K1/K2/O1/O2 on `ReadSnapshot`, sibling of
//! `output_reads.rs` so the surface's tests live with its body.

use redb::ReadableTable;
use shekyl_types::{BlockHash, BlockHeight, KeyImage};

use shekyl_chain_rules::RuleSet;

use super::connect_fixtures::{candidate, connect_chain, facts, judge, spend};
use super::error::{StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::Canonical;
use crate::ids::OutputSlot;
use crate::schema::OUTPUT_AMOUNTS;

fn h(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

fn gi(raw: u64) -> shekyl_types::GlobalOutputIndex {
    shekyl_types::GlobalOutputIndex::from_raw(raw)
}

/// Three blocks: genesis (one miner output), a block with a two-output
/// spend (plus its miner output), a block with one miner output. Global
/// indices run 0..=4 in block / tx / vout order: 0 = miner@0, 1 = miner@1,
/// 2 and 3 = the spend's vouts, 4 = miner@2.
fn output_chain(path: &std::path::Path) -> (ChainStore, Vec<BlockHash>) {
    let store = ChainStore::create(path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 2)], vec![]]);
    (store, hashes)
}

// ------------------------------------------------------------ S-OUT-KI K1

#[test]
fn has_key_image_is_true_for_a_spent_image_and_false_otherwise_on_one_snapshot() {
    let path = tmp("read-has-key-image");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(
        &store,
        &[vec![], vec![spend(0x5e, 1)], vec![spend(0x6f, 1)]],
    );
    let snap = store.begin_read().expect("read");
    // N calls on one snapshot are the batch form `has_key_images` was
    // (SOK-3): every answer is against the same committed state.
    for (image, spent) in [(0x5e, true), (0x6f, true), (0x00, false), (0xee, false)] {
        assert_eq!(
            snap.has_key_image(&KeyImage::from_bytes([image; 32]))
                .expect("read"),
            spent,
            "key image {image:#04x}: membership is exact, `bool` is the shape"
        );
    }
    cleanup(&path);
}

#[test]
fn has_key_image_on_the_snapshot_and_in_the_batch_are_one_body() {
    let path = tmp("read-has-key-image-two-readers");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    let images = [0x5eu8, 0x00];
    let from_snapshot: Vec<bool> = images
        .iter()
        .map(|b| {
            snap.has_key_image(&KeyImage::from_bytes([*b; 32]))
                .expect("read")
        })
        .collect();
    let from_batch: Result<Vec<bool>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(images
            .iter()
            .map(|b| {
                shekyl_chain_rules::ChainView::has_key_image(&view, &KeyImage::from_bytes([*b; 32]))
                    .expect("read")
            })
            .collect())
    });
    assert_eq!(
        from_snapshot,
        from_batch.expect("batch"),
        "the validator's view and the read snapshot answer from one body"
    );
    cleanup(&path);
}

// ------------------------------------------------------------ S-OUT-KI K2

#[test]
fn key_images_yields_exactly_the_connected_set() {
    let path = tmp("read-key-images");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(
        &store,
        &[
            vec![],
            vec![spend(0x5e, 1), spend(0x01, 1)],
            vec![spend(0x6f, 1)],
        ],
    );
    let snap = store.begin_read().expect("read");
    let mut scanned: Vec<[u8; 32]> = snap
        .key_images()
        .expect("open")
        .map(|r| r.expect("item").to_bytes())
        .collect();
    scanned.sort_unstable();
    let mut expected = vec![[0x5eu8; 32], [0x01; 32], [0x6f; 32]];
    expected.sort_unstable();
    assert_eq!(
        scanned, expected,
        "the scan is the connected set, no more and no less — compared as a set, \
         because the digest consumer is order-insensitive and no other consumer exists"
    );
    cleanup(&path);
}

#[test]
fn key_images_on_an_empty_chain_is_an_empty_scan_not_an_error() {
    let path = tmp("read-key-images-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.key_images().expect("open").count(),
        0,
        "the seal creates `spent_keys` (amendment A2), so an empty chain scans as empty"
    );
    cleanup(&path);
}

#[test]
fn a_snapshot_sees_one_committed_state_across_a_concurrent_connect() {
    let path = tmp("read-key-images-snapshot-isolation");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    // Connect another spend after the snapshot was taken.
    let cand = candidate(2, hashes[1], vec![spend(0x6f, 1)]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        batch.connect(judge(&view, cand)?, facts(2, 0), RuleSet::GENESIS)?;
        Ok(())
    });
    out.expect("connect");
    // The older snapshot still answers from the state it was opened on —
    // the C++'s "no getheight + gethash(height-1)" hazard is the handle's
    // shape here, not a warning in prose.
    assert!(!snap
        .has_key_image(&KeyImage::from_bytes([0x6f; 32]))
        .expect("read"));
    assert_eq!(snap.key_images().expect("open").count(), 1);
    // A fresh snapshot sees both.
    let fresh = store.begin_read().expect("read");
    assert!(fresh
        .has_key_image(&KeyImage::from_bytes([0x6f; 32]))
        .expect("read"));
    assert_eq!(fresh.key_images().expect("open").count(), 2);
    cleanup(&path);
}

// --------------------------------------------------------- S-OUT-KI O1 / O2

#[test]
fn output_is_recorded_at_every_index_below_the_count_and_beyond_count_from_it() {
    let path = tmp("read-output");
    let (store, _) = output_chain(&path);
    let snap = store.begin_read().expect("read");

    // Index 0: genesis's miner output, stored under amount 0 with the
    // ct-base commitment, unlock = height + 60 (fixture).
    assert_eq!(
        snap.output(gi(0)).expect("read"),
        AtIndex::Recorded(RecordedOutput {
            pubkey: shekyl_types::OneTimePubkey::from_bytes([0x40; 32]),
            commitment: shekyl_types::CommitmentBytes::from_bytes([0x70; 32]),
            height: h(0),
            unlock_time: crate::codec::stored_timelock(60),
        })
    );
    // Index 3: the spend's second vout, recorded at height 1.
    assert_eq!(
        snap.output(gi(3)).expect("read"),
        AtIndex::Recorded(RecordedOutput {
            pubkey: shekyl_types::OneTimePubkey::from_bytes([0x81; 32]),
            commitment: shekyl_types::CommitmentBytes::from_bytes([0xa1; 32]),
            height: h(1),
            unlock_time: crate::codec::stored_timelock(0),
        })
    );
    // Index 4 is the last; 5 and beyond are `BeyondCount`, never an error
    // and never a default.
    assert!(matches!(
        snap.output(gi(4)).expect("read"),
        AtIndex::Recorded(_)
    ));
    assert_eq!(snap.output(gi(5)).expect("read"), AtIndex::BeyondCount);
    assert_eq!(
        snap.output(gi(u64::MAX)).expect("read"),
        AtIndex::BeyondCount
    );
    cleanup(&path);
}

#[test]
fn output_origin_is_the_global_read_and_agrees_with_output_on_every_index() {
    let path = tmp("read-output-origin");
    let (store, hashes) = output_chain(&path);
    let snap = store.begin_read().expect("read");
    // The spend at height 1 produced indices 2 and 3 as vouts 0 and 1.
    let AtIndex::Recorded(origin) = snap.output_origin(gi(2)).expect("read") else {
        panic!("index 2 is recorded");
    };
    assert_eq!(
        origin.local_index,
        shekyl_types::OutputIndexInTx::from_raw(0)
    );
    let AtIndex::Recorded(origin3) = snap.output_origin(gi(3)).expect("read") else {
        panic!("index 3 is recorded");
    };
    assert_eq!(origin3.tx_hash, origin.tx_hash, "same spend");
    assert_eq!(
        origin3.local_index,
        shekyl_types::OutputIndexInTx::from_raw(1)
    );
    // Miner outputs name their block's miner tx, which is not the block hash.
    let AtIndex::Recorded(miner0) = snap.output_origin(gi(0)).expect("read") else {
        panic!("index 0 is recorded");
    };
    assert_ne!(miner0.tx_hash.as_bytes(), hashes[0].as_bytes());
    assert_eq!(
        snap.output_origin(gi(5)).expect("read"),
        AtIndex::BeyondCount
    );

    // SOK-2 from the read side: `output_amounts[(0, i)].output_id == i` for
    // every recorded index, so O1 and O2 at `i` describe one output.
    for i in 0..5u64 {
        let amounts = snap.open_table(OUTPUT_AMOUNTS).expect("t");
        let record = amounts
            .get(OutputSlot::confidential(gi(i)).key())
            .expect("g")
            .expect("recorded")
            .value()
            .decode()
            .expect("decodes");
        assert_eq!(record.output_id.to_raw(), i, "two counters, one output");
    }
    cleanup(&path);
}

#[test]
fn a_hole_below_the_output_count_is_si9_not_beyond_count() {
    let path = tmp("read-output-hole");
    let (store, _) = output_chain(&path);
    drop(store);
    // Plant the hole through the raw engine: remove `(0, 2)` from
    // `output_amounts`, leaving `output_txs`' count at 5.
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut amounts = txn.open_table(OUTPUT_AMOUNTS).expect("t");
            amounts
                .remove(OutputSlot::confidential(gi(2)).key())
                .expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .output(gi(2))
        .expect_err("a hole below the count is corruption");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::IdNotFresh)
        ),
        "a hole below the count is SI-9 — the count and the keys disagree — got {err:?}"
    );
    // The neighbours are unaffected, and the count still says 5.
    assert!(matches!(
        snap.output(gi(3)).expect("read"),
        AtIndex::Recorded(_)
    ));
    assert_eq!(snap.output(gi(5)).expect("read"), AtIndex::BeyondCount);
    // The read never armed the writer (the halt is the writer's state).
    assert_eq!(store.connect_state(), ConnectState::Live);
    let _ = store;
    cleanup(&path);
}

#[test]
fn a_row_whose_output_id_disagrees_with_its_slot_is_si9_not_served() {
    // `connect` refuses to write this (SOK-2's belt); a raw or corrupt file
    // can still hold it, and serving it would hand out the wrong output
    // under a global index. O1 validates the join where it decodes.
    let path = tmp("read-output-join-mismatch");
    let (store, _) = output_chain(&path);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut amounts = txn.open_table(OUTPUT_AMOUNTS).expect("t");
            let slot = OutputSlot::confidential(gi(1)).key();
            let mut record = amounts
                .get(slot)
                .expect("g")
                .expect("recorded")
                .value()
                .decode()
                .expect("decodes");
            record.output_id = crate::ids::OutputStorageId::from_raw(7);
            amounts
                .insert(slot, record.encoded().as_encoded())
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .output(gi(1))
        .expect_err("a disagreeing join is corruption");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::IdNotFresh)
        ),
        "join mismatch is SI-9, got {err:?}"
    );
    assert!(matches!(
        snap.output(gi(0)).expect("read"),
        AtIndex::Recorded(_)
    ));
    cleanup(&path);
}

#[test]
fn a_stray_row_at_or_beyond_the_count_is_beyond_count_not_served() {
    // Bound first: the count (`output_txs.len()`) decides what exists, so a
    // row planted at index 9 in `output_amounts` is not `Recorded` — the
    // reads never look past the count.
    let path = tmp("read-output-stray");
    let (store, _) = output_chain(&path);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut amounts = txn.open_table(OUTPUT_AMOUNTS).expect("t");
            let record = amounts
                .get(OutputSlot::confidential(gi(0)).key())
                .expect("g")
                .expect("recorded")
                .value()
                .decode()
                .expect("decodes");
            amounts
                .insert(
                    OutputSlot::confidential(gi(9)).key(),
                    record.encoded().as_encoded(),
                )
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.output(gi(9)).expect("read"), AtIndex::BeyondCount);
    assert_eq!(
        snap.output_origin(gi(9)).expect("read"),
        AtIndex::BeyondCount
    );
    cleanup(&path);
}
