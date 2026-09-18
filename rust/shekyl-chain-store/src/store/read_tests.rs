// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The committed-chain read surface (S-CHAIN-R, `DRS_E1_SCHAIN_R.md` §3,
//! §7 commits 3–5), pinned read by read against the shapes the plan rules:
//! `AtHeight` above the dense tip and SI-7 below it, `Option` by hash,
//! `TipState` carrying the writer's state outside the `Option`, ranges
//! half-open and clamped, bodies verified against the recorded identity,
//! `RawBlockBytes` a type and not a name — and, on every SI-7 the snapshot
//! returns, the writer **still `Live`**: a read never arms the halt
//! (`DAEMON_REDB_STORE.md` §3.6.2, the read-side half).

use redb::ReadableTable;
use shekyl_chain_rules::{AtHeight, RuleSetId};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::{candidate, connect_chain, facts, judge, spend, GENESIS_ID};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::Canonical;
use crate::ids::OutputSlot;
use crate::schema::{BLOCK_INFO, CURVE_TREE_ROOTS, OUTPUT_AMOUNTS};

fn h(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

fn is_si7_absent(e: &StoreError, key: &str) -> bool {
    matches!(
        e,
        StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: k,
            fault: CellFault::Absent,
        }) if *k == key
    )
}

// ------------------------------------------------------------------ R1

#[test]
fn tip_on_a_fresh_file_is_none_and_live_not_an_engine_error() {
    let path = tmp("read-tip-fresh");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    // The table exists from the seal (A2), so an empty chain is a value.
    assert_eq!(
        snap.tip().expect("tip"),
        TipState {
            recorded: None,
            connect: ConnectState::Live,
        }
    );
    cleanup(&path);
}

#[test]
fn tip_carries_a_genesis_halt_with_nothing_recorded() {
    let path = tmp("read-tip-halted-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Plant `curve_tree_roots[1]` so the genesis connect's SI-4 belt fires
    // at height 0 — a halt with no recorded tip (SCR-18).
    let planted: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)?
            .insert(1, CurveTreeRoot::from_bytes([1; 32]).encoded().as_encoded())?;
        Ok(())
    });
    planted.expect("plant");
    let g = candidate(0, BlockHash::NULL, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, g)?, facts(0, 0), RuleSetId::GENESIS)?)
    });
    assert!(out.is_err(), "SI-4 refuses the genesis connect");
    let snap = store.begin_read().expect("read");
    let tip = snap.tip().expect("tip");
    assert_eq!(tip.recorded, None, "nothing recorded");
    assert!(
        matches!(tip.connect, ConnectState::Halted { at_height, .. } if at_height == h(0)),
        "and the writer is halted at genesis: {:?}",
        tip.connect
    );
    cleanup(&path);
}

#[test]
fn tip_is_the_last_recorded_block_and_the_writer_is_live() {
    let path = tmp("read-tip-recorded");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    let tip = snap.tip().expect("tip");
    assert_eq!(
        tip.recorded.expect("recorded"),
        shekyl_chain_rules::Tip {
            height: h(1),
            hash: hashes[1],
        }
    );
    assert_eq!(tip.connect, ConnectState::Live);
    cleanup(&path);
}

// ------------------------------------------------------------------ R2

#[test]
fn height_of_is_some_for_a_recorded_hash_and_none_otherwise() {
    let path = tmp("read-height-of");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(snap.height_of(hash).expect("read"), Some(h(i as u64)));
    }
    assert_eq!(
        snap.height_of(&BlockHash::from_bytes([0xee; 32]))
            .expect("read"),
        None,
        "by hash, absence has one meaning"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ R3

#[test]
fn block_info_is_recorded_at_and_below_the_tip_and_above_tip_above_it() {
    let path = tmp("read-block-info");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![spend(0x5e, 2)], vec![]]);
    let snap = store.begin_read().expect("read");
    for height in 0..3u64 {
        let AtHeight::Recorded(info) = snap.block_info(h(height)).expect("read") else {
            panic!("height {height} is recorded");
        };
        assert_eq!(
            info.timestamp,
            shekyl_types::Timestamp::from_raw(1_000 + 60 * height),
            "the fixture's clock"
        );
        assert_eq!(info.cumulative_tx_count, u64::from(height >= 1), "0, 1, 1");
    }
    assert!(matches!(
        snap.block_info(h(3)).expect("read"),
        AtHeight::AboveTip
    ));
    assert!(matches!(
        snap.block_info(h(u64::MAX)).expect("read"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn a_hole_below_the_tip_is_si7_and_does_not_halt_the_writer() {
    let path = tmp("read-hole-no-halt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    drop(store);
    // Delete `block_info[1]` behind the store's back: a hole below the tip.
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(BLOCK_INFO)
            .expect("t")
            .remove(1)
            .expect("remove")
            .expect("row 1 existed");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let e = snap
        .block_info(h(1))
        .expect_err("a hole is SI-7, never AboveTip");
    assert!(is_si7_absent(&e, "block_info"), "{e}");
    // The read-side half of §3.6.2: the snapshot returned the fault and
    // armed nothing. A `BatchView` read of the same row would have poisoned
    // its batch and halted the writer.
    assert_eq!(store.connect_state(), ConnectState::Live);
    assert_eq!(snap.tip().expect("tip").connect, ConnectState::Live);
    // And the same range read reports the hole as that item's error, not
    // as an early end.
    let AtHeight::Recorded(rows) = snap.block_infos(h(0)..h(3)).expect("range") else {
        panic!("start 0 is at or below the tip");
    };
    let rows: Vec<_> = rows.collect();
    assert_eq!(rows.len(), 3);
    assert!(rows[0].is_ok() && rows[2].is_ok());
    assert!(is_si7_absent(
        rows[1].as_ref().expect_err("the hole"),
        "block_info"
    ));
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

// ------------------------------------------------------------------ R4

#[test]
fn block_infos_is_above_tip_when_the_start_is_and_clamps_the_end_otherwise() {
    let path = tmp("read-block-infos");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // Start above the tip: the typed arm, matched — not an empty iterator.
    assert!(matches!(
        snap.block_infos(h(3)..h(10)).expect("range"),
        AtHeight::AboveTip
    ));
    // Start at or below, end past the tip: clamped to `tip + 1`, ascending.
    let AtHeight::Recorded(rows) = snap.block_infos(h(1)..h(10)).expect("range") else {
        panic!("start 1 is recorded");
    };
    let heights: Vec<u64> = rows.map(|r| r.expect("row").0.to_raw()).collect();
    assert_eq!(heights, [1, 2]);
    // Half-open: `start..start + count` yields `count` rows (SCR-20).
    let AtHeight::Recorded(rows) = snap.block_infos(h(0)..h(2)).expect("range") else {
        panic!("start 0 is recorded");
    };
    assert_eq!(rows.count(), 2);
    // An empty half-open range at or below the tip is an empty iterator,
    // not `AboveTip`: the start *is* recorded.
    let AtHeight::Recorded(rows) = snap.block_infos(h(1)..h(1)).expect("range") else {
        panic!("start 1 is recorded");
    };
    assert_eq!(rows.count(), 0);
    // Empty chain: every start is above the (absent) tip.
    let empty = tmp("read-block-infos-empty");
    let fresh = ChainStore::create(&empty, EPOCH).expect("create");
    assert!(matches!(
        fresh
            .begin_read()
            .expect("read")
            .block_infos(h(0)..h(1))
            .expect("range"),
        AtHeight::AboveTip
    ));
    cleanup(&empty);
    cleanup(&path);
}

// ------------------------------------------------------------------ R5–R7

#[test]
fn block_returns_the_body_verified_against_the_recorded_identity() {
    let path = tmp("read-block");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    let AtHeight::Recorded(body) = snap.block(h(1)).expect("read") else {
        panic!("height 1 is recorded");
    };
    assert_eq!(body.hash, hashes[1]);
    assert_eq!(
        body.block.hash(),
        hashes[1],
        "the body hashes to its identity"
    );
    assert_eq!(body.block.transaction_hashes.len(), 1);
    assert!(matches!(
        snap.block(h(2)).expect("read"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn a_rewritten_blob_is_si7_on_block_and_blocks_but_block_blob_still_hands_out_the_bytes() {
    let path = tmp("read-rewritten-blob");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    // Rewrite `blocks[1]` to a different, parseable block: the identity on
    // `block_info[1]` no longer matches.
    let impostor = candidate(1, BlockHash::from_bytes([0x77; 32]), Vec::new())
        .block
        .serialize();
    let out: Result<(), TestErr> = store.write(|batch| {
        batch.open_upsert_table(crate::schema::BLOCKS)?.upsert(
            1,
            crate::codec::Raw::<crate::codec::BlockBody>::new(&impostor),
        )?;
        Ok(())
    });
    out.expect("rewrite");
    let snap = store.begin_read().expect("read");
    let e = snap.block(h(1)).expect_err("verified read refuses");
    assert!(
        matches!(
            e,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "blocks",
                fault: CellFault::Undecodable(_),
            })
        ),
        "{e}"
    );
    let AtHeight::Recorded(rows) = snap.blocks(h(0)..h(3)).expect("range") else {
        panic!("start 0 is recorded");
    };
    let rows: Vec<_> = rows.collect();
    assert!(
        rows[0].is_ok() && rows[2].is_ok(),
        "the neighbours are fine"
    );
    assert!(rows[1].is_err(), "the rewritten row is that item's fault");
    // The unverified reader hands out exactly the bytes on disk (Q2): the
    // sync path forwards them, and a consensus caller cannot get here
    // without naming `RawBlockBytes`.
    let AtHeight::Recorded(raw) = snap.block_blob(h(1)).expect("blob") else {
        panic!("height 1 is recorded");
    };
    assert_eq!(raw.into_wire_bytes(), impostor);
    // And none of it halted the writer.
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

#[test]
fn blocks_range_clamps_at_the_tip_and_yields_the_last_height_of_a_half_open_range() {
    let path = tmp("read-blocks-range");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // `start..start + count` yields `count` rows, the last one included —
    // the inclusive-`h2` port hazard (SCR-20).
    let (start, count) = (1u64, 3u64);
    let AtHeight::Recorded(rows) = snap.blocks(h(start)..h(start + count)).expect("range") else {
        panic!("start 1 is recorded");
    };
    let got: Vec<(u64, BlockHash)> = rows
        .map(|r| {
            let (height, body) = r.expect("row");
            (height.to_raw(), body.block.hash())
        })
        .collect();
    assert_eq!(got.len(), usize::try_from(count).expect("small"));
    assert_eq!(
        got.last().expect("three rows").0,
        start + count - 1,
        "the last height is yielded"
    );
    for (height, hash) in &got {
        assert_eq!(*hash, hashes[usize::try_from(*height).expect("small")]);
    }
    // End past the tip clamps; start past the tip is the typed arm.
    let AtHeight::Recorded(rows) = snap.blocks(h(2)..h(100)).expect("range") else {
        panic!("start 2 is recorded");
    };
    assert_eq!(rows.count(), 2);
    assert!(matches!(
        snap.blocks(h(4)..h(5)).expect("range"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn block_blob_above_the_tip_is_above_tip_and_a_hole_is_si7() {
    let path = tmp("read-blob-classify");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(crate::schema::BLOCKS)
            .expect("t")
            .remove(0)
            .expect("remove")
            .expect("row 0 existed");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert!(matches!(
        snap.block_blob(h(2)).expect("read"),
        AtHeight::AboveTip
    ));
    let e = snap.block_blob(h(0)).expect_err("a hole below the tip");
    assert!(is_si7_absent(&e, "blocks"), "{e}");
    assert_eq!(
        store.connect_state(),
        ConnectState::Live,
        "a read never arms the halt"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ R8–R9 and the fold reads

/// Connect three blocks handing `burned` per height, so R8/R9 have a fold
/// to read: genesis records none whatever it is handed (the `h > 0` half of
/// the C++ guard), a zero writes no row.
fn connect_burning(store: &ChainStore, burns: &[u64]) {
    let mut previous = BlockHash::NULL;
    let mut cands = Vec::new();
    for h in 0..burns.len() as u64 {
        let cand = candidate(h, previous, Vec::new());
        previous = cand.block.hash();
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(
                judge(&view, cand)?,
                facts(h as u64, burns[h]),
                RuleSetId::GENESIS,
            )?;
        }
        Ok(())
    });
    out.expect("chain connects");
}

#[test]
fn block_burn_reads_zero_for_a_block_with_no_row_and_the_amount_otherwise() {
    let path = tmp("read-block-burn");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // genesis is handed 9 and records none; block 1 burns 0 (no row);
    // block 2 burns 25 (a row).
    connect_burning(&store, &[9, 0, 25]);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.block_burn(h(0)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(0)),
        "genesis: no row"
    );
    assert_eq!(
        snap.block_burn(h(1)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(0)),
        "zero burn: no row"
    );
    assert_eq!(
        snap.block_burn(h(2)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(25))
    );
    assert_eq!(snap.block_burn(h(3)).expect("read"), AtHeight::AboveTip);
    cleanup(&path);
}

#[test]
fn block_burn_on_a_chain_that_has_never_burned_is_zero_not_an_engine_error() {
    let path = tmp("read-block-burn-never");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // SCR-17's case: the table exists from the seal (A2), so the absent row
    // is the writer's zero, not `TableDoesNotExist`.
    assert_eq!(
        snap.block_burn(h(1)).expect("read"),
        AtHeight::Recorded(AtomicUnits::ZERO)
    );
    assert_eq!(
        snap.total_burned().expect("read"),
        AtomicUnits::ZERO,
        "absent cell is 0"
    );
    cleanup(&path);
}

#[test]
fn total_burned_is_the_sum_connect_folded() {
    let path = tmp("read-total-burned");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_burning(&store, &[9, 3, 25]);
    let snap = store.begin_read().expect("read");
    // Genesis's 9 is not folded (no row, no pre-image); 3 + 25 is.
    assert_eq!(
        snap.total_burned().expect("read"),
        AtomicUnits::from_raw(28)
    );
    cleanup(&path);
}

#[test]
fn the_fold_reads_return_exactly_what_connect_wrote() {
    let path = tmp("read-fold-reads");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(
        &store,
        &[
            vec![],
            vec![spend(0x5e, 1), spend(0x5f, 1)],
            vec![spend(0x60, 1)],
        ],
    );
    let snap = store.begin_read().expect("read");
    for (height, cum) in [(0u64, 0u64), (1, 2), (2, 3)] {
        assert_eq!(
            snap.cumulative_tx_count(h(height)).expect("read"),
            AtHeight::Recorded(cum)
        );
        assert_eq!(
            snap.long_term_effective_median(h(height)).expect("read"),
            AtHeight::Recorded(facts(height, 0).long_term_effective_median.value),
            "the median handed FOR {height}, at {height}"
        );
    }
    assert_eq!(
        snap.cumulative_tx_count(h(3)).expect("read"),
        AtHeight::AboveTip
    );
    assert_eq!(
        snap.long_term_effective_median(h(3)).expect("read"),
        AtHeight::AboveTip
    );
    cleanup(&path);
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
        batch.connect(judge(&view, cand)?, facts(2, 0), GENESIS_ID)?;
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

/// Three blocks: genesis (one miner output), a block with a two-output
/// spend (plus its miner output), a block with one miner output. Global
/// indices run 0..=4 in block / tx / vout order: 0 = miner@0, 1 = miner@1,
/// 2 and 3 = the spend's vouts, 4 = miner@2.
fn output_chain(path: &std::path::Path) -> (ChainStore, Vec<BlockHash>) {
    let store = ChainStore::create(path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 2)], vec![]]);
    (store, hashes)
}

fn gi(raw: u64) -> shekyl_types::GlobalOutputIndex {
    shekyl_types::GlobalOutputIndex::from_raw(raw)
}

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
            .get((0u64, i))
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
            amounts.remove((0u64, 2u64)).expect("remove");
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
