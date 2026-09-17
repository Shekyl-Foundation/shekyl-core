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

use shekyl_chain_rules::{AtHeight, RuleSetId};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Transaction;

use super::connect_fixtures::{candidate, facts, judge, spend};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{Canonical, CurveRoot};
use crate::schema::{BLOCK_INFO, CURVE_TREE_ROOTS};

fn connect_chain(store: &ChainStore, listed: &[Vec<Transaction>]) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    let mut previous = [0u8; 32];
    let mut cands = Vec::new();
    for (h, txs) in listed.iter().enumerate() {
        let cand = candidate(h as u64, previous, txs.clone());
        previous = cand.block.hash();
        hashes.push(previous);
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(judge(&view, cand)?, facts(h as u64, 0), RuleSetId::GENESIS)?;
        }
        Ok(())
    });
    out.expect("chain connects");
    hashes
}

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
            .insert(1, CurveRoot::from_bytes([1; 32]).encoded().as_encoded())?;
        Ok(())
    });
    planted.expect("plant");
    let g = candidate(0, [0; 32], Vec::new());
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
            hash: BlockHash::from_bytes(hashes[1]),
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
        assert_eq!(
            snap.height_of(&BlockHash::from_bytes(*hash)).expect("read"),
            Some(h(i as u64))
        );
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
        assert_eq!(info.timestamp, 1_000 + 60 * height, "the fixture's clock");
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
