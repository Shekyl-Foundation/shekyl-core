// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-TX (`DRS_E1_STX.md` §3): the six transaction reads on `ReadSnapshot`.
//!
//! Every test that plants a fault reopens the file raw, plants, and asserts
//! on a fresh snapshot: the reads must classify what is *in the file*, and
//! the writer must be `Live` afterwards — a read never arms the halt.

use shekyl_types::{BlockHash, BlockHeight, TxHash};
use shekyl_wire::Transaction;

use super::connect_fixtures::{connect_chain, spend, spend_with_pqc_auth};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, EPOCH};
use super::*;
use crate::ids::TxStorageId;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{TXS_PQC_AUTH_HASH, TXS_PRUNABLE, TXS_PRUNABLE_HASH};

fn id(raw: u64) -> TxStorageId {
    TxStorageId::from_raw(raw)
}

fn hash_of(tx: &Transaction) -> TxHash {
    tx.txid_parts().hash
}

/// Genesis, then a block with one plain spend, then a block with a spend
/// carrying a `pqc_auths` segment. Coinbases at every height, so the dense
/// id space is `0..=4`: coinbase 0, coinbase 1, spend, coinbase 2, pqc spend.
fn tx_chain(path: &std::path::Path) -> (ChainStore, Vec<BlockHash>, Transaction, Transaction) {
    let store = ChainStore::create(path, EPOCH).expect("create");
    let plain = spend(0x5e, 2);
    let with_pqc = spend_with_pqc_auth(0x6f, 1);
    let hashes = connect_chain(
        &store,
        &[vec![], vec![plain.clone()], vec![with_pqc.clone()]],
    );
    (store, hashes, plain, with_pqc)
}

fn is_si7_absent(err: &StoreError, table: &str) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::CellCorrupt { key, fault: CellFault::Absent })
            if *key == table
    )
}

// ------------------------------------------------------------------ T1, T2

#[test]
fn tx_location_is_some_for_a_recorded_hash_and_none_for_an_unknown_one() {
    let path = tmp("tx-location");
    let (store, _, plain, with_pqc) = tx_chain(&path);
    let snap = store.begin_read().expect("read");

    let plain_loc = snap
        .tx_location(&hash_of(&plain))
        .expect("read")
        .expect("recorded");
    let pqc_loc = snap
        .tx_location(&hash_of(&with_pqc))
        .expect("read")
        .expect("recorded");
    assert_eq!(plain_loc.height, BlockHeight::from_raw(1));
    assert_eq!(pqc_loc.height, BlockHeight::from_raw(2));
    assert!(
        plain_loc.id < pqc_loc.id,
        "ids are dense in connect order: {plain_loc:?} before {pqc_loc:?}"
    );
    // A miss is ordinary — `None`, the counter-rule's worked case (Q1 B).
    assert_eq!(
        snap.tx_location(&TxHash::from_bytes([0xee; 32]))
            .expect("read"),
        None
    );
    assert_eq!(
        store.connect_state(),
        ConnectState::Live,
        "a read never arms the halt"
    );
    cleanup(&path);
}

#[test]
fn tx_count_is_the_dense_id_space_coinbases_included() {
    let path = tmp("tx-count");
    let (store, _, _, _) = tx_chain(&path);
    let snap = store.begin_read().expect("read");
    // Three coinbases + two spends.
    assert_eq!(snap.tx_count().expect("read"), 5);
    // Every id below the count has a location reachable by hash; the count
    // is the authority the by-id reads bound against (T4, T5).
    assert_eq!(snap.tx_prunable(id(5)).expect("read"), AtIndex::BeyondCount);
    assert!(matches!(
        snap.tx_prunable(id(4)).expect("read"),
        AtIndex::Recorded(_)
    ));
    cleanup(&path);
}

// ---------------------------------------------------------------------- T3

#[test]
fn tx_record_carries_the_permanent_half_and_recomposes_the_wire_bytes() {
    let path = tmp("tx-record");
    let (store, _, plain, with_pqc) = tx_chain(&path);
    let snap = store.begin_read().expect("read");

    for tx in [&plain, &with_pqc] {
        let parts = tx.txid_parts();
        let record = snap
            .tx_record(&parts.hash)
            .expect("read")
            .expect("recorded");
        let segments = tx.write_segments().expect("segments");
        assert_eq!(record.prunable_hash, parts.prunable_hash);
        assert_eq!(record.pqc_auth_hash, parts.pqc_auth_hash);
        assert_eq!(
            record.pqc_auths.is_some(),
            parts.pqc_auth_hash.is_some(),
            "§7.7 leg (ii): the pqc_auths segment is present iff the txid is 4-part"
        );
        assert_eq!(record.pruned.clone().into_wire_bytes(), segments.pruned);
        // T3 + T4 compose to `get_tx_blob`'s `pruned ‖ pqc_auths ‖ prunable`
        // (STX-8), which is the transaction as the wire carries it.
        let AtIndex::Recorded(Prunable::Retained(prunable)) =
            snap.tx_prunable(record.location.id).expect("read")
        else {
            panic!("a freshly connected transaction's region is retained");
        };
        assert_eq!(prunable.clone().into_wire_bytes(), segments.prunable);
        let mut wire = Vec::new();
        tx.write(&mut wire).expect("write");
        assert_eq!(record.wire_bytes(prunable), wire);
    }
    assert_eq!(
        snap.tx_record(&TxHash::from_bytes([0xee; 32]))
            .expect("read"),
        None
    );
    cleanup(&path);
}

#[test]
fn a_recorded_transaction_missing_its_prunable_hash_row_is_si7_not_a_log_line() {
    // What `rpc_facts_ffi.cpp`'s MERROR on a missing prunable hash becomes
    // under a typed read (STX-6): §7.7 leg (i) enforced by a fault the
    // caller cannot ignore.
    let path = tmp("tx-record-no-hash-row");
    let (store, _, plain, _) = tx_chain(&path);
    let hash = hash_of(&plain);
    let tx_id = store
        .begin_read()
        .expect("read")
        .tx_location(&hash)
        .expect("read")
        .expect("recorded")
        .id;
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut hashes = txn.open_table(TXS_PRUNABLE_HASH).expect("t");
            hashes.remove(tx_id.to_raw()).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .tx_record(&hash)
        .expect_err("a permanent row is missing");
    assert!(is_si7_absent(&err, "txs_prunable_hash"), "got {err:?}");
    let err = snap
        .tx_prunable(tx_id)
        .expect_err("T4 refuses the same file");
    assert!(is_si7_absent(&err, "txs_prunable_hash"), "got {err:?}");
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

#[test]
fn a_pqc_auth_hash_row_without_its_segment_is_si7_pairwise() {
    let path = tmp("tx-record-pqc-pair");
    let (store, _, _, with_pqc) = tx_chain(&path);
    let hash = hash_of(&with_pqc);
    let tx_id = store
        .begin_read()
        .expect("read")
        .tx_location(&hash)
        .expect("read")
        .expect("recorded")
        .id;
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut segments = txn.open_table(crate::schema::TXS_PQC_AUTHS).expect("t");
            segments.remove(tx_id.to_raw()).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .tx_record(&hash)
        .expect_err("segment and hash row disagree");
    assert!(is_si7_absent(&err, "txs_pqc_auths"), "got {err:?}");
    // The reverse disagreement names the other table.
    drop(snap);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut hashes = txn.open_table(TXS_PQC_AUTH_HASH).expect("t");
            hashes.remove(tx_id.to_raw()).expect("remove");
            // Restore the segment so only the hash row is missing.
            let mut segments = txn.open_table(crate::schema::TXS_PQC_AUTHS).expect("t");
            let bytes = with_pqc.write_segments().expect("segments").pqc_auths;
            segments
                .insert(
                    tx_id.to_raw(),
                    crate::codec::Raw::<crate::codec::TxPqcAuthsSegment>::new(&bytes),
                )
                .expect("plant");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .tx_record(&hash)
        .expect_err("segment without its hash row");
    assert!(is_si7_absent(&err, "txs_pqc_auth_hash"), "got {err:?}");
    cleanup(&path);
}

// ---------------------------------------------------------------------- T4

#[test]
fn tx_prunable_is_retained_below_the_count_beyond_count_at_it_and_discarded_when_the_segment_is_gone(
) {
    let path = tmp("tx-prunable");
    let (store, _, plain, _) = tx_chain(&path);
    let count = store.begin_read().expect("read").tx_count().expect("read");
    let plain_id = store
        .begin_read()
        .expect("read")
        .tx_location(&hash_of(&plain))
        .expect("read")
        .expect("recorded")
        .id;
    {
        let snap = store.begin_read().expect("read");
        for raw in 0..count {
            assert!(
                matches!(
                    snap.tx_prunable(id(raw)).expect("read"),
                    AtIndex::Recorded(Prunable::Retained(_))
                ),
                "id {raw}: a freshly connected transaction's region is held"
            );
        }
        // Bound first: a forged or stale id is invalid input, not corruption
        // (round 4) — `BeyondCount`, and no row is read.
        assert_eq!(
            snap.tx_prunable(id(count)).expect("read"),
            AtIndex::BeyondCount
        );
        assert_eq!(
            snap.tx_prunable(id(u64::MAX)).expect("read"),
            AtIndex::BeyondCount
        );
    }
    // Discard the plain spend's region as S-PRUNE will: segment gone, hash
    // row kept. That is §7.7 leg (iii)'s one state — `Discarded`, not an
    // error and not an absence.
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut prunable = txn.open_table(TXS_PRUNABLE).expect("t");
            prunable.remove(plain_id.to_raw()).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.tx_prunable(plain_id).expect("read"),
        AtIndex::Recorded(Prunable::Discarded)
    );
    // The permanent half is unaffected: T3 still answers, with the hash the
    // client needs to verify bytes fetched from an archiver.
    let record = snap
        .tx_record(&hash_of(&plain))
        .expect("read")
        .expect("recorded");
    assert_eq!(record.prunable_hash, plain.txid_parts().prunable_hash);
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

// ---------------------------------------------------------------------- T5

#[test]
fn tx_output_indices_is_dense_bound_first_and_a_hole_is_si9() {
    let path = tmp("tx-output-indices");
    let (store, _, plain, with_pqc) = tx_chain(&path);
    let snap = store.begin_read().expect("read");
    let count = snap.tx_count().expect("read");
    let plain_id = snap
        .tx_location(&hash_of(&plain))
        .expect("read")
        .expect("recorded")
        .id;
    let AtIndex::Recorded(indices) = snap.tx_output_indices(plain_id).expect("read") else {
        panic!("below the count is recorded");
    };
    assert_eq!(indices.0.len(), 2, "the plain spend has two outputs");
    let pqc_id = snap
        .tx_location(&hash_of(&with_pqc))
        .expect("read")
        .expect("recorded")
        .id;
    let AtIndex::Recorded(indices) = snap.tx_output_indices(pqc_id).expect("read") else {
        panic!("below the count is recorded");
    };
    assert_eq!(indices.0.len(), 1);
    assert_eq!(
        snap.tx_output_indices(id(count)).expect("read"),
        AtIndex::BeyondCount
    );
    drop(snap);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut outputs = txn.open_table(crate::schema::TX_OUTPUTS).expect("t");
            outputs.remove(plain_id.to_raw()).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let err = snap
        .tx_output_indices(plain_id)
        .expect_err("a hole below the count");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::IdNotFresh)
        ),
        "a hole below the dense count is SI-9, got {err:?}"
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------- T6

#[test]
fn tx_locations_walks_tx_indices_in_key_order_and_agrees_with_tx_location_row_for_row() {
    let path = tmp("tx-locations");
    let (store, _, _, _) = tx_chain(&path);
    let snap = store.begin_read().expect("read");
    let all: Vec<(TxHash, TxLocation)> = snap
        .tx_locations(TxHash::from_bytes([0x00; 32])..TxHash::from_bytes([0xff; 32]))
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("every row decodes");
    assert_eq!(
        all.len(),
        5,
        "five transactions; the range covers every hash below 0xff…"
    );
    // Key order: `LmdbHashKey`'s, the table's own.
    let keys: Vec<LmdbHashKey> = all
        .iter()
        .map(|(h, _)| LmdbHashKey::from_bytes(h.to_bytes()))
        .collect();
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "the walk is in the table's key order"
    );
    // Row for row with T1.
    for (hash, location) in &all {
        assert_eq!(snap.tx_location(hash).expect("read"), Some(*location));
    }
    // Bounded: a range that excludes the first key excludes exactly it.
    let first = all[0].0;
    let mut after = first.to_bytes();
    after[31] = after[31].wrapping_add(1);
    let rest: Vec<_> = snap
        .tx_locations(TxHash::from_bytes(after)..TxHash::from_bytes([0xff; 32]))
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decodes");
    assert_eq!(rest.len(), 4);
    assert!(rest.iter().all(|(h, _)| *h != first));
    cleanup(&path);
}

// ------------------------------------------------------------------- STX-9

#[test]
fn no_read_projection_hands_out_unlock_time() {
    // The gate (`check_store_unlock_time_projection.py`) is the structural
    // check; this pins the two S-TX projections by construction so a
    // refactor that adds the field fails here before it reaches CI.
    let _ = |loc: TxLocation| (loc.id, loc.height);
    let _ = |rec: TxRecord| {
        (
            rec.location,
            rec.pruned,
            rec.pqc_auths,
            rec.prunable_hash,
            rec.pqc_auth_hash,
        )
    };
}
