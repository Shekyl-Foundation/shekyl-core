// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-TX (`DRS_E1_STX.md` §3): the six transaction reads on `ReadSnapshot`.
//!
//! Every test that plants a fault reopens the file raw, plants, and asserts
//! on a fresh snapshot: the reads must classify what is *in the file*, and
//! the writer must be `Live` afterwards — a read never arms the halt.

use shekyl_types::{BlockHash, BlockHeight, PqcAuthHash, PrunableHash, TxHash};
use shekyl_wire::Transaction;

use super::connect_fixtures::{connect_chain, spend};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, EPOCH};
use super::*;
use crate::codec::{stored_timelock, Canonical, Coded, Raw, TxIndex, TxPrunedSegment};
use crate::ids::TxStorageId;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{TXS_PQC_AUTH_HASH, TXS_PRUNABLE, TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES};

fn id(raw: u64) -> TxStorageId {
    TxStorageId::from_raw(raw)
}

fn hash_of(tx: &Transaction) -> TxHash {
    tx.txid_parts().hash
}

/// Genesis, then a block with one 3-part body (a serve-credit-only
/// transaction — no `pqc_auths` by rule, CEN-H20), then a block with a
/// spend, which carries per-input `pqc_auths` and is 4-part. Coinbases at
/// every height, so the dense id space is `0..=4`: coinbase 0, coinbase 1,
/// serve credit, coinbase 2, spend.
fn tx_chain(path: &std::path::Path) -> (ChainStore, Vec<BlockHash>, Transaction, Transaction) {
    let store = ChainStore::create(path, EPOCH).expect("create");
    let plain = shekyl_chain_rules::harness::fixture::serve_credit_only([0x5e; 32]);
    let with_pqc = spend(15, 2);
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
            "§7.7 leg (ii): the pqc_auths region is present iff the txid is 4-part"
        );
        assert!(
            !matches!(record.pqc_auths, Some(PqcAuths::Discarded)),
            "a freshly connected 4-part transaction's pqc_auths region is retained"
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
        assert_eq!(record.wire_bytes(prunable), Some(wire));
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
fn a_pqc_auth_hash_row_without_its_segment_is_discarded_and_a_segment_without_its_row_is_si7() {
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
    // Hash row present, segment absent: §7.7 leg (iii)'s one state — the
    // retention prune discards `pqc_auths` by shard (DRS-E1 S-PRUNE), so
    // this is *discarded*, never a fault, and the wire cannot be recomposed
    // from this node.
    let record = snap.tx_record(&hash).expect("read").expect("recorded");
    assert_eq!(record.pqc_auths, Some(PqcAuths::Discarded));
    let AtIndex::Recorded(Prunable::Retained(prunable)) =
        snap.tx_prunable(record.location.id).expect("read")
    else {
        panic!("the prunable region was not touched");
    };
    assert_eq!(
        record.wire_bytes(prunable),
        None,
        "a discarded region has no wire bytes here"
    );
    // The reverse disagreement — a segment with no hash row — is SI-7:
    // the hash rows are permanent and nothing may delete one.
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
    assert_eq!(
        indices.0.len(),
        0,
        "the serve credit has no outputs — and a row, dense, never a hole"
    );
    let pqc_id = snap
        .tx_location(&hash_of(&with_pqc))
        .expect("read")
        .expect("recorded")
        .id;
    let AtIndex::Recorded(indices) = snap.tx_output_indices(pqc_id).expect("read") else {
        panic!("below the count is recorded");
    };
    assert_eq!(indices.0.len(), 2, "the spend's two outputs (CEN-I1)");
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
        .tx_locations(LmdbHashKey::MIN..=LmdbHashKey::MAX)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("every row decodes");
    assert_eq!(all.len(), 5, "five transactions; MIN..=MAX is the table");
    // Key order: `LmdbHashKey`'s, the table's own.
    let keys: Vec<LmdbHashKey> = all.iter().map(|(h, _)| LmdbHashKey::from(*h)).collect();
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "the walk is in the table's key order"
    );
    // Row for row with T1.
    for (hash, location) in &all {
        assert_eq!(snap.tx_location(hash).expect("read"), Some(*location));
    }
    let first = keys[0];
    let last = keys[4];
    // Inclusive: a singleton range is the key itself, so MAX is nameable.
    let only_first: Vec<_> = snap
        .tx_locations(first..=first)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decodes");
    assert_eq!(only_first.len(), 1);
    assert_eq!(only_first[0].0, all[0].0);
    // Successor in table order excludes exactly the first key.
    let rest: Vec<_> = snap
        .tx_locations(first.checked_successor().expect("first is not MAX")..=LmdbHashKey::MAX)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decodes");
    assert_eq!(rest.len(), 4);
    assert!(rest.iter().all(|(h, _)| LmdbHashKey::from(*h) != first));
    // An inverted bound in this order is empty, not a silent reshuffle.
    let inverted: Vec<_> = snap
        .tx_locations(last..=first)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decodes");
    assert!(inverted.is_empty());
    cleanup(&path);
}

// ------------------------------------------------ the primary row (round 1)

#[test]
fn a_missing_primary_row_below_the_count_is_si9_on_every_by_id_read_whatever_the_side_rows_hold() {
    // PR #800 review: the bound says the id exists; only the primary proves
    // it. With `txs_pruned[id]` gone and the hash row, the segment and the
    // output indices all still present, T4 and T5 must not serve them.
    let path = tmp("tx-primary-hole");
    let (store, _, plain, _) = tx_chain(&path);
    let plain_id = store
        .begin_read()
        .expect("read")
        .tx_location(&hash_of(&plain))
        .expect("read")
        .expect("recorded")
        .id;
    let count = store.begin_read().expect("read").tx_count().expect("read");
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut pruned = txn.open_table(TXS_PRUNED).expect("t");
            pruned.remove(plain_id.to_raw()).expect("remove");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert!(
        plain_id.to_raw() < count - 1,
        "the hole is below the (now shorter) count, so the bound admits it"
    );
    for (name, err) in [
        ("T4", snap.tx_prunable(plain_id).expect_err("primary hole")),
        (
            "T5",
            snap.tx_output_indices(plain_id).expect_err("primary hole"),
        ),
    ] {
        assert!(
            matches!(
                err,
                StoreError::InvariantViolated(StoreInvariant::IdNotFresh)
            ),
            "{name}: a missing primary below the count is SI-9, got {err:?}"
        );
    }
    // T3 reaches the same row by hash and names the table.
    let err = snap.tx_record(&hash_of(&plain)).expect_err("primary hole");
    assert!(is_si7_absent(&err, "txs_pruned"), "got {err:?}");
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

#[test]
fn an_index_id_at_or_past_the_count_is_si9_on_every_hash_read_even_with_a_stray_primary() {
    // The hash path mints `TxLocation.id`. An index pointing at or past
    // `tx_count` is SI-9 — T4 would call that id `BeyondCount`, and a
    // location T4 refuses is not a location. Planted at `LmdbHashKey::MAX`
    // so T6's inclusive bound is the thing that sees it (a half-open
    // `Range` cannot name a successor of MAX).
    let path = tmp("tx-index-out-of-domain");
    let (store, _, _, _) = tx_chain(&path);
    let count = store.begin_read().expect("read").tx_count().expect("read");
    let planted_id = id(count + 7);
    let planted_hash = TxHash::from_bytes(LmdbHashKey::MAX.to_bytes());
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut indices = txn.open_table(TX_INDICES).expect("t");
            indices
                .insert(
                    LmdbHashKey::MAX,
                    TxIndex {
                        tx_id: planted_id,
                        unlock_time: stored_timelock(0),
                        height: BlockHeight::from_raw(1),
                    }
                    .encoded()
                    .as_encoded(),
                )
                .expect("plant index");
            let mut pruned = txn.open_table(TXS_PRUNED).expect("t");
            pruned
                .insert(planted_id.to_raw(), Raw::<TxPrunedSegment>::new(&[0xaa]))
                .expect("plant stray primary");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    for (name, err) in [
        (
            "T1",
            snap.tx_location(&planted_hash).expect_err("out of domain"),
        ),
        (
            "T3",
            snap.tx_record(&planted_hash).expect_err("out of domain"),
        ),
    ] {
        assert!(
            matches!(
                err,
                StoreError::InvariantViolated(StoreInvariant::IdNotFresh)
            ),
            "{name}: an index id at or past the count is SI-9, got {err:?}"
        );
    }
    assert_eq!(
        snap.tx_prunable(planted_id).expect("read"),
        AtIndex::BeyondCount,
        "by id, past the count is invalid input, not a served stray primary"
    );
    let mut ok = 0;
    let mut si9 = 0;
    for item in snap
        .tx_locations(LmdbHashKey::MIN..=LmdbHashKey::MAX)
        .expect("range")
    {
        match item {
            Ok(_) => ok += 1,
            Err(StoreError::InvariantViolated(StoreInvariant::IdNotFresh)) => si9 += 1,
            Err(e) => panic!("unexpected walk fault: {e:?}"),
        }
    }
    assert_eq!(ok, 5, "the honest rows still walk");
    assert_eq!(
        si9, 1,
        "MAX is included and classified, not dropped by an exclusive end"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------- STX-9

#[test]
fn no_read_projection_hands_out_unlock_time() {
    // The gate (`check_store_unlock_time_projection.py`) is the structural
    // check; this pins the two S-TX projections by construction so a
    // refactor that adds the field fails here before it reaches CI.
    // Exhaustive destructuring, no `..`: a field added to either struct is
    // a compile error here, where a field-access list would stay green
    // (PR #800 review round 3).
    let _ = |loc: TxLocation| {
        let TxLocation { id, height } = loc;
        (id, height)
    };
    let _ = |rec: TxRecord| {
        let TxRecord {
            location,
            pruned,
            pqc_auths,
            prunable_hash,
            pqc_auth_hash,
        } = rec;
        (location, pruned, pqc_auths, prunable_hash, pqc_auth_hash)
    };
}

#[test]
fn the_hash_rows_cannot_hold_a_malformed_digest_so_undecodable_is_unreachable_by_construction() {
    // PR #800 review round 3 asked T4 to decode the hash row, as T3 does,
    // so a malformed row is SI-7 `Undecodable` on both. Both now read it
    // through one reader (`tx_reads::hash_row`) — but the fault the review
    // feared cannot be planted: the codecs are fixed-width 32 and the
    // engine refuses a row of any other width at write time
    // (`redb` asserts the width in `append`), and a 32-byte row *is* a
    // digest — `decode` accepts every one. So the `Undecodable` arm of
    // both hash reads is exercised by type, as T6's is. This pins the two
    // facts that make it so; if either moves, the arm becomes reachable
    // and this test is the prompt to plant the row.
    for width in [
        <Coded<PrunableHash> as redb::Value>::fixed_width(),
        <Coded<PqcAuthHash> as redb::Value>::fixed_width(),
    ] {
        assert_eq!(width, Some(32), "the engine pins the row width");
    }
    let any = [0x5a; 32];
    assert!(PrunableHash::decode(&any).is_ok());
    assert!(PqcAuthHash::decode(&any).is_ok());
    assert!(
        PrunableHash::decode(&any[..31]).is_err(),
        "and a short row would not decode"
    );
}
