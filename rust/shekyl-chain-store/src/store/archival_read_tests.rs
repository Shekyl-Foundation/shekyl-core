// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the archival reads (`store/archival_reads.rs`, DRS-E1 S-ARCH
//! A1, A3–A10). No writer exists yet for these tables (E4's), so every
//! planted state is written raw through the schema's own table handles and
//! asserted on a fresh snapshot — the reads' contract is with the bytes a
//! writer will leave, not with any writer.

use redb::Value;
use shekyl_chain_rules::AtHeight;
use shekyl_store_codec::Coded;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::connect_chain;
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, EPOCH};
use super::*;
use crate::codec::{
    ArchivalLastSlashEpochCell, AttestationWitnessBytes, BondRecord, Canonical, Holdings,
    PropertyCell, RMarket, Raw, SigmaWorkMilli,
};
use crate::ids::ServeCreditKey;
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_R_MARKET,
    ARCHIVAL_SERVE_CREDIT, ARCHIVAL_SIGMA_WORK,
};

fn persona(fill: u8) -> PCanonicalId {
    PCanonicalId::from_bytes([fill; 32])
}

fn shard(n: u64) -> ShardId {
    ShardId::from_raw(n)
}

fn epoch(n: u64) -> SettlementEpoch {
    SettlementEpoch::from_raw(n)
}

fn record() -> BondRecord {
    BondRecord {
        hybrid_pubkey: vec![0x11; 64],
        bond_spend_pk: vec![0x22; 32],
        endpoint: [0x33; 32],
        join_settlement_epoch: epoch(3),
        bonded_total: AtomicUnits::from_raw(5_000_000_000),
        holdings: Holdings::CompleteTree,
        bad_intervals: vec![],
        claimed_settlement_epochs: vec![],
        first_paying_emission_height: None,
    }
}

/// Plant rows raw: `f` receives the open write transaction.
fn plant(path: &std::path::Path, f: impl FnOnce(&redb::WriteTransaction)) {
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    f(&txn);
    txn.commit().expect("commit");
}

fn plant_bond(txn: &redb::WriteTransaction, p: &PCanonicalId, r: &BondRecord) {
    let mut t = txn.open_table(ARCHIVAL_BOND).expect("t");
    t.insert(*p.as_bytes(), r.encoded().as_encoded())
        .expect("insert");
}

fn plant_pass(txn: &redb::WriteTransaction, p: &PCanonicalId, s: u64, e: u64, h: u64) {
    let mut t = txn.open_table(ARCHIVAL_SERVE_CREDIT).expect("t");
    t.insert(
        ServeCreditKey::new(*p, shard(s), epoch(e), BlockHeight::from_raw(h)).key(),
        crate::codec::Present,
    )
    .expect("insert");
}

fn is_si7_undecodable(err: &StoreError, key: &str) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: k,
            fault: CellFault::Undecodable(_)
        }) if *k == key
    )
}

fn is_si15(err: &StoreError, p: &PCanonicalId) -> bool {
    matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::ServeCreditWithoutBond { persona }) if persona == p
    )
}

// ---------------------------------------------------------------------------
// A1 — the bond record
// ---------------------------------------------------------------------------

#[test]
fn a1_absent_is_none_present_decodes_and_a_bad_row_is_si7() {
    let path = tmp("arch-a1");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa1);
    assert_eq!(store.begin_read().unwrap().bond_record(&p).unwrap(), None);
    drop(store);

    let r = record();
    plant(&path, |txn| plant_bond(txn, &p, &r));
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    assert_eq!(
        store.begin_read().unwrap().bond_record(&p).unwrap(),
        Some(r)
    );
    drop(store);

    // A row that is not one encoding of a record — the C++ v7 bytes, say —
    // is SI-7, never a partial or defaulted record.
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_BOND).expect("t");
        let garbage = [0x07u8, 1, 2, 3];
        t.insert(
            *p.as_bytes(),
            <Coded<BondRecord> as Value>::from_bytes(&garbage),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store.begin_read().unwrap().bond_record(&p).unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_bond"), "{err}");
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// A3, A4, A5 — the serve-credit walks
// ---------------------------------------------------------------------------

#[test]
fn a3_last_served_is_the_latest_epoch_per_shard_and_none_when_never_served() {
    let path = tmp("arch-a3");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa3);
    drop(store);
    plant(&path, |txn| {
        plant_bond(txn, &p, &record());
        // shard 7: epochs 4 (two heights) and 9; shard 42: epoch 6 only.
        plant_pass(txn, &p, 7, 4, 40_001);
        plant_pass(txn, &p, 7, 4, 40_002);
        plant_pass(txn, &p, 7, 9, 90_005);
        plant_pass(txn, &p, 42, 6, 60_003);
        // A neighbouring persona's rows must not leak into p's ranges.
        let q = persona(0xa4);
        plant_bond(txn, &q, &record());
        plant_pass(txn, &q, 7, 12, 120_000);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert_eq!(
        snap.last_served_epoch(&p, shard(7)).unwrap(),
        Some(epoch(9))
    );
    assert_eq!(
        snap.last_served_epoch(&p, shard(42)).unwrap(),
        Some(epoch(6))
    );
    assert_eq!(
        snap.last_served_epoch(&p, shard(1)).unwrap(),
        None,
        "never served"
    );
    // A stranger with no rows and no record is an answer, not a fault.
    assert_eq!(
        snap.last_served_epoch(&persona(0xff), shard(7)).unwrap(),
        None
    );
    cleanup(&path);
}

#[test]
fn a4_served_shards_hops_one_seek_per_shard_and_is_empty_for_a_stranger() {
    let path = tmp("arch-a4");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa5);
    drop(store);
    plant(&path, |txn| {
        plant_bond(txn, &p, &record());
        // Three shards, several rows each, out of insertion order.
        plant_pass(txn, &p, 300, 2, 20_000);
        plant_pass(txn, &p, 5, 8, 80_000);
        plant_pass(txn, &p, 5, 3, 30_000);
        plant_pass(txn, &p, 5, 3, 30_001);
        plant_pass(txn, &p, 77, 1, 10_000);
        plant_pass(txn, &p, 77, 11, 110_000);
        plant_pass(txn, &p, 300, 4, 40_000);
        // And the neighbour again.
        let q = persona(0xa6);
        plant_bond(txn, &q, &record());
        plant_pass(txn, &q, 1, 1, 10_000);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    let served = snap.served_shards(&p).unwrap();
    assert_eq!(
        served,
        vec![
            ServedShard {
                shard: shard(5),
                last_served: epoch(8)
            },
            ServedShard {
                shard: shard(77),
                last_served: epoch(11)
            },
            ServedShard {
                shard: shard(300),
                last_served: epoch(4)
            },
        ],
        "shard order is the key's, each with its latest epoch"
    );
    assert!(snap.served_shards(&persona(0xfe)).unwrap().is_empty());
    cleanup(&path);
}

#[test]
fn a5_pass_count_counts_the_pair_epoch_prefix_only() {
    let path = tmp("arch-a5");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa7);
    drop(store);
    plant(&path, |txn| {
        plant_bond(txn, &p, &record());
        plant_pass(txn, &p, 7, 4, 40_001);
        plant_pass(txn, &p, 7, 4, 40_002);
        plant_pass(txn, &p, 7, 4, 40_003);
        plant_pass(txn, &p, 7, 5, 50_000);
        plant_pass(txn, &p, 8, 4, 40_004);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.pass_count(&p, shard(7), epoch(4)).unwrap().to_raw(), 3);
    assert_eq!(snap.pass_count(&p, shard(7), epoch(5)).unwrap().to_raw(), 1);
    assert_eq!(snap.pass_count(&p, shard(8), epoch(4)).unwrap().to_raw(), 1);
    assert_eq!(
        snap.pass_count(&p, shard(7), epoch(6)).unwrap(),
        PassCount::ZERO
    );
    assert!(snap.pass_count(&p, shard(7), epoch(4)).unwrap().any());
    assert!(!PassCount::ZERO.any());
    cleanup(&path);
}

#[test]
fn si15_serve_credit_rows_for_a_persona_with_no_record_are_a_fault_on_every_walk() {
    let path = tmp("arch-si15");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let orphan = persona(0x0f);
    drop(store);
    plant(&path, |txn| {
        // Rows, no bond record: a write that bypassed the connect hook.
        plant_pass(txn, &orphan, 7, 4, 40_001);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert!(is_si15(
        &snap.last_served_epoch(&orphan, shard(7)).unwrap_err(),
        &orphan
    ));
    assert!(is_si15(&snap.served_shards(&orphan).unwrap_err(), &orphan));
    assert!(is_si15(
        &snap.pass_count(&orphan, shard(7), epoch(4)).unwrap_err(),
        &orphan
    ));
    // The belt asserts nothing where the walk found nothing.
    assert_eq!(snap.last_served_epoch(&orphan, shard(9)).unwrap(), None);
    assert_eq!(
        snap.pass_count(&orphan, shard(7), epoch(5)).unwrap(),
        PassCount::ZERO
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// A6, A7, A8 — the close rows
// ---------------------------------------------------------------------------

#[test]
fn a6_to_a8_tell_no_row_from_a_written_zero() {
    let path = tmp("arch-close");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    drop(store);
    plant(&path, |txn| {
        let mut m = txn.open_table(ARCHIVAL_R_MARKET).expect("t");
        m.insert((7u64, 4u64), RMarket::from_raw(0).encoded().as_encoded())
            .expect("insert");
        m.insert((7u64, 5u64), RMarket::from_raw(3).encoded().as_encoded())
            .expect("insert");
        let mut w = txn.open_table(ARCHIVAL_SIGMA_WORK).expect("t");
        w.insert(4u64, SigmaWorkMilli::from_raw(0).encoded().as_encoded())
            .expect("insert");
        let mut b = txn.open_table(ARCHIVAL_BUDGET).expect("t");
        b.insert(4u64, AtomicUnits::from_raw(0).encoded().as_encoded())
            .expect("insert");
        b.insert(5u64, AtomicUnits::from_raw(1_000).encoded().as_encoded())
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    // Written zero and absent are different answers (SAR-8).
    assert_eq!(
        snap.r_market(shard(7), epoch(4)).unwrap(),
        Some(RMarket::from_raw(0))
    );
    assert_eq!(
        snap.r_market(shard(7), epoch(5)).unwrap(),
        Some(RMarket::from_raw(3))
    );
    assert_eq!(snap.r_market(shard(7), epoch(6)).unwrap(), None);
    assert_eq!(snap.r_market(shard(8), epoch(4)).unwrap(), None);
    assert_eq!(
        snap.sigma_work(epoch(4)).unwrap(),
        Some(SigmaWorkMilli::from_raw(0))
    );
    assert_eq!(snap.sigma_work(epoch(5)).unwrap(), None);
    assert_eq!(
        snap.budget(epoch(4)).unwrap(),
        Some(AtomicUnits::from_raw(0))
    );
    assert_eq!(
        snap.budget(epoch(5)).unwrap(),
        Some(AtomicUnits::from_raw(1_000))
    );
    assert_eq!(snap.budget(epoch(6)).unwrap(), None);
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// A9 — the slash watermark cell
// ---------------------------------------------------------------------------

#[test]
fn a9_absent_is_none_never_a_sentinel() {
    let path = tmp("arch-a9");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(
        store
            .begin_read()
            .unwrap()
            .last_settled_slash_epoch()
            .unwrap(),
        None
    );
    drop(store);
    plant(&path, |txn| {
        let mut t = txn.open_table(crate::schema::PROPERTIES).expect("t");
        t.insert(
            ArchivalLastSlashEpochCell::KEY,
            Raw::<crate::codec::PropertyCellBytes>::new(&epoch(12).encode()),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    assert_eq!(
        store
            .begin_read()
            .unwrap()
            .last_settled_slash_epoch()
            .unwrap(),
        Some(epoch(12))
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// A10 — the attestation witness
// ---------------------------------------------------------------------------

#[test]
fn a10_tells_above_tip_from_a_recorded_block_with_no_witness_from_one_with() {
    let path = tmp("arch-a10");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]); // tip 2
    drop(store);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_ATTESTATION_WITNESS).expect("t");
        t.insert(1u64, Raw::<AttestationWitnessBytes>::new(&[0xab, 0xcd]))
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(1))
            .unwrap(),
        AtHeight::Recorded(Some(vec![0xab, 0xcd]))
    );
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(2))
            .unwrap(),
        AtHeight::Recorded(None),
        "a recorded block whose attestation set was empty has no row"
    );
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(3))
            .unwrap(),
        AtHeight::AboveTip
    );
    cleanup(&path);
}
