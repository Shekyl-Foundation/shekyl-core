// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the archival reads (`store/archival_reads.rs`, DRS-E1 S-ARCH
//! A1–A10; DRS-E4 A11–A13). No writer exists yet for these tables (E4's), so every
//! planted state is written raw through the schema's own table handles and
//! asserted on a fresh snapshot — the reads' contract is with the bytes a
//! writer will leave, not with any writer.

use redb::Value;
use shekyl_chain_rules::AtHeight;
use shekyl_store_codec::Coded;
use shekyl_types::archival::MAX_ATTESTATION_WITNESS_BYTES;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::connect_chain;
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, EPOCH};
use super::*;
use crate::codec::{
    ArchivalLastSlashEpochCell, AttestationWitnessBytes, BondRecord, Canonical, Holdings, Present,
    PropertyCell, RMarket, Raw, SigmaWorkMilli, SlashLogEntry, SlashedHolding,
};
use crate::ids::{ServeCreditKey, SlashAppliedKey, SlashLogKey};
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_BUDGET_ACCRUING,
    ARCHIVAL_R_MARKET, ARCHIVAL_SERVE_CREDIT, ARCHIVAL_SIGMA_WORK, ARCHIVAL_SLASH_APPLIED,
    ARCHIVAL_SLASH_LOG,
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
// A2 — the slash log strictly above a height
// ---------------------------------------------------------------------------

fn slash_entry(p: &PCanonicalId, s: u64, e: u64, add: u64) -> SlashLogEntry {
    SlashLogEntry {
        persona: *p,
        shard: shard(s),
        epoch: epoch(e),
        holding: SlashedHolding::Shard {
            add_epoch: epoch(add),
        },
    }
}

fn plant_slash(txn: &redb::WriteTransaction, h: u64, seq: u32, entry: &SlashLogEntry) {
    let mut t = txn.open_table(ARCHIVAL_SLASH_LOG).expect("t");
    t.insert(
        SlashLogKey::new(BlockHeight::from_raw(h), seq).key(),
        entry.encoded().as_encoded(),
    )
    .expect("insert");
}

#[test]
fn a2_is_the_personas_rows_strictly_above_the_height_in_log_order() {
    let path = tmp("arch-a2");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa2);
    let other = persona(0xb2);
    assert!(store
        .begin_read()
        .unwrap()
        .slash_log_after(&p, BlockHeight::ZERO)
        .unwrap()
        .is_empty());
    drop(store);

    // Two of `p`'s slashes at 100 (seq 0 and 1), another persona's between
    // them, one of `p`'s at 250 and one at 400.
    let at_100_a = slash_entry(&p, 7, 1, 0);
    let at_100_b = slash_entry(&p, 9, 1, 0);
    let at_250 = slash_entry(&p, 11, 2, 1);
    let at_400 = SlashLogEntry {
        holding: SlashedHolding::CompleteTree,
        ..slash_entry(&p, 13, 4, 0)
    };
    // One at the last height the key can name, so the boundary case has a
    // row to wrongly return.
    let at_last = slash_entry(&p, 17, 5, 3);
    plant(&path, |txn| {
        plant_slash(txn, 100, 0, &at_100_a);
        plant_slash(txn, 100, 1, &slash_entry(&other, 7, 1, 0));
        plant_slash(txn, 100, 2, &at_100_b);
        plant_slash(txn, 250, 0, &at_250);
        plant_slash(txn, 250, 1, &slash_entry(&other, 11, 2, 0));
        plant_slash(txn, 400, 0, &at_400);
        plant_slash(txn, u64::MAX, 0, &at_last);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    let after = |h: u64| snap.slash_log_after(&p, BlockHeight::from_raw(h)).unwrap();

    // Strictly above: rows *at* `h` are excluded (a slash at `h` is
    // already-removed state at `h`); the other persona's rows never appear.
    assert_eq!(after(0), vec![at_100_a, at_100_b, at_250, at_400, at_last]);
    assert_eq!(after(99), vec![at_100_a, at_100_b, at_250, at_400, at_last]);
    assert_eq!(after(100), vec![at_250, at_400, at_last]);
    assert_eq!(after(249), vec![at_250, at_400, at_last]);
    assert_eq!(after(250), vec![at_400, at_last]);
    assert_eq!(after(399), vec![at_400, at_last]);
    assert_eq!(after(400), vec![at_last]);
    // The last height: nothing is strictly above it, so its own row is not
    // "after" it. The C++ special-cased this to keep `h + 1` from wrapping
    // and scanning the whole log; here the key's `above` has no range to
    // give, and the read is empty with a row sitting at that very height.
    assert_eq!(after(u64::MAX - 1), vec![at_last]);
    assert_eq!(after(u64::MAX), vec![]);
    // A stranger has no rows at any height.
    assert!(snap
        .slash_log_after(&persona(0xc2), BlockHeight::ZERO)
        .unwrap()
        .is_empty());
    drop(snap);
    drop(store);

    // A row that is not one encoding of an entry is SI-7, even when it is
    // another persona's: the read decodes before it filters, because a
    // corrupt log is a corrupt log whoever it names.
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SLASH_LOG).expect("t");
        t.insert(
            SlashLogKey::new(BlockHeight::from_raw(300), 0).key(),
            <Coded<SlashLogEntry> as Value>::from_bytes(&[0xff, 1, 2]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    let err = snap
        .slash_log_after(&p, BlockHeight::from_raw(250))
        .unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_slash_log"), "{err}");
    // Below the bad row the read is unaffected — it never reaches it.
    assert_eq!(
        snap.slash_log_after(&p, BlockHeight::from_raw(300))
            .unwrap(),
        vec![at_400, at_last]
    );
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

#[test]
fn a10_an_empty_or_over_cap_row_is_si7() {
    let path = tmp("arch-a10-ill");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]); // tip 1
    drop(store);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_ATTESTATION_WITNESS).expect("t");
        t.insert(0u64, Raw::<AttestationWitnessBytes>::new(&[]))
            .expect("insert");
        t.insert(
            1u64,
            Raw::<AttestationWitnessBytes>::new(&vec![0xab; MAX_ATTESTATION_WITNESS_BYTES + 1]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    let empty = snap
        .attestation_witness_at(BlockHeight::from_raw(0))
        .unwrap_err();
    assert!(
        is_si7_undecodable(&empty, "archival_attestation_witness"),
        "{empty}"
    );
    let over = snap
        .attestation_witness_at(BlockHeight::from_raw(1))
        .unwrap_err();
    assert!(
        is_si7_undecodable(&over, "archival_attestation_witness"),
        "{over}"
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// A11–A13 — the transition's reads (DRS-E4 commit 4)
// ---------------------------------------------------------------------------

#[test]
fn a11_bond_records_is_every_record_in_persona_key_order() {
    let path = tmp("arch-a11");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(store.begin_read().unwrap().bond_records().unwrap(), vec![]);
    drop(store);

    // Planted out of order; read back in key order, which is what the
    // slash scan's log sequence is a function of.
    let (hi, lo, mid) = (persona(0xc0), persona(0x01), persona(0x7f));
    let mut r_lo = record();
    r_lo.bonded_total = AtomicUnits::from_raw(1);
    let mut r_mid = record();
    r_mid.bonded_total = AtomicUnits::from_raw(2);
    let mut r_hi = record();
    r_hi.bonded_total = AtomicUnits::from_raw(3);
    plant(&path, |txn| {
        plant_bond(txn, &hi, &r_hi);
        plant_bond(txn, &lo, &r_lo);
        plant_bond(txn, &mid, &r_mid);
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    assert_eq!(
        store.begin_read().unwrap().bond_records().unwrap(),
        vec![(lo, r_lo), (mid, r_mid), (hi, r_hi)]
    );
    drop(store);

    // One undecodable row faults the whole walk (SI-7) — a scan that
    // silently skipped a record would slash the wrong universe.
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_BOND).expect("t");
        t.insert(
            *mid.as_bytes(),
            <Coded<BondRecord> as Value>::from_bytes(&[0x07u8, 1, 2, 3]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store.begin_read().unwrap().bond_records().unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_bond"), "{err}");
    cleanup(&path);
}

#[test]
fn a12_slash_applied_is_membership_of_the_exact_triple() {
    let path = tmp("arch-a12");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa2);
    assert!(!store
        .begin_read()
        .unwrap()
        .slash_applied(&p, shard(7), epoch(3))
        .unwrap());
    drop(store);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SLASH_APPLIED).expect("t");
        t.insert(SlashAppliedKey::new(p, shard(7), epoch(3)).key(), Present)
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert!(snap.slash_applied(&p, shard(7), epoch(3)).unwrap());
    // Every other coordinate of the triple is a different member.
    assert!(!snap.slash_applied(&p, shard(7), epoch(4)).unwrap());
    assert!(!snap.slash_applied(&p, shard(8), epoch(3)).unwrap());
    assert!(!snap
        .slash_applied(&persona(0xa3), shard(7), epoch(3))
        .unwrap());
    cleanup(&path);
}

#[test]
fn a13_budget_accruing_is_the_open_epochs_row_and_none_otherwise() {
    let path = tmp("arch-a13");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(
        store
            .begin_read()
            .unwrap()
            .budget_accruing(epoch(4))
            .unwrap(),
        None
    );
    drop(store);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_BUDGET_ACCRUING).expect("t");
        t.insert(4u64, AtomicUnits::from_raw(0).encoded().as_encoded())
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    // A written zero (an epoch whose blocks so far accrued nothing) is not
    // absence — the same distinction A8 keeps.
    assert_eq!(
        snap.budget_accruing(epoch(4)).unwrap(),
        Some(AtomicUnits::from_raw(0))
    );
    assert_eq!(snap.budget_accruing(epoch(3)).unwrap(), None);
    assert_eq!(snap.budget_accruing(epoch(5)).unwrap(), None);
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// The archival snapshot (E4 §3.8.1) — every family, the two projections
// ---------------------------------------------------------------------------

#[test]
fn archival_snapshot_is_every_family_as_rows_with_the_projections_applied() {
    use crate::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};

    let path = tmp("arch-snapshot");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // An empty store is ten families of no rows — never an omitted record.
    let empty = store.begin_read().unwrap().archival_snapshot().unwrap();
    assert_eq!(empty, ArchivalSnapshot::empty());
    // Two connected blocks accrue into the open epoch: the one row the
    // production writer puts in `archival_budget_accruing` is a snapshot
    // row from the first connect on, which is why the C++ walker sums its
    // per-height accruals rather than reporting "no open epoch".
    connect_chain(&store, &[vec![], vec![]]); // tip 1
    let after_connect = store.begin_read().unwrap().archival_snapshot().unwrap();
    assert_eq!(after_connect.rows(SnapshotFamily::BudgetAccruing).len(), 1);
    assert_eq!(after_connect.row_count(), 1);
    let accrued = store
        .begin_read()
        .unwrap()
        .budget_accruing(epoch(0))
        .unwrap()
        .expect("the open epoch accrued");
    drop(store);

    let p = persona(0xd1);
    let q = persona(0xd2);
    let entry = slash_entry(&p, 7, 3, 0);
    plant(&path, |txn| {
        plant_bond(txn, &p, &record());
        plant_bond(txn, &q, &record());
        plant_pass(txn, &p, 7, 3, 300);
        let mut m = txn.open_table(ARCHIVAL_R_MARKET).expect("t");
        m.insert((7u64, 2u64), RMarket::from_raw(0).encoded().as_encoded())
            .expect("insert");
        m.insert((7u64, 3u64), RMarket::from_raw(2).encoded().as_encoded())
            .expect("insert");
        let mut w = txn.open_table(ARCHIVAL_SIGMA_WORK).expect("t");
        w.insert(3u64, SigmaWorkMilli::from_raw(5).encoded().as_encoded())
            .expect("insert");
        let mut b = txn.open_table(ARCHIVAL_BUDGET).expect("t");
        b.insert(3u64, AtomicUnits::from_raw(9).encoded().as_encoded())
            .expect("insert");
        let mut a = txn.open_table(ARCHIVAL_ATTESTATION_WITNESS).expect("t");
        a.insert(1u64, Raw::<AttestationWitnessBytes>::new(&[1, 2, 3]))
            .expect("insert");
        plant_slash(txn, 1, 0, &entry);
        let mut s = txn.open_table(ARCHIVAL_SLASH_APPLIED).expect("t");
        s.insert(SlashAppliedKey::new(p, shard(7), epoch(3)).key(), Present)
            .expect("insert");
        let mut props = txn.open_table(crate::schema::PROPERTIES).expect("t");
        props
            .insert(
                ArchivalLastSlashEpochCell::KEY,
                Raw::<crate::codec::PropertyCellBytes>::new(&epoch(3).encode()),
            )
            .expect("insert");
    });

    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let got = store.begin_read().unwrap().archival_snapshot().unwrap();

    // What the same state looks like built through the constructors — the
    // path the C++ walker's marshalled fields take.
    let mut want = ArchivalSnapshot::empty();
    want.push_bond(&p, &record()).unwrap();
    want.push_bond(&q, &record()).unwrap();
    want.push_serve_credit(&p, shard(7), epoch(3), BlockHeight::from_raw(300))
        .unwrap();
    want.push_r_market(shard(7), epoch(3), RMarket::from_raw(2))
        .unwrap();
    want.push_sigma_work(epoch(3), SigmaWorkMilli::from_raw(5))
        .unwrap();
    want.push_budget(epoch(3), AtomicUnits::from_raw(9))
        .unwrap();
    want.push_attestation_witness(BlockHeight::from_raw(1), &[1, 2, 3])
        .unwrap();
    want.push_slash_log(BlockHeight::from_raw(1), 0, &entry)
        .unwrap();
    want.push_slash_applied(&p, shard(7), epoch(3)).unwrap();
    want.set_budget_accruing(epoch(0), accrued).unwrap();
    want.set_last_slash_epoch(epoch(3)).unwrap();
    assert_eq!(got, want);
    assert!(got.diff(&want).is_identical());

    // The written `RMarket(0)` at epoch 2 is a stored row (A6 reads it) and
    // not a snapshot row (§3.6): the C++ close writes zeros redb's does not.
    assert_eq!(got.rows(SnapshotFamily::RMarket).len(), 1);
    assert_eq!(got.rows(SnapshotFamily::Bond).len(), 2);
    assert_eq!(got.row_count(), 11);

    // The body round-trips, so what the trace carries is what the read saw.
    let back = ArchivalSnapshot::read_body(&mut got.body().as_slice()).unwrap();
    assert_eq!(back, got);
    cleanup(&path);
}

#[test]
fn archival_snapshot_refuses_a_second_accruing_row_as_si23() {
    let path = tmp("arch-snapshot-si23");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    drop(store);
    plant(&path, |txn| {
        let mut acc = txn.open_table(ARCHIVAL_BUDGET_ACCRUING).expect("t");
        acc.insert(4u64, AtomicUnits::from_raw(1).encoded().as_encoded())
            .expect("insert");
        acc.insert(5u64, AtomicUnits::from_raw(2).encoded().as_encoded())
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store.begin_read().unwrap().archival_snapshot().unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::AccruingNotSingular { .. })
        ),
        "{err}"
    );
    cleanup(&path);
}
