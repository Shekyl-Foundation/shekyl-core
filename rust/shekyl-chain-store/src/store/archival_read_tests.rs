// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the archival reads (`store/archival_reads.rs`, DRS-E1 S-ARCH
//! A1–A10; DRS-E4 A11–A13; `SO-D10` A14–A16; `SO-D11` A17). Every planted state is
//! written raw through the schema's own table handles and asserted on a
//! fresh snapshot: the reads' contract is with the bytes a writer leaves,
//! not with any writer, so the reads are tested apart from the writers
//! (`archival_write_tests`, `slash_scan_bench_tests`).

use std::collections::{BTreeMap, BTreeSet};

use redb::Value;
use shekyl_chain_rules::{AtHeight, SlashLogFloor};
use shekyl_store_codec::Coded;
use shekyl_types::archival::{
    IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome, SettlementRow,
    MAX_ATTESTATION_WITNESS_BYTES,
};
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
use crate::ids::{IssuedDrawKey, ServeCreditKey, SettlementKey, SlashAppliedKey, SlashLogKey};
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_BUDGET_ACCRUING,
    ARCHIVAL_ISSUED_DIGEST, ARCHIVAL_ISSUED_DRAW, ARCHIVAL_R_MARKET, ARCHIVAL_SERVE_CREDIT,
    ARCHIVAL_SETTLEMENT, ARCHIVAL_SIGMA_WORK, ARCHIVAL_SLASH_APPLIED, ARCHIVAL_SLASH_LOG,
};

pub(super) fn persona(fill: u8) -> PCanonicalId {
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

/// Plant rows raw: `f` receives the open write transaction. Shared with
/// `prune_tests`, which plants slash rows across the retirement floor.
pub(super) fn plant(path: &std::path::Path, f: impl FnOnce(&redb::WriteTransaction)) {
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

pub(super) fn slash_entry(p: &PCanonicalId, s: u64, e: u64, add: u64) -> SlashLogEntry {
    SlashLogEntry {
        persona: *p,
        shard: shard(s),
        epoch: epoch(e),
        holding: SlashedHolding::Shard {
            add_epoch: epoch(add),
        },
    }
}

pub(super) fn plant_slash(txn: &redb::WriteTransaction, h: u64, seq: u32, entry: &SlashLogEntry) {
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
    // The rows are planted, not connected, and no boundary has run: the
    // log has no retirement floor, so every read here hands A2 `NONE`.
    // The floor's own arm (SI-26) is exercised where a chain crosses the
    // window, not on a planted table.
    let floor = SlashLogFloor::NONE;
    assert!(store
        .begin_read()
        .unwrap()
        .slash_log_after(&p, BlockHeight::ZERO, floor)
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
    let after = |h: u64| {
        snap.slash_log_after(&p, BlockHeight::from_raw(h), floor)
            .unwrap()
    };

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
        .slash_log_after(&persona(0xc2), BlockHeight::ZERO, floor)
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
        .slash_log_after(&p, BlockHeight::from_raw(250), floor)
        .unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_slash_log"), "{err}");
    // Below the bad row the read is unaffected — it never reaches it.
    assert_eq!(
        snap.slash_log_after(&p, BlockHeight::from_raw(300), floor)
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
// A14–A17 — settlement's reads (`SO-D10`, A17 from `SO-D11`). Every row is planted: the reads
// are tested apart from the slash pass that writes the rows
// (`slash_scan_bench_tests`).
// ---------------------------------------------------------------------------

#[test]
fn a14_settlement_row_is_the_exact_triple_and_absent_is_not_a_miss() {
    let path = tmp("arch-a14");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa4);
    assert_eq!(
        store
            .begin_read()
            .unwrap()
            .settlement_row(&p, shard(7), epoch(3))
            .unwrap(),
        None
    );
    drop(store);
    let missed = SettlementRow::settle(1, 5).expect("a row");
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SETTLEMENT).expect("t");
        t.insert(
            SettlementKey::new(p, shard(7), epoch(3)).key(),
            missed.encoded().as_encoded(),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    let read = snap
        .settlement_row(&p, shard(7), epoch(3))
        .unwrap()
        .expect("planted");
    assert_eq!(read, missed);
    assert_eq!(read.outcome(), SettlementOutcome::Missed);
    // Every other coordinate is another pair or epoch, and has no row.
    assert_eq!(snap.settlement_row(&p, shard(7), epoch(4)).unwrap(), None);
    assert_eq!(snap.settlement_row(&p, shard(8), epoch(3)).unwrap(), None);
    assert_eq!(
        snap.settlement_row(&persona(0xa5), shard(7), epoch(3))
            .unwrap(),
        None
    );
    drop(snap);
    drop(store);

    // A stored outcome its own counts do not give is not a row (SI-7):
    // Served on one pass of three.
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SETTLEMENT).expect("t");
        t.insert(
            SettlementKey::new(p, shard(7), epoch(3)).key(),
            <Coded<SettlementRow> as Value>::from_bytes(&[0x01u8, 1, 3]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store
        .begin_read()
        .unwrap()
        .settlement_row(&p, shard(7), epoch(3))
        .unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_settlement"), "{err}");
    cleanup(&path);
}

#[test]
fn a15_issued_draws_is_one_epoch_in_pair_then_height_then_draw_order() {
    let path = tmp("arch-a15");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(
        store.begin_read().unwrap().issued_draws(epoch(5)).unwrap(),
        vec![]
    );
    drop(store);

    let (lo, hi) = (persona(0x01), persona(0xc0));
    let draw = |persona, shard_n, h, j, revealed, passed| IndexedDraw {
        persona,
        shard: shard(shard_n),
        issuing_height: BlockHeight::from_raw(h),
        draw: j,
        state: IssuedDraw {
            revealed_at: BlockHeight::from_raw(revealed),
            passed,
        },
    };
    // Epoch 5's rows, in the order the read must return them.
    let expected = vec![
        draw(lo, 7, 100, 0, 101, false),
        draw(lo, 7, 100, 3, 101, true),
        draw(lo, 7, 102, 1, 110, false),
        draw(lo, 9, 90, 0, 91, true),
        draw(hi, 2, 95, 2, 96, false),
    ];
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_ISSUED_DRAW).expect("t");
        let mut put = |e: u64, d: &IndexedDraw| {
            t.insert(
                IssuedDrawKey::new(epoch(e), d.persona, d.shard, d.issuing_height, d.draw).key(),
                d.state.encoded().as_encoded(),
            )
            .expect("insert");
        };
        // Planted in reverse; neighbours in epochs 4 and 6 for the same
        // pair must not appear.
        for d in expected.iter().rev() {
            put(5, d);
        }
        put(4, &draw(lo, 7, 100, 0, 101, true));
        put(6, &draw(hi, 2, 95, 2, 96, true));
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.issued_draws(epoch(5)).unwrap(), expected);
    assert_eq!(snap.issued_draws(epoch(4)).unwrap().len(), 1);
    assert_eq!(snap.issued_draws(epoch(7)).unwrap(), vec![]);
    drop(snap);
    drop(store);

    // A pass flag that is neither 0 nor 1 faults the walk (SI-7): a
    // settlement that skipped the row would count a different list.
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_ISSUED_DRAW).expect("t");
        t.insert(
            IssuedDrawKey::new(epoch(5), lo, shard(7), BlockHeight::from_raw(100), 3).key(),
            <Coded<IssuedDraw> as Value>::from_bytes(&[0u8, 0, 0, 0, 0, 0, 0, 0, 2]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store
        .begin_read()
        .unwrap()
        .issued_draws(epoch(5))
        .unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_issued_draw"), "{err}");
    cleanup(&path);
}

#[test]
fn a16_issued_digest_is_the_epochs_cell_and_zero_when_nothing_was_folded() {
    let path = tmp("arch-a16");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(
        store.begin_read().unwrap().issued_digest(epoch(5)).unwrap(),
        IssuedDigest::ZERO
    );
    drop(store);
    let digest = IssuedDigest::from_bytes([0x5a; 32]);
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_ISSUED_DIGEST).expect("t");
        t.insert(5u64, digest.encoded().as_encoded())
            .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.issued_digest(epoch(5)).unwrap(), digest);
    assert_eq!(snap.issued_digest(epoch(4)).unwrap(), IssuedDigest::ZERO);
    assert_eq!(snap.issued_digest(epoch(6)).unwrap(), IssuedDigest::ZERO);
    cleanup(&path);
}

/// `(P, 0, 0)..=(P, MAX, MAX)`. The hop is this range; a hand-built tuple
/// would be a second definition of `SO-D2`.
#[test]
fn settlement_key_range_is_the_persona() {
    let p = persona(0xa7);
    let persona_span = SettlementKey::persona_range(p);
    assert_eq!(
        *persona_span.start(),
        SettlementKey::new(p, ShardId::ZERO, SettlementEpoch::ZERO).key()
    );
    assert_eq!(
        *persona_span.end(),
        SettlementKey::new(
            p,
            ShardId::from_raw(u64::MAX),
            SettlementEpoch::from_raw(u64::MAX)
        )
        .key()
    );
}

/// A17 hops shards and point-reads the cited epochs. A gap between shard
/// ids, a Missed row, a NonObservation, an uncited Served row, another
/// persona, and epochs given out of order each have one answer: the cited
/// epochs' Served shards, ascending, each shard once. The epochs are a
/// set, so a repeated citation cannot be asked. A corrupt row on an
/// epoch the caller did not cite is not decoded; the same bytes on a cited
/// epoch are SI-7.
#[test]
fn a17_served_at_hops_shards_and_point_reads_the_cited_epochs() {
    let path = tmp("arch-a17");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(0xa7);
    let other = persona(0xa8);
    assert!(store
        .begin_read()
        .unwrap()
        .served_at(&p, &BTreeSet::from([epoch(2), epoch(9)]))
        .unwrap()
        .is_empty());
    drop(store);

    let served = SettlementRow::settle(2, 3).expect("two of three");
    let missed = SettlementRow::settle(1, 3).expect("one of three");
    let unobserved = SettlementRow::settle(0, 1).expect("fewer than three");
    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SETTLEMENT).expect("t");
        t.insert(
            SettlementKey::new(p, shard(1), epoch(2)).key(),
            missed.encoded().as_encoded(),
        )
        .expect("insert");
        t.insert(
            SettlementKey::new(p, shard(1), epoch(9)).key(),
            served.encoded().as_encoded(),
        )
        .expect("insert");
        t.insert(
            SettlementKey::new(p, shard(5), epoch(7)).key(),
            served.encoded().as_encoded(),
        )
        .expect("insert");
        t.insert(
            SettlementKey::new(p, shard(100), epoch(2)).key(),
            served.encoded().as_encoded(),
        )
        .expect("insert");
        t.insert(
            SettlementKey::new(p, shard(100), epoch(9)).key(),
            unobserved.encoded().as_encoded(),
        )
        .expect("insert");
        t.insert(
            SettlementKey::new(other, shard(1), epoch(2)).key(),
            served.encoded().as_encoded(),
        )
        .expect("insert");
        // Uncited, and not a settlement its counts give: decoding it is
        // SI-7. The hop leaves an epoch the caller did not name unread.
        t.insert(
            SettlementKey::new(p, shard(1), epoch(4)).key(),
            <Coded<SettlementRow> as Value>::from_bytes(&[0x01, 1, 3]),
        )
        .expect("insert");
    });

    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().unwrap();
    assert!(snap.served_at(&p, &BTreeSet::new()).unwrap().is_empty());
    let cited = snap
        .served_at(&p, &BTreeSet::from([epoch(9), epoch(2)]))
        .unwrap();
    let mut expect = BTreeMap::new();
    expect.insert(epoch(2), vec![shard(100)]);
    expect.insert(epoch(9), vec![shard(1)]);
    assert_eq!(cited, expect);
    assert_eq!(
        snap.served_at(&other, &BTreeSet::from([epoch(2)])).unwrap(),
        BTreeMap::from([(epoch(2), vec![shard(1)])])
    );
    drop(snap);
    drop(store);

    plant(&path, |txn| {
        let mut t = txn.open_table(ARCHIVAL_SETTLEMENT).expect("t");
        t.insert(
            SettlementKey::new(p, shard(1), epoch(9)).key(),
            <Coded<SettlementRow> as Value>::from_bytes(&[0x01, 1, 3]),
        )
        .expect("insert");
    });
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store
        .begin_read()
        .unwrap()
        .served_at(&p, &BTreeSet::from([epoch(9)]))
        .unwrap_err();
    assert!(is_si7_undecodable(&err, "archival_settlement"), "{err}");
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
