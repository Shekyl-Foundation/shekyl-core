// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three S-CHAIN-W amendments S-CHAIN-R's layout commit carries
//! (`DRS_E1_SCHAIN_R.md` §3.6, §3.7, §7 commit 2b), each pinned by the gate
//! the plan names for it:
//!
//! - **A1** — `BlockInfo::cumulative_tx_count` is the store's running total
//!   (`cum(0) == |txs(0)|`, `cum(h) − cum(h−1) == |txs(h)|`), through a pop
//!   and a re-connect; `long_term_effective_median` is read back at exactly
//!   the height it was handed **for** (SCR-19), and the journal reverses it.
//! - **A2** — every table with a writer exists from the seal, none of the
//!   `Unshaped` ones do, and a sealed file missing one is refused (SI-7).
//! - **A3** — `txs_pqc_auth_hash` has a row for a 4-part txid and none for
//!   the coinbase or a 3-part serve credit, the row is the identity's value, and a
//!   pop removes it with the rest of the block.

use redb::ReadableTableMetadata;
use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::RuleSet;
use shekyl_types::{BlockHeight, LongTermWeight};

use super::connect_fixtures::{candidate, connect_chain, facts, judge, spend};
use super::error::{CellFault, StoreCannot, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{BlockInfo, Canonical, CurveTreeState};
use crate::schema::{
    self, BLOCKS, BLOCK_BURN, BLOCK_INFO, CURVE_TREE_CHECKPOINTS, CURVE_TREE_LEAVES,
    CURVE_TREE_META, TXS_PQC_AUTH_HASH, UNDO_LOG,
};

fn block_info(store: &ChainStore, height: u64) -> Option<BlockInfo> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(BLOCK_INFO).expect("sealed");
    table
        .get(height)
        .expect("get")
        .map(|g| g.value().decode().expect("decodes"))
}

// ------------------------------------------------------------------ A1

#[test]
fn cumulative_tx_count_is_the_running_total_through_pop_and_reconnect() {
    let path = tmp("a1-cum-tx-count");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // |txs| per height: 0, 2, 1 → cum 0, 2, 3.
    connect_chain(
        &store,
        &[vec![], vec![spend(9, 1), spend(10, 1)], vec![spend(11, 1)]],
    );
    let cum = |h| block_info(&store, h).expect("row").cumulative_tx_count;
    assert_eq!(
        cum(0),
        0,
        "cum(0) == |txs(0)| — the genesis case, stated alone"
    );
    assert_eq!(cum(1) - cum(0), 2);
    assert_eq!(cum(2) - cum(1), 1);
    assert_eq!(cum(2), 3);

    // Pop the tip: the row goes with it; the parent's total is untouched.
    let popped: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(popped.expect("pop").height, BlockHeight::from_raw(2));
    assert!(block_info(&store, 2).is_none());
    assert_eq!(cum(1), 2);

    // Re-connect a different block 2 with three transactions: the total
    // resumes from the parent's row, not from anything the popped block left.
    let b1_hash = block_info(&store, 1).expect("row").hash;
    let b2 = candidate(2, b1_hash, vec![spend(12, 1), spend(13, 1), spend(14, 1)]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b2)?, facts(2, 0), RuleSet::GENESIS)?)
    });
    out.expect("reconnect");
    assert_eq!(cum(2) - cum(1), 3);
    assert_eq!(cum(2), 5);
    cleanup(&path);
}

#[test]
fn long_term_effective_median_is_stored_at_the_height_it_is_in_force_for() {
    let path = tmp("a1-ltem-index");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    // `facts(h, _)` hands a distinct median per height (`300_000 + 7h`); the
    // row at `h` carries the value handed **for** `h` — not `h − 1`'s, not
    // `h + 1`'s (SCR-19).
    for h in 0..3u64 {
        assert_eq!(
            block_info(&store, h)
                .expect("row")
                .long_term_effective_median,
            facts(h, 0).long_term_effective_median.value,
            "block_info[{h}] carries the median in force for {h}"
        );
    }
    // A pop of 2 and a re-connect with a different value: the journal
    // reverses the row, the new connect replaces it.
    let popped: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    popped.expect("pop");
    assert!(
        block_info(&store, 2).is_none(),
        "the row went with the block"
    );
    let b1_hash = block_info(&store, 1).expect("row").hash;
    let mut different = facts(2, 0);
    different.long_term_effective_median = Fact::passed_through(LongTermWeight::from_raw(424_242));
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let b2 = candidate(2, b1_hash, Vec::new());
        Ok(batch.connect(judge(&view, b2)?, different, RuleSet::GENESIS)?)
    });
    out.expect("reconnect");
    assert_eq!(
        block_info(&store, 2)
            .expect("row")
            .long_term_effective_median,
        LongTermWeight::from_raw(424_242)
    );
    assert_eq!(
        block_info(&store, 1)
            .expect("row")
            .long_term_effective_median,
        facts(1, 0).long_term_effective_median.value,
        "the parent's row is not what a connect at 2 writes"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ A2

#[test]
fn the_seal_creates_every_table_with_a_writer_and_no_unshaped_one() {
    let path = tmp("a2-seal-set");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    // Written-by-nothing-yet tables exist, empty: a chain that has never
    // burned has a `block_burn` table (SCR-17's motivating case).
    for (name, exists) in [
        ("blocks", snap.open_table(BLOCKS).is_ok()),
        ("block_burn", snap.open_table(BLOCK_BURN).is_ok()),
        ("undo_log", snap.open_table(UNDO_LOG).is_ok()),
        (
            "txs_pqc_auth_hash",
            snap.open_table(TXS_PQC_AUTH_HASH).is_ok(),
        ),
    ] {
        assert!(exists, "{name} is sealed");
    }
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("t")
        .is_empty()
        .expect("len"));
    // `Unshaped` tables are not: they have no writer to have a file
    // presence for, and creating them would make "no writer yet" a fact the
    // file could not tell from "empty".
    assert!(
        snap.open_table(CURVE_TREE_CHECKPOINTS).is_err(),
        "curve_tree_checkpoints is Unshaped and not sealed"
    );
    // S-CURVE's shaped curve tables are sealed; the summary is a **written**
    // row, not an empty table (`SCU-Q1`, SCU-1).
    assert!(snap
        .open_table(CURVE_TREE_LEAVES)
        .expect("sealed")
        .is_empty()
        .expect("len"));
    let meta = snap.open_table(CURVE_TREE_META).expect("sealed");
    assert_eq!(meta.len().expect("len"), 1, "one summary row");
    assert_eq!(
        meta.get(())
            .expect("get")
            .expect("the seal wrote it")
            .value()
            .decode(),
        Ok(CurveTreeState::EMPTY)
    );
    // The set is the catalogue's own: exactly the non-`Unshaped` targets.
    let sealed = schema::UNDO_TARGETS.iter().filter(|t| t.sealed()).count();
    let unshaped = schema::catalogue()
        .iter()
        .filter(|spec| spec.value == <crate::codec::Unshaped as redb::Value>::type_name())
        .count();
    assert_eq!(sealed + unshaped, schema::catalogue().len());
    // 28 → 22 at layout 11: S-ARCH shaped six archival tables
    // (`DRS_E1_SARCH.md` §4 — the plan's "seven" counted the `properties`
    // cell, which is not a table); the journals, settlement, slash-applied,
    // accrual and segment rows and the pool, alt and txpool tables stay
    // `Unshaped` for their increments.
    assert_eq!(unshaped, 22, "the §11.1(f) count at this layout");
    cleanup(&path);
}

#[test]
fn a_sealed_file_missing_a_sealed_table_is_refused_as_si7() {
    let path = tmp("a2-missing-table");
    ChainStore::create(&path, EPOCH).expect("create");
    // Delete one sealed table behind the store's back.
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        assert!(txn.delete_table(BLOCK_BURN).expect("delete"));
        txn.commit().expect("commit");
    }
    let refused = ChainStore::create(&path, EPOCH).expect_err("verify refuses");
    assert_eq!(
        refused.to_string(),
        StoreError::from(StoreInvariant::CellCorrupt {
            key: "block_burn",
            fault: CellFault::Absent,
        })
        .to_string(),
        "the missing table is named as the cell"
    );
    // Not a version or schedule problem: the version cell was current, so
    // the table set is what is wrong, and the file is named for that.
    assert!(!matches!(
        refused,
        StoreError::Cannot(
            StoreCannot::SchemaVersionAbsent | StoreCannot::SchemaVersionMismatch { .. }
        )
    ));
    cleanup(&path);
}

/// The version check comes **before** the seal-set check: a file at another
/// version is *foreign*, not *corrupt*, and is named as such even where its
/// table set would also fail the current seal's check.
#[test]
fn a_file_at_another_version_is_a_version_mismatch_not_a_missing_table() {
    let path = tmp("a2-version-before-seal-set");
    ChainStore::create(&path, EPOCH).expect("create");
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        // Both at once: the version cell says v3, and a v4-sealed table is
        // gone. The refusal must name the version.
        txn.open_table(crate::schema::PROPERTIES)
            .expect("properties")
            .insert(
                <crate::codec::SchemaVersionCell as crate::codec::PropertyCell>::KEY,
                crate::codec::Raw::<crate::codec::PropertyCellBytes>::new(
                    &crate::codec::SchemaVersion::new(3).encode(),
                ),
            )
            .expect("rewrite version");
        assert!(txn.delete_table(TXS_PQC_AUTH_HASH).expect("delete"));
        txn.commit().expect("commit");
    }
    let refused = ChainStore::create(&path, EPOCH).expect_err("verify refuses");
    assert!(
        matches!(
            refused,
            StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found, .. })
                if found == crate::codec::SchemaVersion::new(3)
        ),
        "{refused}"
    );
    cleanup(&path);
}

/// A file whose `properties` table was written under another value shape
/// cannot be opened far enough to read its version: redb refuses the table
/// type first. That is `StoreCannot::LayoutForeign`, not an engine error —
/// §11.1(a)'s "older refuses too", one step earlier.
#[test]
fn a_file_with_a_foreign_header_table_type_is_layout_foreign() {
    let path = tmp("a2-layout-foreign");
    {
        // A `properties` table under the pre-§11.1(f) shape, with nothing
        // else: the raw engine writes what this store never will.
        const OLD: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("properties");
        let db = redb::Database::create(&path).expect("raw create");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(OLD)
            .expect("old-shaped properties")
            .insert("schema_version", 2u64.to_le_bytes().as_slice())
            .expect("v2 cell");
        txn.commit().expect("commit");
    }
    let refused = ChainStore::create(&path, EPOCH).expect_err("verify refuses");
    assert_eq!(
        refused.to_string(),
        StoreError::from(StoreCannot::LayoutForeign {
            expected: crate::codec::SCHEMA_VERSION,
        })
        .to_string()
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ A3

#[test]
fn txs_pqc_auth_hash_has_a_row_iff_the_txid_is_4_part_and_it_is_the_identitys() {
    let path = tmp("a3-row-iff-4-part");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Every spend carries per-input auths (the wire reads `nvin` of them),
    // so a spend is 4-part; the 3-part non-coinbase transaction is the
    // serve-credit-only shape, whose `pqc_auths` are empty by rule (CEN-H20)
    // — the countersignature rides the vin.
    let four_part = spend(9, 1);
    let three_part = fixture::serve_credit_only([0x5f; 32]);
    let expected = four_part
        .txid_parts()
        .pqc_auth_hash
        .expect("one pqc_auth makes the txid 4-part");
    assert!(three_part.txid_parts().pqc_auth_hash.is_none());
    // Block 1 lists the 4-part spend then the 3-part one: tx_ids 0 (genesis
    // miner), 1 (block-1 miner), 2 (four_part), 3 (three_part).
    connect_chain(&store, &[vec![], vec![four_part, three_part]]);
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(TXS_PQC_AUTH_HASH).expect("sealed");
    assert_eq!(table.len().expect("len"), 1, "one 4-part txid, one row");
    assert_eq!(
        table
            .get(2)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(expected),
        "the row is the identity's third component, not a re-hash"
    );
    for (tx_id, why) in [
        (0, "genesis coinbase"),
        (1, "block-1 coinbase"),
        (3, "3-part serve credit"),
    ] {
        assert!(
            table.get(tx_id).expect("g").is_none(),
            "tx_id {tx_id} ({why}) is 3-part: no row, never a sentinel"
        );
    }
    drop(table);
    drop(snap);

    // The row is journaled: a pop of block 1 removes it with the block.
    let popped: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    popped.expect("pop");
    let snap = store.begin_read().expect("read");
    assert!(snap
        .open_table(TXS_PQC_AUTH_HASH)
        .expect("sealed")
        .is_empty()
        .expect("len"));
    cleanup(&path);
}

#[test]
fn the_second_rust_only_table_is_catalogued_last_and_named() {
    let ordinal = schema::ordinal_of("txs_pqc_auth_hash").expect("catalogued");
    // The journal stores ordinals as `u32`. A catalogue that does not fit
    // that width cannot be journaled, so the length check fails here
    // rather than at the first pop.
    let catalogue_len =
        u32::try_from(schema::catalogue().len()).expect("catalogue length fits in a table ordinal");
    assert_eq!(
        ordinal.index() + 1,
        catalogue_len,
        "txs_pqc_auth_hash is the final catalogue slot"
    );
    // 47 LMDB mirrors plus the two Rust-only tables (`undo_log`,
    // `txs_pqc_auth_hash`) at SCHEMA_VERSION 10.
    assert_eq!(catalogue_len, 49);
    let names: Vec<&str> = schema::RUST_ONLY_TABLES.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["undo_log", "txs_pqc_auth_hash"]);
    // One 32-byte codec; `Coded<PqcAuthHash>` on the value side.
    assert_eq!(
        <shekyl_types::PqcAuthHash as Canonical>::FIXED_WIDTH,
        Some(32)
    );
}
