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
//!   and a re-connect; `long_term_effective_median` is the verdict's median
//!   in force **for** the height (SCR-19; derived since E6 slice 7), written
//!   at that height and reversed by the journal.
//! - **A2** — every table with a writer exists from the seal, none of the
//!   `Unshaped` ones do, and a sealed file missing one is refused (SI-7).
//! - **A3** — `txs_pqc_auth_hash` has a row for a 4-part txid and none for
//!   the coinbase or a 3-part serve credit, the row is the identity's value, and a
//!   pop removes it with the rest of the block.

use redb::ReadableTableMetadata;
use shekyl_chain_rules::RuleSet;
use shekyl_types::{BlockHeight, LongTermWeight};

use super::connect_fixtures::{
    candidate, connect_chain, connect_chain_anchored, credited, judge, spend, spend_at,
    spendable_prefix, FIRST_SPEND_HEIGHT,
};
use super::error::{CellFault, StoreCannot, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{BlockInfo, Canonical, CurveTreeState};
use crate::schema::{
    self, ARCHIVAL_SETTLEMENT, BLOCKS, BLOCK_BURN, BLOCK_INFO, CURVE_TREE_LEAVES, CURVE_TREE_META,
    TXS_PQC_AUTH_HASH, UNDO_LOG,
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
    // |txs| per height: none through the prefix, then 2, 1 → cum 0 …, 2, 3.
    let first = FIRST_SPEND_HEIGHT;
    let second = first + 1;
    let hashes = connect_chain(
        &store,
        &spendable_prefix(&[vec![spend(9, 2), spend(10, 2)], vec![spend(11, 2)]]),
    );
    let cum = |h| block_info(&store, h).expect("row").cumulative_tx_count;
    assert_eq!(
        cum(0),
        0,
        "cum(0) == |txs(0)| — the genesis case, stated alone"
    );
    assert_eq!(cum(first - 1), 0, "nothing listed through the prefix");
    assert_eq!(cum(first) - cum(first - 1), 2);
    assert_eq!(cum(second) - cum(first), 1);
    assert_eq!(cum(second), 3);

    // Pop the tip: the row goes with it; the parent's total is untouched.
    let popped: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(popped.expect("pop").height, BlockHeight::from_raw(second));
    assert!(block_info(&store, second).is_none());
    assert_eq!(cum(first), 2);

    // Re-connect a different block with three transactions: the total
    // resumes from the parent's row, not from anything the popped block left.
    let parent_hash = block_info(&store, first).expect("row").hash;
    let b2 = candidate(
        second,
        parent_hash,
        vec![
            spend_at(&hashes, second, 12, 2),
            spend_at(&hashes, second, 13, 2),
            spend_at(&hashes, second, 14, 2),
        ],
    );
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b2)?, RuleSet::GENESIS)?)
    });
    out.expect("reconnect");
    assert_eq!(cum(second) - cum(first), 3);
    assert_eq!(cum(second), 5);
    cleanup(&path);
}

#[test]
fn long_term_effective_median_is_stored_at_the_height_it_is_in_force_for() {
    let path = tmp("a1-ltem-index");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    // Since E6 slice 7 the row is the **verdict's** median (CEN-G6), not a
    // handed value: `Medians::derive(connecting)` reads the window that
    // ends at the connecting height, so the row at `h` can only be the
    // median in force **for** `h` (SCR-19) — the indexing is the
    // derivation's, held where the window is (`block_weight_tests`, the
    // store's conformance test). What the store owns is that it writes the
    // verdict's value and reverses it: on a light chain every height reads
    // the zone's floor arm.
    let zone = LongTermWeight::from_raw(shekyl_economics::FULL_REWARD_ZONE);
    for h in 0..3u64 {
        assert_eq!(
            block_info(&store, h)
                .expect("row")
                .long_term_effective_median,
            zone,
            "block_info[{h}] carries the median derived for {h}"
        );
    }
    // A pop of 2 and a re-connect: the journal reverses the row, the new
    // connect writes the re-derived one — and the parent's row is untouched.
    let popped: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    popped.expect("pop");
    assert!(
        block_info(&store, 2).is_none(),
        "the row went with the block"
    );
    let b1_hash = block_info(&store, 1).expect("row").hash;
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let b2 = candidate(2, b1_hash, Vec::new());
        Ok(batch.connect(judge(&view, b2)?, RuleSet::GENESIS)?)
    });
    out.expect("reconnect");
    assert_eq!(
        block_info(&store, 2)
            .expect("row")
            .long_term_effective_median,
        zone
    );
    assert_eq!(
        block_info(&store, 1)
            .expect("row")
            .long_term_effective_median,
        zone,
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
        snap.open_table(ARCHIVAL_SETTLEMENT).is_err(),
        "archival_settlement is Unshaped and not sealed"
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
    // cell, which is not a table). 22 → 20 at layout 12: S-POOL **evicted**
    // `txpool_meta` and `txpool_blob` to the pool file (`DRS_E1_SPOOL.md`
    // §4; not shaped here — gone from here). 20 → 18 at layout 13: S-ALT
    // shaped `alt_blocks` and **folded** `archival_alt_attestation_witness`
    // into it (`DRS_E1_SALT.md` §4; `FOLDED_INTO`). The journals,
    // settlement, slash-applied, accrual and segment rows stay `Unshaped`
    // for their increments. 18 → 12 at layout 15: DRS-E3 commit 1 **did not
    // port** four (`NOT_PORTED`: the pending set is a view of the block
    // index, two were the C++'s pop journals, the checkpoint is a view of
    // the meta row — `DRS_E3_CURVE_WRITER.md` §3.7) and **shaped** the two
    // position maps (`Coded<TreePosition>` / `Coded<GlobalOutputIndex>`).
    // 12 → 3 at layout 18: DRS-E4 commit 1 **did not port** seven archival
    // tables (`NOT_PORTED`: five pop journals and the close log are views of
    // the undo log, the per-height accrual rows a view of the emission
    // split, the freeze registry retired — `DRS_E4_ARCHIVAL_WRITER.md`
    // §3.3, §3.4) and **shaped** `archival_slash_log` and
    // `archival_slash_applied`. What remains `Unshaped` is the two dead
    // tables (`txs`, `hf_starting_heights`) and `archival_settlement`, held
    // for SO-D8's cutover with its blocker named.
    assert_eq!(unshaped, 3, "the §11.1(f) count at this layout");
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
    // so a spend is 4-part — here the join-market post, a spend that opens
    // the record the 3-part body needs; the 3-part non-coinbase transaction
    // is the serve-credit-only shape, whose `pqc_auths` are empty by rule
    // (CEN-H20) — its countersignature is over the pass record (CEN-J10) —
    // and which connects only behind its join (CEN-L7, DRS-E4 commit 4).
    let [four_part, three_part] = credited(9, [0x5f; 32]);
    assert!(four_part.txid_parts().pqc_auth_hash.is_some());
    assert!(three_part.txid_parts().pqc_auth_hash.is_none());
    // The first spend block lists the 4-part join then the 3-part credit:
    // tx_ids 0..=FIRST_SPEND_HEIGHT are the coinbases (one per block through
    // that one), then four_part, then three_part. The expectation is read
    // off the join **as connected**: anchoring signs every auth slot, and
    // the third component is over the auths.
    let (_, connected) =
        connect_chain_anchored(&store, &spendable_prefix(&[vec![four_part, three_part]]));
    let expected = connected
        .last()
        .and_then(|block| block.first())
        .expect("the spend block lists the join first")
        .txid_parts()
        .pqc_auth_hash
        .expect("a pqc_auth per input makes the txid 4-part");
    let four_part_id = FIRST_SPEND_HEIGHT + 1;
    let three_part_id = four_part_id + 1;
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(TXS_PQC_AUTH_HASH).expect("sealed");
    assert_eq!(table.len().expect("len"), 1, "one 4-part txid, one row");
    assert_eq!(
        table
            .get(four_part_id)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(expected),
        "the row is the identity's third component, not a re-hash"
    );
    for (tx_id, why) in [
        (0, "genesis coinbase"),
        (FIRST_SPEND_HEIGHT, "the spend block's coinbase"),
        (three_part_id, "3-part serve credit"),
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
fn the_rust_only_tables_are_catalogued_last_and_named() {
    let ordinal = schema::ordinal_of("txs_pqc_auth_hash").expect("catalogued");
    let last = schema::ordinal_of("txs_archival_len").expect("catalogued");
    // The journal stores ordinals as `u32`. A catalogue that does not fit
    // that width cannot be journaled, so the length check fails here
    // rather than at the first pop.
    let catalogue_len =
        u32::try_from(schema::catalogue().len()).expect("catalogue length fits in a table ordinal");
    // `txs_pqc_auth_hash` was appended last (A3); `txs_archival_len`
    // (`SHT-Q2`) was appended after it, so the two hold the final slots.
    assert_eq!(ordinal.index() + 1, last.index());
    assert_eq!(
        last.index() + 1,
        catalogue_len,
        "txs_archival_len is the final catalogue slot"
    );
    // 33 LMDB mirrors plus the five Rust-only tables
    // (`archival_budget_accruing`, `curve_tree_leaf_counts`, `undo_log`,
    // `txs_pqc_auth_hash`, `txs_archival_len`) at SCHEMA_VERSION 19 — 47
    // mirrors until S-POOL moved `txpool_meta` / `txpool_blob` to the pool
    // file (layout 12, `schema::MIRRORED_ELSEWHERE`), 45 until S-ALT folded
    // `archival_alt_attestation_witness` into `alt_blocks` (layout 13,
    // `schema::FOLDED_INTO`), 44 until DRS-E3 did not port four tree-side
    // tables (layout 15, `schema::NOT_PORTED`) and added
    // `curve_tree_leaf_counts`; 44 when `SHT-Q2` added `txs_archival_len`
    // (layout 18); 38 since DRS-E4 did not port seven archival tables and
    // added `archival_budget_accruing` (layout 19).
    assert_eq!(catalogue_len, 38);
    let names: Vec<&str> = schema::RUST_ONLY_TABLES.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "archival_budget_accruing",
            "curve_tree_leaf_counts",
            "undo_log",
            "txs_pqc_auth_hash",
            "txs_archival_len"
        ]
    );
    // One 32-byte codec; `Coded<PqcAuthHash>` on the value side.
    assert_eq!(
        <shekyl_types::PqcAuthHash as Canonical>::FIXED_WIDTH,
        Some(32)
    );
    // One 8-byte codec; `Coded<ArchivalLength>` on the value side.
    assert_eq!(
        <shekyl_types::ArchivalLength as Canonical>::FIXED_WIDTH,
        Some(8)
    );
}
