// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `connect` tests (S-CHAIN-W commit 6): the write set row by row against
//! the LMDB layouts, a two-block batch with a spend, connect → pop →
//! digest-equal, and every belt fired from a hand-built violation.
//!
//! Blocks go through the real `validate` under `RuleSet::GENESIS` — the
//! rules landed so far (E6 slice 1: A2, B1, B2, B5, B6, B7) pass every
//! well-formed fixture here, and coverage records exactly those rows — so
//! `connect` is exercised through its public signature. Every store here is
//! a fresh file (SCW-17). Fixtures live in `connect_fixtures.rs`.

use redb::ReadableTableMetadata;
use shekyl_chain_rules::{RowStatus, RuleSet, RuleSetId};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::{
    at, candidate, connect_chain, connect_chain_with_burn, connect_genesis,
    connect_with_image_planted_under_the_token, facts, judge, spend_at, spendable_prefix,
    FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::undo::Replayed;
use super::*;
use crate::codec::{
    stored_timelock, BlockInfo, Canonical, CoverageGaps, OutKey, OutTx, Raw, RuleSetInForce,
    TotalBurnedCell, TxIndex, TxOutputIndices, TxPrunedSegment, FACT_FIELDS,
};
use crate::ids::OutputSlot;
use crate::lmdb_order::{Hash32, LmdbHashKey};
use crate::schema::{
    BLOCKS, BLOCK_BURN, BLOCK_HEIGHTS, BLOCK_INFO, CURVE_TREE_ROOTS, HF_VERSIONS, OUTPUT_AMOUNTS,
    OUTPUT_TXS, SPENT_KEYS, TXS_PQC_AUTHS, TXS_PRUNABLE, TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES,
    TX_OUTPUTS, UNDO_LOG,
};
use shekyl_chain_rules::harness::fixture;

// ---------------------------------------------------------------- rows

#[test]
fn genesis_connect_writes_every_row_of_the_write_set_at_the_lmdb_layouts() {
    let path = tmp("connect-genesis");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (connected, block) = connect_genesis(&store, 0);
    assert_eq!(connected.height, BlockHeight::ZERO);
    // miner tx: spent_keys 0, tx_indices 1, txs_pruned 1, txs_prunable 1,
    // txs_prunable_hash 1, output_txs 1, output_amounts 1, tx_outputs 1;
    // root 1; blocks 1, block_heights 1, block_info 1; hf_versions 1.
    assert_eq!(connected.journaled, 12, "no pqc_auths row, no burn rows");

    let miner = &block.miner_transaction;
    let miner_hash = Hash32::from(miner.hash());
    let block_hash = Hash32::from(block.hash());
    let snap = store.begin_read().expect("read");

    // block tables
    assert_eq!(
        snap.open_table(BLOCKS)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().bytes().to_vec()),
        Some(block.serialize()),
        "blocks[0] is the judged block re-serialized"
    );
    assert_eq!(
        snap.open_table(BLOCK_HEIGHTS)
            .expect("t")
            .get(LmdbHashKey::from(block_hash))
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(BlockHeight::ZERO)
    );
    let info = snap
        .open_table(BLOCK_INFO)
        .expect("t")
        .get(0)
        .expect("g")
        .expect("row")
        .value()
        .decode()
        .expect("decodes");
    assert_eq!(
        info,
        BlockInfo {
            timestamp: shekyl_types::Timestamp::from_raw(1_000),
            coins_generated: AtomicUnits::from_raw(1_000_000),
            weight: shekyl_types::BlockWeight::from_raw(1_000),
            // Derived by the validator, not passed through: block 0's work
            // is its own target, 1 (CEN-D4; E6 slice 2).
            cumulative_difficulty: CumulativeDifficulty::from_raw(1),
            hash: shekyl_types::BlockHash::from(block_hash),
            rct_outputs: 1,
            long_term_weight: shekyl_types::LongTermWeight::from_raw(900),
            // `cum(0) == |transactions(0)|`: the genesis fixture lists none.
            cumulative_tx_count: 0,
            // The value handed **for** height 0, read back at height 0
            // (SCR-19): the fixture's `300_000 + 7 * h`.
            long_term_effective_median: shekyl_types::LongTermWeight::from_raw(300_000),
        }
    );
    assert_eq!(
        snap.open_table(HF_VERSIONS)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(RuleSetInForce(RuleSetId::GENESIS)),
        "hf_versions[h] is the rule set in force's id (SCW-16; the id, not the set — RD-Q10)"
    );
    assert_eq!(
        snap.open_table(CURVE_TREE_ROOTS)
            .expect("t")
            .get(1)
            .expect("g")
            .expect("row at h + 1")
            .value()
            .decode()
            .expect("decodes"),
        CurveTreeRoot::from_bytes([0xc0; 32]),
        "the root after genesis is keyed at 1"
    );
    assert!(snap
        .open_table(CURVE_TREE_ROOTS)
        .expect("t")
        .get(0)
        .expect("g")
        .is_none());

    // transaction tables
    assert_eq!(
        snap.open_table(TX_INDICES)
            .expect("t")
            .get(LmdbHashKey::from(miner_hash))
            .expect("g")
            .expect("row")
            .value()
            .decode()
            .expect("decodes"),
        TxIndex {
            tx_id: crate::ids::TxStorageId::from_raw(0),
            unlock_time: stored_timelock(60),
            height: BlockHeight::from_raw(0)
        }
    );
    let segments = miner.write_segments().expect("segments");
    assert_eq!(
        snap.open_table(TXS_PRUNED)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().bytes().to_vec()),
        Some(segments.pruned)
    );
    assert!(
        snap.open_table(TXS_PQC_AUTHS).is_err()
            || snap
                .open_table(TXS_PQC_AUTHS)
                .expect("t")
                .get(0)
                .expect("g")
                .is_none(),
        "a coinbase has no pqc_auths row (LMDB parity)"
    );
    assert_eq!(
        snap.open_table(TXS_PRUNABLE)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().bytes().to_vec()),
        Some(Vec::new()),
        "a coinbase has an EMPTY prunable row (LMDB parity)"
    );
    assert_eq!(
        snap.open_table(TXS_PRUNABLE_HASH)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(miner.prunable_hash()),
        "keccak256 of the empty region, not the null hash"
    );
    assert_eq!(
        snap.open_table(TX_OUTPUTS)
            .expect("t")
            .get(0)
            .expect("g")
            .expect("row")
            .value()
            .decode()
            .expect("decodes"),
        TxOutputIndices(vec![crate::ids::AmountIndex::from_raw(0)])
    );

    // output tables
    assert_eq!(
        snap.open_table(OUTPUT_TXS)
            .expect("t")
            .get(0)
            .expect("g")
            .expect("row")
            .value()
            .decode()
            .expect("decodes"),
        OutTx {
            tx_hash: shekyl_types::TxHash::from(miner_hash),
            local_index: shekyl_types::OutputIndexInTx::from_raw(0)
        }
    );
    let amounts = snap.open_table(OUTPUT_AMOUNTS).expect("t");
    let rows: Vec<((u64, u64), OutKey)> = amounts
        .range::<(u64, u64)>(..)
        .expect("range")
        .map(|r| {
            let (k, v) = r.expect("row");
            (k.value(), v.value().decode().expect("decodes"))
        })
        .collect();
    assert_eq!(
        rows,
        vec![(
            (0, 0),
            OutKey {
                output_id: crate::ids::OutputStorageId::from_raw(0),
                pubkey: shekyl_types::OneTimePubkey::from_bytes(fixture::G),
                unlock_time: stored_timelock(60),
                height: BlockHeight::from_raw(0),
                commitment: shekyl_types::CommitmentBytes::from_bytes(fixture::TWO_G),
            }
        )],
        "keyed (amount 0, amount_index 0) with the ct-base commitment; the key carries the index"
    );

    // no burn, no key images, no total_burned yet — and the table *exists*
    // from the seal (A2, SCR-17): absent-table is never read as empty-table.
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("sealed: exists on a chain that never burned")
        .is_empty()
        .expect("len"));
    assert!(snap
        .open_table(SPENT_KEYS)
        .expect("t")
        .is_empty()
        .expect("len"));
    assert_eq!(snap.get_property::<TotalBurnedCell>().expect("cell"), None);
    // one undo row, with exactly the journaled count
    let undo = snap
        .open_table(UNDO_LOG)
        .expect("t")
        .get(0)
        .expect("g")
        .expect("row")
        .value()
        .decode()
        .expect("decodes");
    assert_eq!(undo.0.len(), 12);
    cleanup(&path);
}

#[test]
fn two_blocks_in_one_batch_with_a_spend_and_a_burn() {
    let path = tmp("connect-two");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // The chain below the two blocks under test: everything up to the block
    // before the first admissible spend height, so the pair is a
    // coinbase-only block and, on it, the first block that may list a spend.
    let s = FIRST_SPEND_HEIGHT;
    let below = connect_chain(&store, &vec![Vec::new(); at(s - 1)]);
    let g = candidate(s - 1, below[at(s - 2)], Vec::new());
    let g_hash = g.block.hash();
    let mut hashes = below.clone();
    hashes.push(g_hash);
    let b1 = candidate(s, g_hash, vec![spend_at(&hashes, s, 9, 2)]);
    let b1_hash = b1.block.hash();
    let spend_hash = b1.transactions[0].hash();

    let out: Result<(Connected, Connected), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let c0 = batch.connect(judge(&view, g)?, facts(s - 1, 0), RuleSet::GENESIS)?;
        // The spend block is validated against a view that already holds
        // its parent and connected in the same batch.
        let c1 = batch.connect(judge(&view, b1)?, facts(s, 25), RuleSet::GENESIS)?;
        Ok((c0, c1))
    });
    let (c0, c1) = out.expect("both connect");
    assert_eq!(c0.height, BlockHeight::from_raw(s - 1));
    assert_eq!(c1.height, BlockHeight::from_raw(s));
    // the spend block: miner tx 7 (tx_indices, txs_pruned, txs_prunable,
    // txs_prunable_hash, output_txs, member, tx_outputs) + spend 12 (1 key
    // image + the same 4 tx rows + the 4-part txid's txs_pqc_auths segment
    // and txs_pqc_auth_hash row + 2 outputs × (output_txs + member) +
    // tx_outputs) + root 1 + block 3 + hf 1 + block_burn 1 + total_burned 1
    // = 26.
    assert_eq!(c1.journaled, 26);
    // Dense store ids: one coinbase per block through the spend block
    // (tx_ids `0..=s`, output_ids likewise), then the spend (tx_id `s + 1`,
    // output_ids `s + 1`, `s + 2`); amount_index under 0 equals output_id.
    let spend_id = s + 1;

    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.open_table(BLOCKS).expect("t").len().expect("len"),
        s + 1
    );
    assert!(
        snap.open_table(SPENT_KEYS)
            .expect("t")
            .get(LmdbHashKey::from_bytes(fixture::point(9)))
            .expect("g")
            .is_some(),
        "the spend's key image is recorded"
    );
    assert_eq!(
        snap.open_table(BLOCK_HEIGHTS)
            .expect("t")
            .get(LmdbHashKey::from(b1_hash))
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(BlockHeight::from_raw(s))
    );
    let spend_index = snap
        .open_table(TX_INDICES)
        .expect("t")
        .get(LmdbHashKey::from(spend_hash))
        .expect("g")
        .expect("row")
        .value()
        .decode()
        .expect("decodes");
    assert_eq!(
        spend_index.tx_id,
        crate::ids::TxStorageId::from_raw(spend_id)
    );
    assert_eq!(spend_index.height, BlockHeight::from_raw(s));
    assert_eq!(
        snap.open_table(TX_OUTPUTS)
            .expect("t")
            .get(spend_id)
            .expect("g")
            .expect("row")
            .value()
            .decode()
            .expect("decodes"),
        TxOutputIndices(vec![
            crate::ids::AmountIndex::from_raw(s + 1),
            crate::ids::AmountIndex::from_raw(s + 2),
        ])
    );
    assert_eq!(
        snap.open_table(OUTPUT_TXS).expect("t").len().expect("len"),
        s + 3
    );
    assert_eq!(
        snap.open_table(OUTPUT_AMOUNTS)
            .expect("t")
            .len()
            .expect("len"),
        s + 3,
        "one bucket: amount_index runs over every output under amount 0, and equals output_id"
    );
    let info1 = snap
        .open_table(BLOCK_INFO)
        .expect("t")
        .get(s)
        .expect("g")
        .expect("row")
        .value()
        .decode()
        .expect("decodes");
    assert_eq!(
        info1.rct_outputs, 3,
        "this block's outputs only (1 + 2): per-block, not cumulative (CEN-L15)"
    );
    assert_eq!(
        snap.open_table(BLOCK_BURN)
            .expect("t")
            .get(s)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(AtomicUnits::from_raw(25))
    );
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("t")
        .get(s - 1)
        .expect("g")
        .is_none());
    assert_eq!(
        snap.get_property::<TotalBurnedCell>().expect("cell"),
        Some(AtomicUnits::from_raw(25))
    );
    // The spend's prunable row is its prunable segment, byte-for-byte — the
    // wire's `pruned ‖ pqc_auths ‖ prunable` split (STX-8), derived from the
    // fixture rather than pinned as a length. (Until E6 slice 5 the fixture
    // was the storage-pruned form and this row was empty; CEN-H19 refuses
    // that form at consensus.)
    let expected_prunable = spend_at(&hashes, s, 9, 2)
        .write_segments()
        .expect("segments")
        .prunable;
    assert!(!expected_prunable.is_empty());
    assert_eq!(
        snap.open_table(TXS_PRUNABLE)
            .expect("t")
            .get(spend_id)
            .expect("g")
            .map(|g| g.value().bytes().to_vec()),
        Some(expected_prunable)
    );
    cleanup(&path);
}

#[test]
fn pop_by_replay_returns_the_store_to_the_state_before_the_block() {
    let path = tmp("connect-pop");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // The chain below the first admissible spend height, each block handed
    // `burned = 3`. Snapshot every table's row count and total_burned after it.
    let s = FIRST_SPEND_HEIGHT;
    let hashes = connect_chain_with_burn(&store, &vec![Vec::new(); at(s)], 3);
    fn len<K: redb::Key + 'static, V: redb::Value + 'static>(
        snap: &ReadSnapshot<'_>,
        t: redb::TableDefinition<'static, K, V>,
    ) -> u64 {
        snap.open_table(t)
            .map(|t| t.len().expect("len"))
            .unwrap_or(0)
    }
    let counts = |store: &ChainStore| -> (u64, u64, u64, u64, u64, Option<AtomicUnits>) {
        let snap = store.begin_read().expect("read");
        (
            len(&snap, BLOCKS),
            len(&snap, TX_INDICES),
            len(&snap, OUTPUT_TXS),
            len(&snap, CURVE_TREE_ROOTS),
            len(&snap, SPENT_KEYS),
            snap.get_property::<TotalBurnedCell>().expect("cell"),
        )
    };
    let before = counts(&store);
    // Genesis was handed `burned = 3` and recorded none: the burn phase is
    // guarded `h > 0 && burned > 0` as a whole (`blockchain.cpp:6148`), so
    // the fold holds the blocks above genesis only. One coinbase, one
    // output, one root per block; nothing spent.
    assert_eq!(
        before,
        (s, s, s, s, 0, Some(AtomicUnits::from_raw(3 * (s - 1))))
    );

    let b1 = candidate(s, hashes[at(s - 1)], vec![spend_at(&hashes, s, 9, 2)]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(s, 4), RuleSet::GENESIS)?)
    });
    out.expect("the spend block connects");
    // `OUTPUT_TXS`: one more coinbase output, plus the spend's two (CEN-I1's
    // minimum since slice 6 commit 2).
    assert_eq!(
        counts(&store),
        (
            s + 1,
            s + 2,
            s + 3,
            s + 1,
            1,
            Some(AtomicUnits::from_raw(3 * (s - 1) + 4))
        )
    );

    let popped: Result<Replayed, TestErr> = store.write(|batch| Ok(batch.replay_undo(s)?));
    assert!(matches!(popped, Ok(Replayed::Entries(_))));
    assert_eq!(
        counts(&store),
        before,
        "every table and the fold are back to the pre-block state"
    );
    let snap = store.begin_read().expect("read");
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("t")
        .get(s)
        .expect("g")
        .is_none());
    assert!(snap
        .open_table(UNDO_LOG)
        .expect("t")
        .get(s)
        .expect("g")
        .is_none());
    cleanup(&path);
}

// ---------------------------------------------------------------- belts

fn expect_row<T: core::fmt::Debug + PartialEq>(out: &Result<T, TestErr>, want: StoreInvariant) {
    assert_eq!(
        *out,
        Err(TestErr::Store(StoreError::from(want).to_string())),
        "{want}"
    );
}

#[test]
fn a_block_whose_parent_is_not_the_tip_is_si2() {
    let path = tmp("connect-parent");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    // CEN-A2 now stands in front of this belt (E6 slice 1): a candidate
    // whose `previous` is not the tip is refused as a verdict and never
    // reaches `connect`. The belt's remaining subject is a verdict that was
    // TRUE when minted and is stale by the time it connects — two siblings
    // judged against the same tip, the second connected after the first
    // moved it. That is exactly what a belt beneath a rule is for.
    let mut sibling = candidate(1, genesis.hash(), Vec::new());
    sibling.block.header.nonce = 8;
    let stale = candidate(1, genesis.hash(), Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let first = judge(&view, sibling)?;
        let second = judge(&view, stale)?; // judged against the same tip: passes A2
        batch.connect(first, facts(1, 0), RuleSet::GENESIS)?; // the tip moves
        Ok(batch.connect(second, facts(1, 0), RuleSet::GENESIS)?) // stale: SI-2
    });
    expect_row(&out, StoreInvariant::TipMismatch);
    assert_eq!(StoreInvariant::TipMismatch.row(), 2);
    // The belt fired before any row of the second block was journaled, and
    // the writer halted at the connecting height it noted for that block —
    // 2, because the first sibling had connected (§3.6.2; PR #757 review).
    // The aborted batch also un-connects the first sibling: nothing landed.
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row: StoreInvariant::TipMismatch,
        }
    );
    cleanup(&path);
}

/// Genesis, plant through `plant`, connect block 1 — SI-9 poisons and
/// halts. The unique assertion is the planted keys; the scaffold is one
/// helper so these belts cannot drift from each other.
fn plant_then_connect_is_si9(
    label: &str,
    plant: impl FnOnce(&mut WriteBatch<'_, '_>) -> Result<(), StoreError>,
) {
    let path = tmp(label);
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    let planted: Result<(), TestErr> = store.write(|batch| {
        plant(batch)?;
        Ok(())
    });
    planted.expect("plant");
    let b1 = candidate(1, genesis.hash(), Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), RuleSet::GENESIS)?)
    });
    expect_row(&out, StoreInvariant::IdNotFresh);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row: StoreInvariant::IdNotFresh,
        }
    );
    cleanup(&path);
}

fn slot(amount: u64, index: u64) -> OutputSlot {
    OutputSlot::new(
        AtomicUnits::from_raw(amount),
        crate::ids::AmountIndex::from_raw(index),
    )
}

fn amount_record(output_id: u64) -> OutKey {
    OutKey {
        output_id: crate::ids::OutputStorageId::from_raw(output_id),
        pubkey: shekyl_types::OneTimePubkey::from_bytes(
            [u8::try_from(output_id & 0xff).expect("byte"); 32],
        ),
        unlock_time: stored_timelock(0),
        height: BlockHeight::from_raw(0),
        commitment: shekyl_types::CommitmentBytes::from_bytes([9; 32]),
    }
}

/// SI-9 on the keyed `output_amounts` (SOK-Q2): density is `last + 1 == len`
/// over the one bucket. A planted row at index 5 makes `len == 2` with
/// `last == 5`, so the next connect poisons before it writes.
#[test]
fn a_gapped_amount_bucket_is_si9() {
    plant_then_connect_is_si9("connect-amount-bucket", |batch| {
        batch
            .open_insert_table(OUTPUT_AMOUNTS, StoreInvariant::IdNotFresh)?
            .insert(slot(0, 5).key(), amount_record(99).encoded().as_encoded())?;
        Ok(())
    });
}

/// The single-bucket premise is checked, not assumed: a row under another
/// amount is a non-miner, non-emission loud vout that reached the store —
/// the validator's hole, SI-9, never a verdict.
#[test]
fn a_second_amount_bucket_is_si9_the_validators_hole_not_a_verdict() {
    plant_then_connect_is_si9("connect-second-bucket", |batch| {
        batch
            .open_insert_table(OUTPUT_AMOUNTS, StoreInvariant::IdNotFresh)?
            .insert(slot(7, 0).key(), amount_record(98).encoded().as_encoded())?;
        Ok(())
    });
}

/// A hole in the confidential bucket compensated by a foreign-bucket row
/// — `(0,0), (0,2), (7,5)` has `len == 3` and bucket-0 `last == 2`. The
/// ends check refuses it: the last key's amount is `7`, not the bucket's.
#[test]
fn a_hole_compensated_by_a_foreign_bucket_row_is_still_si9() {
    plant_then_connect_is_si9("connect-compensated-hole", |batch| {
        let mut amounts = batch.open_insert_table(OUTPUT_AMOUNTS, StoreInvariant::IdNotFresh)?;
        amounts.insert(slot(0, 2).key(), amount_record(2).encoded().as_encoded())?;
        amounts.insert(slot(7, 5).key(), amount_record(3).encoded().as_encoded())?;
        Ok(())
    });
}

/// SOK-2: a planted `output_txs` row makes the next `output_id` 2 while
/// the amount bucket's next index is 1. The two counters disagree; the
/// write refuses a record whose key and `output_id` differ.
#[test]
fn amount_index_and_output_id_diverging_is_si9() {
    plant_then_connect_is_si9("connect-two-counters", |batch| {
        batch
            .open_insert_table(OUTPUT_TXS, StoreInvariant::IdNotFresh)?
            .insert(
                1,
                OutTx {
                    tx_hash: shekyl_types::TxHash::from_bytes([0xab; 32]),
                    local_index: shekyl_types::OutputIndexInTx::from_raw(0),
                }
                .encoded()
                .as_encoded(),
            )?;
        Ok(())
    });
}

/// Unique-key primary: `txs_pruned` keys `{0, 3}` have `len == 2`; using
/// `len` as the next id would insert 2 over the hole.
#[test]
fn a_gapped_txs_pruned_primary_is_si9() {
    plant_then_connect_is_si9("connect-txid-gap", |batch| {
        batch
            .open_insert_table(TXS_PRUNED, StoreInvariant::IdNotFresh)?
            .insert(3, Raw::<TxPrunedSegment>::new(&[0u8; 1]))?;
        Ok(())
    });
}

/// The belt beneath CEN-I7. A key image an earlier block spent is I7's
/// refusal at `validate` (slice 6 commit 4) and never reaches `connect`
/// through `judge`; the belt's remaining subject is the table moving under
/// a token already judged against it, and that is what this plants.
///
/// Until commit 4 this test reached SI-1 with a plain double spend — it was
/// testing the belt as if it were the rule, and the belt passing was the
/// validator's hole made green. This is the shape it should always have
/// had: the rule refuses the spend, and the belt is tested as a belt.
#[test]
fn a_key_image_recorded_under_a_judged_token_is_si1() {
    let path = tmp("connect-ki");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let s = FIRST_SPEND_HEIGHT;
    let hashes = connect_chain(&store, &spendable_prefix(&[]));
    let b1 = candidate(s, hashes[at(s - 1)], vec![spend_at(&hashes, s, 9, 2)]);
    let out = connect_with_image_planted_under_the_token(&store, b1, s);
    expect_row(&out, StoreInvariant::KeyImageNotFresh);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.open_table(BLOCKS).expect("t").len().expect("len"),
        s,
        "nothing landed"
    );
    cleanup(&path);
}

#[test]
fn the_same_transaction_in_two_blocks_is_si3() {
    let path = tmp("connect-txhash");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    // A spend with a fresh key image each time but the SAME body cannot be
    // built (the key image is in the body). The one legal listed shape with
    // no key image is a serve-credit-only transaction: listed twice across
    // blocks, same hash, nothing for SI-1 to see. (A coinbase-shaped body
    // served here until E6 slice 5 landed CEN-H5, which refuses `gen`
    // outside the miner slot — the fixture was the input the row exists to
    // refuse.)
    let dup = fixture::serve_credit_only([0x77; 32]);
    let b1 = candidate(1, genesis.hash(), vec![dup.clone()]);
    let b1_hash = b1.block.hash();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), RuleSet::GENESIS)?)
    });
    out.expect("block 1");
    let b2 = candidate(2, b1_hash, vec![dup]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b2)?, facts(2, 0), RuleSet::GENESIS)?)
    });
    expect_row(&out, StoreInvariant::TxHashNotFresh);
    cleanup(&path);
}

#[test]
fn a_total_burned_fold_that_would_wrap_is_si8_never_a_saturate() {
    let path = tmp("connect-fold");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Genesis records no burn (the `h > 0` guard), so the fold that must
    // overflow is block 1's.
    let (_, genesis) = connect_genesis(&store, 0);
    let seeded: Result<(), TestErr> = store.write(|batch| {
        batch.upsert_property::<TotalBurnedCell>(&AtomicUnits::from_raw(u64::MAX))?;
        Ok(())
    });
    seeded.expect("seed");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(
            judge(&view, candidate(1, genesis.hash(), Vec::new()))?,
            facts(1, 1),
            RuleSet::GENESIS,
        )?)
    });
    expect_row(
        &out,
        StoreInvariant::FoldOverflow {
            cell: "total_burned",
        },
    );
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.get_property::<TotalBurnedCell>().expect("cell"),
        Some(AtomicUnits::from_raw(u64::MAX)),
        "unchanged: the batch aborted"
    );
    cleanup(&path);
}

#[test]
fn a_root_already_recorded_at_the_connecting_height_is_si4() {
    let path = tmp("connect-root");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)?
            .insert(1, CurveTreeRoot::from_bytes([1; 32]).encoded().as_encoded())?;
        Ok(())
    });
    planted.expect("plant");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(
            judge(&view, candidate(0, BlockHash::NULL, Vec::new()))?,
            facts(0, 0),
            RuleSet::GENESIS,
        )?)
    });
    expect_row(&out, StoreInvariant::RootRewritten);
    cleanup(&path);
}

// -------------------------------------------------------- provenance

#[test]
fn a_pass_through_connect_taints_the_file_s_provenance_and_a_derived_one_does_not() {
    let path = tmp("connect-provenance");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert!(store.provenance().is_parity_evidence(), "fresh file");

    // Fully derived facts (the E6-complete shape): nothing is stamped.
    let derived = ConnectFacts {
        weight: Fact::derived(shekyl_types::BlockWeight::from_raw(1_000)),
        long_term_weight: Fact::derived(shekyl_types::LongTermWeight::from_raw(900)),
        coins_generated: Fact::derived(AtomicUnits::from_raw(1_000_000)),
        burned: Fact::derived(AtomicUnits::ZERO),
        root_after: Fact::derived(CurveTreeRoot::from_bytes([0xc0; 32])),
        long_term_effective_median: Fact::derived(shekyl_types::LongTermWeight::from_raw(300_000)),
    };
    let g = candidate(0, BlockHash::NULL, Vec::new());
    let g_hash = g.block.hash();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, g)?, derived, RuleSet::GENESIS)?)
    });
    out.expect("genesis");
    // Derived facts stamp no pass-through. But GENESIS *enforces* every
    // consensus row and the port has implemented only some, so the verdict
    // evaluated exactly the implemented ones — and the file records exactly
    // that: every enforced row the validator has not landed is a coverage
    // gap, and the file is NOT parity evidence. That is C2-R8 §9.4 doing its
    // job, not a defect: a store fed by a partial validator can never be
    // mistaken for one fed by a complete one. (Written against the scaffold
    // as "every enforced row"; E6 slice 1 landed the first rules, so the
    // expectation is now `enforced − implemented`, read off the registry.)
    let after_genesis = store.provenance();
    assert!(after_genesis.passed_through().is_empty());
    let not_yet_landed: Vec<_> = RuleSet::GENESIS
        .enforced()
        .filter(|row| row.status() == RowStatus::Pending)
        .collect();
    assert!(
        !not_yet_landed.is_empty(),
        "the port is not complete: GENESIS still enforces unimplemented rows"
    );
    assert_ne!(
        not_yet_landed.len(),
        RuleSet::GENESIS.enforced().count(),
        "at least one rule has landed, so at least one enforced row is not a gap"
    );
    assert_eq!(
        after_genesis.coverage_gaps().iter().collect::<Vec<_>>(),
        not_yet_landed
    );
    assert!(!after_genesis.is_parity_evidence());
    assert!(after_genesis
        .artifact_stamp()
        .starts_with("apply-policy=full coverage-gaps=[CEN-"));
    assert!(after_genesis
        .artifact_stamp()
        .ends_with("NOT-PARITY-EVIDENCE"));

    // An aborted pass-through connect leaves no new taint.
    let b1 = candidate(1, g_hash, Vec::new());
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        batch.connect(judge(&view, b1.clone())?, facts(1, 0), RuleSet::GENESIS)?;
        Err(TestErr::Abort)
    });
    assert_eq!(out, Err(TestErr::Abort));
    assert_eq!(
        store.provenance(),
        after_genesis,
        "abort: nothing landed, no new taint"
    );

    // A committed pass-through connect stamps exactly the passed fields.
    let mut partial = facts(1, 0);
    partial.burned = Fact::derived(AtomicUnits::ZERO);
    partial.root_after = Fact::derived(CurveTreeRoot::from_bytes([0xc1; 32]));
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, partial, RuleSet::GENESIS)?)
    });
    out.expect("block 1");
    let prov = store.provenance();
    assert!(!prov.is_parity_evidence());
    assert_eq!(
        prov.passed_through().iter().collect::<Vec<_>>(),
        [
            "weight",
            "long_term_weight",
            "coins_generated",
            "long_term_effective_median"
        ]
    );
    assert_eq!(
        prov.coverage_gaps(),
        after_genesis.coverage_gaps(),
        "unchanged"
    );
    assert!(prov.artifact_stamp().contains(
        "passed-through=[weight,long_term_weight,coins_generated,\
         long_term_effective_median] NOT-PARITY-EVIDENCE"
    ));
    // Monotone: a later fully-derived connect cannot narrow it, and a
    // read-only reopen reads the same record from the file.
    drop(store);
    let ro = ChainStore::open_read_only(&path, EPOCH).expect("ro");
    assert_eq!(ro.provenance(), prov);
    assert_eq!(ro.provenance().artifact_stamp(), prov.artifact_stamp());
    cleanup(&path);
}

#[test]
fn coverage_gaps_widen_in_the_committing_batch_and_never_narrow() {
    // No issued rule set enforces a row yet, so `connect` cannot produce a
    // gap end to end; the mechanism is exercised at the header, exactly as
    // `connect` calls it.
    let path = tmp("connect-gaps");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let row = shekyl_chain_rules::CenRow::ALL[3];
    let aborted: Result<(), TestErr> = store.write(|batch| {
        super::header::widen_gaps(batch.txn(), CoverageGaps::of([row]))?;
        Err(TestErr::Abort)
    });
    assert_eq!(aborted, Err(TestErr::Abort));
    assert!(
        store.provenance().coverage_gaps().is_empty(),
        "abort leaves no gap"
    );

    let out: Result<(), TestErr> = store.write(|batch| {
        super::header::widen_gaps(batch.txn(), CoverageGaps::of([row]))?;
        Ok(())
    });
    assert_eq!(out, Ok(()));
    let prov = store.provenance();
    assert!(prov.coverage_gaps().contains(row));
    assert!(!prov.is_parity_evidence());
    assert_eq!(
        prov.artifact_stamp(),
        format!("apply-policy=full coverage-gaps=[{row}] NOT-PARITY-EVIDENCE")
    );
    // A later batch that widens by nothing changes nothing.
    let out: Result<(), TestErr> = store.write(|batch| {
        super::header::widen_gaps(batch.txn(), CoverageGaps::NONE)?;
        Ok(())
    });
    assert_eq!(out, Ok(()));
    assert_eq!(store.provenance(), prov);
    cleanup(&path);
}

#[test]
fn deleted_by_and_the_persisted_field_names_are_one_list() {
    let declared: Vec<&str> = ConnectFacts::DELETED_BY.iter().map(|d| d.field).collect();
    assert_eq!(
        declared, FACT_FIELDS,
        "ConnectFacts::DELETED_BY order is the codec's bit order"
    );
}

#[test]
fn passed_through_names_the_rows_that_delete_each_fact() {
    let all = facts(0, 0);
    let remaining: Vec<&str> = all.passed_through().map(|d| d.field).collect();
    assert_eq!(
        remaining,
        [
            "weight",
            "long_term_weight",
            "coins_generated",
            "burned",
            "root_after",
            "long_term_effective_median"
        ],
        "six: cumulative_difficulty left with E6 slice 2 (CEN-D4 derives it)"
    );
    let mut some = all;
    some.coins_generated = Fact::derived(AtomicUnits::from_raw(1_000_000));
    some.root_after = Fact::derived(CurveTreeRoot::from_bytes([0xc0; 32]));
    let remaining: Vec<DeletedBy> = some.passed_through().collect();
    assert_eq!(remaining.len(), 4);
    assert!(remaining
        .iter()
        .all(|d| !d.rows.is_empty() && !d.slice.is_empty()));
    assert!(remaining
        .iter()
        .any(|d| d.field == "burned" && d.rows.contains(&"CEN-F17")));
    assert_eq!(
        ConnectFacts::DELETED_BY.len(),
        6,
        "seven until E6 slice 2 derived cumulative_difficulty"
    );
}
