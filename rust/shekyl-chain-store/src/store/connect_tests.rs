// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `connect` tests (S-CHAIN-W commit 6): the write set row by row against
//! the LMDB layouts, a two-block batch with a spend, connect → pop →
//! digest-equal, and every belt fired from a hand-built violation.
//!
//! Blocks go through the real `validate` under `RuleSet::GENESIS` — the
//! rules landed so far (E6 slice 1: 4.B's version rows) pass every
//! well-formed fixture here, and coverage records exactly those rows — so
//! `connect` is exercised through its public signature. Every store here is
//! a fresh file (SCW-17).

use redb::ReadableTableMetadata;
use shekyl_chain_rules::{validate, Candidate, ChainValid, RowStatus, RuleSet, RuleSetId};
use shekyl_types::{BlockHeight, CurveTreeRoot};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::undo::Replayed;
use super::view::BatchView;
use super::*;
use crate::codec::{
    BlockInfo, Canonical, CoverageGaps, CurveRoot, OutKey, OutTx, TotalBurnedCell, TxIndex,
    TxOutputIndices, UndoLog, FACT_FIELDS,
};
use crate::lmdb_order::{Hash32, LmdbHashKey};
use crate::schema::{
    BLOCKS, BLOCK_BURN, BLOCK_HEIGHTS, BLOCK_INFO, CURVE_TREE_ROOTS, HF_VERSIONS, OUTPUT_AMOUNTS,
    OUTPUT_TXS, SPENT_KEYS, TXS_PQC_AUTHS, TXS_PRUNABLE, TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES,
    TX_OUTPUTS, UNDO_LOG,
};

// ------------------------------------------------------------ fixtures

fn coinbase(height: u64, outputs: usize) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height + 60,
            inputs: vec![Input::Gen(height)],
            outputs: (0..outputs)
                .map(|i| Output {
                    amount: 0,
                    key: [0x40 + u8::try_from(i).expect("small"); 32],
                    view_tag: 1,
                })
                .collect(),
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]; outputs],
            enc_labels: vec![[0x66; 9]; outputs],
            commitments: (0..outputs)
                .map(|i| [0x70 + u8::try_from(i).expect("small"); 32])
                .collect(),
        }),
    }
}

/// A spend-shaped listed transaction in the storage-pruned form (no
/// prunable, no pqc_auths): one key image in, `outputs` outputs. No landed
/// rule reads a transaction yet (4.H/4.I are later slices), so it is
/// admitted; what it exercises is the write set, not consensus.
pub(super) fn spend(key_image: u8, outputs: usize) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image: [key_image; 32],
            }],
            outputs: (0..outputs)
                .map(|i| Output {
                    amount: 0,
                    key: [0x80 + u8::try_from(i).expect("small"); 32],
                    view_tag: 2,
                })
                .collect(),
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 7,
            reference_block: [0x99; 32],
            base: CtBase {
                enc_amounts: vec![[0x11; 9]; outputs],
                enc_labels: vec![[0x22; 9]; outputs],
                commitments: (0..outputs)
                    .map(|i| [0xa0 + u8::try_from(i).expect("small"); 32])
                    .collect(),
            },
            pqc_auths: Vec::new(),
            prunable: None,
        },
    }
}

/// The root the header at `height` must carry under CEN-B5: the tree state
/// *at* `height` — the `root_after` the connect of `height − 1` wrote
/// (`facts(height − 1)`), or the empty tree at genesis. Kept in one place
/// with `facts` so the two cannot drift.
pub(super) fn root_at_height(height: u64) -> CurveTreeRoot {
    match height.checked_sub(1) {
        None => CurveTreeRoot::EMPTY,
        Some(parent) => facts(parent, 0).root_after.value,
    }
}

pub(super) fn candidate(height: u64, previous: [u8; 32], listed: Vec<Transaction>) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            // CEN-B5 landed (E6 slice 1): the header carries the state at
            // its height, not a placeholder.
            curve_tree_root: root_at_height(height).to_bytes(),
            attestation_root: [0x33; 32],
        },
        miner_transaction: coinbase(height, 1),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

pub(super) fn facts(height: u64, burned: u64) -> ConnectFacts {
    ConnectFacts {
        weight: Fact::passed_through(1_000 + height),
        long_term_weight: Fact::passed_through(900 + height),
        cumulative_difficulty: Fact::passed_through(u128::from(height + 1) * 100),
        coins_generated: Fact::passed_through((height + 1) * 1_000_000),
        burned: Fact::passed_through(burned),
        root_after: Fact::passed_through(CurveTreeRoot::from_bytes(
            [0xc0 + u8::try_from(height).expect("small"); 32],
        )),
    }
}

fn judge<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    Ok(validate(candidate, view, &RuleSet::GENESIS)?
        .expect("the fixtures satisfy every landed rule"))
}

const GENESIS_ID: RuleSetId = RuleSetId::GENESIS;

fn connect_genesis(store: &ChainStore, burned: u64) -> (Connected, Block) {
    let cand = candidate(0, [0; 32], Vec::new());
    let block = cand.block.clone();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, cand)?;
        Ok(batch.connect(valid, facts(0, burned), GENESIS_ID)?)
    });
    (out.expect("genesis connects"), block)
}

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
    let miner_hash = Hash32::from_bytes(miner.hash());
    let block_hash = Hash32::from_bytes(block.hash());
    let snap = store.begin_read().expect("read");

    // block tables
    assert_eq!(
        snap.open_table(BLOCKS)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().to_vec()),
        Some(block.serialize()),
        "blocks[0] is the judged block re-serialized"
    );
    assert_eq!(
        snap.open_table(BLOCK_HEIGHTS)
            .expect("t")
            .get(LmdbHashKey::from(block_hash))
            .expect("g")
            .map(|g| g.value()),
        Some(0)
    );
    let info = BlockInfo::decode(
        snap.open_table(BLOCK_INFO)
            .expect("t")
            .get(0)
            .expect("g")
            .expect("row")
            .value(),
    )
    .expect("decodes");
    assert_eq!(
        info,
        BlockInfo {
            timestamp: 1_000,
            coins_generated: 1_000_000,
            weight: 1_000,
            cumulative_difficulty: 100,
            hash: block_hash,
            rct_outputs: 1,
            long_term_weight: 900,
        }
    );
    assert_eq!(
        snap.open_table(HF_VERSIONS)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value()),
        Some(GENESIS_ID.to_raw()),
        "hf_versions[h] is the rule set in force (SCW-16)"
    );
    assert_eq!(
        CurveRoot::decode(
            snap.open_table(CURVE_TREE_ROOTS)
                .expect("t")
                .get(1)
                .expect("g")
                .expect("row at h + 1")
                .value()
        )
        .expect("decodes"),
        CurveRoot::from_bytes([0xc0; 32]),
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
        TxIndex::decode(
            snap.open_table(TX_INDICES)
                .expect("t")
                .get(LmdbHashKey::from(miner_hash))
                .expect("g")
                .expect("row")
                .value()
        )
        .expect("decodes"),
        TxIndex {
            tx_id: 0,
            unlock_time: 60,
            height: 0
        }
    );
    let segments = miner.write_segments().expect("segments");
    assert_eq!(
        snap.open_table(TXS_PRUNED)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value().to_vec()),
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
            .map(|g| g.value().to_vec()),
        Some(Vec::new()),
        "a coinbase has an EMPTY prunable row (LMDB parity)"
    );
    assert_eq!(
        snap.open_table(TXS_PRUNABLE_HASH)
            .expect("t")
            .get(0)
            .expect("g")
            .map(|g| g.value()),
        Some(Hash32::from_bytes(miner.prunable_hash())),
        "keccak256 of the empty region, not the null hash"
    );
    assert_eq!(
        TxOutputIndices::decode(
            snap.open_table(TX_OUTPUTS)
                .expect("t")
                .get(0)
                .expect("g")
                .expect("row")
                .value()
        )
        .expect("decodes"),
        TxOutputIndices(vec![0])
    );

    // output tables
    assert_eq!(
        OutTx::decode(
            snap.open_table(OUTPUT_TXS)
                .expect("t")
                .get(0)
                .expect("g")
                .expect("row")
                .value()
        )
        .expect("decodes"),
        OutTx {
            tx_hash: miner_hash,
            local_index: 0
        }
    );
    let members: Vec<OutKey> = snap
        .open_multimap_table(OUTPUT_AMOUNTS)
        .expect("t")
        .get(0)
        .expect("g")
        .map(|m| OutKey::decode(m.expect("member").value()).expect("decodes"))
        .collect();
    assert_eq!(
        members,
        vec![OutKey {
            amount_index: 0,
            output_id: 0,
            pubkey: [0x40; 32],
            unlock_time: 60,
            height: 0,
            commitment: [0x70; 32],
        }],
        "stored under amount 0 with the ct-base commitment"
    );

    // no burn, no key images, no total_burned yet
    assert!(snap.open_table(BLOCK_BURN).is_err());
    assert!(snap
        .open_table(SPENT_KEYS)
        .expect("t")
        .is_empty()
        .expect("len"));
    assert_eq!(snap.get_property::<TotalBurnedCell>().expect("cell"), None);
    // one undo row, with exactly the journaled count
    let undo = UndoLog::decode(
        snap.open_table(UNDO_LOG)
            .expect("t")
            .get(0)
            .expect("g")
            .expect("row")
            .value(),
    )
    .expect("decodes");
    assert_eq!(undo.0.len(), 12);
    cleanup(&path);
}

#[test]
fn two_blocks_in_one_batch_with_a_spend_and_a_burn() {
    let path = tmp("connect-two");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let g = candidate(0, [0; 32], Vec::new());
    let g_hash = g.block.hash();
    let b1 = candidate(1, g_hash, vec![spend(0x5e, 2)]);
    let b1_hash = b1.block.hash();
    let spend_hash = b1.transactions[0].hash();

    let out: Result<(Connected, Connected), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let c0 = batch.connect(judge(&view, g)?, facts(0, 0), GENESIS_ID)?;
        // Block 1 is validated against a view that already holds block 0
        // and connected in the same batch.
        let c1 = batch.connect(judge(&view, b1)?, facts(1, 25), GENESIS_ID)?;
        Ok((c0, c1))
    });
    let (c0, c1) = out.expect("both connect");
    assert_eq!(c0.height, BlockHeight::ZERO);
    assert_eq!(c1.height, BlockHeight::from_raw(1));
    // block 1: miner tx 7 (tx_indices, txs_pruned, txs_prunable,
    // txs_prunable_hash, output_txs, member, tx_outputs) + spend 10 (1 key
    // image + the same 4 tx rows + 2 outputs × (output_txs + member) +
    // tx_outputs) + root 1 + block 3 + hf 1 + block_burn 1 + total_burned 1
    // = 24.
    assert_eq!(c1.journaled, 24);

    let snap = store.begin_read().expect("read");
    assert_eq!(snap.open_table(BLOCKS).expect("t").len().expect("len"), 2);
    assert!(
        snap.open_table(SPENT_KEYS)
            .expect("t")
            .get(LmdbHashKey::from_bytes([0x5e; 32]))
            .expect("g")
            .is_some(),
        "the spend's key image is recorded"
    );
    assert_eq!(
        snap.open_table(BLOCK_HEIGHTS)
            .expect("t")
            .get(LmdbHashKey::from_bytes(b1_hash))
            .expect("g")
            .map(|g| g.value()),
        Some(1)
    );
    // Dense store ids across the two blocks: tx_ids 0 (g miner), 1 (b1
    // miner), 2 (spend); output_ids 0, 1, 2, 3; amount_index under 0: 0..4.
    let spend_index = TxIndex::decode(
        snap.open_table(TX_INDICES)
            .expect("t")
            .get(LmdbHashKey::from_bytes(spend_hash))
            .expect("g")
            .expect("row")
            .value(),
    )
    .expect("decodes");
    assert_eq!(spend_index.tx_id, 2);
    assert_eq!(spend_index.height, 1);
    assert_eq!(
        TxOutputIndices::decode(
            snap.open_table(TX_OUTPUTS)
                .expect("t")
                .get(2)
                .expect("g")
                .expect("row")
                .value()
        )
        .expect("decodes"),
        TxOutputIndices(vec![2, 3])
    );
    assert_eq!(
        snap.open_table(OUTPUT_TXS).expect("t").len().expect("len"),
        4
    );
    assert_eq!(
        snap.open_multimap_table(OUTPUT_AMOUNTS)
            .expect("t")
            .get(0)
            .expect("g")
            .len(),
        4
    );
    let info1 = BlockInfo::decode(
        snap.open_table(BLOCK_INFO)
            .expect("t")
            .get(1)
            .expect("g")
            .expect("row")
            .value(),
    )
    .expect("decodes");
    assert_eq!(
        info1.rct_outputs, 3,
        "this block's outputs only (1 + 2): per-block, not cumulative (CEN-L15)"
    );
    assert_eq!(
        snap.open_table(BLOCK_BURN)
            .expect("t")
            .get(1)
            .expect("g")
            .map(|g| g.value()),
        Some(25)
    );
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("t")
        .get(0)
        .expect("g")
        .is_none());
    assert_eq!(
        snap.get_property::<TotalBurnedCell>().expect("cell"),
        Some(25)
    );
    // The spend's prunable row is empty (storage-pruned form) and its
    // prunable hash is keccak256("") — the same value a coinbase carries.
    assert_eq!(
        snap.open_table(TXS_PRUNABLE)
            .expect("t")
            .get(2)
            .expect("g")
            .map(|g| g.value().len()),
        Some(0)
    );
    cleanup(&path);
}

#[test]
fn pop_by_replay_returns_the_store_to_the_state_before_the_block() {
    let path = tmp("connect-pop");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 3);
    // Snapshot every table's row count and total_burned after genesis.
    fn len<K: redb::Key + 'static, V: redb::Value + 'static>(
        snap: &ReadSnapshot<'_>,
        t: redb::TableDefinition<'static, K, V>,
    ) -> u64 {
        snap.open_table(t)
            .map(|t| t.len().expect("len"))
            .unwrap_or(0)
    }
    let counts = |store: &ChainStore| -> (u64, u64, u64, u64, u64, Option<u64>) {
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
    let after_genesis = counts(&store);
    // Genesis was handed `burned = 3` and recorded none: the burn phase is
    // guarded `h > 0 && burned > 0` as a whole (`blockchain.cpp:6148`), so
    // there is no `total_burned` cell yet.
    assert_eq!(after_genesis, (1, 1, 1, 1, 0, None));

    let b1 = candidate(1, genesis.hash(), vec![spend(0x5e, 1)]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 4), GENESIS_ID)?)
    });
    out.expect("block 1 connects");
    assert_eq!(counts(&store), (2, 3, 3, 2, 1, Some(4)));

    let popped: Result<Replayed, TestErr> = store.write(|batch| Ok(batch.replay_undo(1)?));
    assert!(matches!(popped, Ok(Replayed::Entries(_))));
    assert_eq!(
        counts(&store),
        after_genesis,
        "every table and the fold are back to the pre-block state"
    );
    let snap = store.begin_read().expect("read");
    assert!(snap
        .open_table(BLOCK_BURN)
        .expect("t")
        .get(1)
        .expect("g")
        .is_none());
    assert!(snap
        .open_table(UNDO_LOG)
        .expect("t")
        .get(1)
        .expect("g")
        .is_none());
    cleanup(&path);
}

// ---------------------------------------------------------------- belts

fn expect_row(out: &Result<Connected, TestErr>, want: StoreInvariant) {
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
        batch.connect(first, facts(1, 0), GENESIS_ID)?; // the tip moves
        Ok(batch.connect(second, facts(1, 0), GENESIS_ID)?) // stale: SI-2
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

#[test]
fn an_in_force_id_no_schedule_issued_is_refused_as_unknown_not_as_a_mismatch() {
    let path = tmp("connect-ruleset");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Raw id 7 is issued by no schedule. The verdict necessarily carries an
    // issued id, so comparing first would always report a mismatch and the
    // unknown-id refusal could never fire; `connect` resolves `in_force`
    // first (PR #757 review). `RuleSetNotInForce` is reached only once a
    // second rule set is issued — with GENESIS the sole set, a verdict's id
    // and an issued `in_force` cannot differ.
    let unissued = RuleSetId::from_raw(7);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, candidate(0, [0; 32], Vec::new()))?;
        Ok(batch.connect(valid, facts(0, 0), unissued)?)
    });
    let want = StoreCannot::RuleSetUnknown(unissued);
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));
    assert_eq!(StoreError::from(want).class(), ErrorClass::Cannot);
    assert!(
        RuleSet::for_id(unissued).is_none(),
        "the premise of the test"
    );
    // Nothing landed: the refusal came before any write.
    let snap = store.begin_read().expect("read");
    assert!(snap.open_table(BLOCKS).is_err());
    cleanup(&path);
}

/// SI-9 for the derived `amount_index`: redb orders `output_amounts`
/// members by index prefix *then* payload, so a second member under one
/// index with a different payload is "new" to redb. `connect` checks
/// `last + 1 == len` and that the first/last prefixes are not duplicated
/// at the ends, so a hole or Copilot's `[0, 2, 2]` poisons before a second
/// member under one index can be written.
#[test]
fn a_gapped_or_duplicated_amount_bucket_is_si9_not_a_second_member() {
    let path = tmp("connect-amount-bucket");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    // Genesis put one member (index 0) under amount 0. Plant a foreign member
    // whose prefix skips to 5: len becomes 2 but the highest prefix is 5.
    let planted: Result<(), TestErr> = store.write(|batch| {
        let hole = OutKey {
            amount_index: 5,
            output_id: 99,
            pubkey: [9; 32],
            unlock_time: 0,
            height: 0,
            commitment: [9; 32],
        };
        batch
            .open_multimap_table(OUTPUT_AMOUNTS)?
            .insert(0, hole.encode().as_slice())?;
        Ok(())
    });
    planted.expect("plant");
    let b1 = candidate(1, genesis.hash(), Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), GENESIS_ID)?)
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

fn amount_member(amount_index: u64, output_id: u64) -> OutKey {
    OutKey {
        amount_index,
        output_id,
        pubkey: [u8::try_from(output_id & 0xff).expect("byte"); 32],
        unlock_time: 0,
        height: 0,
        commitment: [9; 32],
    }
}

/// Compensating hole+duplicate at the high end: prefixes `[0, 2, 2]` have
/// `len == 3` and `last == 2`, so `last + 1 == len` alone would accept.
/// The end-peek refuses the duplicated last prefix.
#[test]
fn a_compensating_duplicate_at_the_amount_bucket_end_is_si9() {
    let path = tmp("connect-amount-dup-end");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    let planted: Result<(), TestErr> = store.write(|batch| {
        let mut amounts = batch.open_multimap_table(OUTPUT_AMOUNTS)?;
        amounts.insert(0, amount_member(2, 98).encode().as_slice())?;
        amounts.insert(0, amount_member(2, 99).encode().as_slice())?;
        Ok(())
    });
    planted.expect("plant");
    let b1 = candidate(1, genesis.hash(), Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), GENESIS_ID)?)
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

/// Unique-key primary: `txs_pruned` keys `{0, 3}` have `len == 2`; using
/// `len` as the next id would insert 2 over the hole.
#[test]
fn a_gapped_txs_pruned_primary_is_si9() {
    let path = tmp("connect-txid-gap");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    let planted: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(TXS_PRUNED, StoreInvariant::IdNotFresh)?
            .insert(3, [0u8; 1].as_slice())?;
        Ok(())
    });
    planted.expect("plant");
    let b1 = candidate(1, genesis.hash(), Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), GENESIS_ID)?)
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

#[test]
fn a_key_image_spent_in_an_earlier_block_is_si1() {
    let path = tmp("connect-ki");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    let b1 = candidate(1, genesis.hash(), vec![spend(0x5e, 1)]);
    let b1_hash = b1.block.hash();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), GENESIS_ID)?)
    });
    out.expect("block 1");
    // No landed rule checks key images yet (CEN-I7 is slice 6), so the
    // double spend reaches the store — and the belt beneath the rule catches
    // it as a fatal.
    let b2 = candidate(2, b1_hash, vec![spend(0x5e, 1)]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b2)?, facts(2, 0), GENESIS_ID)?)
    });
    expect_row(&out, StoreInvariant::KeyImageNotFresh);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.open_table(BLOCKS).expect("t").len().expect("len"),
        2,
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
    // built (the key image is in the body), so reuse a coinbase-shaped body
    // as a listed tx: listed twice across blocks, same hash, no key image.
    let dup = coinbase(77, 1);
    let b1 = candidate(1, genesis.hash(), vec![dup.clone()]);
    let b1_hash = b1.block.hash();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, facts(1, 0), GENESIS_ID)?)
    });
    out.expect("block 1");
    let b2 = candidate(2, b1_hash, vec![dup]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b2)?, facts(2, 0), GENESIS_ID)?)
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
        batch.upsert_property::<TotalBurnedCell>(&u64::MAX)?;
        Ok(())
    });
    seeded.expect("seed");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(
            judge(&view, candidate(1, genesis.hash(), Vec::new()))?,
            facts(1, 1),
            GENESIS_ID,
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
        Some(u64::MAX),
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
            .insert(1, CurveRoot::from_bytes([1; 32]).encode().as_slice())?;
        Ok(())
    });
    planted.expect("plant");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(
            judge(&view, candidate(0, [0; 32], Vec::new()))?,
            facts(0, 0),
            GENESIS_ID,
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
        weight: Fact::derived(1_000),
        long_term_weight: Fact::derived(900),
        cumulative_difficulty: Fact::derived(100),
        coins_generated: Fact::derived(1_000_000),
        burned: Fact::derived(0),
        root_after: Fact::derived(CurveTreeRoot::from_bytes([0xc0; 32])),
    };
    let g = candidate(0, [0; 32], Vec::new());
    let g_hash = g.block.hash();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, g)?, derived, GENESIS_ID)?)
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
        batch.connect(judge(&view, b1.clone())?, facts(1, 0), GENESIS_ID)?;
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
    partial.burned = Fact::derived(0);
    partial.root_after = Fact::derived(CurveTreeRoot::from_bytes([0xc1; 32]));
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, b1)?, partial, GENESIS_ID)?)
    });
    out.expect("block 1");
    let prov = store.provenance();
    assert!(!prov.is_parity_evidence());
    assert_eq!(
        prov.passed_through().iter().collect::<Vec<_>>(),
        [
            "weight",
            "long_term_weight",
            "cumulative_difficulty",
            "coins_generated"
        ]
    );
    assert_eq!(
        prov.coverage_gaps(),
        after_genesis.coverage_gaps(),
        "unchanged"
    );
    assert!(prov.artifact_stamp().contains(
        "passed-through=[weight,long_term_weight,cumulative_difficulty,coins_generated] \
         NOT-PARITY-EVIDENCE"
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
            "cumulative_difficulty",
            "coins_generated",
            "burned",
            "root_after"
        ]
    );
    let mut some = all;
    some.cumulative_difficulty = Fact::derived(100);
    some.root_after = Fact::derived(CurveTreeRoot::from_bytes([0xc0; 32]));
    let remaining: Vec<DeletedBy> = some.passed_through().collect();
    assert_eq!(remaining.len(), 4);
    assert!(remaining
        .iter()
        .all(|d| !d.rows.is_empty() && !d.slice.is_empty()));
    assert!(remaining
        .iter()
        .any(|d| d.field == "burned" && d.rows.contains(&"CEN-F17")));
    assert_eq!(ConnectFacts::DELETED_BY.len(), 6);
}
