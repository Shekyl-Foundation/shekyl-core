// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three DRS-E3 reads on the batch view, and the growth the verdict
//! derives from them (`DRS_E3_CURVE_WRITER.md` §3.1–§3.3, §6 commit 4b).
//!
//! What this file pins is the **read side and the derivation**: a
//! recorded block's outputs come back as leaf sources in output order, the
//! drain at `h` takes block `h − 60`'s coinbase then block `h − 10`'s
//! listed outputs, and the verdict carries a non-empty root over them,
//! continuing the tree the connects before it wrote (`grow.rs`, commit 5):
//! the frontier and the per-height count are the store's own rows, and a
//! derived growth starts where they say the tree ends.

use shekyl_chain_rules::{AtHeight, ChainView, RuleSet};
use shekyl_types::{BlockHeight, CurveTreeRoot, GlobalOutputIndex};

use super::connect_fixtures::{
    candidate, candidate_over, connect_chain, judge, root_going_into, spend, spendable_prefix,
    FIRST_SPEND_HEIGHT,
};
use super::error::{CellFault, LeafCountFault, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{Canonical, LeafCount, OutTx, Raw, TxIndex, TxPrunedSegment};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{CURVE_TREE_LEAF_COUNTS, OUTPUT_TXS, TXS_PRUNED, TX_INDICES};

fn h(height: u64) -> BlockHeight {
    BlockHeight::from_raw(height)
}

/// Heights `0..=62`. A two-output spend sits in block `53`, so a connect at
/// `63` drains block `3`'s coinbase and block `53`'s two listed outputs —
/// after the connects at `60`, `61`, `62` drained blocks `0`, `1`, `2`'s
/// coinbases (the tree's first three leaves).
const TIP: u64 = 62;
const SPEND_HEIGHT: u64 = 53;
const _: () = assert!(SPEND_HEIGHT >= FIRST_SPEND_HEIGHT);

fn listing() -> Vec<Vec<shekyl_wire::Transaction>> {
    let mut listed = spendable_prefix(&[]);
    listed.resize(usize::try_from(TIP + 1).expect("small"), Vec::new());
    listed[usize::try_from(SPEND_HEIGHT).expect("small")] = vec![spend(9, 2)];
    listed
}

#[test]
fn outputs_at_returns_a_blocks_outputs_as_leaf_sources_in_output_order() {
    let path = tmp("leaf-outputs-at");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &listing());
    let snap = store.begin_read().expect("read");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Heights below the spend hold one coinbase output each, so block
        // 53's coinbase is global output 53 and its spend's two are 54, 55.
        let AtHeight::Recorded(outputs) = view.outputs_at(h(SPEND_HEIGHT))? else {
            panic!("a recorded height");
        };
        let gids = |sources: &[shekyl_chain_rules::LeafSource]| {
            sources
                .iter()
                .map(|s| s.output.to_raw())
                .collect::<Vec<_>>()
        };
        assert_eq!(gids(&outputs.coinbase), vec![SPEND_HEIGHT]);
        assert_eq!(
            gids(&outputs.listed),
            vec![SPEND_HEIGHT + 1, SPEND_HEIGHT + 2]
        );
        // The key and commitment are the recorded rows'; the CM is the
        // `0x07` entry's point (that all three decompress is what the
        // derivation test below relies on).
        for source in outputs.coinbase.iter().chain(&outputs.listed) {
            let AtIndex::Recorded(recorded) = snap.output(source.output)? else {
                panic!("a recorded output");
            };
            assert_eq!(source.key, recorded.pubkey.to_bytes());
            assert_eq!(source.commitment, recorded.commitment.to_bytes());
            assert_ne!(
                source.pqc_leaf_commitment, [0; 32],
                "the 0x07 entry's point"
            );
            assert_ne!(source.pqc_leaf_commitment, source.key);
        }
        // A coinbase-only height has an empty listed half; past the tip is
        // `AboveTip`, not a fault.
        let AtHeight::Recorded(plain) = view.outputs_at(h(3))? else {
            panic!("a recorded height");
        };
        assert_eq!(plain.coinbase.len(), 1);
        assert!(plain.listed.is_empty());
        assert_eq!(view.outputs_at(h(TIP + 1))?, AtHeight::AboveTip);
        Ok(())
    });
    out.expect("reads");
    cleanup(&path);
}

#[test]
fn the_verdict_derives_the_drain_in_drain_order_over_the_written_tree() {
    let path = tmp("leaf-derive");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // The connects at 60, 61, 62 drained three coinbases: the frontier
        // is a leaf chunk and the root layer over it, and the count going
        // into 63 is 3. Heights 0..=60 went in with an empty tree (SI-18:
        // the count row is written every connect, moving only when
        // something drained).
        let frontier = view.tree_frontier()?;
        assert_eq!(frontier.leaf_count, 3);
        assert_eq!(frontier.layer_count(), 2);
        assert_eq!(view.leaf_count_at(h(0))?, AtHeight::Recorded(0));
        assert_eq!(view.leaf_count_at(h(60))?, AtHeight::Recorded(0));
        assert_eq!(view.leaf_count_at(h(61))?, AtHeight::Recorded(1));
        assert_eq!(view.leaf_count_at(h(TIP + 1))?, AtHeight::Recorded(3));
        assert_eq!(view.leaf_count_at(h(TIP + 2))?, AtHeight::AboveTip);
        assert_eq!(view.depth_at(h(60))?, AtHeight::Recorded(0));
        assert_eq!(view.depth_at(h(TIP + 1))?, AtHeight::Recorded(1));
        // The roots moved with the count (SI-4 / SI-12): unchanged through
        // 60, then a new root per drain.
        assert_eq!(
            view.root_at(h(60))?,
            AtHeight::Recorded(CurveTreeRoot::EMPTY)
        );
        let AtHeight::Recorded(into_61) = view.root_at(h(61))? else {
            panic!("recorded");
        };
        let AtHeight::Recorded(into_63) = view.root_at(h(TIP + 1))? else {
            panic!("recorded");
        };
        assert_ne!(into_61, CurveTreeRoot::EMPTY);
        assert_ne!(into_61, into_63);

        let connecting = TIP + 1;
        let previous = hashes[usize::try_from(TIP).expect("small")];
        let verdict = judge(
            &view,
            candidate_over(into_63, connecting, previous, Vec::new()),
        )?;
        let block = verdict.block();
        let drain = block
            .drain()
            .expect("block 3's coinbase and block 53's listed matured");
        assert_eq!(
            drain.growth().leaf_count_before,
            3,
            "continues the written tree"
        );
        assert_eq!(drain.drained().len(), 3, "one coinbase + two listed");
        assert_eq!(drain.growth().depth, 1);
        assert_eq!(block.root_after(), drain.growth().root);
        assert_ne!(block.root_after(), into_63);
        // Drain order (§3.3): block 3's coinbase (global 3) is leaf 0;
        // block 53's listed outputs (54, 55) follow. Block 53's coinbase
        // and block 3's (empty) listed half are not in this drain.
        assert_eq!(
            drain
                .drained()
                .iter()
                .map(|row| row.output)
                .collect::<Vec<_>>(),
            [3, SPEND_HEIGHT + 1, SPEND_HEIGHT + 2]
                .map(GlobalOutputIndex::from_raw)
                .to_vec()
        );
        Ok(())
    });
    out.expect("derives");
    cleanup(&path);
}

#[test]
fn before_any_window_elapses_the_verdict_carries_the_root_forward_unchanged() {
    let path = tmp("leaf-unchanged");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &spendable_prefix(&[])[..5]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let verdict = judge(&view, candidate(5, hashes[4], Vec::new()))?;
        let block = verdict.block();
        assert!(block.drain().is_none());
        assert_eq!(
            AtHeight::Recorded(block.root_after()),
            view.root_at(h(5))?,
            "nothing matured: the root going into 5 is the root after 5"
        );
        Ok(())
    });
    out.expect("derives");
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// Negative controls (rule 47): each belt the drain and the writer carry must
// be able to fire. Every plant is a raw redb write around `connect` — the
// bypassing write the invariants exist to catch — then a connect or a judge
// on the reopened store.
// ---------------------------------------------------------------------------

/// The spend's hash in the 63-block listing: block 53's one listed tx.
fn listed_hash_at_53(store: &ChainStore) -> shekyl_types::TxHash {
    let snap = store.begin_read().expect("read");
    let AtHeight::Recorded(body) = snap.block(h(SPEND_HEIGHT)).expect("read") else {
        panic!("recorded");
    };
    body.block.transaction_hashes[0]
}

#[test]
fn a_leaf_count_row_that_does_not_chain_to_the_summary_halts_the_next_connect() {
    // SI-18's predecessor half: `curve_tree_leaf_counts[tip + 1]` rewritten
    // to a count the tree does not hold. The next connect reads it as the
    // count it continues from and refuses before writing a row.
    let path = tmp("leaf-si18-predecessor");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        txn.open_table(CURVE_TREE_LEAF_COUNTS)
            .expect("t")
            .insert(TIP + 1, LeafCount::from_raw(7).encoded().as_encoded())
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let root = root_going_into(&store, TIP + 1);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(
            &view,
            candidate_over(
                root,
                TIP + 1,
                hashes[usize::try_from(TIP).expect("small")],
                Vec::new(),
            ),
        )?;
        Ok(batch.connect(valid, RuleSet::GENESIS)?)
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreInvariant::LeafCountNotAdvanced {
                observed: LeafCountFault::PredecessorDisagrees {
                    recorded: 7,
                    summary: 3,
                },
            })
            .to_string()
        ))
    );
    cleanup(&path);
}

#[test]
fn a_tx_index_row_pointing_at_another_height_is_corruption_not_a_drain() {
    // The drain at 63 reads block 53's listed transaction through
    // `tx_indices`; a row whose height is not 53 would hand it a transaction
    // the block does not list. Planted: the spend's index row re-pointed at
    // height 52 (same storage id, so `tx_outputs` still resolves).
    let path = tmp("leaf-index-height");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    let hash = listed_hash_at_53(&store);
    let planted = {
        let snap = store.begin_read().expect("read");
        let location = snap.tx_location(&hash).expect("read").expect("recorded");
        TxIndex {
            tx_id: location.id,
            unlock_time: crate::codec::stored_timelock(0),
            height: h(SPEND_HEIGHT - 1),
        }
    };
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        txn.open_table(TX_INDICES)
            .expect("t")
            .insert(LmdbHashKey::from(hash), planted.encoded().as_encoded())
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let root = root_going_into(&store, TIP + 1);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                TIP + 1,
                hashes[usize::try_from(TIP).expect("small")],
                Vec::new(),
            ),
        )?;
        Ok(())
    });
    let expected = StoreError::from(StoreInvariant::CellCorrupt {
        key: "tx_indices",
        fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
            codec: "tx_index",
            reason: "the row's height is not the block's that lists the transaction",
        }),
    })
    .to_string();
    assert_eq!(out, Err(TestErr::Store(expected)));
    cleanup(&path);
}

#[test]
fn an_output_txs_row_owned_by_another_transaction_is_corruption_not_a_leaf() {
    // The spend's first output (global 54) re-attributed to the coinbase of
    // block 53: `tx_outputs` still lists 54 under the spend, but the primary
    // row says otherwise. The drain refuses to pair the spend's `CM` with an
    // output the store says is not the spend's.
    let path = tmp("leaf-output-owner");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    let miner_hash = {
        let snap = store.begin_read().expect("read");
        let AtHeight::Recorded(body) = snap.block(h(SPEND_HEIGHT)).expect("read") else {
            panic!("recorded");
        };
        body.block.miner_transaction.hash()
    };
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        txn.open_table(OUTPUT_TXS)
            .expect("t")
            .insert(
                SPEND_HEIGHT + 1,
                OutTx {
                    tx_hash: miner_hash,
                    local_index: shekyl_types::OutputIndexInTx::from_raw(0),
                }
                .encoded()
                .as_encoded(),
            )
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let root = root_going_into(&store, TIP + 1);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                TIP + 1,
                hashes[usize::try_from(TIP).expect("small")],
                Vec::new(),
            ),
        )?;
        Ok(())
    });
    let expected = StoreError::from(StoreInvariant::CellCorrupt {
        key: "output_txs",
        fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
            codec: "out_tx",
            reason: "the row does not name this transaction at this output position",
        }),
    })
    .to_string();
    assert_eq!(out, Err(TestErr::Store(expected)));
    cleanup(&path);
}

#[test]
fn a_pruned_row_holding_another_transactions_body_is_corruption_not_a_drain() {
    // `txs_pruned[tx_id]` is reached through `tx_indices[hash]`; a mis-keyed
    // row would lend another transaction's outputs and `0x07` points to the
    // spend's leaves while the height and ownership belts still passed.
    // Planted: block 53's coinbase body under the spend's storage id. The
    // reconstructed identity is not the hash the block names, so the drain
    // halts before it compares output counts.
    let path = tmp("leaf-pruned-identity");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    let hash = listed_hash_at_53(&store);
    let (tx_id, foreign) = {
        let snap = store.begin_read().expect("read");
        let location = snap.tx_location(&hash).expect("read").expect("recorded");
        let AtHeight::Recorded(body) = snap.block(h(SPEND_HEIGHT)).expect("read") else {
            panic!("recorded");
        };
        let segments = body
            .block
            .miner_transaction
            .write_segments()
            .expect("segments");
        (location.id, segments.pruned)
    };
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        txn.open_table(TXS_PRUNED)
            .expect("t")
            .insert(tx_id.to_raw(), Raw::<TxPrunedSegment>::new(&foreign))
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let root = root_going_into(&store, TIP + 1);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                TIP + 1,
                hashes[usize::try_from(TIP).expect("small")],
                Vec::new(),
            ),
        )?;
        Ok(())
    });
    let expected = StoreError::from(StoreInvariant::CellCorrupt {
        key: "txs_pruned",
        fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
            codec: "transaction",
            reason: "the pruned segment is not the transaction the block names",
        }),
    })
    .to_string();
    assert_eq!(out, Err(TestErr::Store(expected)));
    cleanup(&path);
}
