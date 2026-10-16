// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three DRS-E3 reads on the batch view, and the growth the verdict
//! derives from them (`DRS_E3_CURVE_WRITER.md` §3.1–§3.3, §6 commit 4b).
//!
//! What this file pins is the **read side and the derivation**: a
//! recorded block's outputs come back as leaf sources in output order, the
//! drain at `h` takes block `h − W`'s coinbase then block `h − A`'s
//! listed outputs (`W` the unlock window, `A` the spendable age — the rule
//! set's two maturities), and the verdict carries a non-empty root over
//! them, continuing the tree the connects before it wrote (`grow.rs`,
//! commit 5): the frontier and the per-height count are the store's own
//! rows, and a derived growth starts where they say the tree ends.

use shekyl_chain_rules::{AtHeight, ChainView, RuleSet};
use shekyl_fcmp::tree::SELENE_CHUNK_WIDTH;
use shekyl_types::{ArchivalLength, BlockHeight, CurveTreeRoot, GlobalOutputIndex};

use super::connect_fixtures::{
    candidate, candidate_over, connect_chain, connect_chain_anchored, judge, prefix_to,
    root_going_into, spend, spendable_prefix, Listed, FIRST_SPEND_HEIGHT,
};
use super::error::{CellFault, LeafCountFault, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{Canonical, LeafCount, OutTx, Raw, TxIndex, TxPrunedSegment};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{CURVE_TREE_LEAF_COUNTS, OUTPUT_TXS, TXS_ARCHIVAL_LEN, TXS_PRUNED, TX_INDICES};

fn h(height: u64) -> BlockHeight {
    BlockHeight::from_raw(height)
}

/// The unlock window: block `h`'s coinbase drains at `h + W` (CEN-I9).
const W: u64 = RuleSet::GENESIS.mined_money_unlock_window().to_raw();
/// The spendable age: block `h`'s listed outputs drain at `h + A`.
const A: u64 = RuleSet::GENESIS.tx_spendable_age().to_raw();
/// The two-output spend sits at the first spending height — a real spend
/// of genesis's coinbase, the one matured for it.
const SPEND_HEIGHT: u64 = FIRST_SPEND_HEIGHT;
/// The connect the tests probe: where the spend's outputs mature, `A`
/// blocks on. It drains block `PROBE − W`'s coinbase
/// ([`DRAINED_COINBASE`]) and the spend's two listed outputs.
const PROBE: u64 = SPEND_HEIGHT + A;
/// Heights `0..=TIP` are connected; the probe is the next.
const TIP: u64 = PROBE - 1;
/// The coinbase the probe drains.
const DRAINED_COINBASE: u64 = PROBE - W;
/// Leaves in the tree going into the probe: the connects at `W ..= TIP`
/// drained blocks `0 ..= TIP − W`'s coinbases, one each — `TIP − W + 1`.
/// Nothing listed had matured (the spend's outputs do at the probe).
const LEAVES_INTO_PROBE: u64 = TIP - W + 1;
/// The leaf layer packs [`SELENE_CHUNK_WIDTH`] leaves per chunk. The
/// leaves going into the probe fit one chunk with the probe's three to
/// spare, so the frontier there is that chunk and the root layer over it
/// — two layers, depth one — and the probe's drain stays at depth one
/// too. A width or window change that broke this fails here, naming its
/// cause, rather than in the depth assertions below.
const LEAF_CHUNK_WIDTH: u64 = SELENE_CHUNK_WIDTH as u64;
const _: () = assert!(LEAVES_INTO_PROBE + 3 <= LEAF_CHUNK_WIDTH);
/// The first spend's outputs are global `SPEND_HEIGHT + 1` and `+ 2`:
/// one coinbase output per height through the spend block's own
/// (global `SPEND_HEIGHT`), then the spend's two.
const SPEND_VOUT_0: u64 = SPEND_HEIGHT + 1;

fn listing() -> Vec<Vec<Listed>> {
    let mut listed = spendable_prefix(vec![vec![spend()]]);
    listed.resize_with(usize::try_from(TIP + 1).expect("small"), Vec::new);
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
        // Heights below the spend hold one coinbase output each, so the
        // spend block's coinbase is global output `SPEND_HEIGHT` and its
        // spend's two are `SPEND_VOUT_0`, `+ 1`.
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
        assert_eq!(gids(&outputs.listed), vec![SPEND_VOUT_0, SPEND_VOUT_0 + 1]);
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
        let AtHeight::Recorded(plain) = view.outputs_at(h(DRAINED_COINBASE))? else {
            panic!("a recorded height");
        };
        assert_eq!(plain.coinbase.len(), 1);
        assert!(plain.listed.is_empty());
        assert_eq!(view.outputs_at(h(PROBE))?, AtHeight::AboveTip);
        Ok(())
    });
    out.expect("reads");
    cleanup(&path);
}

#[test]
fn the_verdict_derives_the_drain_in_drain_order_over_the_written_tree() {
    let path = tmp("leaf-derive");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing()).hashes;
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // The connects at `W ..= TIP` drained one coinbase each
        // (`LEAVES_INTO_PROBE`): the frontier is a leaf chunk and the root
        // layer over it, and the count going into the probe is that many.
        // Heights `0 ..= W` went in with an empty tree (SI-18: the count
        // row is written every connect, moving only when something
        // drained).
        let frontier = view.tree_frontier()?;
        assert_eq!(frontier.leaf_count, LEAVES_INTO_PROBE);
        assert_eq!(frontier.layer_count(), 2);
        assert_eq!(view.leaf_count_at(h(0))?, AtHeight::Recorded(0));
        assert_eq!(view.leaf_count_at(h(W))?, AtHeight::Recorded(0));
        assert_eq!(view.leaf_count_at(h(W + 1))?, AtHeight::Recorded(1));
        assert_eq!(
            view.leaf_count_at(h(PROBE))?,
            AtHeight::Recorded(LEAVES_INTO_PROBE)
        );
        assert_eq!(view.leaf_count_at(h(PROBE + 1))?, AtHeight::AboveTip);
        assert_eq!(view.depth_at(h(W))?, AtHeight::Recorded(0));
        assert_eq!(view.depth_at(h(PROBE))?, AtHeight::Recorded(1));
        // The roots moved with the count (SI-4 / SI-12): unchanged through
        // `W`, then a new root per drain.
        assert_eq!(
            view.root_at(h(W))?,
            AtHeight::Recorded(CurveTreeRoot::EMPTY)
        );
        let AtHeight::Recorded(into_first_drained) = view.root_at(h(W + 1))? else {
            panic!("recorded");
        };
        let AtHeight::Recorded(into_probe) = view.root_at(h(PROBE))? else {
            panic!("recorded");
        };
        assert_ne!(into_first_drained, CurveTreeRoot::EMPTY);
        assert_ne!(into_first_drained, into_probe);

        let previous = hashes[usize::try_from(TIP).expect("small")];
        let verdict = judge(
            &view,
            candidate_over(into_probe, PROBE, previous, Vec::new()),
        )?;
        let block = verdict.block();
        let drain = block
            .drain()
            .expect("the drained coinbase and the spend's listed outputs matured");
        assert_eq!(
            drain.growth().leaf_count_before,
            LEAVES_INTO_PROBE,
            "continues the written tree"
        );
        assert_eq!(drain.drained().len(), 3, "one coinbase + two listed");
        assert_eq!(drain.growth().depth, 1);
        assert_eq!(block.root_after(), drain.growth().root);
        assert_ne!(block.root_after(), into_probe);
        // Drain order (§3.3): block `PROBE − W`'s coinbase (global
        // `DRAINED_COINBASE`: one output per height below the spend) is
        // leaf `LEAVES_INTO_PROBE`; the spend's listed outputs follow. The
        // spend block's coinbase and the drained block's (empty) listed
        // half are not in this drain.
        assert_eq!(
            drain
                .drained()
                .iter()
                .map(|row| row.output)
                .collect::<Vec<_>>(),
            [DRAINED_COINBASE, SPEND_VOUT_0, SPEND_VOUT_0 + 1]
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
    let hashes = connect_chain(&store, &prefix_to(h(5), Vec::new())).hashes;
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

/// The spend's hash in the listing: the spend block's one listed tx.
fn listed_spend_hash(store: &ChainStore) -> shekyl_types::TxHash {
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
    // A count the tree does not hold: one past what the connects wrote.
    const PLANTED_COUNT: u64 = LEAVES_INTO_PROBE + 1;
    let path = tmp("leaf-si18-predecessor");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing()).hashes;
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        txn.open_table(CURVE_TREE_LEAF_COUNTS)
            .expect("t")
            .insert(
                PROBE,
                LeafCount::from_raw(PLANTED_COUNT).encoded().as_encoded(),
            )
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let root = root_going_into(&store, PROBE);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(
            &view,
            candidate_over(
                root,
                PROBE,
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
                    recorded: PLANTED_COUNT,
                    summary: LEAVES_INTO_PROBE,
                },
            })
            .to_string()
        ))
    );
    cleanup(&path);
}

#[test]
fn a_tx_index_row_pointing_at_another_height_is_corruption_not_a_drain() {
    // The drain at the probe reads the spend block's listed transaction
    // through `tx_indices`; a row whose height is not the spend's would
    // hand it a transaction the block does not list. Planted: the spend's
    // index row re-pointed at the height below (same storage id, so
    // `tx_outputs` still resolves).
    let path = tmp("leaf-index-height");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing()).hashes;
    let hash = listed_spend_hash(&store);
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
    let root = root_going_into(&store, PROBE);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                PROBE,
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
    // The spend's first output (global `SPEND_VOUT_0`) re-attributed to
    // the coinbase of the spend block: `tx_outputs` still lists it under
    // the spend, but the primary row says otherwise. The drain refuses to
    // pair the spend's `CM` with an output the store says is not the
    // spend's.
    let path = tmp("leaf-output-owner");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing()).hashes;
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
                SPEND_VOUT_0,
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
    let root = root_going_into(&store, PROBE);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                PROBE,
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
    // Planted: the spend block's coinbase body under the spend's storage id. The
    // reconstructed identity is not the hash the block names, so the drain
    // halts before it compares output counts.
    let path = tmp("leaf-pruned-identity");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing()).hashes;
    let hash = listed_spend_hash(&store);
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
    let root = root_going_into(&store, PROBE);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        judge(
            &view,
            candidate_over(
                root,
                PROBE,
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

/// The length row is an operand of the identity the drain rebuilds
/// (`SHT-Q2`), so a row that is wrong — one byte long, or missing, which
/// reads as zero — is caught where the row is used: the skeleton no longer
/// hashes to the transaction the block names. That is what lets a shard
/// boundary be cut from this row after the bodies it measured are gone.
#[test]
fn a_wrong_archival_length_row_is_corruption_not_a_drain() {
    for (name, plant) in [("leaf-len-plus-one", Some(1u64)), ("leaf-len-gone", None)] {
        let path = tmp(name);
        let store = ChainStore::create(&path, EPOCH).expect("create");
        let (grown, connected) = connect_chain_anchored(&store, &listing());
        let hashes = grown.hashes;
        let hash = listed_spend_hash(&store);
        let tx_id = {
            let snap = store.begin_read().expect("read");
            snap.tx_location(&hash).expect("read").expect("recorded").id
        };
        // The length `connect` measured, from the body it was handed.
        let recorded = connected
            .iter()
            .flatten()
            .find(|tx| tx.hash() == hash)
            .expect("the listed spend, as connected")
            .archival_len();
        assert_ne!(
            recorded,
            ArchivalLength::ZERO,
            "the spend carries archival good, or a missing row would be right"
        );
        drop(store);
        {
            let db = redb::Database::open(&path).expect("open raw");
            let txn = db.begin_write().expect("write");
            {
                let mut table = txn.open_table(TXS_ARCHIVAL_LEN).expect("t");
                match plant {
                    Some(extra) => {
                        let wrong = ArchivalLength::from_raw(recorded.to_raw() + extra);
                        table
                            .insert(tx_id.to_raw(), wrong.encoded().as_encoded())
                            .expect("plant");
                    }
                    None => {
                        table.remove(tx_id.to_raw()).expect("remove");
                    }
                }
            }
            txn.commit().expect("commit");
        }
        let store = ChainStore::create(&path, EPOCH).expect("reopen");
        let root = root_going_into(&store, PROBE);
        let out: Result<(), TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            judge(
                &view,
                candidate_over(
                    root,
                    PROBE,
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
        assert_eq!(out, Err(TestErr::Store(expected)), "{name}");
        cleanup(&path);
    }
}
