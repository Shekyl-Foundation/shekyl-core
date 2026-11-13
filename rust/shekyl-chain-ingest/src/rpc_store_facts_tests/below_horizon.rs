// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `SB-Q2`'s falsifiers (`DRS_SB_BELOW_HORIZON.md` §5): the wallet, the
//! proof paths and the RPC over a real store connected **past a discard
//! boundary**, with a real spend in the discarded shard.
//!
//! The chain is the shard driver's (`scenario_shard`): real coinbase
//! spends, mined at difficulty 1 under the levered epoch, until shard 0
//! closes at `W` bytes of archival good; then empty blocks to the boundary
//! `(close_epoch(0) + 2) · SEB`, whose connect runs the batch that
//! discards shard 0's bodies (`prune.rs` §4). Nothing is mocked: the store
//! is the production store, the handlers are the daemon's, and the wallet
//! reads them over HTTP through its own `DaemonClient`.
//!
//! One chain, every falsifier: a shard takes a few hundred proofs to
//! close, so this runs in the live lane with the other shard-closing
//! scenarios (`cargo test -p shekyl-chain-ingest --features pipeline --
//! --ignored`).
//!
//! (vi), the arity downgrade, needs no chain: it is a property of the
//! binding and is pinned beside it —
//! `shekyl-engine-core`'s `block_fetch_tests`
//! (`a_third_operand_for_a_prefix_that_carries_none_is_refused`) and
//! `shekyl-wire`'s `pruned_tx_hash_parity` (a carrying prefix served with
//! `pqc_auth_hash: null` neither reproduces the txid nor binds).

use std::sync::Arc;

use shekyl_chain_store::store::{ArchivalGood, AtIndex};
use shekyl_daemon_rpc::reads::{block_list, tx_list};
use shekyl_engine_core::__test_helpers::{fetch_proof_tx_for_test, verify_exhaustive_for_test};
use shekyl_rpc_types::kinds::{Asked, Height, Integer, Size};
use shekyl_rpc_types::wire::block::{BlockListQuery, BlockTx};
use shekyl_rpc_types::wire::shared::{Archived, ArchivedState, OrArchived, Slot, SlotState};
use shekyl_rpc_types::wire::tx::{TxList, TxListQuery};
use shekyl_rpc_types::{HashHex, Nullable};
use shekyl_types::{BlockHeight, ShardId, TxHash};
use shekyl_wire::BoundTx;

use super::reads::{serve_the_block_fetch, serve_the_block_fetch_editing, ReplyEdit};
use super::{facts_over, open_store_under, ApplyPolicy, ChainStore, Mined, Scenario};
use crate::archival_driver::first_spending_height;
use crate::scenario::FreeHash;
use crate::scenario_shard::{
    close_shards, levered_rules, mine_to, EPOCH_BLOCKS, FILL_FROM_COINBASE,
};
use crate::schedule::ChainRules;

/// The store at `path`, opened under the levered rules, and the
/// store-backed facts over it.
fn facts_at(
    path: impl AsRef<std::path::Path>,
    rules: ChainRules,
) -> (Arc<ChainStore>, Arc<super::StoreFacts>) {
    let path: &std::path::Path = path.as_ref();
    let store = Arc::new(open_store_under(
        path,
        &rules.in_force(BlockHeight::ZERO),
        ApplyPolicy::Full,
    ));
    let facts = Arc::new(facts_over(Arc::clone(&store), path, rules));
    (store, facts)
}

/// The wallet's daemon client over a serving stand-in at `url`.
async fn wallet_at(url: String) -> shekyl_engine_core::engine::DaemonClient {
    shekyl_engine_core::engine::DaemonClient::new(
        shekyl_rpc_transport::HttpRpc::new(url)
            .await
            .expect("a client"),
    )
}

/// `tx_list` for `ids` in the form `prune` names, straight through the
/// handler.
fn transactions(facts: &super::StoreFacts, ids: &[TxHash], prune: bool) -> TxList {
    tx_list(
        facts,
        &TxListQuery {
            id: ids
                .iter()
                .map(|id| HashHex::from_bytes(id.to_bytes()))
                .collect(),
            prune,
        },
        false,
    )
    .unwrap_or_else(|_| panic!("answered"))
}

/// `block_list` for one height in the form `prune` names.
fn block_at(
    facts: &super::StoreFacts,
    height: BlockHeight,
    prune: bool,
) -> shekyl_rpc_types::wire::block::Block {
    let listed = block_list(
        facts,
        facts,
        &BlockListQuery {
            height: vec![Height(height.to_raw())],
            prune,
        },
        true,
    )
    .unwrap_or_else(|_| panic!("blocks"));
    let [Slot::Item(block)] = <[_; 1]>::try_from(listed).expect("one slot") else {
        panic!("the block is held");
    };
    block
}

/// The first fill block: every body it lists starts at an archival offset
/// below `W`, so every one is shard 0's.
fn first_fill_block(chain: &[Mined]) -> &Mined {
    chain
        .iter()
        .find(|m| !m.template.transactions.is_empty())
        .expect("the fill listed spends")
}

/// Falsifiers (i)–(v) over one chain. The chain is copied at two
/// moments — the block after shard 0 closed, and past the boundary that
/// discards it — and each copy is read through the same handlers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "closes a real shard: a few hundred proofs; live lane"]
async fn the_wallet_and_the_rpc_read_a_spend_whose_shard_the_store_discarded() {
    let rules = levered_rules();
    let mut scenario = Scenario::open_under("sb-below-horizon", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let [closed] = filled.closed.as_slice() else {
        panic!("one shard closed: {:?}", filled.closed);
    };
    assert_eq!(closed.shard, ShardId::from_raw(0));

    let fill = first_fill_block(&mined).clone();
    let spend = fill.template.transactions[0].clone();
    let spend_id = spend.hash();
    let coinbase_id = fill.template.block.miner_transaction.hash();
    let listed: Vec<TxHash> = fill
        .template
        .transactions
        .iter()
        .map(shekyl_wire::Transaction::hash)
        .collect();
    assert_eq!(fill.template.block.transaction_hashes, listed);

    // Before the boundary: the shard is closed, its bodies still held.
    let before = crate::test_support::tmp("sb-below-horizon-before");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &before).expect("a copy before the boundary");
        })
        .await;

    // Past the boundary: `(close_epoch(0) + 2) · SEB` connects and discards
    // shard 0's bodies; one more block so the tip is past it.
    let close_epoch = closed.close_height.to_raw() / EPOCH_BLOCKS;
    let boundary = (close_epoch + 2) * EPOCH_BLOCKS;
    mine_to(
        &mut scenario,
        &mut mined,
        BlockHeight::from_raw(boundary + 2),
    )
    .await;
    let after = crate::test_support::tmp("sb-below-horizon-after");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &after).expect("a copy past the boundary");
        })
        .await;
    scenario.close().await;

    // The subject exists: the store discarded the spend's good and still
    // holds the skeleton's operands.
    let (store, facts) = facts_at(&after, rules);
    {
        let read = store.begin_read().expect("read");
        let record = read
            .tx_record(&spend_id)
            .expect("read")
            .expect("the spend is recorded");
        assert!(
            matches!(
                read.tx_archival_good(record.location.id).expect("read"),
                AtIndex::Recorded(ArchivalGood::Discarded)
            ),
            "the boundary discarded shard 0's bodies"
        );
        assert_eq!(
            read.tx_shard(record.location).expect("read"),
            ShardId::from_raw(0)
        );
        assert!(
            matches!(
                read.tx_carries_archival_good(record.location.id)
                    .expect("read"),
                AtIndex::Recorded(true)
            ),
            "a spend carries archival good"
        );
    }

    // (i) Refresh: the wallet's block fetch binds every body of the block.
    let url = serve_the_block_fetch(Arc::clone(&facts)).await;
    let wallet = wallet_at(url).await;
    let height = usize::try_from(fill.height.to_raw()).expect("fits");
    let fetched = wallet
        .fetch_scannable_block(height)
        .await
        .expect("the wallet reads a block of the discarded shard");
    assert_eq!(fetched.block.hash(), fill.hash);
    let bound: Vec<TxHash> = fetched.transactions.iter().map(BoundTx::txid).collect();
    assert_eq!(
        bound, listed,
        "every body is bound to the id the block lists"
    );
    assert_eq!(fetched.transactions[0].tx().prefix, spend.prefix);

    // (ii) P-scan: the exhaustiveness check over a range holding the
    // block, anchored on the block before it, passes; a changed body fails.
    let first = fill.height.to_raw() - 1;
    let anchor = mined[usize::try_from(first - 1).expect("fits")].hash;
    let mut batch = Vec::new();
    for h in first..=fill.height.to_raw() + 1 {
        batch.push(
            wallet
                .fetch_scannable_block(usize::try_from(h).expect("fits"))
                .await
                .expect("a block of the range"),
        );
    }
    verify_exhaustive_for_test(BlockHeight::from_raw(first), anchor, &batch)
        .expect("the range verifies exhaustively");
    let mut edited = batch.clone();
    edited[1].transactions[0].modify(|tx| tx.prefix.unlock_time += 1);
    assert!(
        verify_exhaustive_for_test(BlockHeight::from_raw(first), anchor, &edited).is_err(),
        "a body that no longer hashes to the listed id fails the range"
    );

    // (ii), at the wire: one operand of one served skeleton changed, and
    // the wallet refuses the block rather than binding it.
    for (name, edit) in lies(spend_id) {
        let url = serve_the_block_fetch_editing(Arc::clone(&facts), edit).await;
        let lying = wallet_at(url).await;
        let err = lying.fetch_scannable_block(height).await.expect_err(name);
        let shown = err.to_string();
        assert!(
            shown.contains("does not bind"),
            "{name}: refused by the binding, not by something else: {shown}"
        );
    }

    // (iii) Proofs: the proof paths' fetch binds the discarded spend.
    let proof_tx = fetch_proof_tx_for_test(&wallet, spend_id.to_bytes())
        .await
        .expect("a proof fetch for the discarded spend");
    assert_eq!(proof_tx.prefix, spend.prefix);

    // (iv) The RPC's full form: the spend's slot is `archived` with its
    // shard; the block's coinbase answers its whole body.
    let full = transactions(&facts, &[spend_id, coinbase_id], false);
    let [archived, coinbase] = full.as_slice() else {
        panic!("one slot for each id: {full:?}");
    };
    assert_eq!(
        archived,
        &Slot::State(SlotState::Archived(Archived {
            id: HashHex::from_bytes(spend_id.to_bytes()),
            shard: Integer(0),
        }))
    );
    let Slot::Item(coinbase) = coinbase else {
        panic!("the coinbase is held whole: {coinbase:?}");
    };
    assert_eq!(coinbase.id, HashHex::from_bytes(coinbase_id.to_bytes()));
    assert_eq!(
        coinbase.body.0,
        fill.template.block.miner_transaction.serialize(),
        "a coinbase has no archival good and is never archived"
    );

    // (iv) `block_list` without `prune`: the block, with the spend as its
    // `archived` state and the request not failed.
    let whole = block_at(&facts, fill.height, false);
    assert_eq!(whole.body.0, fill.template.block.serialize());
    assert_eq!(whole.tx.len(), listed.len());
    for (slot, id) in whole.tx.iter().zip(&listed) {
        assert_eq!(
            *slot,
            OrArchived::Archived(ArchivedState::Archived(Archived {
                id: HashHex::from_bytes(id.to_bytes()),
                shard: Integer(0),
            }))
        );
    }
    // And under `prune`, the same block's slots are skeletons that rebind.
    let pruned = block_at(&facts, fill.height, true);
    for (slot, id) in pruned.tx.iter().zip(&listed) {
        let OrArchived::Item(slot) = slot else {
            panic!("under prune every slot is a skeleton: {slot:?}");
        };
        let skeleton = shekyl_wire::SkeletonTx {
            unprunable: slot.body.0.clone(),
            prunable_hash: shekyl_types::PrunableHash::from_bytes(
                slot.prunable_hash
                    .present()
                    .expect("asked with prune")
                    .to_bytes(),
            ),
            pqc_auth_hash: slot
                .pqc_auth_hash
                .present()
                .expect("asked with prune")
                .0
                .map(|h| shekyl_types::PqcAuthHash::from_bytes(h.to_bytes())),
            archival_len: shekyl_types::ArchivalLength::from_raw(
                slot.archival_size.present().expect("asked with prune").0,
            ),
        };
        assert_eq!(skeleton.txid().expect("binds"), *id);
    }

    // (v) One shape: the pruned form of the spend is byte-identical before
    // and after its shard was discarded.
    let after_reply = transactions(&facts, &[spend_id], true);
    drop(facts);
    drop(store);
    let (store, facts) = facts_at(&before, rules);
    {
        let read = store.begin_read().expect("read");
        let record = read.tx_record(&spend_id).expect("read").expect("recorded");
        assert!(
            matches!(
                read.tx_archival_good(record.location.id).expect("read"),
                AtIndex::Recorded(ArchivalGood::Retained { .. })
            ),
            "before the boundary the good is held"
        );
    }
    let before_reply = transactions(&facts, &[spend_id], true);
    let ([Slot::Item(before_entry)], [Slot::Item(after_entry)]) =
        (before_reply.as_slice(), after_reply.as_slice())
    else {
        panic!("the spend is held, pruned, on both copies");
    };
    // The one member that may differ is the tip-relative confirmation
    // count — a fact about where the tip is, not about the body. Pin that
    // it is the only one, then compare the wire bytes with it equalised.
    assert!(
        after_entry.confirmations.0 > before_entry.confirmations.0,
        "the after copy is at a higher tip"
    );
    let mut before_entry = before_entry.clone();
    before_entry.confirmations = after_entry.confirmations;
    assert_eq!(
        &before_entry, after_entry,
        "the skeleton is the one shape, whatever the shard's state"
    );
    assert_eq!(
        serde_json::to_vec(&before_entry).expect("json"),
        serde_json::to_vec(after_entry).expect("json"),
        "byte-identical on the wire, the tip's confirmation count aside"
    );
    let parts = spend.txid_parts();
    assert_eq!(
        after_entry.body.0,
        spend.write_segments().expect("Vec write").pruned,
        "the pruned form carries the pruned segment alone"
    );
    assert_eq!(
        after_entry.prunable_hash,
        Asked::Present(HashHex::from_bytes(parts.prunable_hash.to_bytes()))
    );
    assert_eq!(
        after_entry.pqc_auth_hash,
        Asked::Present(Nullable(
            parts
                .pqc_auth_hash
                .map(|h| HashHex::from_bytes(h.to_bytes()))
        ))
    );
    assert_eq!(
        after_entry.archival_size,
        Asked::Present(Size(spend.archival_len().to_raw()))
    );
    drop(facts);
    drop(store);
}

/// One operand of the served skeleton for `target` changed, each its own
/// lie: the pruned bytes, the prunable hash, the archival length, and the
/// third operand dropped (a spend's prefix carries it, so `null` is an
/// arity downgrade on the wire).
fn lies(target: TxHash) -> Vec<(&'static str, ReplyEdit)> {
    let hex_target = HashHex::from_bytes(target.to_bytes());
    let on_target = move |block: &mut shekyl_rpc_types::wire::block::Block,
                          edit: &dyn Fn(&mut BlockTx)| {
        let entry = block
            .tx
            .iter_mut()
            .find_map(|slot| match slot {
                OrArchived::Item(tx) if tx.id == hex_target => Some(tx),
                _ => None,
            })
            .expect("the target is served");
        edit(entry);
    };
    vec![
        (
            "a flipped byte in the pruned segment",
            Arc::new(move |block: &mut shekyl_rpc_types::wire::block::Block| {
                on_target(block, &|e| {
                    let last = e.body.0.len() - 1;
                    e.body.0[last] ^= 0x01;
                });
            }) as ReplyEdit,
        ),
        (
            "a changed prunable hash",
            Arc::new(move |block: &mut shekyl_rpc_types::wire::block::Block| {
                on_target(block, &|e| {
                    let mut h = e
                        .prunable_hash
                        .present()
                        .expect("asked with prune")
                        .to_bytes();
                    h[0] ^= 0x01;
                    e.prunable_hash = Asked::Present(HashHex::from_bytes(h));
                });
            }) as ReplyEdit,
        ),
        (
            "an archival length one byte long",
            Arc::new(move |block: &mut shekyl_rpc_types::wire::block::Block| {
                on_target(block, &|e| {
                    let size = e.archival_size.present().expect("asked with prune");
                    e.archival_size = Asked::Present(Size(size.0 + 1));
                });
            }) as ReplyEdit,
        ),
        (
            "the third operand dropped",
            Arc::new(move |block: &mut shekyl_rpc_types::wire::block::Block| {
                on_target(block, &|e| {
                    assert!(
                        matches!(e.pqc_auth_hash, Asked::Present(Nullable(Some(_)))),
                        "a spend's prefix carries it"
                    );
                    e.pqc_auth_hash = Asked::Present(Nullable(None));
                });
            }) as ReplyEdit,
        ),
    ]
}
