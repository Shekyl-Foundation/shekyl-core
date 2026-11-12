// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A pool-file fault retires the pool.

use super::*;

/// A flush whose pool-file write faults retires the pool, for the
/// service too: the flush answers a store fault, the next pool read is
/// not ready, and mining status reports the pool retired (the review of
/// #1165, M5).
///
/// The retirement does not black out the chain (the landing's N1). The
/// node goes on following the chain, so the chain's reads answer:
///
/// - `daemon_status` answers with the pool's counts `null` and the
///   chain's members as ever;
/// - `tx_list` answers a chain id, and gives an id the chain does not
///   hold a `null` slot, not `{"missing": null}`: whether the pool holds
///   it has no answer;
/// - a key image's spend stays failed closed: a spend the pool may hold
///   is unknowable, and "unspent" is a double spend's first step.
///
/// Red edits: the bridge does not retire the pool; the surroundings do not
/// read the retirement; `pool_counts` refuses on retirement.
#[test]
fn a_flush_over_a_faulted_pool_file_retires_the_pool() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info::{daemon_status, Disclosure};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{txpool_flush, txpool_list};
    use shekyl_daemon_rpc::reads::tx_list;
    use shekyl_rpc_types::errors::ErrorClass;
    use shekyl_rpc_types::wire::shared::{Slot, SlotState};
    use shekyl_rpc_types::wire::tx::{FlushIds, TxListQuery};
    use shekyl_rpc_types::HashHex;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let pool = node.pool().expect("a pool");
    let planted = {
        let mut pool = pool.lock().expect("the pool");
        let txid = pool.plant(
            shekyl_chain_rules::harness::fixture::paying_fee(
                shekyl_chain_rules::harness::fixture::listed([7; 32]),
                1,
            ),
            PoolRecord {
                received: ReceivedHour::from_raw(1),
                public: true,
            },
        );
        pool.refuse_next_commit();
        txid
    };
    let handles = node.handles();
    let flushed = a_runtime().block_on(txpool_flush(
        &*handles.pool,
        &FlushIds {
            id: Some(vec![HashHex::from_bytes(planted.to_bytes())]),
        },
        PoolScope::WithUnbroadcast,
    ));
    let after = txpool_list(&*handles.pool, PoolScope::Broadcast);
    let spent = handles
        .chain
        .key_images_spent(&[shekyl_types::KeyImage::from_bytes([7; 32])]);
    let status = handles.mining.status();
    let info = daemon_status(&*handles.chain, &*handles.chain, Disclosure::FULL, 0);
    // The genesis coinbase: an id the chain holds.
    let genesis = handles
        .chain
        .blocks_by_height(&[shekyl_types::BlockHeight::ZERO])
        .expect("the genesis block");
    let coinbase = shekyl_wire::Block::from_bytes(&genesis.blocks[0].block)
        .expect("a recorded block parses")
        .miner_transaction
        .txid_parts()
        .hash;
    let asked = |id: &shekyl_types::TxHash| HashHex::from_bytes(id.to_bytes());
    let txs = tx_list(
        &*handles.chain,
        &TxListQuery {
            id: vec![asked(&coinbase), asked(&planted)],
            prune: false,
        },
        true,
    );
    node.stop();
    assert_eq!(
        flushed.expect_err("the file faulted").class,
        ErrorClass::StoreFault
    );
    assert_eq!(after.expect_err("retired").class, ErrorClass::NotReady);
    assert_eq!(
        spent.expect_err("a key image's pool spend is unknowable: failed closed"),
        shekyl_daemon_rpc::chain_facts::FactsFault::NotReady
    );
    assert!(
        status.expect("status").pool_retired,
        "the service's pool is retired"
    );
    let info = info.unwrap_or_else(|_| panic!("daemon_status answers over a retired pool"));
    assert_eq!(info.txpool_count.0, None, "the pool's count has no answer");
    assert_eq!(
        info.txpool_private_count.shown().map(|count| count.0),
        Some(None),
        "the host's count is shown with no answer"
    );
    assert_eq!(info.hash, HashHex::from_bytes(genesis_hash().to_bytes()));
    let txs = txs.unwrap_or_else(|_| panic!("tx_list answers over a retired pool"));
    assert_eq!(txs.len(), 2);
    assert!(
        matches!(&txs[0], Slot::Item(entry) if entry.id == asked(&coinbase)),
        "the chain's id is answered"
    );
    assert!(
        !matches!(&txs[1], Slot::State(SlotState::Missing(_))),
        "an unread pool misses nothing"
    );
    assert!(
        matches!(&txs[1], Slot::Unasked),
        "the pool's id has no answer"
    );
}
