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
/// - `get_info` answers `pool_retired` with the pool's counts `null` and
///   the chain's members as ever;
/// - `get_transactions` answers a chain id, and marks an id the chain
///   does not hold as unavailable, not missed: whether the pool holds it
///   has no answer;
/// - `is_key_image_spent` stays failed closed: a spend the pool may hold
///   is unknowable, and "unspent" is a double spend's first step.
///
/// Red edits: the bridge does not retire the pool; the surroundings do not
/// read the retirement; `pool_counts` refuses on retirement.
#[test]
fn a_flush_over_a_faulted_pool_file_retires_the_pool() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info::{get_info, Disclosure};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{flush_txpool, get_transaction_pool};
    use shekyl_daemon_rpc::read_methods::get_transactions;
    use shekyl_rpc_types::errors::ErrorClass;
    use shekyl_rpc_types::methods::Grant;
    use shekyl_rpc_types::{GetTransactionsRequest, HashHex, InfoPool};
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
    let flushed = a_runtime().block_on(flush_txpool(
        &*handles.pool,
        &shekyl_rpc_types::pool::FlushTxpoolRequest {
            txids: vec![shekyl_rpc_types::HashHex::from_bytes(planted.to_bytes())],
        },
    ));
    let after = get_transaction_pool(&*handles.pool, PoolScope::Broadcast);
    let spent = handles
        .chain
        .key_images_spent(&[shekyl_types::KeyImage::from_bytes([7; 32])]);
    let status = handles.mining.status();
    let info = get_info(&*handles.chain, Disclosure::FULL, 0);
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
    let txs = get_transactions(
        &*handles.chain,
        &GetTransactionsRequest {
            txs_hashes: vec![asked(&coinbase).to_string(), asked(&planted).to_string()],
            decode_as_json: false,
            prune: false,
            split: false,
        },
        Grant::HostOnly,
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
    let info = info.expect("get_info answers over a retired pool");
    assert_eq!(info.pool, InfoPool::Retired);
    assert_eq!(
        info.host.shown().map(|host| host.tx_pool_unbroadcast_count),
        Some(None),
        "the host's count is shown with no answer"
    );
    assert_eq!(
        info.health.top_block_hash,
        HashHex::from_bytes(genesis_hash().to_bytes())
    );
    let txs = txs.expect("get_transactions answers over a retired pool");
    assert_eq!(
        txs.txs.iter().map(|tx| tx.tx_hash).collect::<Vec<_>>(),
        vec![asked(&coinbase)],
        "the chain's id is answered"
    );
    assert!(txs.missed_tx.is_empty(), "an unread pool misses nothing");
    assert_eq!(
        txs.unavailable_tx,
        vec![asked(&planted)],
        "the pool's id has no answer"
    );
}
