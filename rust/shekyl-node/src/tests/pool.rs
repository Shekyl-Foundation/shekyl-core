// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A pool-file fault retires the pool.

use super::*;

/// A flush whose pool-file write faults retires the pool, for the
/// service too: the flush answers a store fault, the next pool read is
/// not ready, and mining status reports the pool retired (the review of
/// #1165, M5). The chain handle's pool reads (`is_key_image_spent`,
/// `get_transactions`, `get_info`'s counts) stop reading it too. Red
/// edits: the bridge does not retire the pool; the surroundings do not
/// read the retirement.
#[test]
fn a_flush_over_a_faulted_pool_file_retires_the_pool() {
    use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
    use shekyl_daemon_rpc::info_facts::PoolScope;
    use shekyl_daemon_rpc::pool_methods::{flush_txpool, get_transaction_pool};
    use shekyl_rpc_types::errors::ErrorClass;
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
    let spent = shekyl_daemon_rpc::read_facts::ChainReadFacts::key_images_spent(
        &*handles.chain,
        &[shekyl_types::KeyImage::from_bytes([7; 32])],
    );
    let status = handles.mining.status();
    node.stop();
    assert_eq!(
        flushed.expect_err("the file faulted").class,
        ErrorClass::StoreFault
    );
    assert_eq!(after.expect_err("retired").class, ErrorClass::NotReady);
    assert_eq!(
        spent.expect_err("the chain's pool reads are retired too"),
        shekyl_daemon_rpc::chain_facts::FactsFault::NotReady
    );
    assert!(
        status.expect("status").pool_retired,
        "the service's pool is retired"
    );
}
