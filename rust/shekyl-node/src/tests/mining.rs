// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The posted template, the miner, and the armed levers.

use super::*;

/// `get_block_template` reads the posted job (N2): eight zero bytes
/// at `reserved_offset`, the hashing blob is the block's, and a block
/// an outside miner makes by writing both nonces connects through
/// `submit_block`. Red edit: report the header nonce's offset as the
/// reserved one.
#[test]
fn a_block_made_from_the_template_connects_through_submit_block() {
    use shekyl_daemon_rpc::mining_methods::{get_block_template, submit_block};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let handles = node.handles();
    let reply = get_block_template(&*handles.mining).expect("a template");
    assert_eq!(reply.height, 1);
    let genesis =
        BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
    assert_eq!(reply.prev_hash.to_bytes(), genesis.to_bytes());
    let mut blob = hex::decode(&reply.blocktemplate_blob).expect("hex");
    let extra = usize::try_from(reply.reserved_offset).expect("fits");
    assert_eq!(
        blob[extra..extra + 8],
        [0; 8],
        "the extra nonce is reserved, zeroed"
    );
    let block = shekyl_wire::Block::from_bytes(&blob).expect("a block");
    assert_eq!(
        hex::decode(&reply.blockhashing_blob).expect("hex"),
        block.pow_blob()
    );
    blob[extra..extra + 8].copy_from_slice(&[7; 8]);
    let nonce = usize::try_from(reply.nonce_offset).expect("fits");
    blob[nonce..nonce + 4].copy_from_slice(&42_u32.to_le_bytes());
    let made = shekyl_wire::Block::from_bytes(&blob).expect("still a block");
    assert_eq!(made.header.nonce, 42);
    let submitted = a_runtime()
        .block_on(submit_block(
            &*handles.door,
            shekyl_rpc_types::mining::SubmitBlockRequest {
                body: hex::encode(&blob),
            },
        ))
        .expect("it connects");
    assert_eq!(submitted.block_id.to_bytes(), made.hash().to_bytes());
    let tip = handles.chain.chain_tip().expect("tip");
    assert_eq!(tip.top_hash, made.hash());
    node.stop();
}
/// A block listing a body the pool does not hold answers
/// `MissingBodies` with its index, as RW-Q3's refused-by-the-method
/// class. Red edit: answer every non-connect as `NotReady`.
#[test]
fn a_submitted_block_with_a_missing_body_names_its_index() {
    use shekyl_daemon_rpc::mining_methods::{codes, get_block_template, submit_block};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let handles = node.handles();
    let reply = get_block_template(&*handles.mining).expect("a template");
    let mut block =
        shekyl_wire::Block::from_bytes(&hex::decode(&reply.blocktemplate_blob).expect("hex"))
            .expect("a block");
    block
        .transaction_hashes
        .push(shekyl_types::TxHash::from_bytes([0x5a; 32]));
    let refused = a_runtime()
        .block_on(submit_block(
            &*handles.door,
            shekyl_rpc_types::mining::SubmitBlockRequest {
                body: hex::encode(block.serialize()),
            },
        ))
        .expect_err("a body is missing");
    assert_eq!(
        refused.class,
        shekyl_rpc_types::errors::ErrorClass::RefusedByMethod
    );
    assert_eq!(refused.diagnostic.code, codes::BLOCK_MISSING_BODIES);
    assert_eq!(
        refused.diagnostic.params,
        vec![("indices".to_owned(), "0".to_owned())]
    );
    node.stop();
}
/// With no job posted, the template reads answer `NotReady` with the
/// node's reason, and `mining_status` carries the same diagnostic.
/// Red edit: answer a posted-nothing board with an empty template.
#[test]
fn with_no_address_the_template_reads_say_why() {
    use shekyl_daemon_rpc::mining_methods::{
        codes, get_block_template, get_miner_data, mining_status, start_mining,
    };
    use shekyl_rpc_types::errors::ErrorClass;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let mut posting = node.posting();
    wait_for_posting(&mut posting, &Posting::Withdrawn(NoJob::NoAddress));
    let handles = node.handles();
    for refused in [
        get_block_template(&*handles.mining).map(|_| ()),
        get_miner_data(&*handles.mining).map(|_| ()),
    ] {
        let refused = refused.expect_err("no template");
        assert_eq!(refused.class, ErrorClass::NotReady);
        assert_eq!(refused.diagnostic.code, codes::NO_ADDRESS);
    }
    let status = mining_status(&*handles.mining).expect("status");
    assert!(!status.active);
    assert_eq!(
        status.no_template.map(|why| why.code),
        Some(codes::NO_ADDRESS.to_owned())
    );
    let refused = a_runtime()
        .block_on(start_mining(
            &handles.mining,
            shekyl_rpc_types::mining::StartMiningRequest::default(),
        ))
        .expect_err("no address");
    assert_eq!(refused.class, ErrorClass::RefusedByMethod);
    assert_eq!(refused.diagnostic.code, codes::NO_ADDRESS);
    node.stop();
}
/// `start_mining`, `mining_status` and `stop_mining` over the node's
/// mining control; a second stop is refused by the method. Red edit:
/// answer `stop_mining` OK whether or not the miner ran.
#[test]
fn the_miner_starts_reports_and_stops_through_the_handlers() {
    use shekyl_daemon_rpc::mining_methods::{codes, mining_status, start_mining, stop_mining};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let handles = node.handles();
    let one = shekyl_rpc_types::mining::StartMiningRequest {
        threads: shekyl_rpc_types::mining::MinerThreads::Count(
            std::num::NonZeroU32::new(1).expect("one"),
        ),
    };
    match a_runtime().block_on(start_mining(&handles.mining, one)) {
        Ok(_) => {}
        Err(refused) if refused.diagnostic.code == codes::ONE_PERMIT => {
            node.stop();
            return;
        }
        Err(other) => panic!("the miner did not start: {other:?}"),
    }
    let status = mining_status(&*handles.mining).expect("status");
    assert!(status.active);
    assert_eq!(status.threads_count, 1);
    assert!(status.height >= 1, "a job is posted");
    assert!(status.no_template.is_none());
    a_runtime()
        .block_on(stop_mining(&handles.mining))
        .expect("it stops");
    let again = a_runtime()
        .block_on(stop_mining(&handles.mining))
        .expect_err("not running");
    assert_eq!(again.diagnostic.code, codes::STOPPED);
    node.stop();
}
/// `generateblocks(3)`, armed, reaches the tip plus three and stops the
/// miner it started; without `dev-rpc` it is refused outside the
/// grant (DX-Q3, Q8). Red edit: leave the miner running.
#[test]
fn generateblocks_reaches_three_more_and_is_refused_unarmed() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, generateblocks};
    use shekyl_rpc_types::errors::ErrorClass;
    let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
    let unarmed_dir = tempfile::tempdir().expect("temp");
    let unarmed = open_posted(unarmed_dir.path(), &[]);
    assert!(!unarmed.armed_levers());
    let refused = admit_armed(row, unarmed.armed_levers()).expect_err("unarmed");
    assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
    unarmed.stop();

    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &["--dev-rpc"]);
    let armed = admit_armed(row, node.armed_levers()).expect("armed");
    let handles = node.handles();
    let generated = a_runtime().block_on(generateblocks(
        &handles.mining,
        &*handles.door,
        &*handles.chain,
        armed,
        shekyl_rpc_types::mining::GenerateBlocksRequest { count: 3 },
    ));
    let generated = match generated {
        Ok(generated) => generated,
        Err(refused) if refused.diagnostic.code == codes::ONE_PERMIT => {
            node.stop();
            return;
        }
        Err(other) => panic!("generateblocks: {other:?}"),
    };
    assert!(
        generated.height >= 4,
        "genesis and three: {}",
        generated.height
    );
    assert!(generated.blocks.len() >= 3);
    assert!(!node.mining().running(), "the miner it started is stopped");
    node.stop();
}
/// A thread count past the host's parallelism is refused by the method,
/// naming both numbers, and starts no miner (the review of #1165, M1).
/// Red edit: drop the bound.
#[test]
fn a_thread_count_past_the_hosts_parallelism_starts_nothing() {
    use shekyl_daemon_rpc::mining_methods::{codes, start_mining};
    use shekyl_rpc_types::errors::ErrorClass;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let handles = node.handles();
    let host = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let past = shekyl_rpc_types::mining::StartMiningRequest {
        threads: shekyl_rpc_types::mining::MinerThreads::Count(
            std::num::NonZeroU32::new(u32::try_from(host + 1).expect("fits")).expect("not zero"),
        ),
    };
    let refused = a_runtime().block_on(start_mining(&handles.mining, past));
    let running = node.mining().running();
    node.stop();
    let refused = refused.expect_err("past the parallelism");
    assert_eq!(refused.class, ErrorClass::RefusedByMethod);
    assert_eq!(refused.diagnostic.code, codes::TOO_MANY_THREADS);
    assert!(!running, "no miner started");
}
/// After `Node::stop`, mining control starts no miner (the review of
/// #1165). Red edit: start without reading the latch.
#[test]
fn no_miner_starts_after_the_node_stops() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let mining = node.mining();
    node.stop();
    let refused = mining.start(None);
    let running = mining.running();
    let _stopped = mining.stop();
    assert!(
        matches!(refused, Err(crate::MiningRefused::NodeStopped)),
        "{refused:?}"
    );
    assert!(!running);
}
/// `generateblocks` on a node chain sync does not call synced is refused
/// at once with the reason, and leaves no miner running: nothing could
/// move the tip (the review of #1165, M2). Red edit: wait on the tip
/// alone, with no check of the posted job before or during the wait.
#[test]
fn generateblocks_on_a_node_that_is_not_synced_is_refused_at_once() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, generateblocks};
    use shekyl_rpc_types::errors::ErrorClass;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_mining(dir.path(), "testnet", shekyl_address::Network::Testnet);
    let mut posting = node.posting();
    wait_for_posting(
        &mut posting,
        &Posting::Withdrawn(NoJob::NotSynced(SyncState::NoView)),
    );
    let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
    let handles = node.handles();
    let answered = a_runtime().block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            generateblocks(
                &handles.mining,
                &*handles.door,
                &*handles.chain,
                admit_armed(row, true).expect("armed"),
                shekyl_rpc_types::mining::GenerateBlocksRequest { count: 1 },
            ),
        )
        .await
    });
    let running = node.mining().running();
    node.stop();
    let refused = answered
        .expect("answered at once, not waited out")
        .expect_err("not synced");
    assert_eq!(refused.class, ErrorClass::NotReady);
    assert_eq!(refused.diagnostic.code, codes::NOT_SYNCED);
    assert!(!running, "no miner left running");
}
/// The job withdrawn mid-wait ends `generateblocks` with the reason and
/// stops the miner it started (the review of #1165, M2). Red edit: wait
/// on the tip alone.
#[test]
fn a_job_withdrawn_mid_wait_ends_generateblocks() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, generateblocks};
    use shekyl_rpc_types::errors::ErrorClass;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
    let handles = node.handles();
    let sync = node.sync().clone();
    let answered = a_runtime().block_on(async {
        let withdraw = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sync.send_replace(SyncState::NoView);
            std::future::pending::<()>().await;
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                answered = generateblocks(
                    &handles.mining,
                    &*handles.door,
                    &*handles.chain,
                    admit_armed(row, true).expect("armed"),
                    shekyl_rpc_types::mining::GenerateBlocksRequest { count: 1_000_000 },
                ) => answered,
                () = withdraw => unreachable!("pending"),
            }
        })
        .await
    });
    let running = node.mining().running();
    node.stop();
    let refused = match answered.expect("ended by the withdrawal, not waited out") {
        Err(refused) if refused.diagnostic.code == codes::ONE_PERMIT => return,
        other => other.expect_err("withdrawn"),
    };
    assert_eq!(refused.class, ErrorClass::NotReady);
    assert_eq!(refused.diagnostic.code, codes::NOT_SYNCED);
    assert!(!running, "the miner it started is stopped");
}
/// A `generateblocks` call dropped mid-wait stops the miner it started
/// (the review of #1165, M2). Red edit: the guard stops nothing.
#[test]
fn dropping_generateblocks_stops_the_miner_it_started() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, generateblocks};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
    let handles = node.handles();
    let mining = node.mining();
    let saw_running = a_runtime().block_on(async {
        let call = generateblocks(
            &handles.mining,
            &*handles.door,
            &*handles.chain,
            admit_armed(row, true).expect("armed"),
            shekyl_rpc_types::mining::GenerateBlocksRequest { count: 1_000_000 },
        );
        let watch_it = async {
            while !mining.running() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        tokio::select! {
            answered = call => {
                assert!(answered.is_err(), "a million blocks do not arrive here");
                false
            }
            () = watch_it => true,
        }
    });
    // The runtime's drop above waited on the guard's blocking stop.
    let running = mining.running();
    node.stop();
    if !saw_running {
        return;
    }
    assert!(!running, "dropping the call stopped the miner it started");
}
/// `pop_blocks`, armed (DX-Q3, Q7): a count that would pop genesis is
/// refused by the method before any pop, the node stays up and takes a
/// block, and a count of one pops one. Without `dev-rpc` it is outside
/// the grant. Red edit: let the count past the tip clamp to genesis.
#[test]
fn pop_blocks_refuses_genesis_pops_one_and_the_node_stays_up() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, pop_blocks};
    use shekyl_rpc_types::errors::ErrorClass;
    let row = shekyl_rpc_types::methods::rest_path("/pop_blocks").expect("a row");
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &["--dev-rpc"]);
    assert!(
        admit_armed(row, false).is_err(),
        "unarmed, it is outside the grant"
    );
    let handles = node.handles();
    mine_one(&node, 0);
    mine_one(&node, 1);
    assert_eq!(
        handles
            .chain
            .chain_tip()
            .expect("tip")
            .chain_height
            .to_raw(),
        3
    );
    let pop = |nblocks| {
        let armed = admit_armed(row, node.armed_levers()).expect("armed");
        a_runtime().block_on(pop_blocks(
            &*handles.door,
            armed,
            shekyl_rpc_types::mining::PopBlocksRequest { nblocks },
        ))
    };
    let refused = pop(3).expect_err("genesis is never popped");
    assert_eq!(refused.class, ErrorClass::RefusedByMethod);
    assert_eq!(refused.diagnostic.code, codes::POP_BELOW_FLOOR);
    assert_eq!(
        handles
            .chain
            .chain_tip()
            .expect("tip")
            .chain_height
            .to_raw(),
        3
    );
    let popped = pop(1).expect("one pops");
    assert_eq!(popped.height, 2);
    let again = mine_one(&node, 0);
    assert_eq!(handles.chain.chain_tip().expect("tip").top_hash, again);
    node.stop();
}
/// Regtest is synced at open (DX-Q3, Q13), so a node with an address
/// posts the template for the block after genesis with no session at
/// all, and `mining_status` reports the job. Red edit: open regtest at
/// `NoView`.
#[test]
fn a_regtest_node_with_an_address_posts_its_template_with_no_sessions() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_mining(dir.path(), "regtest", shekyl_address::Network::Mainnet);
    let mut posting = node.posting();
    let started = std::time::Instant::now();
    while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "nothing posted: {:?}",
            *posting.borrow()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let (_, job) = node.mining.board.posted().expect("the job");
    assert_eq!(job.height, BlockHeight::from_raw(1));
    let genesis =
        BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
    assert_eq!(job.block.header.previous, genesis);
    let status = node.mining().status();
    assert_eq!(status.no_job, None);
    assert_eq!(status.job.map(|posted| posted.height), Some(job.height));
    assert!(status.miner.is_none(), "the miner starts on request only");
    assert!(node
        .handles()
        .chain
        .chain_tip()
        .is_ok_and(|tip| tip.synchronized));
    node.stop();
}
/// Off regtest, nothing says the node is synced before chain sync's
/// cutover: it posts nothing and says why, and publishing `Synced` on
/// the node's watch posts (DX-Q3, Q13). Red edit: post without reading
/// the watch.
#[test]
fn a_testnet_node_posts_nothing_until_chain_sync_says_synced() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_mining(dir.path(), "testnet", shekyl_address::Network::Testnet);
    let mut posting = node.posting();
    wait_for_posting(
        &mut posting,
        &Posting::Withdrawn(NoJob::NotSynced(SyncState::NoView)),
    );
    assert!(node.mining.board.posted().is_none());
    let reason = node.mining().status().no_job.expect("a reason");
    assert_eq!(
        reason.to_string(),
        "no template: not synced (no sync owner before chain sync's cutover)"
    );
    assert!(node
        .handles()
        .chain
        .chain_tip()
        .is_ok_and(|tip| !tip.synchronized));
    node.sync().send_replace(SyncState::Synced);
    let started = std::time::Instant::now();
    while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "Synced did not post: {:?}",
            *posting.borrow()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(node.mining.board.posted().is_some());
    node.stop();
}
/// Stopping the miner from a tokio task completes, and the node is still
/// up after it: mining control never stops or drops the node (`stop`'s
/// `# Panics`). Red edit: have `MiningControl::stop` stop the node.
#[test]
fn stopping_the_miner_from_a_task_leaves_the_node_running() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_mining(dir.path(), "regtest", shekyl_address::Network::Mainnet);
    let mining = node.mining();
    match mining.start(NonZeroUsize::new(1)) {
        Ok(()) => {}
        Err(MiningRefused::Start(shekyl_miner::MinerStartRefused::OnePermit)) => {
            // A one-permit host never mines; there is nothing to stop.
            node.stop();
            return;
        }
        Err(other) => panic!("the miner did not start: {other}"),
    }
    assert!(mining.running());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let stopped = runtime.block_on(async move {
        tokio::spawn(async move { mining.stop() })
            .await
            .expect("the stop task")
    });
    assert!(stopped, "it was running");
    assert!(!node.mining().running());
    assert!(
        node.handles().door.room().expect("door") > 0,
        "the node is still up"
    );
    node.stop();
}

/// After `pop_blocks`, `generateblocks(1)` on a lone node completes: the
/// pop's reconcile leaves the pool judged at the new tip, so the next
/// template posts and the miner can move the tip (the landing review of
/// #1165, N3).
#[test]
fn generateblocks_after_pop_blocks_completes_on_a_lone_node() {
    use shekyl_daemon_rpc::mining_methods::{admit_armed, codes, generateblocks, pop_blocks};
    let generate = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
    let pop = shekyl_rpc_types::methods::rest_path("/pop_blocks").expect("a row");
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &["--dev-rpc"]);
    let handles = node.handles();
    let run = |count| {
        a_runtime().block_on(async {
            tokio::time::timeout(
                Duration::from_secs(120),
                generateblocks(
                    &handles.mining,
                    &*handles.door,
                    &*handles.chain,
                    admit_armed(generate, true).expect("armed"),
                    shekyl_rpc_types::mining::GenerateBlocksRequest { count },
                ),
            )
            .await
        })
    };
    let first = run(2);
    if let Ok(Err(refused)) = &first {
        if refused.diagnostic.code == codes::ONE_PERMIT {
            node.stop();
            return;
        }
    }
    let popped = a_runtime().block_on(pop_blocks(
        &*handles.door,
        admit_armed(pop, true).expect("armed"),
        shekyl_rpc_types::mining::PopBlocksRequest { nblocks: 1 },
    ));
    let second = run(1);
    let height = handles
        .chain
        .chain_tip()
        .map(|tip| tip.chain_height.to_raw());
    node.stop();
    first.expect("the first call answered").expect("two blocks");
    assert_eq!(popped.expect("one popped").height, 2);
    second
        .expect("generateblocks after a pop answered within its deadline")
        .expect("one block");
    assert_eq!(height.expect("tip"), 3);
}
