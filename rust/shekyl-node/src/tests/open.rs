// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Opening the node, stopping it, and the files it replaces.

use super::*;

/// An empty store connects the pinned genesis, and the chain handle
/// reads it back. Red edit: connect genesis through anything but the
/// door, or answer the handle from a hard-coded hash.
#[test]
fn an_empty_store_holds_the_pinned_genesis_and_the_chain_handle_answers_it() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let want = BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
    let identity = node.handles().chain.identity().expect("identity");
    assert_eq!(identity.genesis_hash, want);
    let at = node
        .handles()
        .chain
        .block_hash_at(BlockHeight::ZERO)
        .expect("height 0");
    assert_eq!(at.hash, Some(want));
    assert!(
        node.handles().door.room().expect("door") > 0,
        "a live door is not the absent handle"
    );
    assert!(!node.handles().mining.running().expect("mining"));
    assert_eq!(node.handles().pool.broadcast_count().expect("pool"), 0);
    node.stop();
}
/// `Node::stop` waits, so it refuses to run inside a tokio runtime
/// (`# Panics`); afterwards the node still stops from outside one. Red
/// edit: drop the `debug_assert`.
#[cfg(debug_assertions)]
#[test]
fn stopping_the_node_inside_a_runtime_is_refused() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let inside = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async { node.stop() });
    }));
    let refusal = inside.expect_err("stop ran inside a runtime");
    let said = refusal
        .downcast_ref::<&str>()
        .map(|said| (*said).to_owned())
        .or_else(|| refusal.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        said.contains("Node::stop waits"),
        "the node's own refusal, not tokio's: {said}"
    );
    drop(runtime);
    node.stop();
    assert!(node.mining.board.posted().is_none());
}
/// The blocking pool has a thread for every task that can be
/// outstanding at once (module docs, "Blocking threads"): more than the
/// permits and the window together, so permit waiters alone never fill
/// it. Red edit: size it at the permits.
#[test]
fn the_blocking_pool_exceeds_the_permits_and_the_window() {
    for permits in [1, 2, 8, 64] {
        for window in [1, 32] {
            let threads = blocking_threads(
                NonZeroUsize::new(permits).expect("nonzero"),
                NonZeroUsize::new(window).expect("nonzero"),
            );
            assert!(threads.get() > permits + window, "{permits} + {window}");
        }
    }
}
/// Stop closes the store, withdraws the board, and a second stop is a
/// no-op. A handle held past stop is not ready. Red edit: leave the
/// facts slot filled, or skip the second stop.
#[test]
fn stop_closes_the_store_withdraws_the_board_and_a_second_stop_is_a_no_op() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let (block, _) = pinned_genesis(Network::Regtest).expect("genesis");
    // The follower's first word, so it does not withdraw the job below:
    // no mine-address, no template.
    let mut posting = node.posting();
    wait_for_posting(&mut posting, &Posting::Withdrawn(NoJob::NoAddress));
    node.mining.board.publish(Job {
        offsets: block
            .blob_offsets()
            .expect("genesis reserves the extra nonce"),
        next_seed: None,
        reward: shekyl_units::AtomicUnits::ZERO,
        median_weight: 0,
        already_generated: shekyl_units::AtomicUnits::ZERO,
        listed: Vec::new(),
        block,
        height: BlockHeight::from_raw(1),
        seed: BlockHash::from_bytes([1; 32]),
        difficulty: Difficulty::from_raw(1),
    });
    assert!(node.mining.board.posted().is_some(), "the job was posted");
    node.stop();
    assert!(
        node.mining.board.posted().is_none(),
        "stop withdraws the board"
    );
    node.stop();
    let rules =
        ChainRules::new(Chain::Regtest, None, FakechainSchedule::PRODUCTION).expect("rules");
    let horizons = Horizons::under(&rules.in_force(BlockHeight::ZERO)).expect("horizons");
    let store = ChainStore::with_release(
        dir.path().join("chain.db"),
        ApplyPolicy::Full,
        horizons,
        &ReleaseAnchors::EMPTY,
    )
    .expect("the store closed, so it opens again");
    let snap = store.begin_read().expect("read");
    let tip = snap.tip().expect("tip").recorded.expect("genesis");
    let want = BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain));
    assert_eq!(tip.hash, want);
    assert_eq!(
        node.handles().chain.identity(),
        Err(FactsFault::NotReady),
        "the handle does not answer after the store closes"
    );
}
/// A `pow_hash` waiting on a hasher permit does not hold the facts
/// lock: a chain read returns while that wait is in progress.
///
/// [`shekyl_hash_budget::Budget::waiting`] is the signal. It rises
/// inside `acquire`, which runs inside the read, so the chain read
/// starts only once the slot guard would already be held. The permits
/// stay held until that read returns, so a guard that spanned the wait
/// fails `READ_BOUND`. Both bounds are failure limits: the enter loop
/// returns when the wait is visible, and a read that finishes returns
/// at once.
///
/// Red edit: hold the slot mutex across `read`.
#[test]
fn a_pow_hash_in_flight_does_not_hold_the_facts_lock() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use shekyl_daemon_rpc::chain_facts::ChainFacts;
    use shekyl_daemon_rpc::read_facts::{ChainReadFacts, PowSeed};
    use shekyl_hash_budget::Class;

    /// The hash thread has not reached `acquire`.
    const ENTER_BOUND: Duration = Duration::from_secs(5);
    /// The chain read shared the permit wait. The permits are still held.
    const READ_BOUND: Duration = Duration::from_secs(2);

    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let budget = node.budget();
    // Every free permit. `pow_hash` then waits in `acquire` instead of
    // hashing, which is the wait a chain read must not share.
    let held: Vec<_> = (0..budget.permits())
        .map_while(|_| budget.try_acquire(Class::Chain))
        .collect();
    assert!(
        budget.try_acquire(Class::CalcPow).is_none(),
        "a calc_pow permit was still free"
    );
    let hashing = {
        let chain = Arc::clone(&node.handles().chain);
        std::thread::spawn(move || {
            ChainReadFacts::pow_hash(&*chain, &[], PowSeed::Given(BlockHash::NULL))
        })
    };
    let entered = Instant::now();
    while budget.waiting(Class::CalcPow) == 0 {
        if hashing.is_finished() {
            let finished = hashing.join().expect("pow thread");
            panic!("pow_hash finished without waiting for a permit: {finished:?}");
        }
        assert!(
            entered.elapsed() < ENTER_BOUND,
            "pow_hash did not wait for a permit"
        );
        std::thread::yield_now();
    }
    let (done, arrived) = mpsc::channel();
    let reading = {
        let chain = Arc::clone(&node.handles().chain);
        std::thread::spawn(move || {
            let _read = ChainFacts::chain_tip(&*chain).is_ok();
            let _sent = done.send(()).is_ok();
        })
    };
    assert!(
        arrived.recv_timeout(READ_BOUND).is_ok(),
        "a chain read waited on the pow hash, so the facts lock is held across the permit wait"
    );
    drop(held);
    let hashed = hashing.join().expect("pow thread");
    assert!(
        hashed.is_ok(),
        "the hash finishes once a permit is free: {hashed:?}"
    );
    reading.join().expect("the chain read");
}
/// The node's stop handle is the latch `main` passed in. The absent
/// handle is not ready, never a success. Red edit: call the latch from
/// the absent handle, or ignore `request_stop`.
#[test]
fn the_stop_handle_asks_the_latch_and_the_absent_one_does_not() {
    let asked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&asked);
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(
        dir.path(),
        Arc::new(move || flag.store(true, Ordering::SeqCst)),
    );
    shekyl_daemon_rpc::node_methods::stop_daemon(&*node.handles().stop).expect("asks");
    assert!(asked.load(Ordering::SeqCst), "the handler asked the latch");
    assert_eq!(
        Handles::absent().stop.request_stop(),
        Err(FactsFault::NotReady)
    );
    node.stop();
}
/// A chain file at another layout is removed and a fresh store holds
/// genesis. A file that is not a store is refused and left in place.
/// Red edit: refuse the version mismatch, or wipe a corrupt header.
#[test]
fn a_foreign_chain_file_is_replaced_and_a_corrupt_one_is_kept() {
    use shekyl_chain_store::codec::SCHEMA_VERSION;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    node.stop();
    let chain = dir.path().join("chain.db");
    put_chain_version(&chain, SCHEMA_VERSION.get() + 1);
    let node = open_at(dir.path(), Arc::new(|| {}));
    assert_eq!(
        node.handles()
            .chain
            .block_hash_at(BlockHeight::ZERO)
            .expect("height 0")
            .hash,
        Some(genesis_hash())
    );
    node.stop();
    put_chain_version(&chain, SCHEMA_VERSION.get());
    let garbage = b"not a chain store";
    std::fs::write(&chain, garbage).expect("overwrite");
    let config = config_at(dir.path());
    let opened = Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    });
    assert!(
        opened.is_err(),
        "a corrupt chain file is not a layout mismatch"
    );
    assert_eq!(std::fs::read(&chain).expect("still there"), garbage);
}
/// A pool file at another version is recreated and the node starts. A
/// pool file that is not a pool file is refused and kept. Red edit:
/// refuse the version, or delete the corrupt file.
#[test]
fn a_foreign_pool_file_is_recreated_and_a_corrupt_one_is_kept() {
    use shekyl_chain_store::pool::POOL_SCHEMA_VERSION;
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    node.stop();
    let pool = dir.path().join("pool.db");
    put_pool_version(&pool, POOL_SCHEMA_VERSION.get() + 1);
    let node = open_at(dir.path(), Arc::new(|| {}));
    assert_eq!(node.handles().pool.broadcast_count().expect("pool"), 0);
    node.stop();
    let garbage = b"not a pool file";
    std::fs::write(&pool, garbage).expect("overwrite");
    let config = config_at(dir.path());
    let opened = Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    });
    assert!(opened.is_err(), "a corrupt pool file is refused");
    assert_eq!(std::fs::read(&pool).expect("still there"), garbage);
}
/// One regtest lever is filled from production on the other side and
/// the node opens. A cap that is not strictly inside the epoch is
/// refused. Red edit: require the two levers to be set together, or
/// accept a cap outside the epoch.
#[test]
fn one_archival_lever_opens_and_a_cap_outside_the_epoch_does_not() {
    let dir = tempfile::tempdir().expect("temp");
    let config = dev_config(dir.path(), &["--dev-archival-reorg-depth", "10"]);
    let node = Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    })
    .expect("one lever, the other side production");
    node.stop();
    let refused = dev_config(
        dir.path(),
        &[
            "--dev-settlement-epoch-blocks",
            "10",
            "--dev-archival-reorg-depth",
            "10",
        ],
    );
    let opened = Node::open(OpenArgs {
        config: &refused,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    });
    assert!(
        opened.is_err(),
        "a reorg cap that is not inside the epoch is refused"
    );
}
