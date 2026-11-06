// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The body-store actor's contract: reads by message return the stored
//! bytes, an awaited shutdown closes the file, and erase reaches the store.

use std::sync::Arc;

use shekyl_p_host::HeldShardSource;
use shekyl_p_store::{BodyStore, StoreKey};
use shekyl_types::ShardId;

use super::BodyStoreHandle;

fn key() -> StoreKey {
    StoreKey::from_bytes([0x3c; 32])
}

/// A frame spanning several storage chunks, so the read is chunk by chunk.
fn frame() -> Vec<u8> {
    (0..200_000_u32)
        .map(|i| u8::try_from(i % 251).expect("fits"))
        .collect()
}

/// Every chunk of `id`, read through the serving path's source on the
/// blocking pool, as the endpoint reads it.
async fn read_through(source: Arc<dyn HeldShardSource>, id: ShardId) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let held = source.open_shard(id).expect("open")?;
        let mut body = Vec::new();
        for index in 0..held.chunk_count() {
            body.extend_from_slice(&source.read_chunk(&held, index).expect("chunk"));
        }
        Some(body)
    })
    .await
    .expect("blocking read")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_shard_is_served_through_the_owner_chunk_by_chunk() {
    let handle = BodyStoreHandle::spawn(BodyStore::open_ephemeral(key()).expect("open"));
    handle.put_for_test(ShardId::from_raw(4), &frame()).await;
    let source: Arc<dyn HeldShardSource> = Arc::new(handle.reads());

    assert_eq!(
        read_through(Arc::clone(&source), ShardId::from_raw(4)).await,
        Some(frame()),
        "the served bytes are the stored frame"
    );
    assert_eq!(
        read_through(source, ShardId::from_raw(5)).await,
        None,
        "a shard the store does not hold is an ordinary miss"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erase_through_the_owner_makes_the_shard_a_miss() {
    let handle = BodyStoreHandle::spawn(BodyStore::open_ephemeral(key()).expect("open"));
    handle.put_for_test(ShardId::from_raw(1), b"held").await;
    handle
        .erase(vec![1, 2])
        .await
        .expect("erase, a missing row included");
    assert_eq!(
        read_through(Arc::new(handle.reads()), ShardId::from_raw(1)).await,
        None
    );
}

/// The close half of §11.1: once the awaited shutdown returns, the file is
/// closed, so the same path opens at once with no retry, and the serving
/// path's reads are refused rather than served from a store nobody owns.
/// Repeated, on a loaded multi-thread runtime, because the unawaited drop
/// this replaces lost the race only sometimes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_awaited_shutdown_closes_the_file_for_an_immediate_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wallet.pstore");
    let mut store = BodyStore::open(&path, key()).expect("create");
    for round in 0..25_u64 {
        let handle = BodyStoreHandle::spawn(store);
        handle
            .put_for_test(ShardId::from_raw(round), b"frame")
            .await;
        let reads = handle.reads();
        handle.shutdown().await;

        let refused = tokio::task::spawn_blocking(move || reads.open_shard(ShardId::from_raw(0)))
            .await
            .expect("blocking read");
        assert!(
            refused.is_err(),
            "round {round}: a stopped owner serves nothing"
        );

        store = BodyStore::open(&path, key())
            .unwrap_or_else(|e| panic!("round {round}: the file is still held: {e}"));
        assert!(
            store.holds(ShardId::from_raw(round)).expect("holds"),
            "round {round}: the reopened file is the one the owner wrote"
        );
    }
}

/// The stake engine's shutdown is the one the engine's close awaits, and it
/// must stop the body store's owner as well as its own actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stake_engine_shutdown_closes_the_body_store_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wallet.pstore");
    let stake = super::super::handle::StakeEngineHandle::spawn(
        std::collections::BTreeMap::new(),
        std::collections::BTreeSet::new(),
        None,
        BodyStore::open(&path, key()).expect("create"),
        [0; 16],
    );
    stake
        .bodies
        .put_for_test(ShardId::from_raw(3), b"frame")
        .await;
    let reads = stake.bodies.reads();
    stake.shutdown().await;

    let refused = tokio::task::spawn_blocking(move || reads.open_shard(ShardId::from_raw(3)))
        .await
        .expect("blocking read");
    assert!(
        refused.is_err(),
        "a stopped stake engine's store serves nothing"
    );
    let reopened = BodyStore::open(&path, key()).expect("the file is closed at once");
    assert!(reopened.holds(ShardId::from_raw(3)).expect("holds"));
}

/// The owner's store work runs at serving priority (§9.8). The reading is
/// taken on the actor's thread, by a message, so it is not the test
/// thread's nice value.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_does_its_store_work_at_serving_priority() {
    let handle = BodyStoreHandle::spawn(BodyStore::open_ephemeral(key()).expect("open"));
    assert_eq!(
        handle.nice_for_test().await,
        shekyl_thread_priority::SERVING_NICE,
        "the body-store worker lowered itself before it took store work"
    );
    handle.shutdown().await;
}
