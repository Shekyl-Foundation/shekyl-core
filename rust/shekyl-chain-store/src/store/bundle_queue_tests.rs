// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue's own contract (`store/bundle_queue.rs`, SI-41): what
//! it holds, what it refuses, what survives a reopen, and what the open's
//! reconcile drops. The store does not judge a bundle, so these bundles
//! are bytes; the admission that judges them is the ingest connector's,
//! and `admission_chain_tests` drives a real one through to a connect.
//!
//! Every test names the edit that turns it red.

use redb::ReadableTableMetadata;
use shekyl_archival_retention::{
    BundleBody, BundleKept, BundleRecord, BundleRef, PassBitmap, BUNDLE_SIGNATURE_LEN,
    BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_types::{BlockHash, BlockHeight};

use super::store_tests::{cleanup, tmp, EPOCH};
use super::*;
use crate::codec::{Canonical, QueuedBody};
use crate::schema::{ARCHIVAL_BUNDLE_BODY, ARCHIVAL_BUNDLE_QUEUE};

const CAPACITY: u64 = 3;

fn tip() -> (BlockHeight, BlockHash) {
    (
        BlockHeight::from_raw(500),
        BlockHash::from_bytes([0x7A; 32]),
    )
}

/// A bundle for `h` with one pass. The bytes are not a valid bundle: the
/// store does not judge, and a fill makes each body distinct by `h`.
fn bundle(h: u64) -> (BundleRef, BundleBody) {
    let tag = u8::try_from(h % 251).expect("below 251");
    let kept = BundleKept {
        h: BlockHeight::from_raw(h),
        seed: [tag; 32],
        passes: PassBitmap::from_passes(4, [2]).expect("in range"),
        support: PassBitmap::none(),
    };
    let record = BundleRecord {
        attempt: 0,
        anchor_height: BlockHeight::from_raw(1),
        delivery_digest: [tag; 32],
        receipt: [tag; BUNDLE_SIGNATURE_LEN],
    };
    let body = BundleBody::new(
        &[tag; BUNDLE_WITNESS_KEY_LEN],
        &[tag; BUNDLE_SIGNATURE_LEN],
        &[record],
    );
    (BundleRef::of(&kept, &body), body)
}

fn queue(store: &ChainStore, h: u64) -> Result<(), StoreError> {
    let (reference, body) = bundle(h);
    let (height, hash) = tip();
    store.write(|batch| batch.queue_bundle(&reference, &body, height, hash, CAPACITY))
}

fn entries(store: &ChainStore) -> Vec<QueueEntry> {
    store
        .begin_read()
        .expect("snapshot")
        .queued_bundles()
        .expect("the queue reads")
}

fn cannot(result: Result<(), StoreError>) -> QueueCannot {
    match result {
        Err(StoreError::Cannot(StoreCannot::Queue(cannot))) => cannot,
        other => panic!("expected a queue refusal, got {other:?}"),
    }
}

/// An entry and its body go in together and come back together, keyed by
/// `h`, with the tip they were admitted against. Red edit: drop the body
/// insert — the read is SI-41 instead of the entry.
#[test]
fn a_queued_bundle_reads_back_with_its_body_and_tip() {
    let path = tmp("queue-roundtrip");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    queue(&store, 30).expect("queued");
    let read = entries(&store);
    assert_eq!(
        read.iter().map(|e| e.h.to_raw()).collect::<Vec<_>>(),
        [30, 40]
    );
    let (reference, body) = bundle(40);
    assert_eq!(read[1].queued.reference, reference);
    assert_eq!(read[1].body, body);
    assert_eq!((read[1].queued.tip_height, read[1].queued.tip_hash), tip());
    drop(store);
    cleanup(&path);
}

/// One per `h`: the second offer for a height is refused and the first
/// stands. A body that is not the reference's is refused before anything
/// is written. Red edit: let the insert overwrite — the second assertion
/// reads the second bundle's seed.
#[test]
fn one_bundle_per_height_and_a_body_that_is_not_its_references_is_refused() {
    let path = tmp("queue-one-per-h");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    let (mut second, body) = bundle(40);
    second = BundleRef::new(
        BundleKept {
            seed: [0xEE; 32],
            ..second.kept().clone()
        },
        body.prunable_hash(),
    );
    let (height, hash) = tip();
    assert_eq!(
        cannot(store.write(|batch| batch.queue_bundle(&second, &body, height, hash, CAPACITY))),
        QueueCannot::Held {
            h: BlockHeight::from_raw(40)
        }
    );
    assert_eq!(entries(&store)[0].queued.reference.seed(), &[40; 32]);

    let (reference, _) = bundle(41);
    let (_, other_body) = bundle(42);
    assert_eq!(
        cannot(store.write(|batch| batch.queue_bundle(
            &reference,
            &other_body,
            height,
            hash,
            CAPACITY
        ))),
        QueueCannot::BodyNotReferenced {
            h: BlockHeight::from_raw(41)
        }
    );
    assert_eq!(entries(&store).len(), 1);
    drop(store);
    cleanup(&path);
}

/// The bound: at `capacity` the next offer is refused. Removing an entry
/// removes its body and makes room. Red edit: leave the body behind on
/// removal — the next read is SI-41.
#[test]
fn the_queue_is_bounded_and_removal_takes_the_body() {
    let path = tmp("queue-bound");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    for h in [10, 11, 12] {
        queue(&store, h).expect("queued");
    }
    assert_eq!(
        cannot(queue(&store, 13)),
        QueueCannot::Full { capacity: CAPACITY }
    );
    let removed: Result<bool, StoreError> =
        store.write(|batch| batch.unqueue_bundle(BlockHeight::from_raw(11)));
    assert!(removed.expect("removed"));
    let absent: Result<bool, StoreError> =
        store.write(|batch| batch.unqueue_bundle(BlockHeight::from_raw(11)));
    assert!(!absent.expect("nothing to remove"));
    let bodies = store
        .begin_read()
        .expect("snapshot")
        .txn()
        .open_table(ARCHIVAL_BUNDLE_BODY)
        .expect("the body table")
        .len()
        .expect("a count");
    assert_eq!(bodies, 2, "the removed entry's body went with it");
    queue(&store, 13).expect("room again");
    drop(store);
    cleanup(&path);
}

/// The queue is persisted: a reopen reads what was queued. Red edit: keep
/// the queue in memory — the reopened store reads nothing.
#[test]
fn the_queue_survives_a_reopen() {
    let path = tmp("queue-reopen");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    drop(store);
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    assert_eq!(entries(&store).len(), 1);
    drop(store);
    cleanup(&path);
}

/// The open's reconcile drops a body no entry names and an entry whose
/// body is gone, and reports both; a clean store reports nothing. Before
/// the reconcile, the queue's read refuses the disagreement as SI-41.
/// Red edit: have the reconcile keep the orphan body — the report is
/// clean and the read after it is still SI-41.
#[test]
fn the_open_reconcile_drops_what_has_no_holder_and_says_so() {
    let path = tmp("queue-reconcile");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    queue(&store, 41).expect("queued");
    let clean: Result<QueueReconciled, StoreError> =
        store.write(|batch| batch.reconcile_bundle_queue());
    assert!(clean.expect("reconciled").is_clean());

    // Plant the two disagreements outside the write path: a body with no
    // entry, and an entry whose body is removed.
    let (_, orphan) = bundle(77);
    let (_, held_41) = bundle(41);
    let planted: Result<(), StoreError> = store.write(|batch| {
        let mut bodies = batch
            .txn()
            .open_table(ARCHIVAL_BUNDLE_BODY)
            .map_err(|e| StoreError::from(EngineError::Table(e)))?;
        bodies
            .insert(
                orphan.prunable_hash(),
                QueuedBody(orphan.clone()).encoded().as_encoded(),
            )
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        bodies
            .remove(held_41.prunable_hash())
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(())
    });
    planted.expect("planted");

    let refused = store.begin_read().expect("snapshot").queued_bundles();
    assert!(
        matches!(
            refused,
            Err(StoreError::InvariantViolated(StoreInvariant::BundleBodyHolder(
                BodyHolderFault::EntryWithoutBody { h }
            ))) if h == BlockHeight::from_raw(41)
        ),
        "{refused:?}"
    );

    let report: Result<QueueReconciled, StoreError> =
        store.write(|batch| batch.reconcile_bundle_queue());
    let report = report.expect("reconciled");
    assert_eq!(report.bodies_without_holder, vec![orphan.prunable_hash()]);
    assert_eq!(report.entries_without_body, vec![BlockHeight::from_raw(41)]);
    let left = entries(&store);
    assert_eq!(left.iter().map(|e| e.h.to_raw()).collect::<Vec<_>>(), [40]);
    let queue_rows = store
        .begin_read()
        .expect("snapshot")
        .txn()
        .open_table(ARCHIVAL_BUNDLE_QUEUE)
        .expect("the queue table")
        .len()
        .expect("a count");
    assert_eq!(queue_rows, 1);
    drop(store);
    cleanup(&path);
}

/// A body no entry names is SI-41 at the queue's read once the open has
/// passed. Red edit: compare the counts with `<=` — the orphan reads as
/// held.
#[test]
fn a_body_without_a_holder_is_si_41() {
    let path = tmp("queue-orphan");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    let (_, orphan) = bundle(77);
    let planted: Result<(), StoreError> = store.write(|batch| {
        batch
            .txn()
            .open_table(ARCHIVAL_BUNDLE_BODY)
            .map_err(|e| StoreError::from(EngineError::Table(e)))?
            .insert(
                orphan.prunable_hash(),
                QueuedBody(orphan.clone()).encoded().as_encoded(),
            )
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(())
    });
    planted.expect("planted");
    let refused = store.begin_read().expect("snapshot").queued_bundles();
    assert!(
        matches!(
            refused,
            Err(StoreError::InvariantViolated(
                StoreInvariant::BundleBodyHolder(BodyHolderFault::BodyWithoutHolder)
            ))
        ),
        "{refused:?}"
    );
    drop(store);
    cleanup(&path);
}

/// A retip of a height the queue does not hold is SI-41, and catching it
/// does not save the batch. The chain writer stays live: the queue is not
/// chain work. Red edit: drop the poison arm — the closure's `Ok` commits
/// and the held entry's tip changes. Red edit: note a connecting height
/// before the arm — the writer halts.
#[test]
fn a_swallowed_retip_of_an_absent_entry_poisons_and_leaves_the_writer_live() {
    let path = tmp("queue-retip-absent");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    queue(&store, 40).expect("queued");
    let (_height, hash) = tip();
    let rewritten = BlockHash::from_bytes([0x11; 32]);
    let missing = BlockHeight::from_raw(41);
    let at = BlockHeight::from_raw(40);
    let result = store.write(|batch| -> Result<(), StoreError> {
        let refused = batch.retip_bundle(missing, at, rewritten);
        assert!(
            matches!(
                refused,
                Err(StoreError::InvariantViolated(StoreInvariant::BundleBodyHolder(
                    BodyHolderFault::EntryAbsent { h },
                ))) if h == missing
            ),
            "{refused:?}"
        );
        batch.retip_bundle(at, at, rewritten)?;
        Ok(())
    });
    assert!(
        matches!(
            result,
            Err(StoreError::InvariantViolated(StoreInvariant::BundleBodyHolder(
                BodyHolderFault::EntryAbsent { h },
            ))) if h == missing
        ),
        "a swallowed absence still refuses the commit: {result:?}"
    );
    let held = entries(&store);
    assert_eq!(held.len(), 1);
    assert_eq!(
        held[0].queued.tip_hash, hash,
        "the retip after the catch did not land"
    );
    assert!(
        store.connect_state().is_live(),
        "a queue fault does not halt the chain writer"
    );
    store
        .write(|_| Ok::<(), StoreError>(()))
        .expect("a later write proceeds");
    drop(store);
    cleanup(&path);
}
