// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Open over a file whose entry does not parse: the entry is dropped and
//! named, and the pool opens. A reconcile that faults — on a chain read or
//! on the file's write — changes nothing, in memory or in the file, and the
//! next one makes the same judgements. Reconciling real entries — mined,
//! admitted again, kept — needs real spends and is `shekyl-chain-ingest`'s.

use shekyl_chain_rules::harness::fixture::{listed_on, spendable_chain};
use shekyl_chain_rules::harness::FaultingView;
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::pool::{PoolRecord, PoolStore, Standing};
use shekyl_types::{KeyImage, TxHash, UnixSeconds};
use shekyl_units::AtomicUnits;

use super::Removed;
use crate::pool::{Pool, PoolFault};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "shekyl-mempool-{name}-{}-{:?}.redb",
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&path));
    path
}

const ADMITTED: PoolRecord = PoolRecord {
    weight: 1,
    fee: AtomicUnits::from_raw(1),
    receive_time: UnixSeconds::from_raw(1),
    public: true,
    standing: Standing::Admitted { proven: None },
};

/// A pool at `path` holding two fixture spends as admitted entries — each
/// refused on its bytes when judged again, so a reconcile removes both.
fn two_planted(path: &std::path::Path) -> (Pool, [TxHash; 2]) {
    let chain = spendable_chain();
    let (mut pool, _) = Pool::create(path).unwrap();
    let a = pool.plant(listed_on(&chain, [0x41; 32]), ADMITTED);
    let b = pool.plant(listed_on(&chain, [0x42; 32]), ADMITTED);
    (pool, [a, b])
}

/// What the file holds, by hash.
fn filed(pool: &Pool) -> Vec<TxHash> {
    let snapshot = pool.store().begin_read().unwrap();
    snapshot
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().txid)
        .collect()
}

#[test]
fn a_chain_fault_mid_reconcile_leaves_the_pool_as_it_was() {
    let path = tmp("reconcile-read-fault");
    let (mut pool, held) = two_planted(&path);
    let images = pool.key_images().len();
    let fault = pool.reconcile(
        &FaultingView::default(),
        &RuleSet::GENESIS,
        &AdmissionPolicy::GENESIS,
    );
    assert!(matches!(fault, Err(PoolFault::Chain(_))), "{fault:?}");
    assert_eq!(pool.len(), 2, "the index still holds both entries");
    assert_eq!(pool.key_images().len(), images, "and their key images");
    assert!(held.iter().all(|txid| pool.record(txid) == Some(ADMITTED)));
    assert_eq!(
        pool.key_images().spender(&KeyImage::from_bytes([0x41; 32])),
        Some(held[0])
    );

    // The retry makes the judgements the faulted one would have.
    let chain = spendable_chain();
    let reconciled = chain.with_view(|view| {
        pool.reconcile(&view, &RuleSet::GENESIS, &AdmissionPolicy::GENESIS)
            .unwrap()
    });
    assert_eq!(reconciled.removed.len(), 2);
    assert!(pool.is_empty() && pool.key_images().is_empty());
    assert!(filed(&pool).is_empty(), "the file followed");
    drop(pool);
    drop(std::fs::remove_file(&path));
}

#[test]
fn a_refused_write_leaves_the_index_and_the_file_as_they_were_and_the_retry_writes_them() {
    let path = tmp("reconcile-write-fault");
    let (mut pool, held) = two_planted(&path);
    let chain = spendable_chain();
    pool.refuse_next_write = true;
    let fault =
        chain.with_view(|view| pool.reconcile(&view, &RuleSet::GENESIS, &AdmissionPolicy::GENESIS));
    assert!(matches!(fault, Err(PoolFault::Store(_))), "{fault:?}");
    assert_eq!(pool.len(), 2, "the index did not run ahead of the file");
    assert!(held.iter().all(|txid| pool.record(txid) == Some(ADMITTED)));
    assert_eq!(pool.key_images().len(), 2);
    assert_eq!(
        filed(&pool),
        sorted(held),
        "the aborted batch took its removals back"
    );

    let reconciled = chain.with_view(|view| {
        pool.reconcile(&view, &RuleSet::GENESIS, &AdmissionPolicy::GENESIS)
            .unwrap()
    });
    assert_eq!(reconciled.removed.len(), 2, "the retry judged both again");
    assert!(pool.is_empty() && pool.key_images().is_empty());
    assert!(
        filed(&pool).is_empty(),
        "and wrote what the faulted one could not"
    );
    drop(pool);
    drop(std::fs::remove_file(&path));
}

fn sorted(mut txids: [TxHash; 2]) -> Vec<TxHash> {
    txids.sort();
    txids.to_vec()
}

#[test]
fn an_entry_that_does_not_parse_is_dropped_at_open() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "shekyl-mempool-unparseable-{}-{:?}.redb",
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&path));
    let txid = TxHash::from_bytes([0x51; 32]);
    {
        let (store, _) = PoolStore::create(&path).unwrap();
        let record = PoolRecord {
            weight: 1,
            fee: AtomicUnits::from_raw(1),
            receive_time: UnixSeconds::from_raw(1),
            public: true,
            standing: Standing::Admitted { proven: None },
        };
        store
            .write(|batch| batch.insert(txid, &record, b"not a transaction"))
            .unwrap();
    }
    let chain = spendable_chain();
    chain.with_view(|view| {
        let (pool, _, reconciled) =
            Pool::open(&path, &view, &RuleSet::GENESIS, &AdmissionPolicy::GENESIS).unwrap();
        assert!(pool.is_empty());
        assert_eq!(reconciled.removed, vec![(txid, Removed::Unparseable)]);
    });
    let (store, _) = PoolStore::create(&path).unwrap();
    assert!(
        store.begin_read().unwrap().is_empty().unwrap(),
        "the file lost it too"
    );
    drop(store);
    drop(std::fs::remove_file(&path));
}
