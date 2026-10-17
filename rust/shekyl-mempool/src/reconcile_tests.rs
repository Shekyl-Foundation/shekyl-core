// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Open over a file whose entry does not parse: the entry is dropped and
//! named, and the pool opens. Reconciling real entries — mined, admitted
//! again, kept — needs real spends and is `shekyl-chain-ingest`'s.

use shekyl_chain_rules::harness::fixture::spendable_chain;
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::pool::{PoolRecord, PoolStore, Standing};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_units::AtomicUnits;

use super::Removed;
use crate::pool::Pool;

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
