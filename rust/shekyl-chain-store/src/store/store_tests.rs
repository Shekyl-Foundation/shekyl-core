// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-TXN tests. Sibling of the production files so the workflow stays
//! under the size the decomposition ratchet exists to protect. Header and
//! provenance tests are in `header_tests.rs`.

use redb::TableDefinition;

use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::family_set::FamilySet;

pub(super) const PROBE: TableDefinition<&str, u64> = TableDefinition::new("__e1_probe");

pub(super) fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shekyl-chain-store-{}-{}-{:?}.redb",
        name,
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&p));
    p
}

pub(super) fn cleanup(path: &std::path::Path) {
    drop(std::fs::remove_file(path));
}

#[test]
fn a_store_defaults_to_full_apply_and_a_fresh_file_is_evidence() {
    let path = tmp("policy");
    let store = ChainStore::create(&path).expect("create");
    assert_eq!(store.apply_policy(), ApplyPolicy::Full);
    assert!(store.provenance().is_parity_evidence());
    cleanup(&path);
}

#[test]
fn an_empty_stub_is_refused_at_open() {
    let path = tmp("empty-stub");
    assert!(matches!(
        ChainStore::with_apply_policy(&path, ApplyPolicy::StubbedFamilies(FamilySet::EMPTY)),
        Err(StoreError::EmptyApplyStub)
    ));
    assert!(!path.exists(), "a refused policy must not create the store");
}

#[test]
fn declared_commit_policy_constants_are_pinned() {
    // A4: explicit, not by omission. THIS BITES AGAINST: lowering DURABILITY,
    // turning TWO_PHASE_COMMIT off, or shrinking CACHE_SIZE in the consts.
    // IT DOES NOT COVER: the consts being APPLIED. redb 4.1.0 has no getter
    // for durability or two-phase commit (only setters, transactions.rs:1269
    // and :1326), so nothing can read the applied value back; an earlier
    // draft copied the consts into the batch and asserted the copy, which
    // compared each const with itself. Deleting the set_* calls in arm_write
    // leaves this green. Application is proven only by begin_batch returning
    // Ok through the `?` on set_durability -- a weaker claim, stated as such.
    assert!(matches!(DURABILITY, Durability::Immediate));
    assert_eq!(CACHE_SIZE, 1024 * 1024 * 1024);
    // TWO_PHASE_COMMIT is pinned at compile time: a constant assertion is the
    // honest form for a constant, and clippy's assertions_on_constants says so.
    const _: () = assert!(
        TWO_PHASE_COMMIT,
        "two-phase commit must stay on: redb's default is off"
    );
    let path = tmp("armed");
    let store = ChainStore::create(&path).expect("create");
    store
        .begin_batch()
        .expect("arming the declared policy is accepted by the engine")
        .abort()
        .expect("abort");
    cleanup(&path);
}

#[test]
fn a_committed_row_is_visible_to_a_later_read() {
    let path = tmp("commit");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("begin");
    {
        let mut table = batch.open_table(PROBE).expect("open");
        table.insert("k", &1_u64).expect("insert");
    }
    batch.commit().expect("commit");
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(PROBE).expect("open read");
    assert_eq!(table.get("k").expect("get").expect("present").value(), 1);
    cleanup(&path);
}

#[test]
fn a_dropped_batch_does_not_persist_its_writes() {
    let path = tmp("drop");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("begin");
    {
        let mut table = batch.open_table(PROBE).expect("open");
        table.insert("k", &1_u64).expect("insert");
    }
    drop(batch);
    assert!(
        store.begin_read().expect("read").open_table(PROBE).is_err(),
        "an aborted create must not leave the probe table"
    );
    store
        .begin_batch()
        .expect("begin after drop")
        .abort()
        .expect("abort");
    cleanup(&path);
}

#[test]
fn abort_is_a_decision_and_does_not_persist() {
    let path = tmp("abort");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("begin");
    {
        let mut table = batch.open_table(PROBE).expect("open");
        table.insert("k", &1_u64).expect("insert");
    }
    batch.abort().expect("abort");
    assert!(store.begin_read().expect("read").open_table(PROBE).is_err());
    cleanup(&path);
}

#[test]
fn a_second_live_batch_is_a_typed_error_not_a_deadlock() {
    let path = tmp("in-progress");
    let store = ChainStore::create(&path).expect("create");
    let first = store.begin_batch().expect("first");
    assert!(matches!(
        store.begin_batch(),
        Err(StoreError::WriteInProgress)
    ));
    first.abort().expect("abort first");
    store
        .begin_batch()
        .expect("after abort")
        .abort()
        .expect("abort");
    cleanup(&path);
}

#[test]
fn a_second_batch_from_another_thread_is_refused_not_queued() {
    // DRS-W17's replacement KAT, refusal half: the C++ batch_start returns
    // false and its callers spin; redb's begin_write would BLOCK on a
    // condvar; this store must do neither. A second thread asking while a
    // batch is live gets WriteInProgress back promptly -- it does not wait
    // for the holder to finish, which is what would happen if the guard were
    // redb's queue rather than the CAS. The wait is bounded so that "queued"
    // is a red verdict, not a hung job: without the bound this test would
    // block on the condvar until the holder is dropped, which it never is
    // until the asker has answered.
    let path = tmp("cross-thread");
    let store = std::sync::Arc::new(ChainStore::create(&path).expect("create"));
    let held = store.begin_batch().expect("holder");
    let (tx, rx) = std::sync::mpsc::channel();
    let asker = {
        let store = std::sync::Arc::clone(&store);
        std::thread::spawn(move || {
            let verdict = match store.begin_batch() {
                Err(StoreError::WriteInProgress) => Ok(()),
                Err(e) => Err(format!("wrong error: {e}")),
                Ok(_) => Err("second batch was GRANTED while one was live".to_owned()),
            };
            tx.send(verdict).expect("main is waiting");
        })
    };
    let verdict = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("asker was QUEUED behind the holder instead of refused");
    // The answer arrived while `held` is still alive: refused, not parked.
    verdict.expect("refused promptly");
    held.abort().expect("abort");
    asker.join().expect("asker thread");
    cleanup(&path);
}

#[test]
fn a_read_snapshot_is_allowed_while_a_write_is_live() {
    let path = tmp("read-during-write");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("write");
    store.begin_read().expect("read during write");
    batch.abort().expect("abort");
    cleanup(&path);
}

#[test]
fn a_stubbed_family_cannot_open_its_table_on_a_write() {
    let path = tmp("stub-open");
    const STUB: &[ArchivalFamily] = &[ArchivalFamily::SlashLog];
    let store = ChainStore::with_apply_policy(&path, ApplyPolicy::stubbed(STUB).expect("stub"))
        .expect("create");
    let batch = store.begin_batch().expect("begin");
    assert!(matches!(
        batch.open_table(crate::schema::ARCHIVAL_SLASH_LOG),
        Err(StoreError::FamilyStubbed(ArchivalFamily::SlashLog))
    ));
    {
        let mut table = batch.open_table(PROBE).expect("non-archival still opens");
        table.insert("k", &1_u64).expect("insert");
    }
    batch.commit().expect("commit");
    cleanup(&path);
}

#[test]
fn the_properties_table_has_no_raw_write_handle() {
    // A raw handle would let a string overwrite `schema_version` or clear
    // the provenance record, which is exactly what the typed surface exists
    // to make unrepresentable. Reads stay raw-capable: nothing can be
    // damaged by looking.
    let path = tmp("properties-typed");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("begin");
    assert!(matches!(
        batch.open_table(crate::schema::PROPERTIES),
        Err(StoreError::PropertiesAreTyped)
    ));
    // Nor by redefining it under another type: the refusal is by name.
    const IMPOSTOR: redb::MultimapTableDefinition<&str, &[u8]> =
        redb::MultimapTableDefinition::new("properties");
    assert!(matches!(
        batch.open_multimap_table(IMPOSTOR),
        Err(StoreError::PropertiesAreTyped)
    ));
    batch.abort().expect("abort");
    store
        .begin_read()
        .expect("read")
        .open_table(crate::schema::PROPERTIES)
        .expect("raw read of properties is allowed");
    cleanup(&path);
}

#[test]
fn a_read_only_store_refuses_at_the_single_refusal_point() {
    let path = tmp("readonly");
    {
        let store = ChainStore::create(&path).expect("create");
        store
            .begin_batch()
            .expect("begin")
            .commit()
            .expect("commit");
    }
    let store = ChainStore::open_read_only(&path).expect("open ro");
    assert!(store.is_read_only());
    assert!(matches!(store.begin_batch(), Err(StoreError::ReadOnly)));
    store.begin_read().expect("read on a read-only store");
    cleanup(&path);
}

// ------------------------------------------------ one file, one writer
//
// `provenance()` mirrors the file's `apply_policy` cell and claims the
// mirror is exact. The claim rests on redb's file lock: exclusive for a
// writable handle, shared for a read-only one. `flock` locks are per open
// file description, so a second open in THIS process contends exactly as a
// second process would, which is what lets the property be tested here
// without spawning one. THESE BITE AGAINST: a redb bump that drops or
// relaxes the lock, or an `open` path in this crate that stops going
// through redb's locked backend.

fn is_already_open(result: &Result<ChainStore, StoreError>) -> bool {
    matches!(
        result,
        Err(StoreError::Open(redb::DatabaseError::DatabaseAlreadyOpen))
    )
}

#[test]
fn a_second_writable_open_is_refused_while_a_writer_is_live() {
    let path = tmp("lock-w-w");
    let live = ChainStore::create(&path).expect("create");
    assert!(
        is_already_open(&ChainStore::create(&path)),
        "two writable handles on one file would let the provenance mirror go stale"
    );
    drop(live);
    ChainStore::create(&path).expect("reopen once the lock is released");
    cleanup(&path);
}

#[test]
fn a_read_only_open_is_refused_while_a_writer_is_live() {
    let path = tmp("lock-w-r");
    let live = ChainStore::create(&path).expect("create");
    assert!(is_already_open(&ChainStore::open_read_only(&path)));
    drop(live);
    cleanup(&path);
}

#[test]
fn a_writable_open_is_refused_while_a_reader_is_live() {
    let path = tmp("lock-r-w");
    drop(ChainStore::create(&path).expect("create"));
    let reader = ChainStore::open_read_only(&path).expect("open ro");
    assert!(
        is_already_open(&ChainStore::create(&path)),
        "a reader's provenance is read once at open; a writer admitted behind it could widen the cell"
    );
    drop(reader);
    cleanup(&path);
}

#[test]
fn two_read_only_handles_coexist() {
    // Shared lock: readers do not exclude readers, and neither can commit,
    // so neither's mirror can be moved by the other.
    let path = tmp("lock-r-r");
    drop(ChainStore::create(&path).expect("create"));
    let first = ChainStore::open_read_only(&path).expect("first ro");
    let second = ChainStore::open_read_only(&path).expect("second ro alongside the first");
    assert_eq!(first.provenance(), second.provenance());
    drop((first, second));
    cleanup(&path);
}

#[test]
fn open_read_only_refuses_a_store_that_does_not_exist() {
    let path = tmp("absent");
    drop(std::fs::remove_file(&path));
    assert!(matches!(
        ChainStore::open_read_only(&path),
        Err(StoreError::Open(_))
    ));
    assert!(!path.exists(), "a read-only open must not create the store");
}
