// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-TXN tests. Sibling of the production files so the workflow stays
//! under the size the decomposition ratchet exists to protect.

use redb::TableDefinition;

use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};

const PROBE: TableDefinition<&str, u64> = TableDefinition::new("__e1_probe");
const SLASH_LOG: TableDefinition<&str, u64> = TableDefinition::new("archival_slash_log");

fn tmp(name: &str) -> std::path::PathBuf {
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

fn cleanup(path: &std::path::Path) {
    drop(std::fs::remove_file(path));
}

#[test]
fn a_store_defaults_to_full_apply_and_reports_it() {
    let path = tmp("policy");
    let store = ChainStore::create(&path).expect("create");
    assert_eq!(store.apply_policy(), ApplyPolicy::Full);
    assert!(store.apply_policy().is_parity_evidence());
    cleanup(&path);
}

#[test]
fn a_stubbed_store_reports_a_non_parity_policy() {
    let path = tmp("stubbed");
    const STUB: &[ArchivalFamily] = &[ArchivalFamily::SlashLog];
    let store = ChainStore::with_apply_policy(&path, ApplyPolicy::stubbed(STUB).expect("stub"))
        .expect("create stubbed");
    assert!(!store.apply_policy().is_parity_evidence());
    assert!(store
        .apply_policy()
        .artifact_stamp()
        .contains("NOT-PARITY-EVIDENCE"));
    cleanup(&path);
}

#[test]
fn an_empty_stub_is_refused_at_open() {
    let path = tmp("empty-stub");
    assert!(matches!(
        ChainStore::with_apply_policy(&path, ApplyPolicy::StubbedFamilies(&[])),
        Err(StoreError::EmptyApplyStub)
    ));
    assert!(!path.exists(), "a refused policy must not create the store");
}

#[test]
fn declared_commit_policy_is_armed_on_the_batch() {
    // A4: explicit, not merely correct. The batch records what was armed
    // after the engine accepted it, so this is the application, not the
    // token sitting in a const the test also names.
    let path = tmp("armed");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("begin");
    assert!(matches!(batch.durability(), Durability::Immediate));
    assert!(matches!(DURABILITY, Durability::Immediate));
    assert_eq!(batch.two_phase_commit(), TWO_PHASE_COMMIT);
    assert_eq!(CACHE_SIZE, 1024 * 1024 * 1024);
    batch.abort().expect("abort");
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
        batch.open_table(SLASH_LOG),
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
