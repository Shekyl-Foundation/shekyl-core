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
use crate::codec::SettlementEpochBlocks;
use crate::family_set::FamilySet;

pub(super) const PROBE: TableDefinition<&str, u64> = TableDefinition::new("__e1_probe");

/// The settlement-epoch schedule every test store is pinned to. A test
/// fixture, not a default: the crate has no default schedule (the value is
/// the caller's), and the mismatch tests in `header_tests.rs` open under
/// `OTHER_EPOCH` to watch the refusal fire.
pub(super) const EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(10_000) {
    Some(e) => e,
    None => unreachable!(),
};

/// A schedule that is not [`EPOCH`].
pub(super) const OTHER_EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(50) {
    Some(e) => e,
    None => unreachable!(),
};

/// The production session pair: `EPOCH` with `D_max`. The retention fits,
/// which is the pair [`ChainStore::open_read_only`](super::ChainStore::open_read_only)
/// is given when a test is not exercising a shortened epoch.
pub(super) fn production_horizons() -> Horizons {
    Horizons::production(EPOCH).expect("SEB > D_MAX")
}

/// A caller's error type over the store's: what `write`'s `E` is for. A
/// closure that wants to abort on purpose returns `Abort`; there is no
/// abort verb because `Err` *is* the abort.
#[derive(Debug, PartialEq)]
pub(super) enum TestErr {
    Abort,
    Store(String),
}

impl From<StoreError> for TestErr {
    fn from(e: StoreError) -> Self {
        Self::Store(e.to_string())
    }
}

/// Abort the batch on purpose.
pub(super) fn abort<T>(_: &mut WriteBatch<'_, '_>) -> Result<T, TestErr> {
    Err(TestErr::Abort)
}

/// The row an insert-once open of the probe table names.
///
/// The probe table is a test fixture, not a schema table, so it has no
/// register row of its own; `open_insert_table` needs *a* `StoreInvariant`
/// to bind and SI-7's is the only variant built. What the tests below
/// assert is that the row the handle was opened with is the row that
/// comes back — not which row it is. S-CHAIN-W's sites bind SI-1 / SI-3
/// / SI-4 at open. IT DOES NOT COVER: uniqueness *being* SI-7.
pub(super) const PROBE_ROW: StoreInvariant = StoreInvariant::CellCorrupt {
    key: "__e1_probe",
    fault: CellFault::Absent,
};

/// Write one probe row `k = v` inside `batch`. A probe row is a fixture
/// register, so this is an `upsert`; the insert-once handle has its own
/// tests.
pub(super) fn probe_row(batch: &WriteBatch<'_, '_>, k: &str, v: u64) -> Result<(), StoreError> {
    batch.open_upsert_table(PROBE)?.upsert(k, &v).map(drop)
}

/// Read probe row `k` from a fresh snapshot: `None` if the table or the
/// row is absent.
pub(super) fn probe_val(store: &ChainStore, k: &str) -> Option<u64> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(PROBE).ok()?;
    table.get(k).expect("get").map(|g| g.value())
}

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
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(store.apply_policy(), ApplyPolicy::Full);
    assert!(store.provenance().is_parity_evidence());
    cleanup(&path);
}

#[test]
fn an_empty_stub_is_refused_at_open() {
    let path = tmp("empty-stub");
    assert!(matches!(
        ChainStore::with_apply_policy(&path, ApplyPolicy::StubbedFamilies(FamilySet::EMPTY), EPOCH),
        Err(StoreError::Cannot(StoreCannot::EmptyApplyStub))
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
    // leaves this green. Application is proven only by `write` arming its
    // batch and passing the `?` on set_durability -- a weaker claim, stated
    // as such.
    assert!(matches!(DURABILITY, Durability::Immediate));
    assert_eq!(CACHE_SIZE, 1024 * 1024 * 1024);
    // TWO_PHASE_COMMIT is pinned at compile time: a constant assertion is the
    // honest form for a constant, and clippy's assertions_on_constants says so.
    const _: () = assert!(
        TWO_PHASE_COMMIT,
        "two-phase commit must stay on: redb's default is off"
    );
    let path = tmp("armed");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // `write` arms the transaction before it runs the closure, so reaching
    // the closure at all is the engine accepting the declared policy.
    assert_eq!(store.write(abort::<()>), Err(TestErr::Abort));
    cleanup(&path);
}

#[test]
fn ok_from_the_closure_commits_and_the_value_comes_back() {
    let path = tmp("commit");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let answer = store
        .write(|batch| -> Result<u64, StoreError> {
            probe_row(batch, "k", 1)?;
            Ok(42)
        })
        .expect("commit");
    assert_eq!(answer, 42);
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(PROBE).expect("open read");
    assert_eq!(table.get("k").expect("get").expect("present").value(), 1);
    cleanup(&path);
}

#[test]
fn err_from_the_closure_aborts_and_nothing_lands() {
    // There is no abort verb: `Err` is the abort, and it is the caller's
    // error that comes back, not a store error wrapping it.
    let path = tmp("abort");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let result = store.write(|batch| -> Result<(), TestErr> {
        probe_row(batch, "k", 1)?;
        Err(TestErr::Abort)
    });
    assert_eq!(result, Err(TestErr::Abort));
    assert!(
        store.begin_read().expect("read").open_table(PROBE).is_err(),
        "an aborted create must not leave the probe table"
    );
    // The write slot was released on the way out.
    store
        .write(|_| Ok::<(), StoreError>(()))
        .expect("a later write proceeds");
    cleanup(&path);
}

#[test]
fn a_store_failure_converts_into_the_callers_error_type() {
    // `E: From<StoreError>`: the store's own refusals arrive in the
    // caller's type, so a connect path can carry its verdict type and the
    // store's failures in one enum without the store knowing the verdict.
    let path = tmp("convert");
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    let ro = ChainStore::open_read_only(&path, production_horizons()).expect("ro");
    assert_eq!(
        ro.write(|_| Ok::<(), TestErr>(())),
        Err(TestErr::Store(
            StoreError::Cannot(StoreCannot::ReadOnly).to_string()
        ))
    );
    cleanup(&path);
}

// ------------------------------------------- two verbs, one poison

#[test]
fn insert_lands_on_a_fresh_key_and_names_the_row_on_a_present_one() {
    let path = tmp("insert");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| batch.open_insert_table(PROBE, PROBE_ROW)?.insert("k", &1))
        .expect("a fresh key lands");
    assert_eq!(probe_val(&store, "k"), Some(1));

    // The closure catches the refusal and carries on as if nothing
    // happened: reads the key, writes another via the overwrite handle,
    // returns Ok. None of that rescues the batch — poison is what
    // `complete` consults.
    let result = store.write(|batch| -> Result<(), StoreError> {
        let mut table = batch.open_insert_table(PROBE, PROBE_ROW)?;
        assert!(
            matches!(
                table.insert("k", &2),
                Err(StoreError::InvariantViolated(row)) if row == PROBE_ROW
            ),
            "the handle's row is the row that comes back"
        );
        assert_eq!(
            table.get("k")?.expect("present").value(),
            1,
            "a refused insert leaves the table untouched"
        );
        drop(table);
        batch.open_upsert_table(PROBE)?.upsert("other", &9)?;
        Ok(())
    });
    assert!(
        matches!(result, Err(StoreError::InvariantViolated(row)) if row == PROBE_ROW),
        "a swallowed violation still refuses the commit, with the same row: {result:?}"
    );
    assert_eq!(
        probe_val(&store, "k"),
        Some(1),
        "nothing the batch wrote landed"
    );
    assert_eq!(probe_val(&store, "other"), None);
    // The write slot was released on the way out.
    store
        .write(|_| Ok::<(), StoreError>(()))
        .expect("a later write proceeds");
    cleanup(&path);
}

#[test]
fn a_propagated_violation_reaches_the_caller_in_the_callers_type() {
    // The ordinary path: the site does not swallow, `?` carries the
    // violation out through `E: From<StoreError>`, and the batch aborts.
    let path = tmp("insert-propagated");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| batch.open_insert_table(PROBE, PROBE_ROW)?.insert("k", &1))
        .expect("seed");
    let result = store.write(|batch| -> Result<(), TestErr> {
        batch.open_insert_table(PROBE, PROBE_ROW)?.insert("k", &2)?;
        unreachable!("the insert was refused");
    });
    assert_eq!(result, Err(TestErr::Store(PROBE_ROW.to_string())));
    assert_eq!(probe_val(&store, "k"), Some(1));
    cleanup(&path);
}

#[test]
fn a_swallowed_violation_outvotes_a_different_err() {
    // THIS BITES AGAINST: `complete` returning the closure's `Err` when
    // poison is armed — that is converting the Halt into something else
    // (C2-R8 Q2). IT DOES NOT COVER: the Ok-and-swallowed path
    // (`insert_lands_on_a_fresh_key_and_names_the_row_on_a_present_one`).
    let path = tmp("insert-err-poison");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| batch.open_insert_table(PROBE, PROBE_ROW)?.insert("k", &1))
        .expect("seed");
    let result = store.write(|batch| -> Result<(), TestErr> {
        assert!(
            matches!(
                batch.open_insert_table(PROBE, PROBE_ROW)?.insert("k", &2),
                Err(StoreError::InvariantViolated(row)) if row == PROBE_ROW
            ),
            "the handle's row is the row that comes back"
        );
        Err(TestErr::Abort)
    });
    assert_eq!(result, Err(TestErr::Store(PROBE_ROW.to_string())));
    assert_eq!(probe_val(&store, "k"), Some(1));
    cleanup(&path);
}

#[test]
fn upsert_replaces_and_returns_the_displaced_value() {
    let path = tmp("upsert");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| -> Result<(), StoreError> {
            let mut table = batch.open_upsert_table(PROBE)?;
            assert!(
                table.upsert("k", &1)?.is_none(),
                "first write displaces nothing"
            );
            assert_eq!(
                table.upsert("k", &2)?.expect("displaced").value(),
                1,
                "the pre-image comes back"
            );
            Ok(())
        })
        .expect("commit");
    assert_eq!(probe_val(&store, "k"), Some(2));
    cleanup(&path);
}

#[test]
fn a_second_live_batch_is_a_typed_error_not_a_deadlock() {
    let path = tmp("in-progress");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|_| -> Result<(), StoreError> {
            assert!(matches!(
                store.write(|_| Ok::<(), StoreError>(())),
                Err(StoreError::Cannot(StoreCannot::WriteInProgress))
            ));
            Ok(())
        })
        .expect("outer commits");
    store
        .write(|_| Ok::<(), StoreError>(()))
        .expect("after the outer batch is gone");
    cleanup(&path);
}

#[test]
fn the_brand_unifies_within_one_batch_only() {
    // The positive half of the brand: a helper that demands two handles of
    // the same batch accepts the one batch twice. The negative half — two
    // `write` calls' batches refused at compile time — is the
    // `compile_fail` doctest on `ChainStore::write`.
    fn same_batch<'id>(_: &WriteBatch<'_, 'id>, _: &WriteBatch<'_, 'id>) {}
    let path = tmp("brand");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| -> Result<(), StoreError> {
            same_batch(batch, batch);
            Ok(())
        })
        .expect("commit");
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
    let store = std::sync::Arc::new(ChainStore::create(&path, EPOCH).expect("create"));
    let asker = store
        .write(|_| -> Result<std::thread::JoinHandle<()>, StoreError> {
            let (tx, rx) = std::sync::mpsc::channel();
            let asker = {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    let verdict = match store.write(|_| Ok::<(), StoreError>(())) {
                        Err(StoreError::Cannot(StoreCannot::WriteInProgress)) => Ok(()),
                        Err(e) => Err(format!("wrong error: {e}")),
                        Ok(()) => Err("second batch was GRANTED while one was live".to_owned()),
                    };
                    tx.send(verdict).expect("main is waiting");
                })
            };
            let verdict = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("asker was QUEUED behind the holder instead of refused");
            // The answer arrived while this batch is still live: refused,
            // not parked.
            verdict.expect("refused promptly");
            Ok(asker)
        })
        .expect("holder commits");
    asker.join().expect("asker thread");
    cleanup(&path);
}

#[test]
fn a_read_snapshot_is_allowed_while_a_write_is_live() {
    let path = tmp("read-during-write");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|_| -> Result<(), StoreError> {
            store.begin_read().expect("read during write");
            Ok(())
        })
        .expect("commit");
    cleanup(&path);
}

#[test]
fn a_stubbed_family_cannot_open_its_table_on_a_write() {
    let path = tmp("stub-open");
    const STUB: &[ArchivalFamily] = &[ArchivalFamily::SlashLog];
    let store =
        ChainStore::with_apply_policy(&path, ApplyPolicy::stubbed(STUB).expect("stub"), EPOCH)
            .expect("create");
    store
        .write(|batch| -> Result<(), StoreError> {
            assert!(matches!(
                batch.open_upsert_table(crate::schema::ARCHIVAL_SLASH_LOG),
                Err(StoreError::Cannot(StoreCannot::FamilyStubbed(
                    ArchivalFamily::SlashLog
                )))
            ));
            probe_row(batch, "k", 1).expect("non-archival still opens");
            Ok(())
        })
        .expect("commit");
    cleanup(&path);
}

#[test]
fn the_properties_table_has_no_raw_write_handle() {
    // A raw handle would let a string overwrite `schema_version` or clear
    // the provenance record, which is exactly what the typed surface exists
    // to make unrepresentable. Reads stay raw-capable: nothing can be
    // damaged by looking.
    let path = tmp("properties-typed");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    assert_eq!(
        store.write(|batch| {
            assert!(matches!(
                batch.open_upsert_table(crate::schema::PROPERTIES),
                Err(StoreError::Cannot(StoreCannot::PropertiesAreTyped))
            ));
            assert!(matches!(
                batch.open_insert_table(crate::schema::PROPERTIES, PROBE_ROW),
                Err(StoreError::Cannot(StoreCannot::PropertiesAreTyped))
            ));
            // Nor by redefining it under another type: the refusal is by
            // name. (This leg was a multimap impostor until S-OUT-KI's layout
            // commit retired the multimap opener; a keyed impostor proves the
            // same thing against the opener that survives.)
            const IMPOSTOR: redb::TableDefinition<&str, &[u8]> =
                redb::TableDefinition::new("properties");
            assert!(matches!(
                batch.open_insert_table(IMPOSTOR, PROBE_ROW),
                Err(StoreError::Cannot(StoreCannot::PropertiesAreTyped))
            ));
            abort::<()>(batch)
        }),
        Err(TestErr::Abort)
    );
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
        let store = ChainStore::create(&path, EPOCH).expect("create");
        store.write(|_| Ok::<(), StoreError>(())).expect("commit");
    }
    let store = ChainStore::open_read_only(&path, production_horizons()).expect("open ro");
    assert!(store.is_read_only());
    assert!(matches!(
        store.write(|_| Ok::<(), StoreError>(())),
        Err(StoreError::Cannot(StoreCannot::ReadOnly))
    ));
    store.begin_read().expect("read on a read-only store");
    cleanup(&path);
}

// ------------------------------------------------ one file, one writer
//
// `provenance()` mirrors the file's `apply_policy` cell and claims the
// mirror is exact. Across handles the claim rests on redb's file lock:
// exclusive for a writable handle, shared for a read-only one. `flock`
// locks are per open file description, so a second open in THIS process
// contends exactly as a second process would, which is what lets the
// property be tested here without spawning one. Inside one handle the
// mirror's only mutator, `Shared::publish`, takes its write lock itself and
// holds it across the engine commit and the assignment (`shared.rs`, tested
// there), so a commit path that assigns without the lock is not writable.
// THESE BITE AGAINST: a redb bump that drops or relaxes the flock, or an
// `open` path in this crate that stops going through redb's locked backend.

fn is_already_open(result: &Result<ChainStore, StoreError>) -> bool {
    matches!(
        result,
        Err(StoreError::Engine(EngineError::Open(
            redb::DatabaseError::DatabaseAlreadyOpen
        )))
    )
}

#[test]
fn a_second_writable_open_is_refused_while_a_writer_is_live() {
    let path = tmp("lock-w-w");
    let live = ChainStore::create(&path, EPOCH).expect("create");
    assert!(
        is_already_open(&ChainStore::create(&path, EPOCH)),
        "two writable handles on one file would let the provenance mirror go stale"
    );
    drop(live);
    ChainStore::create(&path, EPOCH).expect("reopen once the lock is released");
    cleanup(&path);
}

#[test]
fn a_read_only_open_is_refused_while_a_writer_is_live() {
    let path = tmp("lock-w-r");
    let live = ChainStore::create(&path, EPOCH).expect("create");
    assert!(is_already_open(&ChainStore::open_read_only(
        &path,
        production_horizons()
    )));
    drop(live);
    cleanup(&path);
}

#[test]
fn a_writable_open_is_refused_while_a_reader_is_live() {
    let path = tmp("lock-r-w");
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    let reader = ChainStore::open_read_only(&path, production_horizons()).expect("open ro");
    assert!(
        is_already_open(&ChainStore::create(&path, EPOCH)),
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
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    let first = ChainStore::open_read_only(&path, production_horizons()).expect("first ro");
    let second = ChainStore::open_read_only(&path, production_horizons())
        .expect("second ro alongside the first");
    assert_eq!(first.provenance(), second.provenance());
    drop((first, second));
    cleanup(&path);
}

#[test]
fn open_read_only_refuses_a_store_that_does_not_exist() {
    let path = tmp("absent");
    drop(std::fs::remove_file(&path));
    assert!(matches!(
        ChainStore::open_read_only(&path, production_horizons()),
        Err(StoreError::Engine(EngineError::Open(_)))
    ));
    assert!(!path.exists(), "a read-only open must not create the store");
}

#[test]
fn an_existing_file_that_is_not_a_store_is_refused_untouched() {
    // The reopen arm must never initialize: an empty file at the path --
    // left by another process, or the shape a path removed between
    // `create_new`'s AlreadyExists and the open would take under an
    // open-or-create -- is refused as-is. Were the arm `create`, redb would
    // turn it into a headerless database, `verify` would refuse that, and
    // the file would stay behind for every later open to refuse.
    let path = tmp("not-a-store");
    std::fs::write(&path, b"").expect("empty file");
    assert!(matches!(
        ChainStore::with_apply_policy(&path, ApplyPolicy::Full, EPOCH),
        Err(StoreError::Engine(EngineError::Open(_)))
    ));
    assert_eq!(
        std::fs::metadata(&path).expect("still present").len(),
        0,
        "the reopen arm initialized a file it did not create"
    );
    cleanup(&path);
}
