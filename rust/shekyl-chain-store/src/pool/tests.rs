// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file — DRS-E1 S-POOL commit 1 (`DRS_E1_SPOOL.md` §7): create,
//! open and recreate; every operation on the empty file; each refusal;
//! the enumeration; SI-16 named; the header's four refusals and its one
//! recreation.

use redb::{Durability, TableDefinition};
use shekyl_store_codec::{Blob, Raw};
use shekyl_types::{FcmpVerificationHash, NetZone, TxHash, UnixSeconds};
use shekyl_units::AtomicUnits;

use super::schema::{POOL_BLOB, POOL_HEADER, POOL_META};
use super::*;
use crate::codec::PropertyCellBytes;
use crate::store::{ErrorClass, StoreCannot};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shekyl-pool-store-{}-{}-{:?}.redb",
        name,
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&p));
    p
}

fn txid(n: u8) -> TxHash {
    TxHash::from_bytes([n; 32])
}

fn arrived_fluff() -> PoolRecord {
    PoolRecord {
        weight: 1,
        fee: AtomicUnits::from_raw(1),
        receive_time: UnixSeconds::from_raw(1),
        relay_state: RelayState::Arrived {
            zone: NetZone::Public,
            phase: ArrivedPhase::Fluff { last_relayed: None },
        },
        relayed: false,
        double_spend_seen: false,
        readiness: Readiness::default(),
        fcmp_cache: None,
    }
}

fn originated_held() -> PoolRecord {
    PoolRecord {
        relay_state: RelayState::Originated {
            phase: OriginatedPhase::Held { last_attempt: None },
            responsibility: Responsibility::Armed,
        },
        ..arrived_fluff()
    }
}

fn arrived_stem() -> PoolRecord {
    PoolRecord {
        relay_state: RelayState::Arrived {
            zone: NetZone::Public,
            phase: ArrivedPhase::Stem {
                next_attempt: UnixSeconds::from_raw(50),
            },
        },
        ..arrived_fluff()
    }
}

fn cannot(err: &StoreError) -> Option<PoolCannot> {
    match err {
        StoreError::Cannot(StoreCannot::Pool(c)) => Some(*c),
        _ => None,
    }
}

#[test]
fn durability_is_the_chain_files() {
    // `SPL-Q4`: one durability policy, per file. The pool takes the chain
    // file's constants; this pins that it did not pick a weaker one.
    assert!(matches!(DURABILITY, Durability::Immediate));
    const { assert!(TWO_PHASE_COMMIT) };
}

#[test]
fn create_then_open_then_every_read_on_the_empty_file() {
    let path = tmp("empty");
    let (store, how) = PoolStore::create(&path).unwrap();
    assert_eq!(how, PoolOpen::Created);
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.len().unwrap(), 0);
    assert!(snap.is_empty().unwrap());
    assert_eq!(snap.record(&txid(1)).unwrap(), None);
    assert_eq!(snap.blob(&txid(1)).unwrap(), None);
    assert_eq!(snap.entries().unwrap().count(), 0);
    drop(snap);
    drop(store);
    let (_store, how) = PoolStore::create(&path).unwrap();
    assert_eq!(how, PoolOpen::Opened);
    drop(std::fs::remove_file(&path));
}

#[test]
fn insert_update_remove_and_their_refusals() {
    let path = tmp("ops");
    let (store, _) = PoolStore::create(&path).unwrap();
    let h = txid(7);
    let rec = arrived_fluff();

    // P2 on a stranger.
    let err = store
        .write(|b| b.update(&h, &rec))
        .expect_err("update of an unheld entry");
    assert_eq!(cannot(&err), Some(PoolCannot::NotHeld));
    assert_eq!(err.class(), ErrorClass::Cannot);

    // P1 with an empty blob.
    let err = store
        .write(|b| b.insert(h, &rec, &[]))
        .expect_err("empty blob");
    assert_eq!(cannot(&err), Some(PoolCannot::EmptyBlob));

    // P1, then P1 again.
    store.write(|b| b.insert(h, &rec, b"tx-bytes")).unwrap();
    let err = store
        .write(|b| b.insert(h, &rec, b"tx-bytes"))
        .expect_err("second insert");
    assert_eq!(cannot(&err), Some(PoolCannot::AlreadyHeld));

    // Reads see it.
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.len().unwrap(), 1);
    assert_eq!(snap.record(&h).unwrap(), Some(rec));
    assert_eq!(snap.blob(&h).unwrap().as_deref(), Some(&b"tx-bytes"[..]));
    drop(snap);

    // P2 changes the record, keeps the blob and the origin.
    let relayed = PoolRecord {
        relayed: true,
        relay_state: RelayState::Arrived {
            zone: NetZone::Public,
            phase: ArrivedPhase::Fluff {
                last_relayed: Some(UnixSeconds::from_raw(9)),
            },
        },
        ..rec
    };
    store.write(|b| b.update(&h, &relayed)).unwrap();
    let snap = store.begin_read().unwrap();
    assert_eq!(snap.record(&h).unwrap(), Some(relayed));
    assert_eq!(snap.blob(&h).unwrap().as_deref(), Some(&b"tx-bytes"[..]));
    drop(snap);

    // P2 that changes the origin: provenance is permanent (§92.4).
    let err = store
        .write(|b| b.update(&h, &originated_held()))
        .expect_err("origin change");
    assert_eq!(cannot(&err), Some(PoolCannot::OriginChanged));

    // P3 twice: idempotent.
    store.write(|b| b.remove(&h)).unwrap();
    store.write(|b| b.remove(&h)).unwrap();
    assert_eq!(store.begin_read().unwrap().len().unwrap(), 0);
    drop(std::fs::remove_file(&path));
}

/// The walk is enforced at the write. Same phase may change its clock; a
/// backwards step is [`PoolCannot::PhaseNotForward`]; a forward step lands.
/// An originated entry cannot be constructed as fluff — that phase is not
/// in [`OriginatedPhase`].
#[test]
fn the_walk_is_enforced_at_the_write_and_a_null_cache_is_refused() {
    let path = tmp("walk");
    let (store, _) = PoolStore::create(&path).unwrap();
    let h = txid(3);
    store
        .write(|b| b.insert(h, &arrived_fluff(), b"x"))
        .unwrap();

    let err = store
        .write(|b| b.update(&h, &arrived_stem()))
        .expect_err("fluff does not walk back to stem");
    assert_eq!(cannot(&err), Some(PoolCannot::PhaseNotForward));
    assert_eq!(
        store.begin_read().unwrap().record(&h).unwrap(),
        Some(arrived_fluff())
    );

    let stemmed = txid(4);
    store
        .write(|b| b.insert(stemmed, &arrived_stem(), b"s"))
        .unwrap();
    let fluffed = PoolRecord {
        relay_state: RelayState::Arrived {
            zone: NetZone::Public,
            phase: ArrivedPhase::Fluff {
                last_relayed: Some(UnixSeconds::from_raw(9)),
            },
        },
        relayed: true,
        ..arrived_stem()
    };
    store.write(|b| b.update(&stemmed, &fluffed)).unwrap();
    assert_eq!(
        store.begin_read().unwrap().record(&stemmed).unwrap(),
        Some(fluffed)
    );

    let local = txid(5);
    store
        .write(|b| b.insert(local, &originated_held(), b"l"))
        .unwrap();
    let yielded = PoolRecord {
        relay_state: RelayState::Originated {
            phase: OriginatedPhase::Block {
                last_relayed: Some(UnixSeconds::from_raw(11)),
            },
            responsibility: Responsibility::Disarmed,
        },
        ..originated_held()
    };
    store.write(|b| b.update(&local, &yielded)).unwrap();
    let stored = store.begin_read().unwrap().record(&local).unwrap().unwrap();
    assert_eq!(stored.origin(), Origin::Originated);
    assert_eq!(stored, yielded);

    let mut null_cache = arrived_fluff();
    null_cache.fcmp_cache = Some(FcmpVerificationHash::from_bytes([0; 32]));
    let err = store
        .write(|b| b.insert(txid(6), &null_cache, b"n"))
        .expect_err("null verification hash");
    assert_eq!(cannot(&err), Some(PoolCannot::NullFcmpCache));
    drop(std::fs::remove_file(&path));
}

#[test]
fn an_err_from_the_closure_aborts_the_whole_batch() {
    let path = tmp("abort");
    let (store, _) = PoolStore::create(&path).unwrap();
    let outcome: Result<(), StoreError> = store.write(|b| {
        b.insert(txid(1), &arrived_fluff(), b"a")?;
        b.insert(txid(2), &arrived_fluff(), b"b")?;
        Err(PoolCannot::NotHeld.into())
    });
    assert!(outcome.is_err());
    assert_eq!(
        store.begin_read().unwrap().len().unwrap(),
        0,
        "nothing landed"
    );
    drop(std::fs::remove_file(&path));
}

#[test]
fn entries_enumerate_in_key_order_with_blobs_on_demand() {
    let path = tmp("entries");
    let (store, _) = PoolStore::create(&path).unwrap();
    let originated = originated_held();
    store
        .write(|b| {
            b.insert(txid(9), &arrived_fluff(), b"nine")?;
            b.insert(txid(2), &originated, b"two")?;
            b.insert(txid(5), &arrived_fluff(), b"five")
        })
        .unwrap();
    let snap = store.begin_read().unwrap();
    let entries: Vec<PoolEntry> = snap.entries().unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        entries.iter().map(|e| e.txid).collect::<Vec<_>>(),
        vec![txid(2), txid(5), txid(9)],
        "natural key order (SPL-8)"
    );
    assert_eq!(entries[0].record, originated);
    assert_eq!(entries[0].blob(&snap).unwrap(), b"two");
    assert_eq!(entries[2].blob(&snap).unwrap(), b"nine");
    // The class filter is the consumer's fold.
    let public = entries
        .iter()
        .filter(|e| e.record.matches(shekyl_types::RelayCategory::Broadcasted))
        .count();
    assert_eq!(public, 2);
    assert_eq!(snap.len().unwrap(), 3);
    drop(std::fs::remove_file(&path));
}

/// SI-16, both directions, named by the read that found it.
#[test]
fn an_unpaired_entry_is_si16() {
    let path = tmp("si16");
    let (store, _) = PoolStore::create(&path).unwrap();
    store
        .write(|b| b.insert(txid(1), &arrived_fluff(), b"one"))
        .unwrap();
    // Plant a meta row with no blob, and a blob with no meta, past the store.
    {
        let txn = store.db.begin_write().unwrap();
        {
            let mut meta = txn.open_table(POOL_META).unwrap();
            meta.insert(txid(2).to_bytes(), arrived_fluff().encoded().as_encoded())
                .unwrap();
            let mut blobs = txn.open_table(POOL_BLOB).unwrap();
            blobs
                .insert(txid(3).to_bytes(), Raw::<PoolTxBytes>::new(b"orphan"))
                .unwrap();
        }
        txn.commit().unwrap();
    }
    let snap = store.begin_read().unwrap();
    let entry = snap
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.txid == txid(2))
        .unwrap();
    match entry.blob(&snap) {
        Err(StoreError::InvariantViolated(StoreInvariant::PoolEntryUnpaired { txid: t })) => {
            assert_eq!(t, txid(2));
        }
        other => panic!("expected SI-16, got {other:?}"),
    }
    // The blob read itself is the other direction: a blob with no meta row
    // is SI-16, not `Some` bytes for an entry `len` does not count.
    match snap.blob(&txid(3)) {
        Err(StoreError::InvariantViolated(StoreInvariant::PoolEntryUnpaired { txid: t })) => {
            assert_eq!(t, txid(3));
        }
        other => panic!("expected SI-16 on the orphan blob, got {other:?}"),
    }
    match snap.blob(&txid(2)) {
        Err(StoreError::InvariantViolated(StoreInvariant::PoolEntryUnpaired { txid: t })) => {
            assert_eq!(t, txid(2));
        }
        other => panic!("expected SI-16 on the meta-only row, got {other:?}"),
    }
    assert_eq!(snap.record(&txid(3)).unwrap(), None);
    drop(snap);
    // Inserting over the half-entry names it too.
    let err = store
        .write(|b| b.insert(txid(3), &arrived_fluff(), b"three"))
        .expect_err("blob without meta");
    assert!(matches!(
        err,
        StoreError::InvariantViolated(StoreInvariant::PoolEntryUnpaired { .. })
    ));
    assert_eq!(err.class(), ErrorClass::Invariant);
    // `remove` clears either half, idempotently.
    store.write(|b| b.remove(&txid(2))).unwrap();
    store.write(|b| b.remove(&txid(3))).unwrap();
    store
        .write(|b| b.insert(txid(3), &arrived_fluff(), b"three"))
        .unwrap();
    drop(std::fs::remove_file(&path));
}

#[test]
fn an_undecodable_meta_row_is_si7() {
    let path = tmp("si7");
    let (store, _) = PoolStore::create(&path).unwrap();
    {
        let txn = store.db.begin_write().unwrap();
        {
            let mut meta = txn.open_table(POOL_META).unwrap();
            // A relay-state tag of 0xff: refused, never `Fluff` (SPL-14).
            let mut bytes = arrived_fluff().encode();
            bytes[24] = 0xff;
            meta.insert(
                txid(4).to_bytes(),
                <shekyl_store_codec::Coded<PoolRecord> as redb::Value>::from_bytes(&bytes),
            )
            .unwrap();
        }
        txn.commit().unwrap();
    }
    let snap = store.begin_read().unwrap();
    match snap.record(&txid(4)) {
        Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt { key, .. })) => {
            assert_eq!(key, "pool_meta");
        }
        other => panic!("expected SI-7, got {other:?}"),
    }
    drop(std::fs::remove_file(&path));
}

/// `SPL-Q8`: a sealed pool file at another version is recreated; a file
/// that is not this store's is refused, never deleted.
#[test]
fn another_version_recreates_and_everything_else_is_refused() {
    // (1) Another version: recreated, the old contents gone.
    let path = tmp("recreate");
    let (store, _) = PoolStore::create(&path).unwrap();
    store
        .write(|b| b.insert(txid(1), &arrived_fluff(), b"one"))
        .unwrap();
    {
        let txn = store.db.begin_write().unwrap();
        {
            let mut header = txn.open_table(POOL_HEADER).unwrap();
            let other = crate::codec::SchemaVersion::new(SCHEMA_VERSION.get() + 1);
            header
                .insert(
                    POOL_VERSION_KEY,
                    Raw::<PropertyCellBytes>::new(&other.encode()),
                )
                .unwrap();
        }
        txn.commit().unwrap();
    }
    drop(store);
    let (store, how) = PoolStore::create(&path).unwrap();
    assert_eq!(
        how,
        PoolOpen::Recreated {
            from: crate::codec::SchemaVersion::new(SCHEMA_VERSION.get() + 1)
        }
    );
    assert_eq!(store.begin_read().unwrap().len().unwrap(), 0);
    drop(store);
    drop(std::fs::remove_file(&path));

    // (2) A sealed file whose version cell does not decode: refused, kept.
    let path = tmp("badcell");
    let (store, _) = PoolStore::create(&path).unwrap();
    {
        let txn = store.db.begin_write().unwrap();
        {
            let mut header = txn.open_table(POOL_HEADER).unwrap();
            header
                .insert(POOL_VERSION_KEY, Raw::<PropertyCellBytes>::new(b"\x01\x02"))
                .unwrap();
        }
        txn.commit().unwrap();
    }
    drop(store);
    let before = std::fs::metadata(&path).unwrap().len();
    let err = PoolStore::create(&path).expect_err("undecodable header");
    assert!(matches!(
        err,
        StoreError::Cannot(StoreCannot::PoolFileForeign)
    ));
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        before,
        "not deleted"
    );
    drop(std::fs::remove_file(&path));

    // (3) A redb file with no pool header at all: refused, kept.
    let path = tmp("noheader");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            const OTHER: TableDefinition<u64, Blob<PropertyCellBytes>> =
                TableDefinition::new("something_else");
            txn.open_table(OTHER).unwrap();
        }
        txn.commit().unwrap();
    }
    let err = PoolStore::create(&path).expect_err("no header");
    assert!(matches!(
        err,
        StoreError::Cannot(StoreCannot::PoolFileForeign)
    ));
    assert!(path.exists(), "not deleted");
    drop(std::fs::remove_file(&path));

    // (3b) A sealed file at the current version whose table set is not the
    // seal's — one table deleted, one re-typed: refused, kept (Copilot,
    // PR #851: without the check these opened as `Opened` and failed at the
    // first op as a bare engine error).
    let deleted = |txn: &redb::WriteTransaction| {
        txn.delete_table(POOL_BLOB).unwrap();
    };
    let retyped = |txn: &redb::WriteTransaction| {
        txn.delete_table(POOL_META).unwrap();
        const FOREIGN: TableDefinition<u64, Blob<PropertyCellBytes>> =
            TableDefinition::new("pool_meta");
        txn.open_table(FOREIGN).unwrap();
    };
    type Tamper<'a> = &'a dyn Fn(&redb::WriteTransaction);
    let tampers: [(&str, Tamper<'_>); 2] = [("deleted", &deleted), ("retyped", &retyped)];
    for (label, tamper) in tampers {
        let path = tmp(&format!("tampered-{label}"));
        let (store, _) = PoolStore::create(&path).unwrap();
        {
            let txn = store.db.begin_write().unwrap();
            tamper(&txn);
            txn.commit().unwrap();
        }
        drop(store);
        let before = std::fs::metadata(&path).unwrap().len();
        let err = PoolStore::create(&path).expect_err("tampered table set");
        assert!(
            matches!(err, StoreError::Cannot(StoreCannot::PoolFileForeign)),
            "{label}: {err:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            before,
            "{label}: not deleted"
        );
        drop(std::fs::remove_file(&path));
    }

    // (4) Not a redb database at all: refused, kept, byte for byte.
    let path = tmp("notredb");
    std::fs::write(&path, b"this is not a redb file, and it is somebody's").unwrap();
    let err = PoolStore::create(&path).expect_err("not redb");
    assert!(
        matches!(err, StoreError::Cannot(StoreCannot::PoolFileForeign)),
        "{err:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"this is not a redb file, and it is somebody's"
    );
    drop(std::fs::remove_file(&path));
}
