// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Header and provenance tests (DRS-E1 increment 2): the schema-version
//! seal and its refusals, the persisted provenance record, and the typed
//! `properties` cell surface.
//!
//! Corruption cases write through a **raw** `redb::Database` on the same
//! path — the "modified by something other than this crate" scenario the
//! `CellCorrupt` docs describe — because the store's own surface has no
//! way to damage its header, which is the point.

use shekyl_types::BlockCount;
use shekyl_units::AtomicUnits;

use super::store_tests::{cleanup, probe_row, tmp, TestErr, EPOCH, OTHER_EPOCH, PROBE};
use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{
    ApplyPolicyCell, Canonical, ProbeCell, PropertyCell, PropertyCellBytes, Raw, SchemaVersion,
    SchemaVersionCell, TotalBurnedCell, SCHEMA_VERSION,
};
use crate::family_set::FamilySet;
use crate::schema::PROPERTIES;

const SLASH: &[ArchivalFamily] = &[ArchivalFamily::SlashLog];
const BOND: &[ArchivalFamily] = &[ArchivalFamily::Bond];

fn stubbed(families: &[ArchivalFamily]) -> ApplyPolicy {
    ApplyPolicy::stubbed(families).expect("non-empty")
}

/// Create a store, commit one probe row, drop the handle.
fn seeded(path: &std::path::Path, policy: ApplyPolicy) {
    let store = ChainStore::with_apply_policy(path, policy, EPOCH).expect("create");
    store
        .write(|batch| probe_row(batch, "k", 1))
        .expect("commit");
}

/// Commit an empty batch on `store`; the provenance after it.
fn commit_empty(store: &ChainStore) -> Provenance {
    store.write(|_| Ok::<(), StoreError>(())).expect("commit");
    store.provenance()
}

/// Write raw bytes to a `properties` cell, bypassing the store entirely.
fn raw_put(path: &std::path::Path, key: &str, value: Option<&[u8]>) {
    let db = redb::Database::open(path).expect("raw open");
    let txn = db.begin_write().expect("raw write");
    {
        let mut t = txn.open_table(PROPERTIES).expect("raw properties");
        match value {
            Some(v) => drop(
                t.insert(key, Raw::<PropertyCellBytes>::new(v))
                    .expect("raw insert"),
            ),
            None => drop(t.remove(key).expect("raw remove")),
        }
    }
    txn.commit().expect("raw commit");
}

/// Read raw bytes from a `properties` cell, bypassing the store. `None` if
/// the cell — or the whole table — is absent. redb admits one handle per
/// file per process, so callers drop their `ChainStore` first.
fn raw_get(path: &std::path::Path, key: &str) -> Option<Vec<u8>> {
    let db = redb::Database::open(path).expect("raw open");
    let txn = db.begin_read().expect("raw read");
    let t = match txn.open_table(PROPERTIES) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return None,
        Err(e) => panic!("raw properties: {e}"),
    };
    t.get(key)
        .expect("raw get")
        .map(|g| g.value().bytes().to_vec())
}

// ---------------------------------------------------------------- seal

#[test]
fn a_fresh_store_is_sealed_in_its_first_transaction() {
    let path = tmp("seal");
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    // Sealed at create — before any batch — with the pinned key bytes and
    // the canonical encodings, readable by anything that speaks redb.
    assert_eq!(
        raw_get(&path, "schema_version").as_deref(),
        Some(SCHEMA_VERSION.encode().as_slice())
    );
    assert_eq!(
        raw_get(&path, "apply_policy").as_deref(),
        Some(FamilySet::EMPTY.encode().as_slice())
    );
    // The schedule pin, under the C++ store's key, as LE u64 (SCW-2).
    assert_eq!(
        raw_get(&path, "settlement_epoch_blocks").as_deref(),
        Some(10_000u64.to_le_bytes().as_slice())
    );
    cleanup(&path);
}

// ------------------------------------------------- settlement-epoch pin

#[test]
fn a_file_reopens_under_its_pinned_schedule_and_refuses_another() {
    let path = tmp("epoch-pin");
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    let same = ChainStore::create(&path, EPOCH).expect("same schedule reopens");
    assert_eq!(same.settlement_epoch_blocks(), EPOCH);
    drop(same);

    let want = StoreCannot::SettlementEpochMismatch {
        pinned: EPOCH,
        session: OTHER_EPOCH,
    };
    // A 50-block schedule cannot run the production retention (`D_max` ≥
    // 50), so the session names its own — the pin check is what this test
    // is about, and it fires after the horizons are admitted.
    let other_horizons = Horizons::new(OTHER_EPOCH, BlockCount::from_raw(10)).expect("inside");
    assert!(
        matches!(
            ChainStore::with_horizons(&path, ApplyPolicy::default(), other_horizons),
            Err(StoreError::Cannot(got)) if got == want
        ),
        "a writable open under another schedule is refused"
    );
    assert!(
        matches!(
            ChainStore::create(&path, OTHER_EPOCH),
            Err(StoreError::Cannot(
                StoreCannot::RetentionNotInsideEpoch { .. }
            ))
        ),
        "the production retention does not fit a 50-block schedule; that refusal comes first"
    );
    assert!(
        matches!(
            ChainStore::open_read_only(&path, OTHER_EPOCH),
            Err(StoreError::Cannot(got)) if got == want
        ),
        "a reader interprets epoch-derived rows too, so it is refused the same way"
    );
    // The refusal is a `Cannot`, and it names the remedy.
    let msg = StoreError::from(want).to_string();
    assert!(
        msg.contains("built with settlement epochs of 10000 blocks/epoch"),
        "{msg}"
    );
    assert!(msg.contains("50 blocks/epoch"), "{msg}");
    assert!(msg.contains("fresh data directory"), "{msg}");
    // Neither refusal rewrote the pin.
    assert_eq!(
        raw_get(&path, "settlement_epoch_blocks").as_deref(),
        Some(10_000u64.to_le_bytes().as_slice())
    );
    let ro = ChainStore::open_read_only(&path, EPOCH).expect("reader under the pinned schedule");
    assert_eq!(ro.settlement_epoch_blocks(), EPOCH);
    cleanup(&path);
}

#[test]
fn a_missing_zero_or_malformed_pin_is_corruption_not_unpinned() {
    // The C++ read `0`/absent as "unpinned" and pinned on first init. A file
    // this crate wrote is never unpinned, so each of those is SI-7.
    let path = tmp("epoch-corrupt");
    drop(ChainStore::create(&path, EPOCH).expect("create"));
    for (label, bytes) in [
        ("absent", None),
        ("zero", Some(&0u64.to_le_bytes()[..])),
        ("short", Some(&[1u8, 2][..])),
    ] {
        raw_put(&path, "settlement_epoch_blocks", bytes);
        for open in [
            ChainStore::create(&path, EPOCH).err(),
            ChainStore::open_read_only(&path, EPOCH).err(),
        ] {
            let e = open.unwrap_or_else(|| panic!("{label}: opened a store with a bad pin"));
            assert!(
                matches!(
                    e,
                    StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                        key: "settlement_epoch_blocks",
                        ..
                    })
                ),
                "{label}: {e}"
            );
            assert_eq!(e.class(), ErrorClass::Invariant, "{label}");
        }
    }
    cleanup(&path);
}

#[test]
fn total_burned_is_a_writable_chain_state_cell() {
    let path = tmp("total-burned");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| -> Result<(), StoreError> {
            assert_eq!(batch.get_property::<TotalBurnedCell>()?, None);
            batch.upsert_property::<TotalBurnedCell>(&AtomicUnits::from_raw(5))?;
            // The connect-side fold: checked, never saturating (SI-8 is the
            // belt `connect` binds; this is the cell it folds into).
            let next = batch
                .get_property::<TotalBurnedCell>()?
                .unwrap_or(AtomicUnits::ZERO)
                .checked_add(AtomicUnits::from_raw(7))
                .expect("no overflow in test");
            batch.upsert_property::<TotalBurnedCell>(&next)
        })
        .expect("commit");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.get_property::<TotalBurnedCell>().expect("get"),
        Some(AtomicUnits::from_raw(12))
    );
    drop(snap);
    drop(store);
    assert_eq!(
        raw_get(&path, "total_burned").as_deref(),
        Some(12u64.to_le_bytes().as_slice()),
        "the C++ key, LE u64"
    );
    cleanup(&path);
}

#[test]
fn a_fresh_store_created_under_a_stub_is_tainted_from_its_first_byte() {
    let path = tmp("seal-stubbed");
    let store = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("create");
    assert_eq!(store.provenance().stubbed(), FamilySet::of(SLASH));
    assert!(!store.provenance().is_parity_evidence());
    drop(store);
    assert_eq!(
        raw_get(&path, "apply_policy").as_deref(),
        Some(FamilySet::of(SLASH).encode().as_slice()),
        "persisted at seal, not first commit"
    );
    cleanup(&path);
}

// ------------------------------------------------------------ refusals

#[test]
fn a_different_version_is_refused_in_both_directions() {
    let path = tmp("version");
    seeded(&path, ApplyPolicy::Full);
    for other in [0_u64, SCHEMA_VERSION.get() + 1, u64::MAX] {
        raw_put(
            &path,
            "schema_version",
            Some(&SchemaVersion::new(other).encode()),
        );
        let found = SchemaVersion::new(other);
        assert!(
            matches!(
                ChainStore::create(&path, EPOCH),
                Err(StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found: f, expected }))
                    if f == found && expected == SCHEMA_VERSION
            ),
            "writable reopen at v{other}"
        );
        assert!(
            matches!(
                ChainStore::open_read_only(&path, EPOCH),
                Err(StoreError::Cannot(StoreCannot::SchemaVersionMismatch { found: f, .. })) if f == found
            ),
            "read-only reopen at v{other}"
        );
        // Refusal is a pure read: the file's cell is exactly as we left it.
        assert_eq!(
            raw_get(&path, "schema_version").as_deref(),
            Some(found.encode().as_slice()),
            "a refused open must not re-stamp the file"
        );
    }
    cleanup(&path);
}

#[test]
fn a_file_with_no_version_cell_is_refused_not_read_as_v1() {
    // §11.1(a): absent reads as refuse. Two shapes of absence.
    let path = tmp("absent-cell");
    seeded(&path, ApplyPolicy::Full);
    raw_put(&path, "schema_version", None);
    assert!(matches!(
        ChainStore::create(&path, EPOCH),
        Err(StoreError::Cannot(StoreCannot::SchemaVersionAbsent))
    ));
    assert!(matches!(
        ChainStore::open_read_only(&path, EPOCH),
        Err(StoreError::Cannot(StoreCannot::SchemaVersionAbsent))
    ));
    cleanup(&path);

    // A redb file nothing in this crate wrote: no properties table at all.
    let foreign = tmp("foreign");
    {
        let db = redb::Database::create(&foreign).expect("foreign create");
        let txn = db.begin_write().expect("w");
        txn.open_table(PROBE).expect("some other table");
        txn.commit().expect("c");
    }
    assert!(matches!(
        ChainStore::create(&foreign, EPOCH),
        Err(StoreError::Cannot(StoreCannot::SchemaVersionAbsent))
    ));
    assert!(matches!(
        ChainStore::open_read_only(&foreign, EPOCH),
        Err(StoreError::Cannot(StoreCannot::SchemaVersionAbsent))
    ));
    assert!(
        raw_get(&foreign, "schema_version").is_none(),
        "refusing must not seal a foreign file"
    );
    cleanup(&foreign);
}

#[test]
fn a_malformed_header_cell_is_corruption_not_a_version() {
    let path = tmp("corrupt");
    seeded(&path, ApplyPolicy::Full);

    // Wrong width on the version cell.
    raw_put(&path, "schema_version", Some(&[1, 0, 0]));
    assert!(matches!(
        ChainStore::create(&path, EPOCH),
        Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: "schema_version",
            fault: CellFault::Undecodable(crate::codec::CodecError::Length {
                codec: "schema_version",
                expected: 8,
                actual: 3,
            }),
        }))
    ));
    raw_put(&path, "schema_version", Some(&SCHEMA_VERSION.encode()));

    // Provenance missing entirely: the seal always writes it, so this is
    // a foreign edit, not "an older file".
    raw_put(&path, "apply_policy", None);
    assert!(matches!(
        ChainStore::open_read_only(&path, EPOCH),
        Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: "apply_policy",
            fault: CellFault::Absent,
        }))
    ));

    // Provenance with a bit that names no family.
    raw_put(&path, "apply_policy", Some(&[0, 0, 0, 0x80]));
    assert!(matches!(
        ChainStore::create(&path, EPOCH),
        Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: "apply_policy",
            fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
                codec: "family_set",
                ..
            }),
        }))
    ));
    cleanup(&path);
}

// ---------------------------------------------------------- provenance

#[test]
fn a_stubbed_commit_taints_the_file_and_a_full_session_cannot_clean_it() {
    let path = tmp("taint");
    seeded(&path, ApplyPolicy::Full);

    // The stubbed session: its commit widens the record and the handle's
    // view moves with it (the mirror is exact — `ChainStore::provenance`).
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("stubbed reopen");
    assert!(
        s.provenance().is_parity_evidence(),
        "not tainted until a commit"
    );
    let after = commit_empty(&s);
    assert_eq!(after.stubbed(), FamilySet::of(SLASH));
    drop(s);

    // A later Full session reads the file's history, not its own intent.
    let full = ChainStore::create(&path, EPOCH).expect("Full reopen");
    assert_eq!(full.apply_policy(), ApplyPolicy::Full);
    assert_eq!(full.provenance().stubbed(), FamilySet::of(SLASH));
    assert!(!full.provenance().is_parity_evidence());
    assert!(full
        .provenance()
        .artifact_stamp()
        .contains("NOT-PARITY-EVIDENCE"));
    // And committing under Full does not narrow it.
    let still = commit_empty(&full);
    assert_eq!(still.stubbed(), FamilySet::of(SLASH));
    drop(full);

    // The falsifier: a read-only handle reads the persisted policy.
    let ro = ChainStore::open_read_only(&path, EPOCH).expect("ro");
    assert_eq!(ro.provenance().stubbed(), FamilySet::of(SLASH));
    assert_eq!(
        ro.begin_read()
            .expect("read")
            .get_property::<ApplyPolicyCell>()
            .expect("cell"),
        Some(FamilySet::of(SLASH))
    );
    cleanup(&path);
}

#[test]
fn taint_is_a_union_across_sessions() {
    let path = tmp("taint-union");
    seeded(&path, stubbed(BOND));
    {
        let s = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("reopen");
        assert_eq!(s.provenance().stubbed(), FamilySet::of(BOND), "inherits");
        let after = commit_empty(&s);
        assert_eq!(
            after.stubbed(),
            FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog])
        );
    }
    let ro = ChainStore::open_read_only(&path, EPOCH).expect("ro");
    assert_eq!(
        ro.provenance().stubbed(),
        FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog])
    );
    assert_eq!(
        ro.provenance().artifact_stamp(),
        "apply-policy=STUBBED[archival_bond,archival_slash_log] NOT-PARITY-EVIDENCE"
    );
    cleanup(&path);
}

#[test]
fn an_aborted_stubbed_batch_leaves_no_taint() {
    // The taint is written inside the batch's transaction, so it goes
    // wherever the batch's rows go: nowhere, when the closure aborts.
    let path = tmp("taint-abort");
    seeded(&path, ApplyPolicy::Full);
    {
        let s = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("reopen");
        let result = s.write(|b| -> Result<(), TestErr> {
            probe_row(b, "x", 2)?;
            Err(TestErr::Abort)
        });
        assert_eq!(result, Err(TestErr::Abort));
        assert!(s.provenance().is_parity_evidence(), "abort");
    }
    assert!(ChainStore::open_read_only(&path, EPOCH)
        .expect("ro")
        .provenance()
        .is_parity_evidence());
    cleanup(&path);
}

#[test]
fn a_stubbed_commit_with_no_rows_still_taints() {
    // Conservative by design: the event is the commit under a stub, not the
    // row count. A sufficiency run that commits nothing was still a
    // sufficiency run, and the file's record errs toward "not evidence".
    let path = tmp("taint-empty");
    seeded(&path, ApplyPolicy::Full);
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("reopen");
    assert!(!commit_empty(&s).is_parity_evidence());
    cleanup(&path);
}

#[test]
fn the_taint_commits_atomically_with_the_rows() {
    // Both the probe row and the widened cell come from one commit, so a
    // snapshot sees both or neither. A snapshot begun before the commit
    // sees neither; one begun after sees both.
    let path = tmp("taint-atomic");
    seeded(&path, ApplyPolicy::Full);
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH), EPOCH).expect("reopen");
    let before = s.begin_read().expect("snapshot before");
    s.write(|b| probe_row(b, "row", 7)).expect("c");
    let after = s.begin_read().expect("snapshot after");

    assert_eq!(
        before.get_property::<ApplyPolicyCell>().expect("cell"),
        Some(FamilySet::EMPTY)
    );
    assert!(before
        .open_table(PROBE)
        .expect("probe")
        .get("row")
        .expect("get")
        .is_none());
    assert_eq!(
        after.get_property::<ApplyPolicyCell>().expect("cell"),
        Some(FamilySet::of(SLASH))
    );
    assert_eq!(
        after
            .open_table(PROBE)
            .expect("probe")
            .get("row")
            .expect("get")
            .expect("row")
            .value(),
        7
    );
    cleanup(&path);
}

// ------------------------------------------------------- typed cells
//
// `ProbeCell` is the crate's test-only chain-state cell, declared next to
// the sealed trait in `codec::property` because that is the only place a
// cell can be declared (the seal is the point). The real chain-state cells
// land with the surfaces that write them.

#[test]
fn a_chain_state_cell_round_trips_through_the_typed_surface() {
    let path = tmp("typed-cell");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    store
        .write(|batch| -> Result<(), StoreError> {
            assert_eq!(batch.get_property::<ProbeCell>()?, None);
            batch.upsert_property::<ProbeCell>(&0x0102_0304_0506_0708)?;
            assert_eq!(
                batch.get_property::<ProbeCell>()?,
                Some(0x0102_0304_0506_0708),
                "a batch sees its own write"
            );
            Ok(())
        })
        .expect("c");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.get_property::<ProbeCell>().expect("get"),
        Some(0x0102_0304_0506_0708)
    );
    // Header cells are readable through the same surface.
    assert_eq!(
        snap.get_property::<SchemaVersionCell>().expect("get"),
        Some(SCHEMA_VERSION)
    );
    drop(snap);
    drop(store);
    // Stored under the canonical encoding — the same bytes the digest folds.
    assert_eq!(
        raw_get(&path, ProbeCell::KEY).as_deref(),
        Some(0x0102_0304_0506_0708_u64.encode().as_slice())
    );
    cleanup(&path);
}

#[test]
fn a_corrupt_chain_state_cell_is_refused_on_read() {
    let path = tmp("typed-corrupt");
    seeded(&path, ApplyPolicy::Full);
    raw_put(&path, ProbeCell::KEY, Some(&[1, 2, 3]));
    let store = ChainStore::open_read_only(&path, EPOCH).expect("header is fine");
    assert!(matches!(
        store
            .begin_read()
            .expect("read")
            .get_property::<ProbeCell>(),
        Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: "__e1_probe_cell",
            fault: CellFault::Undecodable(_),
        }))
    ));
    cleanup(&path);
}

#[test]
fn a_corrupt_cell_read_through_a_batch_poisons_it() {
    // SI-7 seen through the batch, not produced by it: the closure reads
    // the bad cell, gets the violation, discards it, overwrites the cell
    // with something valid and returns Ok. The batch still does not land.
    let path = tmp("typed-corrupt-poison");
    seeded(&path, ApplyPolicy::Full);
    raw_put(&path, ProbeCell::KEY, Some(&[1, 2, 3]));
    let store = ChainStore::create(&path, EPOCH).expect("header is fine");
    let result = store.write(|batch| -> Result<(), StoreError> {
        assert!(batch.get_property::<ProbeCell>().is_err());
        batch.upsert_property::<ProbeCell>(&7)?;
        assert_eq!(
            batch.get_property::<ProbeCell>()?,
            Some(7),
            "the batch's own repair reads back inside the batch"
        );
        Ok(())
    });
    assert!(
        matches!(
            result,
            Err(StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "__e1_probe_cell",
                fault: CellFault::Undecodable(_),
            }))
        ),
        "the commit refuses with the violation the closure swallowed: {result:?}"
    );
    drop(store);
    assert_eq!(
        raw_get(&path, ProbeCell::KEY).as_deref(),
        Some(&[1u8, 2, 3][..]),
        "the repair did not land: a poisoned batch aborts"
    );
    cleanup(&path);
}

// The write bound is the permission: `upsert_property::<SchemaVersionCell>`
// and `upsert_property::<ApplyPolicyCell>` do not compile. Pinned by the
// `compile_fail` doctests on `WriteBatch::upsert_property`.
