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

use super::store_tests::{cleanup, tmp, PROBE};
use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{
    ApplyPolicyCell, Canonical, ChainState, PropertyCell, SchemaVersion, SchemaVersionCell,
    SCHEMA_VERSION,
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
    let store = ChainStore::with_apply_policy(path, policy).expect("create");
    let batch = store.begin_batch().expect("begin");
    {
        let mut t = batch.open_table(PROBE).expect("probe");
        t.insert("k", &1_u64).expect("insert");
    }
    batch.commit().expect("commit");
}

/// Write raw bytes to a `properties` cell, bypassing the store entirely.
fn raw_put(path: &std::path::Path, key: &str, value: Option<&[u8]>) {
    let db = redb::Database::open(path).expect("raw open");
    let txn = db.begin_write().expect("raw write");
    {
        let mut t = txn.open_table(PROPERTIES).expect("raw properties");
        match value {
            Some(v) => drop(t.insert(key, v).expect("raw insert")),
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
    t.get(key).expect("raw get").map(|g| g.value().to_vec())
}

// ---------------------------------------------------------------- seal

#[test]
fn a_fresh_store_is_sealed_in_its_first_transaction() {
    let path = tmp("seal");
    drop(ChainStore::create(&path).expect("create"));
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
    cleanup(&path);
}

#[test]
fn a_fresh_store_created_under_a_stub_is_tainted_from_its_first_byte() {
    let path = tmp("seal-stubbed");
    let store = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("create");
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
                ChainStore::create(&path),
                Err(StoreError::SchemaVersionMismatch { found: f, expected })
                    if f == found && expected == SCHEMA_VERSION
            ),
            "writable reopen at v{other}"
        );
        assert!(
            matches!(
                ChainStore::open_read_only(&path),
                Err(StoreError::SchemaVersionMismatch { found: f, .. }) if f == found
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
        ChainStore::create(&path),
        Err(StoreError::SchemaVersionAbsent)
    ));
    assert!(matches!(
        ChainStore::open_read_only(&path),
        Err(StoreError::SchemaVersionAbsent)
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
        ChainStore::create(&foreign),
        Err(StoreError::SchemaVersionAbsent)
    ));
    assert!(matches!(
        ChainStore::open_read_only(&foreign),
        Err(StoreError::SchemaVersionAbsent)
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
        ChainStore::create(&path),
        Err(StoreError::CellCorrupt {
            key: "schema_version",
            fault: CellFault::Undecodable(crate::codec::CodecError::Length {
                codec: "schema_version",
                expected: 8,
                actual: 3,
            }),
        })
    ));
    raw_put(&path, "schema_version", Some(&SCHEMA_VERSION.encode()));

    // Provenance missing entirely: the seal always writes it, so this is
    // a foreign edit, not "an older file".
    raw_put(&path, "apply_policy", None);
    assert!(matches!(
        ChainStore::open_read_only(&path),
        Err(StoreError::CellCorrupt {
            key: "apply_policy",
            fault: CellFault::Absent,
        })
    ));

    // Provenance with a bit that names no family.
    raw_put(&path, "apply_policy", Some(&[0, 0, 0, 0x80]));
    assert!(matches!(
        ChainStore::create(&path),
        Err(StoreError::CellCorrupt {
            key: "apply_policy",
            fault: CellFault::Undecodable(crate::codec::CodecError::Invalid {
                codec: "family_set",
                ..
            }),
        })
    ));
    cleanup(&path);
}

// ---------------------------------------------------------- provenance

#[test]
fn a_stubbed_commit_taints_the_file_and_a_full_session_cannot_clean_it() {
    let path = tmp("taint");
    seeded(&path, ApplyPolicy::Full);

    // The stubbed session: its commit returns the widened record and the
    // handle's view moves with it.
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("stubbed reopen");
    assert!(
        s.provenance().is_parity_evidence(),
        "not tainted until a commit"
    );
    let after = s.begin_batch().expect("b").commit().expect("c");
    assert_eq!(after.stubbed(), FamilySet::of(SLASH));
    assert_eq!(s.provenance(), after);
    drop(s);

    // A later Full session reads the file's history, not its own intent.
    let full = ChainStore::create(&path).expect("Full reopen");
    assert_eq!(full.apply_policy(), ApplyPolicy::Full);
    assert_eq!(full.provenance().stubbed(), FamilySet::of(SLASH));
    assert!(!full.provenance().is_parity_evidence());
    assert!(full
        .provenance()
        .artifact_stamp()
        .contains("NOT-PARITY-EVIDENCE"));
    // And committing under Full does not narrow it.
    let still = full.begin_batch().expect("b").commit().expect("c");
    assert_eq!(still.stubbed(), FamilySet::of(SLASH));
    drop(full);

    // The falsifier: a read-only handle reads the persisted policy.
    let ro = ChainStore::open_read_only(&path).expect("ro");
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
        let s = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("reopen");
        assert_eq!(s.provenance().stubbed(), FamilySet::of(BOND), "inherits");
        let after = s.begin_batch().expect("b").commit().expect("c");
        assert_eq!(
            after.stubbed(),
            FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog])
        );
    }
    let ro = ChainStore::open_read_only(&path).expect("ro");
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
fn an_aborted_or_dropped_stubbed_batch_leaves_no_taint() {
    // The taint is written inside the batch's transaction, so it goes
    // wherever the batch's rows go: nowhere, on abort or drop.
    let path = tmp("taint-abort");
    seeded(&path, ApplyPolicy::Full);
    {
        let s = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("reopen");
        let b = s.begin_batch().expect("b");
        b.open_table(PROBE)
            .expect("probe")
            .insert("x", &2)
            .expect("i");
        b.abort().expect("abort");
        assert!(s.provenance().is_parity_evidence(), "abort");
        let b = s.begin_batch().expect("b");
        b.open_table(PROBE)
            .expect("probe")
            .insert("x", &2)
            .expect("i");
        drop(b);
        assert!(s.provenance().is_parity_evidence(), "drop");
    }
    assert!(ChainStore::open_read_only(&path)
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
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("reopen");
    let after = s.begin_batch().expect("b").commit().expect("c");
    assert!(!after.is_parity_evidence());
    cleanup(&path);
}

#[test]
fn the_taint_commits_atomically_with_the_rows() {
    // Both the probe row and the widened cell come from one commit, so a
    // snapshot sees both or neither. A snapshot begun before the commit
    // sees neither; one begun after sees both.
    let path = tmp("taint-atomic");
    seeded(&path, ApplyPolicy::Full);
    let s = ChainStore::with_apply_policy(&path, stubbed(SLASH)).expect("reopen");
    let before = s.begin_read().expect("snapshot before");
    let b = s.begin_batch().expect("b");
    b.open_table(PROBE)
        .expect("probe")
        .insert("row", &7)
        .expect("i");
    b.commit().expect("c");
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

/// A chain-state cell that exists only in this test module. The real ones
/// (`total_burned`, …) land with the surfaces that write them.
#[derive(Clone, Copy, Debug)]
struct ProbeCell;

impl PropertyCell for ProbeCell {
    const KEY: &'static str = "__e1_probe_cell";
    type Scope = ChainState;
    type Value = u64;
}

#[test]
fn a_chain_state_cell_round_trips_through_the_typed_surface() {
    let path = tmp("typed-cell");
    let store = ChainStore::create(&path).expect("create");
    let batch = store.begin_batch().expect("b");
    assert_eq!(batch.get_property::<ProbeCell>().expect("get"), None);
    batch
        .put_property::<ProbeCell>(&0x0102_0304_0506_0708)
        .expect("put");
    assert_eq!(
        batch.get_property::<ProbeCell>().expect("get own write"),
        Some(0x0102_0304_0506_0708)
    );
    batch.commit().expect("c");
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
    let store = ChainStore::open_read_only(&path).expect("header is fine");
    assert!(matches!(
        store
            .begin_read()
            .expect("read")
            .get_property::<ProbeCell>(),
        Err(StoreError::CellCorrupt {
            key: "__e1_probe_cell",
            fault: CellFault::Undecodable(_),
        })
    ));
    cleanup(&path);
}

// The write bound is the permission: `put_property::<SchemaVersionCell>`
// and `put_property::<ApplyPolicyCell>` do not compile. Pinned by the
// `compile_fail` doctests on `WriteBatch::put_property`.
