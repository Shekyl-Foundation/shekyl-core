// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pop-journal tests (S-CHAIN-W commit 1): recording through every verb,
//! reverse replay, the floor, the unsealed refusal, and the SI-6 / SI-7
//! belts a damaged row trips. Sibling of `undo.rs` for the same reason
//! `store_tests.rs` is a sibling of `mod.rs`.

use redb::ReadableTableMetadata;

use super::connect_fixtures::candidate;
use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE, PROBE_ROW};
use super::undo::Replayed;
use super::*;
use crate::codec::{
    forged, post_image, stored_timelock, BlockBody, Canonical, OutKey, ProbeCell, PropertyCell,
    Raw, RuleSetInForce, UndoEntry, UndoLog,
};
use crate::ids::{OutputSlot, OutputStorageId};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{
    ordinal_of, BLOCKS, BLOCK_HEIGHTS, HF_VERSIONS, OUTPUT_AMOUNTS, PROPERTIES, UNDO_LOG,
};
use shekyl_chain_rules::RuleSetId;
use shekyl_types::{BlockHash, BlockHeight, CommitmentBytes, OneTimePubkey};

fn hash(byte: u8) -> LmdbHashKey {
    LmdbHashKey::from_bytes([byte; 32])
}

/// An `output_amounts` row for the tests: the `(0, index)` key LMDB's
/// one bucket has, with a record that names its index in every field.
fn out_key(byte: u8) -> OutKey {
    OutKey {
        output_id: OutputStorageId::from_raw(u64::from(byte)),
        pubkey: OneTimePubkey::from_bytes([byte; 32]),
        unlock_time: stored_timelock(0),
        height: BlockHeight::from_raw(u64::from(byte)),
        commitment: CommitmentBytes::from_bytes([byte; 32]),
    }
}

fn slot(index: u64) -> (u64, u64) {
    OutputSlot::new(
        OutputSlot::CONFIDENTIAL_AMOUNT,
        crate::ids::AmountIndex::from_raw(index),
    )
    .key()
}

fn slot_bytes(index: u64) -> Box<[u8]> {
    let (amount, index) = slot(index);
    [amount.to_le_bytes(), index.to_le_bytes()]
        .concat()
        .into_boxed_slice()
}

/// The connect-shaped write set the tests journal: one insert per keyed
/// shape (including the tuple-keyed `output_amounts`), one upsert over a
/// present key and one over an absent key, one chain-state cell.
fn connect_like(batch: &WriteBatch<'_, '_>, height: u64) -> Result<usize, StoreError> {
    let byte = u8::try_from(height).expect("test heights fit a byte");
    let recording = batch.record_undo(height);
    let blob = candidate(height, BlockHash::NULL, Vec::new())
        .block
        .serialize();
    batch
        .open_insert_table(BLOCKS, PROBE_ROW)?
        .insert(height, Raw::<BlockBody>::new(&blob))?;
    batch.open_insert_table(BLOCK_HEIGHTS, PROBE_ROW)?.insert(
        hash(byte),
        BlockHeight::from_raw(height).encoded().as_encoded(),
    )?;
    let mut hf = batch.open_upsert_table(HF_VERSIONS)?;
    hf.upsert(
        0,
        RuleSetInForce(RuleSetId::from_raw(byte))
            .encoded()
            .as_encoded(),
    )?; // present after the first connect: prior restored
    hf.upsert(
        height,
        RuleSetInForce(RuleSetId::from_raw(1))
            .encoded()
            .as_encoded(),
    )?; // absent: undo removes it
    drop(hf);
    batch
        .open_insert_table(OUTPUT_AMOUNTS, PROBE_ROW)?
        .insert(slot(height), out_key(byte).encoded().as_encoded())?;
    batch.upsert_property::<ProbeCell>(&(100 + height))?;
    recording.seal()
}

fn undo_row(store: &ChainStore, height: u64) -> Option<UndoLog> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(UNDO_LOG).ok()?;
    let guard = table.get(height).expect("get")?;
    Some(guard.value().decode().expect("row decodes"))
}

#[test]
fn every_verb_journals_its_pre_image_in_write_order() {
    let path = tmp("undo-record");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let seeded: Result<(), TestErr> = store.write(|batch| {
        // Unjournaled seed, so the `hf_versions[0]` upsert below has a prior.
        batch.open_upsert_table(HF_VERSIONS)?.upsert(
            0,
            RuleSetInForce(RuleSetId::from_raw(7))
                .encoded()
                .as_encoded(),
        )?;
        Ok(())
    });
    seeded.expect("seed");
    let count: Result<usize, TestErr> = store.write(|batch| Ok(connect_like(batch, 1)?));
    assert_eq!(count, Ok(6));

    let row = undo_row(&store, 1).expect("row written");
    let ord = |name: &str| ordinal_of(name).expect("catalogued");
    assert_eq!(
        row.0,
        vec![
            UndoEntry::Inserted {
                table: ord("blocks"),
                key: Box::new(1u64.to_le_bytes()),
                post: post_image(&candidate(1, BlockHash::NULL, Vec::new()).block.serialize()),
            },
            UndoEntry::Inserted {
                table: ord("block_heights"),
                key: Box::new([1u8; 32]),
                post: post_image(&1u64.to_le_bytes()),
            },
            UndoEntry::Replaced {
                table: ord("hf_versions"),
                key: Box::new(0u64.to_le_bytes()),
                prior: Some(Box::new([7])),
                post: post_image(&[1]),
            },
            UndoEntry::Replaced {
                table: ord("hf_versions"),
                key: Box::new(1u64.to_le_bytes()),
                prior: None,
                post: post_image(&[1]),
            },
            UndoEntry::Inserted {
                table: ord("output_amounts"),
                key: slot_bytes(1),
                post: post_image(&out_key(1).encode()),
            },
            UndoEntry::Replaced {
                table: ord("properties"),
                key: Box::from(ProbeCell::KEY.as_bytes()),
                prior: None,
                post: post_image(&101u64.encode()),
            },
        ]
    );
    // The row's own insert is not in the row, and nothing before the
    // recording began is.
    assert!(row.0.iter().all(|e| e.table() != ord("undo_log")));
    cleanup(&path);
}

#[test]
fn replay_restores_every_table_and_deletes_the_row_then_the_floor_is_reached() {
    let path = tmp("undo-replay");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let seeded: Result<(), TestErr> = store.write(|batch| {
        batch.open_upsert_table(HF_VERSIONS)?.upsert(
            0,
            RuleSetInForce(RuleSetId::from_raw(7))
                .encoded()
                .as_encoded(),
        )?;
        batch
            .open_insert_table(OUTPUT_AMOUNTS, PROBE_ROW)?
            .insert(slot(0), out_key(0xee).encoded().as_encoded())?;
        batch.upsert_property::<ProbeCell>(&5)?;
        Ok(())
    });
    seeded.expect("seed");
    let connected: Result<usize, TestErr> = store.write(|batch| Ok(connect_like(batch, 1)?));
    assert_eq!(connected, Ok(6));

    // State after connect.
    {
        let snap = store.begin_read().expect("read");
        assert!(snap
            .open_table(BLOCKS)
            .expect("t")
            .get(1)
            .expect("g")
            .is_some());
        assert_eq!(
            snap.open_table(HF_VERSIONS)
                .expect("t")
                .get(0)
                .expect("g")
                .map(|g| g.value().decode().expect("decodes")),
            Some(RuleSetInForce(RuleSetId::from_raw(1)))
        );
        assert_eq!(snap.get_property::<ProbeCell>().expect("cell"), Some(101));
    }

    let popped: Result<Replayed, TestErr> = store.write(|batch| Ok(batch.replay_undo(1)?));
    assert_eq!(popped, Ok(Replayed::Entries(6)));

    let snap = store.begin_read().expect("read");
    assert!(snap
        .open_table(BLOCKS)
        .expect("t")
        .get(1)
        .expect("g")
        .is_none());
    assert!(snap
        .open_table(BLOCK_HEIGHTS)
        .expect("t")
        .get(hash(1))
        .expect("g")
        .is_none());
    let hf = snap.open_table(HF_VERSIONS).expect("t");
    assert_eq!(
        hf.get(0)
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(RuleSetInForce(RuleSetId::from_raw(7))),
        "prior restored"
    );
    assert!(hf.get(1).expect("g").is_none(), "absent-before key removed");
    let amounts = snap.open_table(OUTPUT_AMOUNTS).expect("t");
    let keys: Vec<(u64, u64)> = amounts
        .range::<(u64, u64)>(..)
        .expect("range")
        .map(|r| r.expect("row").0.value())
        .collect();
    assert_eq!(
        keys,
        vec![slot(0)],
        "the seeded row survives, the connected one goes"
    );
    assert_eq!(
        amounts
            .get(slot(0))
            .expect("g")
            .map(|g| g.value().decode().expect("decodes")),
        Some(out_key(0xee))
    );
    assert_eq!(snap.get_property::<ProbeCell>().expect("cell"), Some(5));
    assert!(undo_row(&store, 1).is_none(), "the row is consumed");
    drop(snap);

    let again: Result<Replayed, TestErr> = store.write(|batch| Ok(batch.replay_undo(1)?));
    assert_eq!(
        again,
        Ok(Replayed::NoRow),
        "below the floor there is nothing to pop"
    );
    cleanup(&path);
}

#[test]
fn two_heights_in_one_batch_pop_in_lifo_order() {
    let path = tmp("undo-lifo");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let counts: Result<(usize, usize), TestErr> =
        store.write(|batch| Ok((connect_like(batch, 1)?, connect_like(batch, 2)?)));
    assert_eq!(counts, Ok((6, 6)));
    assert!(undo_row(&store, 1).is_some() && undo_row(&store, 2).is_some());

    let popped: Result<(Replayed, Replayed), TestErr> =
        store.write(|batch| Ok((batch.replay_undo(2)?, batch.replay_undo(1)?)));
    assert_eq!(popped, Ok((Replayed::Entries(6), Replayed::Entries(6))));
    let snap = store.begin_read().expect("read");
    assert!(snap.open_table(BLOCKS).expect("t").is_empty().expect("len"));
    // `hf_versions[0]` was absent before block 1 wrote it (block 1's
    // upsert found nothing), so two pops remove it entirely.
    assert!(snap
        .open_table(HF_VERSIONS)
        .expect("t")
        .is_empty()
        .expect("len"));
    cleanup(&path);
}

#[test]
fn a_present_output_key_is_refused_not_journaled_and_the_first_row_survives_the_pop() {
    // Under the multimap a second identical member was "not new" and not
    // journaled; under the keyed table a present `(amount, amount_index)` is
    // an SI-9 breach — `insert` refuses it and arms the batch. What the
    // journal holds is the one write that happened.
    let path = tmp("undo-present-key");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let seeded: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(OUTPUT_AMOUNTS, PROBE_ROW)?
            .insert(slot(0), out_key(9).encoded().as_encoded())?;
        Ok(())
    });
    seeded.expect("seed");
    let out: Result<usize, TestErr> = store.write(|batch| {
        let recording = batch.record_undo(1);
        let mut amounts = batch.open_insert_table(OUTPUT_AMOUNTS, PROBE_ROW)?;
        amounts.insert(slot(1), out_key(1).encoded().as_encoded())?;
        let again = amounts.insert(slot(1), out_key(1).encoded().as_encoded());
        assert!(
            matches!(again, Err(StoreError::InvariantViolated(_))),
            "a present key is refused, not accepted as 'not new'"
        );
        drop(amounts);
        Ok(recording.seal()?)
    });
    // The refusal armed the batch, so the write closure's outcome is the
    // poison, whatever it returned; the seeded row is untouched either way.
    assert!(out.is_err(), "an armed batch does not commit");
    let snap = store.begin_read().expect("read");
    let amounts = snap.open_table(OUTPUT_AMOUNTS).expect("t");
    assert_eq!(amounts.len().expect("len"), 1);
    assert!(amounts.get(slot(0)).expect("g").is_some());
    cleanup(&path);
}

#[test]
fn an_unsealed_recording_refuses_the_commit_and_lands_nothing() {
    let path = tmp("undo-unsealed");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        let recording = batch.record_undo(4);
        let blob = candidate(4, BlockHash::NULL, Vec::new()).block.serialize();
        batch
            .open_insert_table(BLOCKS, PROBE_ROW)?
            .insert(4, Raw::<BlockBody>::new(&blob))?;
        drop(recording);
        Ok(())
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::UndoUnsealed { height: 4 }).to_string()
        ))
    );
    let snap = store.begin_read().expect("read");
    assert!(
        snap.open_table(BLOCKS)
            .expect("sealed: exists from create (A2)")
            .is_empty()
            .expect("len"),
        "nothing landed"
    );
    cleanup(&path);
}

#[test]
fn sealing_over_a_recorded_height_is_si6_and_poisons_the_batch() {
    let path = tmp("undo-collide");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let first: Result<usize, TestErr> = store.write(|batch| Ok(connect_like(batch, 1)?));
    assert_eq!(first, Ok(6));
    // The closure swallows the violation and returns Ok; the batch still
    // refuses with the row.
    let second: Result<(), TestErr> = store.write(|batch| {
        let recording = batch.record_undo(1);
        let swallowed = recording.seal();
        assert!(swallowed.is_err());
        Ok(())
    });
    let want = StoreInvariant::UndoLogIncoherent {
        height: 1,
        fault: UndoFault::RowAlreadyRecorded,
    };
    assert_eq!(
        second,
        Err(TestErr::Store(StoreError::from(want).to_string()))
    );
    assert_eq!(want.row(), 6);
    cleanup(&path);
}

/// Write a hand-built row at `height` with no recording live.
fn plant_row(store: &ChainStore, height: u64, bytes: &[u8]) {
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(UNDO_LOG, PROBE_ROW)?
            .insert(height, forged(bytes))?;
        Ok(())
    });
    out.expect("planted");
}

fn replay_err(store: &ChainStore, height: u64) -> String {
    let out: Result<Replayed, TestErr> = store.write(|batch| Ok(batch.replay_undo(height)?));
    match out {
        Err(TestErr::Store(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_entry_whose_target_is_gone_is_si6() {
    let path = tmp("undo-target");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let row = UndoLog(vec![
        UndoEntry::Inserted {
            table: ordinal_of("blocks").expect("catalogued"),
            key: Box::new(77u64.to_le_bytes()), // never written
            post: post_image(&[0]),
        },
        UndoEntry::Replaced {
            table: ordinal_of("hf_versions").expect("catalogued"),
            key: Box::new(3u64.to_le_bytes()), // never written either
            prior: Some(Box::new([1])),
            post: post_image(&[2]),
        },
    ]);
    plant_row(&store, 9, &row.encode());
    // Reverse order: entry 1 (the Replaced) is tried first.
    let want = StoreInvariant::UndoLogIncoherent {
        height: 9,
        fault: UndoFault::EntryNotReversible { index: 1 },
    };
    assert_eq!(replay_err(&store, 9), StoreError::from(want).to_string());
    assert!(
        undo_row(&store, 9).is_some(),
        "a refused replay lands nothing, the row stays"
    );
    cleanup(&path);
}

#[test]
fn a_row_that_does_not_decode_or_names_no_table_or_wrong_shape_is_si7() {
    let path = tmp("undo-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");

    drop(store);
    // Garbage bytes cannot go through the crate handle: `check_row` refuses
    // them as `RowIllFormed`. SI-7 is a file that already holds them.
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(UNDO_LOG)
            .expect("t")
            .insert(1, forged(&[0xff, 0xff]))
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let msg = replay_err(&store, 1);
    assert!(
        msg.starts_with("SI-7 violated: typed cell `undo_log` is undecodable"),
        "{msg}"
    );

    let no_such_table = UndoLog(vec![UndoEntry::Inserted {
        table: crate::schema::TableOrdinal::from_index(9_999),
        key: Box::new([0; 8]),
        post: post_image(&[0]),
    }]);
    plant_row(&store, 2, &no_such_table.encode());
    let msg = replay_err(&store, 2);
    assert!(
        msg.contains("names a table ordinal the catalogue does not have"),
        "{msg}"
    );

    // (Tag 2, the retired multimap member, is refused at the codec — the
    // `codec::undo` tests pin it — so no entry shape can reach the target
    // dispatch that the target's table cannot hold.)

    let wrong_width = UndoLog(vec![UndoEntry::Inserted {
        table: ordinal_of("blocks").expect("catalogued"),
        key: Box::new([0; 3]), // `blocks` is keyed by u64: from_bytes would panic
        post: post_image(&[0]),
    }]);
    plant_row(&store, 4, &wrong_width.encode());
    let msg = replay_err(&store, 4);
    assert!(msg.contains("wrong width for a fixed-width type"), "{msg}");

    let not_utf8 = UndoLog(vec![UndoEntry::Replaced {
        table: ordinal_of("properties").expect("catalogued"),
        key: Box::new([0xff, 0xfe]),
        prior: None,
        post: post_image(&[0]),
    }]);
    plant_row(&store, 5, &not_utf8.encode());
    let msg = replay_err(&store, 5);
    assert!(msg.contains("not UTF-8"), "{msg}");

    // An `Inserted` entry has no `prior` for `well_formed` to refuse, so an
    // entry naming an `Unshaped` table must be refused on the shape alone —
    // before `remove` could reach the uninhabited `from_bytes`.
    // `curve_tree_checkpoints` has no Rust writer at this layout.
    let unshaped = UndoLog(vec![UndoEntry::Inserted {
        table: ordinal_of("curve_tree_checkpoints").expect("catalogued"),
        key: Box::new([0; 8]),
        post: post_image(&[0]),
    }]);
    plant_row(&store, 6, &unshaped.encode());
    let msg = replay_err(&store, 6);
    assert!(msg.contains("names an unshaped table"), "{msg}");
    cleanup(&path);
}

#[test]
#[should_panic(expected = "not in the schema catalogue and cannot be journaled")]
fn writing_an_uncatalogued_table_while_recording_is_a_crate_bug() {
    let path = tmp("undo-uncatalogued");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let unreachable: Result<(), TestErr> = store.write(|batch| {
        let recording = batch.record_undo(1);
        batch.open_upsert_table(PROBE)?.upsert("k", &1)?;
        recording.seal()?;
        Ok(())
    });
    drop(unreachable);
}

#[test]
fn a_probe_table_writes_freely_while_no_recording_is_live() {
    let path = tmp("undo-probe-ok");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        batch.open_upsert_table(PROBE)?.upsert("k", &1)?;
        Ok(())
    });
    assert_eq!(out, Ok(()));
    assert_eq!(super::store_tests::probe_val(&store, "k"), Some(1));
    // And `properties` is catalogued, so the header's own cells are readable
    // through the same ordinal the journal would record.
    assert!(ordinal_of(redb::TableHandle::name(&PROPERTIES)).is_some());
    cleanup(&path);
}
