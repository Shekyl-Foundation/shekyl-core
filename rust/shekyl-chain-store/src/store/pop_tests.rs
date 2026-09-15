// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `pop` and the writer halt (S-CHAIN-W commit 7): connect → pop returns
//! the store to its prior state; the floor at genesis and at an empty
//! chain; SI-6 when the journal's top is not the tip; the halt latched by a
//! poisoned connect or pop, refusing every later write while reads stay
//! open, and NOT latched by a violation in a batch that connected nothing.

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_chain_rules::{validate, Candidate, ChainValid, RuleSet, RuleSetId};
use shekyl_types::BlockHeight;
use shekyl_wire::Transaction;

use super::connect_tests::{candidate, facts, spend};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE, PROBE_ROW};
use super::view::BatchView;
use super::*;
use crate::codec::TotalBurnedCell;
use crate::schema::{BLOCKS, BLOCK_INFO, SPENT_KEYS, UNDO_LOG};

fn judge<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    Ok(validate(candidate, view, &RuleSet::GENESIS)?.expect("zero rules refuse nothing"))
}

/// Connect `blocks` (genesis first) in one batch; returns each block's hash.
fn connect_chain(store: &ChainStore, listed: &[Vec<Transaction>]) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    let mut previous = [0u8; 32];
    let mut cands = Vec::new();
    for (h, txs) in listed.iter().enumerate() {
        let cand = candidate(h as u64, previous, txs.clone());
        previous = cand.block.hash();
        hashes.push(previous);
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(judge(&view, cand)?, facts(h as u64, 3), RuleSetId::GENESIS)?;
        }
        Ok(())
    });
    out.expect("chain connects");
    hashes
}

fn tip_height(store: &ChainStore) -> Option<u64> {
    let snap = store.begin_read().expect("read");
    let table = snap.open_table(BLOCK_INFO).ok()?;
    table.last().expect("last").map(|(h, _)| h.value())
}

#[test]
fn pop_removes_the_tip_and_pops_a_reorg_depth_in_one_batch() {
    let path = tmp("pop-basic");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(
        &store,
        &[vec![], vec![spend(0x5e, 1)], vec![spend(0x5f, 1)]],
    );
    assert_eq!(tip_height(&store), Some(2));
    let burned_after_three = {
        let snap = store.begin_read().expect("read");
        snap.get_property::<TotalBurnedCell>().expect("cell")
    };
    assert_eq!(burned_after_three, Some(9));

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    let popped = out.expect("pop 2");
    assert_eq!(popped.height, BlockHeight::from_raw(2));
    assert!(popped.reversed > 0);
    assert_eq!(tip_height(&store), Some(1));
    {
        let snap = store.begin_read().expect("read");
        assert_eq!(
            snap.get_property::<TotalBurnedCell>().expect("cell"),
            Some(6)
        );
        assert!(snap
            .open_table(SPENT_KEYS)
            .expect("t")
            .get(crate::lmdb_order::LmdbHashKey::from_bytes([0x5f; 32]))
            .expect("g")
            .is_none());
        assert!(snap
            .open_table(UNDO_LOG)
            .expect("t")
            .get(2)
            .expect("g")
            .is_none());
    }

    // A two-deep reorg pops twice in one batch — block 1 then block 0 is
    // refused (genesis), so the batch aborts as a whole and block 1 stays.
    let out: Result<(Popped, Popped), TestErr> =
        store.write(|batch| Ok((batch.pop()?, batch.pop()?)));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::PopBelowFloor { tip: 0, floor: 1 }).to_string()
        )),
        "genesis is never poppable, and the refusal aborts the whole batch"
    );
    assert_eq!(
        tip_height(&store),
        Some(1),
        "the first pop did not land either"
    );

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|p| p.height), Ok(BlockHeight::from_raw(1)));
    assert_eq!(tip_height(&store), Some(0));
    assert!(store.connect_state().is_live());
    cleanup(&path);
}

#[test]
fn pop_on_an_empty_chain_is_refused_not_fatal() {
    let path = tmp("pop-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::ChainEmpty).to_string()
        ))
    );
    assert!(store.connect_state().is_live(), "a refusal does not halt");
    cleanup(&path);
}

#[test]
fn a_journal_whose_top_is_not_the_tip_is_si6_and_halts_the_writer() {
    let path = tmp("pop-si6");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]);
    // Write around the journal: a third block-info row with no undo row.
    let planted: Result<(), TestErr> = store.write(|batch| {
        let mut info = batch.open_insert_table(BLOCK_INFO, PROBE_ROW)?;
        let row = info.get(1)?.expect("block 1").value().to_vec();
        info.insert(2, row.as_slice())?;
        Ok(())
    });
    planted.expect("plant");

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    let want = StoreInvariant::UndoLogIncoherent {
        height: 2,
        fault: UndoFault::TopIsNotTip { top: 1 },
    };
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));

    // The writer is halted at the height pop worked at, on the row that
    // caught it; every later write is refused; reads stay open.
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row: want,
        }
    );
    let refused: Result<(), TestErr> = store.write(|batch| {
        batch.open_upsert_table(PROBE)?.upsert("k", &1)?;
        Ok(())
    });
    assert_eq!(
        refused,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::WriterHalted {
                at_height: 2,
                row: want,
            })
            .to_string()
        ))
    );
    let snap = store.begin_read().expect("reads stay open");
    assert_eq!(snap.open_table(BLOCKS).expect("t").len().expect("len"), 2);
    drop(snap);
    // Not persisted: a fresh handle over the same file is live again (the
    // check that reruns the belts is the operator's path, not a latch).
    drop(store);
    let reopened = ChainStore::create(&path, EPOCH).expect("reopen");
    assert!(reopened.connect_state().is_live());
    cleanup(&path);
}

#[test]
fn a_poisoned_connect_halts_the_writer_but_a_probe_violation_does_not() {
    let path = tmp("pop-halt-connect");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // A violation in a batch that connected nothing aborts that batch only.
    let probe: Result<(), TestErr> = store.write(|batch| {
        let mut t = batch.open_insert_table(PROBE, PROBE_ROW)?;
        t.insert("k", &1)?;
        t.insert("k", &2)?;
        Ok(())
    });
    assert!(matches!(probe, Err(TestErr::Store(_))));
    assert!(
        store.connect_state().is_live(),
        "no connect or pop: no halt"
    );

    // A connect whose belt fires halts the writer at the connecting height.
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let double = candidate(2, hashes[1], vec![spend(0x5e, 1)]);
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, double)?, facts(2, 0), RuleSetId::GENESIS)?)
    });
    assert!(matches!(out, Err(TestErr::Store(ref m)) if m.starts_with("SI-1 violated")));
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row: StoreInvariant::KeyImageNotFresh,
        }
    );
    let refused: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert!(matches!(
        refused,
        Err(TestErr::Store(ref m)) if m.contains("writer is halted since height 2")
    ));
    cleanup(&path);
}
