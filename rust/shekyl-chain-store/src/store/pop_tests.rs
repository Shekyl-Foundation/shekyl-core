// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `pop` and the writer halt (S-CHAIN-W commit 7): connect → pop returns
//! the store to its prior state; the floor at genesis and at an empty
//! chain; SI-6 when the journal's top is not the tip; the halt latched by a
//! poisoned connect or pop, refusing every later write while reads stay
//! open, and NOT latched by a violation in a batch that connected nothing.

use redb::ReadableTableMetadata;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use super::connect_fixtures::{
    at, candidate, connect_chain_with_burn, connect_with_image_planted_under_the_token, spend,
    spend_at, spendable_prefix, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE, PROBE_ROW};
use super::*;
use crate::codec::{forged, BlockBody, Canonical, Raw, TotalBurnedCell};
use crate::schema::{BLOCKS, BLOCK_INFO, SPENT_KEYS, UNDO_LOG};

fn connect_chain(store: &ChainStore, listed: &[Vec<Transaction>]) -> Vec<BlockHash> {
    connect_chain_with_burn(store, listed, 3)
}

fn tip_height(store: &ChainStore) -> Option<u64> {
    let snap = store.begin_read().expect("read");
    snap.tip().expect("tip").recorded.map(|t| t.height.to_raw())
}

#[test]
fn pop_removes_the_tip_and_pops_a_reorg_depth_in_one_batch() {
    let path = tmp("pop-basic");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // The spendable prefix, then two spend blocks: the tip is `s + 1`.
    let s = FIRST_SPEND_HEIGHT;
    let tip = s + 1;
    connect_chain(
        &store,
        &spendable_prefix(&[vec![spend(9, 2)], vec![spend(10, 2)]]),
    );
    assert_eq!(tip_height(&store), Some(tip));
    let burned_after_all = {
        let snap = store.begin_read().expect("read");
        snap.get_property::<TotalBurnedCell>().expect("cell")
    };
    // Every block handed `burned = 3`; genesis records none (the `h > 0`
    // half of the C++ guard, `blockchain.cpp:6148`), so the fold is `tip`
    // blocks' worth.
    assert_eq!(burned_after_all, Some(AtomicUnits::from_raw(3 * tip)));

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    let popped = out.expect("pop the tip");
    assert_eq!(popped.height, BlockHeight::from_raw(tip));
    assert!(popped.reversed > 0);
    assert_eq!(tip_height(&store), Some(tip - 1));
    {
        let snap = store.begin_read().expect("read");
        assert_eq!(
            snap.get_property::<TotalBurnedCell>().expect("cell"),
            Some(AtomicUnits::from_raw(3 * (tip - 1))),
            "the tip's burn restored to the pre-image its parent left"
        );
        assert!(snap
            .open_table(SPENT_KEYS)
            .expect("t")
            .get(crate::lmdb_order::LmdbHashKey::from_bytes(
                shekyl_chain_rules::harness::fixture::point(10),
            ))
            .expect("g")
            .is_none());
        assert!(snap
            .open_table(UNDO_LOG)
            .expect("t")
            .get(tip)
            .expect("g")
            .is_none());
    }

    // A reorg that pops the whole chain in one batch — every block down to
    // 1, then block 0 is refused (genesis), so the batch aborts as a whole
    // and nothing popped.
    let out: Result<(), TestErr> = store.write(|batch| {
        for _ in 0..tip {
            batch.pop()?;
        }
        Ok(())
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::PopBelowFloor { tip: 0, floor: 1 }).to_string()
        )),
        "genesis is never poppable, and the refusal aborts the whole batch"
    );
    assert_eq!(
        tip_height(&store),
        Some(tip - 1),
        "none of the earlier pops landed either"
    );

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert_eq!(out.map(|p| p.height), Ok(BlockHeight::from_raw(tip - 1)));
    assert_eq!(tip_height(&store), Some(tip - 2));
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
        let row = info.get(1)?.expect("block 1").value().bytes().to_vec();
        info.insert(2, forged(&row))?;
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

    // A connect whose belt fires halts the writer at the connecting height
    // (SI-1, reached by the spent-keys table moving under a judged token:
    // a double spend itself is CEN-I7's refusal before `connect`). Before
    // slice 6 commit 4 a plain double spend reached this belt, which tested
    // it as the rule; this is the belt tested as a belt, the shape the test
    // should always have had.
    let hashes = connect_chain(&store, &spendable_prefix(&[vec![spend(9, 2)]]));
    let next = FIRST_SPEND_HEIGHT + 1;
    let double = candidate(
        next,
        hashes[at(FIRST_SPEND_HEIGHT)],
        vec![spend_at(&hashes, next, 10, 2)],
    );
    let out = connect_with_image_planted_under_the_token(&store, double, next);
    assert!(matches!(out, Err(TestErr::Store(ref m)) if m.starts_with("SI-1 violated")));
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(next),
            row: StoreInvariant::KeyImageNotFresh,
        }
    );
    let refused: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    let halted = format!("writer is halted since height {next}");
    assert!(matches!(
        refused,
        Err(TestErr::Store(ref m)) if m.contains(&halted)
    ));
    cleanup(&path);
}

/// SI-6's second arm is exact: an inverse that finds the key present but
/// holding a value other than the one the journaled write left — something
/// wrote around the journal — is `PostImageMismatch`, poisons the batch and
/// halts the writer. Pop never quietly "repairs" a row it did not write.
#[test]
fn a_row_rewritten_around_the_journal_makes_pop_si6_not_a_silent_repair() {
    let path = tmp("pop-post-image");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let tip = FIRST_SPEND_HEIGHT;
    connect_chain(&store, &spendable_prefix(&[vec![spend(9, 2)]]));
    // Write around the journal: overwrite `blocks[tip]` through an upsert
    // handle in a batch that records nothing.
    let impostor = candidate(tip, BlockHash::from_bytes([0x77; 32]), Vec::new())
        .block
        .serialize();
    let around: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_upsert_table(BLOCKS)?
            .upsert(tip, Raw::<BlockBody>::new(&impostor))?;
        Ok(())
    });
    around.expect("the unjournaled overwrite lands");

    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert!(
        matches!(
            out,
            Err(TestErr::Store(ref m))
                if m.starts_with("SI-6 violated") && m.contains("not the one the journaled write left")
        ),
        "{out:?}"
    );
    assert!(
        matches!(
            store.connect_state(),
            ConnectState::Halted {
                row: StoreInvariant::UndoLogIncoherent {
                    height,
                    fault: UndoFault::PostImageMismatch { .. },
                },
                ..
            } if height == tip
        ),
        "{:?}",
        store.connect_state()
    );
    // Nothing landed: the tip is where it was and the rewritten row is intact.
    assert_eq!(tip_height(&store), Some(tip));
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.open_table(BLOCKS)
            .expect("t")
            .get(tip)
            .expect("g")
            .map(|g| g.value().bytes().to_vec()),
        Some(impostor)
    );
    cleanup(&path);
}

/// A block recorded at the tip with no journal row is SI-6, not the pop
/// floor: nothing deletes undo rows until S-PRUNE lands (and it will
/// persist the floor it establishes), so an empty journal under a
/// non-empty chain is a journal that does not describe its tables.
#[test]
fn a_recorded_tip_with_no_journal_row_is_si6_not_the_floor() {
    let path = tmp("pop-no-row");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Two heights written by hand, journaling nothing.
    let planted: Result<(), TestErr> = store.write(|batch| {
        for h in 0..2u64 {
            let info = crate::codec::BlockInfo {
                timestamp: shekyl_types::Timestamp::from_raw(h),
                coins_generated: shekyl_units::AtomicUnits::ZERO,
                weight: shekyl_types::BlockWeight::ZERO,
                cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
                hash: shekyl_types::BlockHash::from_bytes(
                    [u8::try_from(h).expect("two heights"); 32],
                ),
                rct_outputs: 0,
                long_term_weight: shekyl_types::LongTermWeight::ZERO,
                cumulative_tx_count: 0,
                long_term_effective_median: shekyl_types::LongTermWeight::ZERO,
            };
            batch
                .open_insert_table(BLOCK_INFO, PROBE_ROW)?
                .insert(h, info.encoded().as_encoded())?;
        }
        Ok(())
    });
    planted.expect("plant");
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    assert!(
        matches!(
            out,
            Err(TestErr::Store(ref m)) if m.starts_with("SI-6 violated") && m.contains("no row for it")
        ),
        "{out:?}"
    );
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row: StoreInvariant::UndoLogIncoherent {
                height: 1,
                fault: UndoFault::NoRowForTip,
            },
        }
    );
    cleanup(&path);
}
