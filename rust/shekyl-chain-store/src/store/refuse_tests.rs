// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WriteBatch::refuse_corrupt` (DRS-E2 RD-Q4, SI-10): the validator's
//! `Corrupt` observation arms the batch exactly as a belt would — nothing
//! the batch wrote lands, the writer halts at the connecting height, and
//! later writes are refused.

use shekyl_chain_rules::Corrupt;
use shekyl_types::BlockHeight;

use super::connect_fixtures::{candidate, connect_genesis, facts, judge, GENESIS_ID};
use super::error::{StoreCannot, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

fn observed() -> Corrupt {
    Corrupt::CumulativeDifficultyNotMonotone {
        at: BlockHeight::from_raw(1),
    }
}

#[test]
fn a_refused_corrupt_halts_the_writer_at_the_connecting_height_and_lands_nothing() {
    let path = tmp("refuse-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    // The batch connects a valid block first, then the validator (reading
    // through the same view, at what is now tip + 1 = 2) reports Corrupt.
    // The refusal poisons the whole batch: the connected block is gone too.
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, candidate(1, genesis.hash(), Vec::new()))?;
        let connected = batch.connect(valid, facts(1, 0), GENESIS_ID)?;
        Err(batch.refuse_corrupt(observed()))?;
        Ok(connected)
    });
    let row = StoreInvariant::DifficultyRecordIncoherent(observed());
    assert_eq!(
        out,
        Err(TestErr::Store(StoreError::from(row).to_string())),
        "the refusal is the InvariantViolated the closure propagated"
    );
    assert_eq!(row.row(), 10);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row,
        },
        "halted at the height the batch was working at (§3.6.2)"
    );
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.tip().expect("tip").recorded.map(|t| t.height),
        Some(BlockHeight::from_raw(0)),
        "the block connected before the refusal did not land"
    );
    drop(snap);
    let later: Result<(), TestErr> = store.write(|_| Ok(()));
    assert_eq!(
        later,
        Err(TestErr::Store(
            StoreError::from(StoreCannot::WriterHalted { at_height: 2, row }).to_string()
        )),
        "every later write is refused with the halt"
    );
    cleanup(&path);
}

#[test]
fn a_refusal_without_a_view_still_halts_at_tip_plus_one() {
    // The pipeline always opened the view (the validator read through it),
    // but the halt's height must not depend on that.
    let path = tmp("refuse-corrupt-noview");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_genesis(&store, 0);
    let out: Result<(), TestErr> = store.write(|batch| Err(batch.refuse_corrupt(observed()))?);
    assert!(out.is_err());
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row: StoreInvariant::DifficultyRecordIncoherent(observed()),
        }
    );
    cleanup(&path);
}

#[test]
fn the_first_row_wins_when_a_belt_already_fired() {
    // Poison is first-wins for belts; a refusal after a belt keeps the
    // belt's row, and a belt after a refusal keeps the refusal's.
    let path = tmp("refuse-corrupt-first-wins");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let (_, genesis) = connect_genesis(&store, 0);
    let stale_then_refuse: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut sibling = candidate(1, genesis.hash(), Vec::new());
        sibling.block.header.nonce = 8;
        let first = judge(&view, sibling)?;
        let second = judge(&view, candidate(1, genesis.hash(), Vec::new()))?;
        batch.connect(first, facts(1, 0), GENESIS_ID)?;
        let belt = batch.connect(second, facts(1, 0), GENESIS_ID); // SI-2 arms first
        assert!(belt.is_err());
        let refusal = batch.refuse_corrupt(observed());
        assert!(
            matches!(
                refusal,
                StoreError::InvariantViolated(StoreInvariant::DifficultyRecordIncoherent(_))
            ),
            "the refusal still returns its own row to the caller: {refusal}"
        );
        Err(refusal)?
    });
    assert!(stale_then_refuse.is_err());
    assert!(
        matches!(
            store.connect_state(),
            ConnectState::Halted {
                row: StoreInvariant::TipMismatch,
                ..
            }
        ),
        "the belt that fired first is the halt's row: {:?}",
        store.connect_state()
    );
    cleanup(&path);
}

#[test]
fn every_corrupt_arm_is_si10_and_names_itself() {
    let arms = [
        Corrupt::CumulativeDifficultyNotMonotone {
            at: BlockHeight::from_raw(41),
        },
        Corrupt::CumulativeDifficultyOverflow,
        Corrupt::ZeroTarget,
    ];
    let needles = ["height 41 is below its parent", "overflows", "is zero"];
    for (arm, needle) in arms.into_iter().zip(needles) {
        let row = StoreInvariant::DifficultyRecordIncoherent(arm);
        assert_eq!(row.row(), 10);
        let text = row.to_string();
        assert!(text.starts_with("SI-10 violated: "), "{text}");
        assert!(text.contains(needle), "{text}");
    }
}
