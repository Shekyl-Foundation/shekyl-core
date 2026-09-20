// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SI-10: the validator's `Corrupt` arms the halt (`WriteBatch::refuse_corrupt`,
//! DRS-E2 RD-Q4). Own file so `connect_tests` stays the write-set and belt
//! suite rather than growing past the 1k line.

use shekyl_chain_rules::{ChainView, RuleSet};
use shekyl_types::BlockHeight;

use super::connect_fixtures::{candidate, connect_chain, facts, judge};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

fn expect_row<T: core::fmt::Debug + PartialEq>(out: &Result<T, TestErr>, want: StoreInvariant) {
    assert_eq!(
        *out,
        Err(TestErr::Store(StoreError::from(want).to_string())),
        "{want}"
    );
}

#[test]
fn a_corrupt_seen_by_the_validator_poisons_the_batch_and_halts_the_writer() {
    // The pipeline shape: read the branded view, get `Fault::Corrupt` back
    // from `validate`, hand it in. The store did not see the violation; it
    // supplies the consequence — poison, no commit, writer halted at the
    // connecting height the view read noted (§3.6.2).
    let path = tmp("connect-refuse-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new(), Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let _view = batch.chain_view(); // notes tip + 1 = 2
        Err(batch
            .refuse_corrupt(
                shekyl_chain_rules::Corrupt::CumulativeDifficultyNotMonotone {
                    at: BlockHeight::from_raw(1),
                },
            )
            .into())
    });
    expect_row(&out, StoreInvariant::WorkNotIncreasing { height: 1 });
    assert_eq!(StoreInvariant::WorkNotIncreasing { height: 1 }.row(), 10);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row: StoreInvariant::WorkNotIncreasing { height: 1 },
        }
    );
    // Halted means halted: a fresh batch's connect is refused before it
    // reaches the tables.
    let again: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let tip = ChainView::tip(&view)?.expect("two blocks").hash;
        let cand = candidate(2, tip, Vec::new());
        Ok(batch.connect(judge(&view, cand)?, facts(2, 0), RuleSet::GENESIS)?)
    });
    assert!(again.is_err(), "the writer stays halted: {again:?}");
    cleanup(&path);
}

#[test]
fn refusing_a_corrupt_is_chain_work_even_when_nothing_else_in_the_batch_was() {
    // No `chain_view` first: the method notes the connecting height itself,
    // so the halt fires — §3.6.2's "no chain work, no halt" cannot apply to
    // a batch whose chain was just found inconsistent.
    let path = tmp("connect-refuse-corrupt-notes");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        Err(batch
            .refuse_corrupt(
                shekyl_chain_rules::Corrupt::CumulativeDifficultyNotMonotone {
                    at: BlockHeight::ZERO,
                },
            )
            .into())
    });
    expect_row(&out, StoreInvariant::WorkNotIncreasing { height: 0 });
    // The halt reports the connecting height the method noted for itself:
    // one block recorded, so tip + 1 = 1.
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row: StoreInvariant::WorkNotIncreasing { height: 0 },
        }
    );
    cleanup(&path);
}

#[test]
fn a_cumulative_difficulty_overflow_is_the_fold_belt_not_a_new_row() {
    let path = tmp("connect-refuse-corrupt-overflow");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let _view = batch.chain_view();
        Err(batch
            .refuse_corrupt(shekyl_chain_rules::Corrupt::CumulativeDifficultyOverflow)
            .into())
    });
    let overflow = StoreInvariant::FoldOverflow {
        cell: "block_info.cumulative_difficulty",
    };
    expect_row(&out, overflow);
    assert_eq!(overflow.row(), 8);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row: overflow,
        }
    );
    cleanup(&path);
}
