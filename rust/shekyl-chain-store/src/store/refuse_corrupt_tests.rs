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

/// CEN-F20's fault — a `cumulative_tx_count` prefix sum that decreases — is
/// SI-13, armed by the validator's read and halting the writer at the
/// connecting height like the work belt (SI-10) does.
#[test]
fn a_decreasing_tx_count_is_the_fold_belt_observed_by_the_validator() {
    let path = tmp("connect-refuse-corrupt-tx-count");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let _view = batch.chain_view();
        Err(batch
            .refuse_corrupt(shekyl_chain_rules::Corrupt::TxCountNotMonotone {
                at: BlockHeight::from_raw(0),
            })
            .into())
    });
    let row = StoreInvariant::FoldNotMonotone {
        cell: "block_info.cumulative_tx_count",
        height: 0,
    };
    expect_row(&out, row);
    assert_eq!(row.row(), 13);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row,
        }
    );
    cleanup(&path);
}

/// A rule's parent-side read answered `AboveTip` below the connecting
/// height (`Corrupt::HoleBelowTip`, E6 slice 6) is SI-7 — the same
/// `CellCorrupt { block_info, Absent }` row `chain_reads::absent` arms when
/// the store itself finds a dense-range row missing — observed from the
/// rule side this time, and it halts the writer at the connecting height
/// exactly as the other observed-by-the-validator rows do. Pinned here so
/// the arm cannot be remapped to another row, or lose the terminal halt,
/// without this test naming it (#852 review).
#[test]
fn a_hole_below_the_tip_seen_by_the_validator_is_si7_and_halts_the_writer() {
    let path = tmp("connect-refuse-corrupt-hole-below-tip");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new(), Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let _view = batch.chain_view();
        Err(batch
            .refuse_corrupt(shekyl_chain_rules::Corrupt::HoleBelowTip {
                at: BlockHeight::from_raw(1),
                record: shekyl_chain_rules::PerHeightRecord::Block,
            })
            .into())
    });
    let row = StoreInvariant::CellCorrupt {
        key: "block_info",
        fault: CellFault::Absent,
    };
    expect_row(&out, row);
    assert_eq!(row.row(), 7);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row,
        }
    );
    // Halted means halted: the next connect is refused before it reaches
    // the tables.
    let again: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let tip = ChainView::tip(&view)?.expect("two blocks").hash;
        let cand = candidate(2, tip, Vec::new());
        Ok(batch.connect(judge(&view, cand)?, facts(2, 0), RuleSet::GENESIS)?)
    });
    assert!(again.is_err(), "the writer stays halted: {again:?}");
    cleanup(&path);
}

/// The same class, the other record. CEN-I12's root read and the producer's
/// `root_at` both raise `HoleBelowTip` for the curve-tree root; mapping
/// every hole onto `block_info` would halt the writer against the wrong
/// table. The cell is the record's.
#[test]
fn a_missing_root_below_the_tip_is_si7_on_curve_tree_roots() {
    let path = tmp("connect-refuse-corrupt-root-hole");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[Vec::new()]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let _view = batch.chain_view();
        Err(batch
            .refuse_corrupt(shekyl_chain_rules::Corrupt::HoleBelowTip {
                at: BlockHeight::ZERO,
                record: shekyl_chain_rules::PerHeightRecord::CurveTreeRoot,
            })
            .into())
    });
    let row = StoreInvariant::CellCorrupt {
        key: "curve_tree_roots",
        fault: CellFault::Absent,
    };
    expect_row(&out, row);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(1),
            row,
        }
    );
    cleanup(&path);
}

/// A producer read opens a batch and aborts it. The slot is released —
/// `inspect` is not `write`.
#[test]
fn inspect_aborts_so_a_later_write_still_runs() {
    let path = tmp("inspect-aborts");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<Option<BlockHeight>, TestErr> = store.inspect(|batch| {
        let view = batch.chain_view();
        Ok(ChainView::tip(&view)?.map(|t| t.height))
    });
    assert_eq!(out.expect("inspect"), None);
    let again: Result<(), TestErr> = store.write(|_batch| Ok(()));
    assert!(again.is_ok(), "the slot was released: {again:?}");
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

/// Poison inside `inspect` halts the writer and commits nothing, the same
/// latch `write` arms.
#[test]
fn inspect_of_a_hole_halts_the_writer() {
    let path = tmp("inspect-hole-halts");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.inspect(|batch| {
        let _view = batch.chain_view();
        Err(batch
            .refuse_corrupt(shekyl_chain_rules::Corrupt::HoleBelowTip {
                at: BlockHeight::ZERO,
                record: shekyl_chain_rules::PerHeightRecord::Block,
            })
            .into())
    });
    let row = StoreInvariant::CellCorrupt {
        key: "block_info",
        fault: CellFault::Absent,
    };
    expect_row(&out, row);
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::ZERO,
            row,
        }
    );
    let again: Result<(), TestErr> = store.write(|_batch| Ok(()));
    assert!(again.is_err(), "the writer stays halted: {again:?}");
    cleanup(&path);
}
