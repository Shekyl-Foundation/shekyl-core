// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The draw-count rows the archival writer stores (`SO-D12` increment 3).
//!
//! A child of `archival_write_tests` so these tests call that file's
//! `connect_empty` and `pop`. A windowless schedule writes
//! [`BlockDraws::ZERO`] and [`SupportCount::NONE`], and the boundary
//! retires both on the same floor. The next height reads
//! the prior row, and an opening block starts again from [`BlockDraws::ZERO`].
//! A reduction past the shortfall, and a missing prior row, halt the writer
//! through `refuse_corrupt` (SI-33).

use shekyl_archival_retention::{draw_count, draw_horizon};
use shekyl_chain_rules::{BlockDrawsFloor, Corrupt, DrawCountFault, RuleSet};
use shekyl_store_codec::Canonical;
use shekyl_types::archival::{BlockDraws, SupportCount};
use shekyl_types::{BlockCount, BlockHeight};

use crate::apply_policy::ApplyPolicy;

use super::super::connect_fixtures::Grown;
use super::super::store_tests::{cleanup, tmp, TestErr};
use super::super::{ChainStore, Horizons, StoreError, StoreInvariant};
use super::{connect_empty, pair, pop};

fn draws_of(store: &ChainStore, height: BlockHeight, floor: BlockDrawsFloor) -> Option<BlockDraws> {
    store
        .begin_read()
        .expect("read")
        .block_draws(height, floor)
        .expect("the floor admits the read")
}

fn support_of(
    store: &ChainStore,
    height: BlockHeight,
    floor: BlockDrawsFloor,
) -> Option<SupportCount> {
    store
        .begin_read()
        .expect("read")
        .support_block_count(height, floor)
        .expect("the floor admits the read")
}

/// A windowless schedule writes a zero row at every height, including the
/// opening block. The boundary of `B` retires below `(B − 1)·SEB`, and a
/// pop does not put a retired row back. Red edit: skip the row, or retire
/// it through the undo log.
#[test]
fn a_windowless_schedule_writes_a_zero_row_that_the_boundary_retires() {
    let path = tmp("windowless_draws");
    let rules = RuleSet::fakechain(None, pair(2, 1));
    let store = ChainStore::with_horizons(
        &path,
        ApplyPolicy::Full,
        Horizons::new(
            rules.settlement_schedule().blocks(),
            BlockCount::from_raw(1),
            BlockCount::from_raw(1),
        )
        .expect("the cap is inside the epoch"),
    )
    .expect("create");
    let mut grown = Grown::new();
    let zero = BlockDraws::ZERO;
    for height in 0u64..=3 {
        let delta = connect_empty(&store, &mut grown, rules);
        assert_eq!(delta.draws(), zero);
        assert_eq!(delta.support_count(), SupportCount::NONE);
        assert_eq!(
            draws_of(&store, BlockHeight::from_raw(height), BlockDrawsFloor::NONE),
            Some(zero)
        );
        assert_eq!(
            support_of(&store, BlockHeight::from_raw(height), BlockDrawsFloor::NONE),
            Some(SupportCount::NONE)
        );
    }
    pop(&store);
    grown.pop();
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(3), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(3), BlockDrawsFloor::NONE),
        None
    );
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);

    // Height 4 is the boundary of B = 2. Rows strictly below `(2 − 1)·2` go.
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);
    assert_eq!(delta.support_count(), SupportCount::NONE);
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(0), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(0), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(1), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(1), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(2), BlockDrawsFloor::NONE),
        Some(zero)
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(2), BlockDrawsFloor::NONE),
        Some(SupportCount::NONE)
    );
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(4), BlockDrawsFloor::NONE),
        Some(zero)
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(4), BlockDrawsFloor::NONE),
        Some(SupportCount::NONE)
    );

    let floor = BlockDrawsFloor::retired_by(2, rules.settlement_schedule());
    let refused = store
        .begin_read()
        .expect("read")
        .block_draws(BlockHeight::ZERO, floor)
        .unwrap_err();
    assert!(
        matches!(
            refused,
            StoreError::InvariantViolated(StoreInvariant::BlockDrawsReadBelowFloor {
                asked,
                floor: kept
            }) if asked == BlockHeight::ZERO && kept == floor.height().expect("a floor")
        ),
        "{refused:?}"
    );
    let refused_support = store
        .begin_read()
        .expect("read")
        .support_block_count(BlockHeight::ZERO, floor)
        .unwrap_err();
    assert!(
        matches!(
            refused_support,
            StoreError::InvariantViolated(StoreInvariant::BlockDrawsReadBelowFloor {
                asked,
                floor: kept
            }) if asked == BlockHeight::ZERO && kept == floor.height().expect("a floor")
        ),
        "{refused_support:?}"
    );

    pop(&store);
    grown.pop();
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(0), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(4), BlockDrawsFloor::NONE),
        None
    );
    assert_eq!(
        support_of(&store, BlockHeight::from_raw(4), BlockDrawsFloor::NONE),
        None
    );
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);
    assert_eq!(delta.support_count(), SupportCount::NONE);
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(0), BlockDrawsFloor::NONE),
        None
    );
    cleanup(&path);
}

fn plant_draws(path: &std::path::Path, height: BlockHeight, row: BlockDraws) {
    super::super::archival_read_tests::plant(path, |txn| {
        let mut table = txn
            .open_table(crate::schema::ARCHIVAL_BLOCK_DRAWS)
            .expect("the draw table");
        table
            .insert(height.to_raw(), row.encoded().as_encoded())
            .expect("overwrite");
    });
}

/// The count of `h + 1` reads the row at `h`, and an opening block starts
/// from zero even when the row before it carries a shortfall. `|D|` is
/// empty on this chain, so the count is zero and the carry is the prior's.
/// Red edit: recompute from the row the writer just stored, or carry the
/// shortfall across `h_open`.
#[test]
fn the_count_reads_the_prior_row_and_resets_at_the_opening_block() {
    let path = tmp("draw_count_order");
    let rules = RuleSet::fakechain(None, pair(20, 1));
    let horizons = Horizons::new(
        rules.settlement_schedule().blocks(),
        BlockCount::from_raw(4),
        BlockCount::from_raw(1),
    )
    .expect("the cap is inside the epoch");
    let mut grown = Grown::new();
    {
        let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("create");
        connect_empty(&store, &mut grown, rules);
    }
    let planted = BlockDraws {
        count: 4,
        carry: 0x11,
        shortfall: 1000,
        issued_short: 250,
        revealed: false,
    };
    plant_draws(&path, BlockHeight::from_raw(0), planted);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("reopen");
    let delta = connect_empty(&store, &mut grown, rules);
    let window = rules
        .settlement_schedule()
        .challenge_response_blocks()
        .expect("20 blocks has a window of 1")
        .get();
    let (count, carry) = draw_count(0, 750, draw_horizon(1, 20, window), 20, planted.carry)
        .expect("the horizon fits");
    assert_eq!(delta.draws().shortfall, 750);
    assert_eq!(delta.draws().carry, carry);
    assert_eq!(u64::from(delta.draws().count), count);
    assert_eq!(delta.draws().issued_short, 0);
    assert!(!delta.draws().revealed);
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(0), BlockDrawsFloor::NONE),
        Some(planted)
    );

    for _ in 2..=19 {
        connect_empty(&store, &mut grown, rules);
    }
    drop(store);
    let across = BlockDraws {
        count: 9,
        carry: 5,
        shortfall: 999,
        issued_short: 0,
        revealed: false,
    };
    plant_draws(&path, BlockHeight::from_raw(19), across);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("reopen");
    let open = connect_empty(&store, &mut grown, rules);
    assert_eq!(
        open.draws(),
        BlockDraws::ZERO,
        "an opening block does not inherit the shortfall"
    );
    assert_eq!(
        draws_of(&store, BlockHeight::from_raw(19), BlockDrawsFloor::NONE),
        Some(across)
    );
    cleanup(&path);
}

/// SI-33's two count arms, through `refuse_corrupt` as the ingest would
/// hand them on. A missing prior row, and a reduction larger than the
/// stored shortfall. Red edit: clamp the reduction, or treat a missing
/// row as a zero.
#[test]
fn a_count_fault_halts_the_writer_through_refuse_corrupt() {
    let rules = RuleSet::fakechain(None, pair(20, 1));
    let horizons = Horizons::new(
        rules.settlement_schedule().blocks(),
        BlockCount::from_raw(4),
        BlockCount::from_raw(1),
    )
    .expect("the cap is inside the epoch");

    let excess = tmp("draw_count_excess");
    {
        let store =
            ChainStore::with_horizons(&excess, ApplyPolicy::Full, horizons).expect("create");
        let mut grown = Grown::new();
        connect_empty(&store, &mut grown, rules);
        drop(store);
        plant_draws(
            &excess,
            BlockHeight::from_raw(0),
            BlockDraws {
                issued_short: 1,
                ..BlockDraws::ZERO
            },
        );
        let store =
            ChainStore::with_horizons(&excess, ApplyPolicy::Full, horizons).expect("reopen");
        let out: Result<(), TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let Err(corrupt) = grown.judge_empty_or_corrupt(&view, &rules)? else {
                panic!("the count accepted a reduction past the shortfall");
            };
            assert_eq!(
                corrupt,
                Corrupt::DrawCount {
                    height: BlockHeight::from_raw(1),
                    why: DrawCountFault::IssuedExceedsShortfall {
                        issued: 1,
                        shortfall: 0,
                    },
                }
            );
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
            panic!("aborted, not refused");
        };
        assert!(
            refused.contains("issued 1 against a shortfall of 0"),
            "{refused}"
        );
    }
    cleanup(&excess);

    let missing = tmp("draw_count_missing");
    let store = ChainStore::with_horizons(&missing, ApplyPolicy::Full, horizons).expect("create");
    let mut grown = Grown::new();
    connect_empty(&store, &mut grown, rules);
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_BLOCK_DRAWS,
                StoreInvariant::TipMismatch,
            )?
            .remove(0)?;
        let view = batch.chain_view();
        let Err(corrupt) = grown.judge_empty_or_corrupt(&view, &rules)? else {
            panic!("the count accepted a height whose prior row is gone");
        };
        assert_eq!(
            corrupt,
            Corrupt::DrawCount {
                height: BlockHeight::from_raw(1),
                why: DrawCountFault::MissingPrior {
                    prior: BlockHeight::ZERO,
                },
            }
        );
        Err(batch.refuse_corrupt(corrupt).into())
    });
    let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
        panic!("aborted, not refused");
    };
    assert!(
        refused.contains("no draw row is recorded at height 0"),
        "{refused}"
    );
    cleanup(&missing);
}
