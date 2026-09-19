// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for CEN-D4 and CEN-D6 (`CHAIN_RULES_SLICE_2.md` §5): the
//! genesis constant below `N`, the window assembly past it (checked
//! against the one implementation over the same series — what "adopted"
//! means), monotonicity observed from the validator's side, the
//! cumulative fold, and the type that refuses zero.

use super::*;
use crate::harness::fixture::{recorded, recorded_with_work, root};
use crate::harness::{Faulted, FaultingView, MockChain};
use shekyl_difficulty::{GENESIS_DIFFICULTY, N};

/// A chain of `len` blocks whose timestamps and work follow a non-uniform
/// series, so a window assembled from the wrong heights or in the wrong
/// order produces a different LWMA-1 output.
fn worked_chain(len: usize) -> (MockChain, Vec<Timestamp>, Vec<CumulativeDifficulty>) {
    let mut timestamps = Vec::with_capacity(len);
    let mut work = Vec::with_capacity(len);
    let mut ts = 1_000u64;
    let mut cum = 0u128;
    let mut chain = MockChain::default();
    for i in 0..len {
        // Solvetimes that vary (60..=180 s) and per-block work that grows.
        ts += 60 + (u64::try_from(i).expect("small") * 37) % 121;
        cum += 400 + u128::try_from(i).expect("small") * 3;
        timestamps.push(Timestamp::from_raw(ts));
        work.push(CumulativeDifficulty::from_raw(cum));
        chain = chain.push(
            recorded_with_work(ts, CumulativeDifficulty::from_raw(cum)),
            root(u8::try_from(i % 250).expect("fits") + 1),
        );
    }
    (chain, timestamps, work)
}

fn target_on(chain: &MockChain) -> (Target, RuleCoverage) {
    let connecting = BlockHeight::from_raw(chain.tip().map_or(0, |t| t.height.to_raw() + 1));
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let target = match D4::target(&view, connecting, &mut coverage) {
            Ok(target) => target,
            Err(fault) => panic!("unexpected fault: {fault}"),
        };
        (target, coverage)
    })
}

// --- CEN-D4 ---------------------------------------------------------------

#[test]
fn cen_d4_genesis_admission_is_the_genesis_constant() {
    let (target, coverage) = target_on(&MockChain::default());
    assert_eq!(
        target.difficulty(),
        Difficulty::from_raw(GENESIS_DIFFICULTY)
    );
    assert!(coverage.contains(CenRow::D4));
    assert!(coverage.contains(CenRow::D6), "the mint records D6");
}

#[test]
fn cen_d4_below_n_blocks_is_the_genesis_constant() {
    // Tip at N − 1 (N blocks recorded): `chain_height = N − 1 < N`.
    let (chain, _, _) = worked_chain(N_USIZE);
    let (target, _) = target_on(&chain);
    assert_eq!(
        target.difficulty(),
        Difficulty::from_raw(GENESIS_DIFFICULTY)
    );
}

#[test]
fn cen_d4_at_n_blocks_the_window_opens_and_matches_the_one_implementation() {
    // Tip at N (N + 1 blocks recorded): the first height whose window is
    // full — heights 0..=N, exactly N + 1 entries.
    let (chain, timestamps, work) = worked_chain(N_USIZE + 1);
    let (target, _) = target_on(&chain);
    let expected =
        lwma1_next(BlockHeight::from_raw(N), &timestamps, &work).expect("a full, monotone window");
    assert_eq!(target.difficulty(), expected);
    assert_ne!(
        expected,
        Difficulty::from_raw(GENESIS_DIFFICULTY),
        "the series is chosen so the window's output is observable"
    );
}

#[test]
fn cen_d4_past_n_the_window_is_the_newest_n_plus_one_oldest_first() {
    // Tip at N + 6: the window is heights 6..=N + 6. A window off by one
    // height, or reversed, yields a different difficulty over this series.
    let len = N_USIZE + 7;
    let (chain, timestamps, work) = worked_chain(len);
    let (target, _) = target_on(&chain);
    let chain_height = len - 1;
    let first = chain_height - N_USIZE;
    let expected = lwma1_next(
        BlockHeight::from_raw(u64::try_from(chain_height).expect("small")),
        &timestamps[first..=chain_height],
        &work[first..=chain_height],
    )
    .expect("full window");
    assert_eq!(target.difficulty(), expected);
    // The negative control on the assembly: the wrong window disagrees.
    let off_by_one = lwma1_next(
        BlockHeight::from_raw(u64::try_from(chain_height).expect("small")),
        &timestamps[first - 1..chain_height],
        &work[first - 1..chain_height],
    )
    .expect("also a full window");
    assert_ne!(
        target.difficulty(),
        off_by_one,
        "the fixture can tell the windows apart"
    );
}

#[test]
fn cen_d4_non_monotone_work_is_a_corrupt_view_not_a_verdict() {
    let (mut chain, _, _) = worked_chain(N_USIZE + 1);
    // Break SI-8 inside the window: a block whose work is below its parent's.
    let at = BlockHeight::from_raw(5);
    chain = chain.push(
        recorded_with_work(9_999_999, CumulativeDifficulty::ZERO),
        root(0xee),
    );
    let _ = at;
    let connecting = BlockHeight::from_raw(chain.tip().expect("blocks").height.to_raw() + 1);
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        match D4::target(&view, connecting, &mut coverage) {
            Err(Fault::Corrupt(Corrupt::CumulativeDifficultyNotMonotone { at })) => {
                assert_eq!(
                    at.to_raw(),
                    connecting.to_raw() - 1,
                    "the offending height is named"
                );
            }
            other => panic!("expected a corrupt-view fault, got {other:?}"),
        }
    });
}

#[test]
fn cen_d4_propagates_a_view_fault() {
    let view = FaultingView::default();
    let mut coverage = RuleCoverage::EMPTY;
    // Past N the window must be read; the first read faults.
    match D4::target(&view, BlockHeight::from_raw(N + 1), &mut coverage) {
        Err(Fault::View(Faulted)) => {}
        other => panic!("expected the view's fault, got {other:?}"),
    }
}

// --- cumulative work ------------------------------------------------------

#[test]
fn cumulative_after_is_the_parents_work_plus_the_target() {
    let (chain, _, work) = worked_chain(3);
    let (target, _) = target_on(&chain);
    let connecting = BlockHeight::from_raw(3);
    let after =
        chain.with_view(|view| D4::cumulative_after(&view, connecting, target).expect("no fault"));
    assert_eq!(
        after.to_raw(),
        work[2].to_raw() + target.difficulty().to_raw()
    );
}

#[test]
fn cumulative_after_genesis_is_the_target_alone() {
    let chain = MockChain::default();
    let (target, _) = target_on(&chain);
    let after = chain.with_view(|view| {
        D4::cumulative_after(&view, BlockHeight::ZERO, target).expect("no fault")
    });
    assert_eq!(after.to_raw(), target.difficulty().to_raw());
}

#[test]
fn cumulative_after_overflow_is_a_corrupt_view() {
    let chain = MockChain::default().push(
        recorded_with_work(1_000, CumulativeDifficulty::from_raw(u128::MAX)),
        root(1),
    );
    let (target, _) = target_on(&chain);
    chain.with_view(
        |view| match D4::cumulative_after(&view, BlockHeight::from_raw(1), target) {
            Err(Fault::Corrupt(Corrupt::CumulativeDifficultyOverflow)) => {}
            other => panic!("expected an overflow fault, got {other:?}"),
        },
    );
}

// --- CEN-D6 ---------------------------------------------------------------

#[test]
fn cen_d6_zero_cannot_become_a_target() {
    let mut coverage = RuleCoverage::EMPTY;
    assert_eq!(
        D6::mint(Difficulty::ZERO, &mut coverage),
        Err(Corrupt::ZeroTarget)
    );
    assert!(
        coverage.contains(CenRow::D6),
        "the row records even when it refuses"
    );
    let target = D6::mint(Difficulty::from_raw(1), &mut coverage).expect("one is a target");
    assert_eq!(target.difficulty(), Difficulty::from_raw(1));
}

#[test]
fn a_recorded_block_with_no_work_is_still_a_valid_short_chain() {
    // `recorded(ts)` records zero work; below N no rule reads it.
    let chain = MockChain::default().push(recorded(1_000), root(1));
    let (target, _) = target_on(&chain);
    assert_eq!(
        target.difficulty(),
        Difficulty::from_raw(GENESIS_DIFFICULTY)
    );
}
