// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The per-epoch floors against the readers they bound. Arithmetic over the
//! schedule and plain heights, no chain (rule 50, exemption 1): each test
//! sweeps every height of a short schedule and states the reader's own
//! expression beside the floor, so a `LAG` one off in either direction
//! fails here — one too high refuses a read the chain makes, one too low
//! keeps a row no block asks for.

use super::*;
use shekyl_archival_retention::{
    claim_window_floor, settlement_retention_floor, SLASH_GRACE_EPOCHS,
};
use shekyl_types::archival::SettlementEpochBlocks;

const SEB: u64 = 10;
/// Past the claim window by enough epochs that every floor is above zero.
const EPOCHS: u64 = MAX_CLAIM_AGE_W + 8;

fn schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(SEB).expect("non-zero"))
}

fn heights() -> impl Iterator<Item = BlockHeight> {
    (1..EPOCHS * SEB).map(BlockHeight::from_raw)
}

fn kept<F: EpochFamily>(floor: EpochFloor<F>) -> u64 {
    floor.kept_from().map_or(0, SettlementEpoch::to_raw)
}

/// The claim window and the failure window's retention bound are the
/// claimable floor, at every height. Red edit: `LAG = W + 1` — a claim at
/// the window's floor is refused.
#[test]
fn the_claimable_floor_is_the_claim_window_and_the_failure_windows_bound() {
    let schedule = schedule();
    for h in heights() {
        let floor = EpochFloor::<Claimable>::under(h, schedule);
        let epoch = schedule.epoch_at_height(h.to_raw());
        assert_eq!(kept(floor), claim_window_floor(epoch), "at {h:?}");
        assert_eq!(
            kept(floor),
            settlement_retention_floor(schedule, h).to_raw(),
            "at {h:?}"
        );
    }
}

/// The pass of `E` connects at `slash_deadline_height(E)` and reads `E`'s
/// settling rows: exactly the floor there. Red edit: `LAG = k − 1` — the
/// pass is refused its own epoch.
#[test]
fn the_settling_floor_is_the_epoch_its_pass_settles() {
    let schedule = schedule();
    for e in 1..EPOCHS - SLASH_GRACE_EPOCHS - 1 {
        let pass = BlockHeight::from_raw(schedule.slash_deadline_height(e));
        let floor = EpochFloor::<Settling>::under(pass, schedule);
        assert_eq!(kept(floor), e, "the pass of {e}");
    }
}

/// CEN-J15 reads at the watermark as of the parent: the latest epoch whose
/// pass is at or below it. That is never below the pricing floor, and is
/// the floor itself in the first block of an epoch. Red edit: `LAG = k` —
/// that first block's price is refused.
#[test]
fn the_pricing_floor_is_the_lowest_watermark_a_block_reads_at() {
    let schedule = schedule();
    let watermark = |parent: u64| {
        (0..EPOCHS)
            .take_while(|&e| schedule.slash_deadline_height(e) <= parent)
            .last()
    };
    let mut touched = 0;
    for h in heights() {
        let Some(read) = watermark(h.to_raw() - 1) else {
            continue;
        };
        let floor = EpochFloor::<Pricing>::under(h, schedule);
        assert!(floor.retains(SettlementEpoch::from_raw(read)), "at {h:?}");
        if h.to_raw().is_multiple_of(SEB) && floor.kept_from().is_some() {
            assert_eq!(kept(floor), read, "the first block of an epoch, {h:?}");
            touched += 1;
        }
    }
    assert!(touched > 0, "the tight case was reached");
}

/// The batch of `B` retires below the floor of `(B − 1)·SEB + 1`, the
/// lowest height that can connect after it, and every height from there up
/// has a floor at or above it — so a block a reorg re-connects never asks
/// for a retired row. Red edit: retire at `under(boundary)` — the
/// re-connected first block of `B − 1` then reads below what was retired.
#[test]
fn every_height_that_can_follow_a_batch_reads_at_or_above_what_it_retired() {
    fn holds<F: EpochFamily>(schedule: SettlementSchedule) {
        for b in 2..EPOCHS {
            let retired = EpochFloor::<F>::at_boundary(BlockHeight::from_raw(b * SEB), schedule);
            let lowest = BlockHeight::from_raw((b - 1) * SEB + 1);
            assert_eq!(
                EpochFloor::<F>::under(lowest, schedule),
                retired,
                "{}: the lowest re-connectable height of {b}",
                core::any::type_name::<F>()
            );
            for h in (lowest.to_raw()..EPOCHS * SEB).map(BlockHeight::from_raw) {
                assert!(
                    kept(EpochFloor::<F>::under(h, schedule)) >= kept(retired),
                    "{}: {h:?} after the batch of {b}",
                    core::any::type_name::<F>()
                );
            }
        }
    }
    holds::<Claimable>(schedule());
    holds::<Settling>(schedule());
    holds::<Pricing>(schedule());
}

/// A chain younger than a family's reach retires nothing of it, and a
/// floor of nothing retains every epoch.
#[test]
fn a_young_chain_retires_nothing() {
    let schedule = schedule();
    let young = BlockHeight::from_raw(MAX_CLAIM_AGE_W * SEB);
    assert_eq!(
        EpochFloor::<Claimable>::under(young, schedule),
        EpochFloor::NONE
    );
    assert_eq!(
        EpochFloor::<Settling>::at_boundary(BlockHeight::from_raw(SEB), schedule),
        EpochFloor::NONE
    );
    assert!(EpochFloor::<Pricing>::NONE.retains(SettlementEpoch::from_raw(0)));
}

/// The Release journal keeps rows strictly above `h_open` of the settling
/// family's oldest kept epoch. At the pass that settles `E` that open is
/// `E`'s, so the walk starts at the first retained height. Red edit: retire
/// at `h_open` itself — the pass's first journal row is gone.
#[test]
fn the_release_journal_starts_one_above_the_oldest_kept_open() {
    let schedule = schedule();
    for h in heights() {
        let settling = EpochFloor::<Settling>::under(h, schedule);
        let journal = ReleaseJournalFloor::of(settling, schedule);
        match settling.kept_from() {
            None => assert_eq!(journal.height(), None, "at {h:?}"),
            Some(epoch) => assert_eq!(
                journal.height().map(BlockHeight::to_raw),
                Some(schedule.open_height(epoch.to_raw()) + 1),
                "at {h:?}"
            ),
        }
    }
    let epoch = 3;
    let pass = BlockHeight::from_raw(schedule.slash_deadline_height(epoch));
    let at_the_pass =
        ReleaseJournalFloor::of(EpochFloor::<Settling>::under(pass, schedule), schedule);
    assert_eq!(
        at_the_pass.height().map(BlockHeight::to_raw),
        Some(schedule.open_height(epoch) + 1),
        "the pass of {epoch} reads from the first retained height"
    );
}
