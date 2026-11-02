// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The support stream's seats on the connect path (`SO-D12` 4b §5.1 item
//! 3; `ARCHIVAL_SUPPORT_DRAW.md` §2, §5).
//!
//! A block's seats are the complete trees its epoch's schedule puts on
//! that height: the support members of the epoch snapshot
//! ([`DrawableEpoch::support_members`], filed at `h_open(E)` with `D`,
//! `SO-D12` S1 ruled 2026-11-01), each at the `c` offsets
//! [`support_seated_at`] names. The transition writes them as the block's
//! row, and the store's bundle view checks a roster it reads against them
//! (SI-42). One function, so the writer and the check cannot compute
//! different schedules.
//!
//! Only scheduled seats are on the connect path before the switch. A seat
//! carried from an unfiled block joins with admission (G3 of the item's
//! brief): until then nothing is admitted on chain, every scheduled seat
//! would read as unfiled, and every tree would be carried onto nearly
//! every block.

use shekyl_archival_retention::{support_seated_at, DrawableEpoch};
use shekyl_types::archival::SupportSeats;
use shekyl_types::BlockHeight;

use crate::SettlementSchedule;

/// The support members of `drawable` that `schedule` seats at `h`, in
/// persona order. `drawable` is the snapshot of `h`'s epoch.
///
/// Empty when the schedule has no response window (the seats are spread
/// over `SEB − W₂`), when the epoch has no member, and at every height a
/// member's offsets miss.
///
/// # Panics
///
/// If `drawable` is not the snapshot of `h`'s epoch. The caller resolves it
/// for that epoch, so a mismatch is a defect, not a chain state.
#[must_use]
pub fn scheduled_seats(
    drawable: &DrawableEpoch,
    h: BlockHeight,
    schedule: SettlementSchedule,
) -> SupportSeats {
    let epoch = schedule.epoch_at(h);
    assert_eq!(
        drawable.epoch(),
        epoch,
        "the seats of {h} read the snapshot of its own epoch"
    );
    let Some(window) = schedule.challenge_response_blocks() else {
        return SupportSeats::EMPTY;
    };
    let open = schedule.open_height(epoch.to_raw());
    let relative = h
        .to_raw()
        .checked_sub(open)
        .expect("a block is at or after its epoch's open");
    let seb = schedule.blocks().get();
    let seated = drawable
        .support_members()
        .iter()
        .map(|(persona, _)| *persona)
        .filter(|persona| support_seated_at(persona, relative, seb, window.get()))
        .collect();
    SupportSeats::new(seated).expect("the snapshot keeps its members in persona order")
}

#[cfg(test)]
#[path = "support_seats_tests.rs"]
mod tests;
