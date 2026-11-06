// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The support stream's seats on the connect path (`SO-D12` 4b §5.1 item
//! 3; `ARCHIVAL_SUPPORT_DRAW.md` §2, §5).
//!
//! A block's seats are the complete trees its epoch's schedule puts on
//! that height: the support members of the epoch snapshot
//! ([`DrawableEpoch::support_roster`], filed at `h_open(E)` with `D`,
//! `SO-D12` S1 ruled 2026-11-01), each at the `c` offsets
//! [`support_seated_at`] names. The transition writes them as the block's
//! row. Admission requires the stored row to equal that value (SI-43,
//! [`shekyl_types::archival::SupportSeats::first_one_sided`]): one function
//! for the schedule, and the row type names where two rows differ, so the
//! writer and the check cannot drift. A member the schedule does not seat
//! is not the row. The carry is staged and off this path; when it joins
//! the transition, the seats that join are the value the comparison takes,
//! and the comparison stays equality.
//!
//! Only scheduled seats are on the connect path before the switch. A seat
//! carried from an unfiled block joins with admission (G3 of the item's
//! brief): until then nothing is admitted on chain, every scheduled seat
//! would read as unfiled, and every tree would be carried onto nearly
//! every block.

use shekyl_archival_retention::{support_seated_at, DrawableEpoch};
use shekyl_types::archival::SupportSeats;
use shekyl_types::BlockHeight;

use crate::fault::{Corrupt, DrawableEpochFault};
use crate::SettlementSchedule;

/// The support members of `drawable` that `schedule` seats at `h`, in
/// persona order. `drawable` is the snapshot of `h`'s epoch.
///
/// Empty when the schedule has no response window (the seats are spread
/// over `SEB − W₂`), when the epoch has no roster (no closed shard at
/// `h_open(E)`) or no member, and at every height a member's offsets miss.
///
/// # Errors
///
/// [`Corrupt::DrawableEpoch`] with [`DrawableEpochFault::OtherEpoch`] when
/// `drawable` is not the snapshot of `h`'s epoch. The caller resolves the
/// snapshot for that epoch, so a mismatch is this node's state, never the
/// block's: the writer halts (SI-30) rather than seat another epoch's
/// members.
pub fn scheduled_seats(
    drawable: &DrawableEpoch,
    h: BlockHeight,
    schedule: SettlementSchedule,
) -> Result<SupportSeats, Corrupt> {
    let epoch = schedule.epoch_at(h);
    if drawable.epoch() != epoch {
        return Err(Corrupt::DrawableEpoch {
            epoch,
            why: DrawableEpochFault::OtherEpoch {
                held: drawable.epoch(),
            },
        });
    }
    // No roster: the archive had no closed shard at `h_open(E)`, so this
    // epoch has no support stream.
    let (Some(roster), Some(window)) = (
        drawable.support_roster(),
        schedule.challenge_response_blocks(),
    ) else {
        return Ok(SupportSeats::EMPTY);
    };
    // `epoch_at(h)` is the epoch whose open is at or below `h`.
    let relative = h.to_raw() - schedule.open_height(epoch.to_raw());
    let seb = schedule.blocks().get();
    let seated = roster
        .members()
        .iter()
        .map(|(persona, _)| *persona)
        .filter(|persona| support_seated_at(persona, relative, seb, window.get()))
        .collect();
    Ok(SupportSeats::new(seated).expect("the snapshot keeps its members in persona order"))
}

#[cfg(test)]
#[path = "support_seats_tests.rs"]
mod tests;
