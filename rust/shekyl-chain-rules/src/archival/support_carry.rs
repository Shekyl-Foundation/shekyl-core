// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The support stream's carry: a scheduled support draw the producer did
//! not file is re-seated later in the same epoch (`ARCHIVAL_SUPPORT_DRAW.md`
//! §2; `SO-D12` S2, ruled 2026-11-01, option 1).
//!
//! **STAGED.** Nothing on the connect path calls this. It joins the
//! transition with admission at the switch (`SO-D12` 4b §5.3): before
//! then nothing is admitted on chain, so every scheduled seat would read
//! as unfiled and every tree would be carried onto nearly every block (G3
//! of item 3's brief). Named consumer: the switch's transition, which
//! writes the carried seats in the block's seat row and the counters in
//! `archival_support_unissued`. Falsifier:
//! `nothing_on_the_connect_path_calls_the_bundle_verifier`, which lists
//! [`seats_with_carry`] and [`SupportCarry`].
//!
//! # The rule
//!
//! - A seat at `h` is **unfiled** when `h`'s bundle is not admitted by the
//!   time `h`'s window closes. The transition first sees that at
//!   `h + W₂ + 1`, the block whose step is handed `h`'s seats as
//!   [`WindowClosed`]. Each unfiled seat adds one to its tree's count,
//!   capped at `c` ([`SupportUnissued::note_unfiled`]).
//! - A tree with a count above zero gets one **carried seat** at each later
//!   block of the same epoch whose own window still closes inside the
//!   epoch (offset below `SEB − W₂`) and where the schedule does not seat
//!   it already: one seat per tree per block. Seating takes one off the
//!   count ([`SupportUnissued::reseated`]).
//! - A carried seat that again goes unfiled is carried again: it is in its
//!   block's seats, so its close counts it like any other.
//! - Whatever is still counted when the epoch's usable span ends **lapses**,
//!   like an unrevealed draw: not a miss. A window that closes in the next
//!   epoch adds nothing to it; each epoch's draws settle in that epoch's
//!   row and retire with it.
//!
//! The count is what the tree is owed: unfiled seats not yet re-seated.
//! It cannot pass `c`, because a tree has at most `c` scheduled seats and
//! a re-seat takes one off before its own close can add one back.

use std::collections::BTreeMap;

use shekyl_archival_retention::{support_span, DrawableEpoch, SupportUnissued};
use shekyl_types::archival::SupportSeats;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};

use crate::fault::Corrupt;
use crate::{scheduled_seats, SettlementSchedule};

/// One epoch's carry over that epoch's snapshot: each tree's count of
/// unfiled seats not yet re-seated. The value the switch's transition keeps
/// in `archival_support_unissued[(persona, epoch)]`.
///
/// The carry holds the snapshot it is for, so a carry and a snapshot of
/// two epochs cannot meet in one step: the carry's epoch is its snapshot's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportCarry<'s> {
    snapshot: &'s DrawableEpoch,
    owed: BTreeMap<PCanonicalId, SupportUnissued>,
}

/// The seats of the block whose window closes at the block being stepped,
/// `h − W₂ − 1`, and whether its bundle was admitted in time.
#[derive(Clone, Copy, Debug)]
pub struct WindowClosed<'a> {
    /// That block's seats, carried ones included, as its row holds them.
    pub seats: &'a SupportSeats,
    /// Whether its bundle was admitted by the close. An admitted bundle
    /// files every seat, passed or not.
    pub filed: bool,
}

impl<'s> SupportCarry<'s> {
    /// The carry of `snapshot`'s epoch at its open: nothing owed.
    #[must_use]
    pub const fn open(snapshot: &'s DrawableEpoch) -> Self {
        Self {
            snapshot,
            owed: BTreeMap::new(),
        }
    }

    /// The epoch this carry is for: its snapshot's.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.snapshot.epoch()
    }

    /// What `persona` is owed now.
    #[must_use]
    pub fn owed(&self, persona: &PCanonicalId) -> SupportUnissued {
        self.owed
            .get(persona)
            .copied()
            .unwrap_or(SupportUnissued::zero())
    }

    /// Every tree owed anything, ascending by persona. At the end of the
    /// usable span this is what lapses.
    pub fn owing(&self) -> impl Iterator<Item = (&PCanonicalId, SupportUnissued)> {
        self.owed
            .iter()
            .filter(|(_, owed)| owed.get() > 0)
            .map(|(persona, owed)| (persona, *owed))
    }
}

/// The seats of the block at `h` under the carry, in persona order: the
/// schedule's seats, and one carried seat for each member owed a draw that
/// the schedule does not seat here, while `h` is inside the usable span.
/// `closed` is the block whose window closes at `h`; its unfiled seats are
/// counted first, so a draw unfiled at `h − W₂ − 1` can be re-seated at
/// `h`.
///
/// `carry` is the carry of `h`'s epoch, over that epoch's snapshot.
///
/// # Errors
///
/// [`Corrupt::DrawableEpoch`] when `carry` is over another epoch's
/// snapshot ([`scheduled_seats`]'s check): this node's state, never the
/// block's, so the writer halts rather than seat another epoch's members.
pub fn seats_with_carry(
    carry: &mut SupportCarry<'_>,
    h: BlockHeight,
    schedule: SettlementSchedule,
    closed: Option<WindowClosed<'_>>,
) -> Result<SupportSeats, Corrupt> {
    let snapshot = carry.snapshot;
    let scheduled = scheduled_seats(snapshot, h, schedule)?;
    let Some(window) = schedule.challenge_response_blocks() else {
        return Ok(scheduled);
    };
    let window = window.get();
    let seb = schedule.blocks().get();
    // `scheduled_seats` checked that `h` is in the carry's epoch, whose
    // open is at or below it.
    let relative = h.to_raw() - schedule.open_height(carry.epoch().to_raw());

    // The block whose window closes here, if it is in this epoch. One in
    // the epoch before belongs to that epoch's row, where it lapsed.
    if let Some(closed) = closed {
        let closes_in_epoch = relative.checked_sub(window + 1).is_some();
        if closes_in_epoch && !closed.filed {
            for persona in closed.seats.as_slice() {
                let owed = carry.owed(persona).note_unfiled();
                carry.owed.insert(*persona, owed);
            }
        }
    }

    let usable = support_span(seb, window).is_some_and(|span| relative < span);
    if !usable {
        return Ok(scheduled);
    }
    let mut seats = scheduled.as_slice().to_vec();
    let members = snapshot
        .support_roster()
        .map_or(&[][..], shekyl_archival_retention::SupportRoster::members);
    for (persona, _) in members {
        let owed = carry.owed(persona);
        if owed.get() == 0 || scheduled.as_slice().binary_search(persona).is_ok() {
            continue;
        }
        carry.owed.insert(*persona, owed.reseated());
        seats.push(*persona);
    }
    seats.sort_unstable();
    Ok(SupportSeats::new(seats).expect("members and the schedule are one persona each"))
}

#[cfg(test)]
#[path = "support_carry_tests.rs"]
mod tests;
