// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Seats in the arrival window.
//!
//! The window is how many arrivals the service holds before they are
//! answered. Three origins share it:
//!
//! - [`Kind::Local`] — a block this node mined. It may use the reserved
//!   seat.
//! - [`Kind::Solicited`] — a span this node asked for. It may use every
//!   seat except the reserve.
//! - [`Kind::Unsolicited`] — a block a peer sent unasked. It may use at
//!   most half of the seats that are not reserved, so a burst cannot fill
//!   the window and lock sync out.
//!
//! [`Room::solicited_available`] is what a sync caller can send. A local
//! arrival waits, on the miner's own thread, when its seat is held.

use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// Where an arrival's seat comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// This node mined it, or submitted it.
    Local,
    /// A peer sent it because this node asked.
    Solicited,
    /// A peer sent it unasked.
    Unsolicited,
}

/// The share of the non-reserved window an unsolicited burst may fill.
const UNSOLICITED_SHARE_DENOMINATOR: usize = 2;

/// Seats kept for a block this node mined, when the window holds more than
/// one arrival. A window of one has no reserve: the one seat still accepts.
const fn reserve_for(capacity: usize) -> usize {
    if capacity > 1 {
        1
    } else {
        0
    }
}

/// Unsolicited seats at `capacity` (module docs).
const fn unsolicited_cap_for(capacity: usize) -> usize {
    capacity.saturating_sub(reserve_for(capacity)) / UNSOLICITED_SHARE_DENOMINATOR
}

struct Seats {
    reserve: usize,
    unsolicited_cap: usize,
    free: usize,
    unsolicited: usize,
    closed: bool,
}

/// The arrival window (module docs).
pub(crate) struct Room {
    seats: Mutex<Seats>,
    changed: Condvar,
}

/// One held seat. Dropping it gives the seat back and wakes a waiter.
pub(crate) struct Seat {
    room: Arc<Room>,
    kind: Kind,
}

impl Room {
    /// A window of `capacity` seats.
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            seats: Mutex::new(Seats {
                reserve: reserve_for(capacity),
                unsolicited_cap: unsolicited_cap_for(capacity),
                free: capacity,
                unsolicited: 0,
                closed: false,
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Seats> {
        self.seats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Close the window and wake every waiter.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// Whether [`close`](Self::close) has run.
    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Seats a solicited caller can take now. Zero when the window is
    /// closed. Unsolicited holdings already count against `free`.
    #[must_use]
    pub(crate) fn solicited_available(&self) -> usize {
        let seats = self.lock();
        if seats.closed {
            return 0;
        }
        seats.free.saturating_sub(seats.reserve)
    }

    /// Take one seat per entry of `kinds`, or none.
    pub(crate) fn try_take(self: &Arc<Self>, kinds: &[Kind]) -> Option<Vec<Seat>> {
        let mut seats = self.lock();
        if !fits(&seats, kinds) {
            return None;
        }
        take(&mut seats, kinds);
        drop(seats);
        Some(self.seats_for(kinds))
    }

    /// Block until a local seat is free, or the window is closed.
    pub(crate) fn wait_local(&self) {
        let mut seats = self.lock();
        while !seats.closed && !fits(&seats, &[Kind::Local]) {
            seats = self
                .changed
                .wait(seats)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn seats_for(self: &Arc<Self>, kinds: &[Kind]) -> Vec<Seat> {
        kinds
            .iter()
            .map(|&kind| Seat {
                room: Arc::clone(self),
                kind,
            })
            .collect()
    }

    fn release(&self, kind: Kind) {
        let mut seats = self.lock();
        seats.free += 1;
        if kind == Kind::Unsolicited {
            seats.unsolicited -= 1;
        }
        drop(seats);
        self.changed.notify_all();
    }
}

/// `kinds` fit in `seats` now.
fn fits(seats: &Seats, kinds: &[Kind]) -> bool {
    if seats.closed {
        return false;
    }
    let mut local = 0usize;
    let mut other = 0usize;
    let mut unsolicited = 0usize;
    for kind in kinds {
        match kind {
            Kind::Local => local += 1,
            Kind::Solicited => other += 1,
            Kind::Unsolicited => {
                other += 1;
                unsolicited += 1;
            }
        }
    }
    seats.unsolicited + unsolicited <= seats.unsolicited_cap
        && other <= seats.free.saturating_sub(seats.reserve)
        && local + other <= seats.free
}

fn take(seats: &mut Seats, kinds: &[Kind]) {
    for kind in kinds {
        seats.free -= 1;
        if *kind == Kind::Unsolicited {
            seats.unsolicited += 1;
        }
    }
}

impl Drop for Seat {
    fn drop(&mut self) {
        self.room.release(self.kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserve_and_the_unsolicited_cap_follow_the_window() {
        let room = Room::new(32);
        assert_eq!(room.solicited_available(), 31);
        let mut unsolicited = Vec::new();
        for _ in 0..15 {
            unsolicited.push(
                room.try_take(&[Kind::Unsolicited])
                    .expect("half of the non-reserved seats"),
            );
        }
        assert!(
            room.try_take(&[Kind::Unsolicited]).is_none(),
            "the sixteenth announcement does not fill the window"
        );
        assert!(room.solicited_available() >= 1, "sync still has a seat");
        assert!(
            room.try_take(&[Kind::Local]).is_some(),
            "a mined block can use the reserve"
        );
    }

    #[test]
    fn a_window_of_one_still_accepts_and_keeps_no_reserve() {
        let room = Room::new(1);
        assert_eq!(room.solicited_available(), 1);
        assert!(room.try_take(&[Kind::Unsolicited]).is_none());
        let held = room.try_take(&[Kind::Solicited]).expect("the one seat");
        assert!(room.try_take(&[Kind::Local]).is_none());
        drop(held);
        assert!(room.try_take(&[Kind::Local]).is_some());
    }

    #[test]
    fn closing_wakes_a_local_waiter_with_nothing_to_take() {
        let room = Room::new(2);
        let held = room.try_take(&[Kind::Local, Kind::Local]).expect("both");
        let waiting = {
            let room = Arc::clone(&room);
            std::thread::spawn(move || room.wait_local())
        };
        room.close();
        waiting.join().expect("joins");
        assert!(room.try_take(&[Kind::Local]).is_none());
        drop(held);
        assert_eq!(room.solicited_available(), 0);
    }
}
