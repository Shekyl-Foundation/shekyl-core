// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Seats in the arrival window.
//!
//! The window is how many arrivals the service holds before they are
//! answered. Three origins share it:
//!
//! - [`Kind::Local`] — a block this node mined, or one submitted to it.
//!   It may use the reserved seat. Local and unsolicited arrivals together
//!   hold at most the unsolicited share plus the reserve, so a flood of
//!   submissions cannot lock sync out either.
//! - [`Kind::Solicited`] — a span this node asked for. It may use every
//!   seat except the reserve.
//! - [`Kind::Unsolicited`] — a block a peer sent unasked. It may use at
//!   most half of the seats that are not reserved, so a burst cannot fill
//!   the window and lock sync out.
//!
//! [`Room::solicited_available`] is what a sync caller can send. A local
//! arrival waits for its seat asynchronously ([`Room::wait_local`]): a
//! waiter holds no thread, so any number of submitters cannot take the
//! blocking threads the arrival holding the seat needs to finish.

use std::sync::{Arc, Mutex, PoisonError};

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

/// Seats local and unsolicited arrivals may hold together at `capacity`:
/// the unsolicited share plus the reserve, and at least one, so a window
/// of one still takes this node's own block (module docs).
const fn foreign_cap_for(capacity: usize) -> usize {
    let cap = unsolicited_cap_for(capacity) + reserve_for(capacity);
    if cap == 0 {
        1
    } else {
        cap
    }
}

struct Seats {
    reserve: usize,
    unsolicited_cap: usize,
    foreign_cap: usize,
    free: usize,
    unsolicited: usize,
    local: usize,
    closed: bool,
}

/// The arrival window (module docs).
pub(crate) struct Room {
    /// Seats the window was opened with. A span longer than this cannot fit.
    capacity: usize,
    seats: Mutex<Seats>,
    /// Woken when a seat is given back or the window closes.
    changed: tokio::sync::Notify,
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
            capacity,
            seats: Mutex::new(Seats {
                reserve: reserve_for(capacity),
                unsolicited_cap: unsolicited_cap_for(capacity),
                foreign_cap: foreign_cap_for(capacity),
                free: capacity,
                unsolicited: 0,
                local: 0,
                closed: false,
            }),
            changed: tokio::sync::Notify::new(),
        })
    }

    /// Seats the window was opened with.
    #[must_use]
    pub(crate) fn window(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Seats> {
        self.seats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Close the window and wake every waiter.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_waiters();
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

    /// Wait until a local seat is free (`true`) or the window is closed
    /// (`false`). The waiter registers before it looks, so a seat given
    /// back between the look and the wait still wakes it.
    pub(crate) async fn wait_local(&self) -> bool {
        loop {
            let changed = self.changed.notified();
            let mut changed = std::pin::pin!(changed);
            changed.as_mut().enable();
            {
                let seats = self.lock();
                if seats.closed {
                    return false;
                }
                if fits(&seats, &[Kind::Local]) {
                    return true;
                }
            }
            changed.await;
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
        match kind {
            Kind::Unsolicited => seats.unsolicited -= 1,
            Kind::Local => seats.local -= 1,
            Kind::Solicited => {}
        }
        drop(seats);
        self.changed.notify_waiters();
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
        && seats.unsolicited + seats.local + unsolicited + local <= seats.foreign_cap
        && other <= seats.free.saturating_sub(seats.reserve)
        && local + other <= seats.free
}

fn take(seats: &mut Seats, kinds: &[Kind]) {
    for kind in kinds {
        seats.free -= 1;
        match kind {
            Kind::Unsolicited => seats.unsolicited += 1,
            Kind::Local => seats.local += 1,
            Kind::Solicited => {}
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
        assert_eq!(room.window(), 32);
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

    /// Submitted blocks are local too, and a flood of them cannot fill the
    /// window: with the unsolicited share they hold at most half the
    /// non-reserved seats plus the reserve, and sync keeps the rest.
    #[test]
    fn local_arrivals_cannot_lock_sync_out() {
        let room = Room::new(32);
        let mut local = Vec::new();
        for _ in 0..16 {
            local.push(
                room.try_take(&[Kind::Local])
                    .expect("the share plus the reserve"),
            );
        }
        assert!(
            room.try_take(&[Kind::Local]).is_none(),
            "the seventeenth submission does not fill the window"
        );
        assert!(
            room.try_take(&[Kind::Unsolicited]).is_none(),
            "local and unsolicited share the cap"
        );
        assert_eq!(room.solicited_available(), 15, "sync keeps its seats");
        let sync: Vec<_> = (0..15)
            .map(|_| room.try_take(&[Kind::Solicited]).expect("a sync seat"))
            .collect();
        drop((local, sync));
        assert_eq!(room.solicited_available(), 31);
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

    #[tokio::test]
    async fn closing_wakes_a_local_waiter_with_nothing_to_take() {
        let room = Room::new(2);
        let held = room
            .try_take(&[Kind::Solicited, Kind::Local])
            .expect("both");
        let waiting = {
            let room = Arc::clone(&room);
            tokio::spawn(async move { room.wait_local().await })
        };
        tokio::task::yield_now().await;
        room.close();
        assert!(!waiting.await.expect("joins"), "closed, not seated");
        assert!(room.try_take(&[Kind::Local]).is_none());
        drop(held);
        assert_eq!(room.solicited_available(), 0);
    }
}
