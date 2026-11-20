// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a ban does to a seat, and how a full list makes room.
//!
//! Barring, lifting and eviction are one policy. A covered seat is barred
//! on its rung, a lift returns it as drawable gray on that rung, and a
//! full gray list drops barred seats before drawable or cooling ones. An
//! outstanding draw is not evicted; when it resolves, a ban that covers
//! the address bars it here, so the order of the ban and the outcome does
//! not matter.

use shekyl_draw_rng::RelayRng;
use shekyl_net_address::NetworkAddress;

use shekyl_transport_layer::{BanEntry, BanSet};

use super::{barred, drawable, GrayPhase, Partition, Seat};
use crate::{GRAY_CAP, WHITE_CAP};

impl Partition {
    /// Where an outstanding draw resolves: to `seat`, or barred when a ban
    /// the peer list holds covers it, keeping its rung (a white seat's is
    /// zero). A seat the lists hold is barred exactly when a ban covers it:
    /// the door refuses a covered address, a ban bars what it covers, and
    /// an outstanding draw, the dialer's while the ban arrives, bars here,
    /// so the order of the ban and the outcome does not matter.
    pub(super) fn resolve_draw(&mut self, address: &NetworkAddress, seat: Seat, bans: &BanSet) {
        let covered = address.ip().is_some_and(|ip| bans.covers(ip));
        let seat = match seat {
            Seat::Gray { failures, .. } if covered => barred(failures),
            Seat::White { .. } if covered => barred(0),
            seat => seat,
        };
        self.move_seat(address, seat);
    }

    /// A ban event the peer list newly holds: bar every seat `entry`
    /// covers. A white seat moves straight to barred gray on rung zero,
    /// with no eviction: gray may sit over its cap until the next gray
    /// insert evicts, as it does for outstanding draws, and the overshoot
    /// is bounded by [`WHITE_CAP`]. Returns how many seats were barred now;
    /// an outstanding draw is counted when its outcome bars it
    /// ([`Self::resolve_draw`]).
    pub(crate) fn ban(&mut self, entry: BanEntry) -> usize {
        let covered: Vec<(NetworkAddress, Seat)> = self
            .seats
            .iter()
            .filter(|(address, _)| address.ip().is_some_and(|ip| entry.covers(ip)))
            .map(|(address, seat)| (address.clone(), *seat))
            .collect();
        let mut barred_now = 0;
        for (address, seat) in covered {
            match seat {
                Seat::White { .. } => {
                    self.move_seat(&address, barred(0));
                    barred_now += 1;
                }
                Seat::Gray {
                    phase: GrayPhase::Drawable,
                    failures,
                    ..
                } => {
                    self.move_seat(&address, barred(failures));
                    barred_now += 1;
                }
                Seat::Gray {
                    phase: GrayPhase::Outstanding | GrayPhase::Barred,
                    ..
                } => {}
            }
        }
        barred_now
    }

    /// A lift event the peer list has dropped: return as drawable gray, on
    /// its rung, every barred seat `entry` covered that no entry in
    /// `remaining` covers. A host lifted inside a banned subnet stays barred
    /// until the subnet's lift. Returns how many seats became drawable.
    pub(crate) fn lift(&mut self, entry: BanEntry, remaining: &BanSet) -> usize {
        let freed: Vec<(NetworkAddress, u32)> = self
            .seats
            .iter()
            .filter_map(|(address, seat)| match seat {
                Seat::Gray {
                    phase: GrayPhase::Barred,
                    failures,
                    ..
                } if address.ip().is_some_and(|ip| entry.covers(ip)) => {
                    Some((address.clone(), *failures))
                }
                _ => None,
            })
            .filter(|(address, _)| !address.ip().is_some_and(|ip| remaining.covers(ip)))
            .collect();
        for (address, failures) in &freed {
            self.move_seat(address, drawable(*failures));
        }
        freed.len()
    }

    /// Drop gray seats until the gray population is within [`GRAY_CAP`],
    /// never `keep` and never an outstanding draw. Barred seats go first,
    /// a uniform pick among them: none can be dialled while its ban holds,
    /// and no peer can make a ban (#1250 deleted the C++ automatic ban, the
    /// only peer-driven writer), so the order cannot be steered (Rick,
    /// 2026-11-01). Then a uniform pick over the drawable and the cooling
    /// seats alike: a cooldown is a delay, not protection (Rick,
    /// 2026-10-24), or dead addresses fed within D-S1 would accumulate
    /// immune to eviction and push the honest ones out. Stops when the only
    /// evictable seat left is `keep`: gray may then sit over the cap by the
    /// outstanding draws.
    pub(super) fn evict_gray_over_cap<R: RelayRng + ?Sized>(
        &mut self,
        keep: &NetworkAddress,
        rng: &mut R,
    ) {
        while self.occupied_gray() > GRAY_CAP {
            let keep_is_barred = matches!(
                self.seat_of(keep),
                Some(Seat::Gray {
                    phase: GrayPhase::Barred,
                    ..
                })
            );
            if another(self.barred, keep_is_barred) {
                let victim = self.pick_accepted(rng, |address, seat| {
                    matches!(
                        seat,
                        Seat::Gray {
                            phase: GrayPhase::Barred,
                            ..
                        }
                    ) && address != keep
                });
                self.leave(&victim);
                continue;
            }
            let keep_is_evictable = matches!(
                self.seat_of(keep),
                Some(Seat::Gray {
                    phase: GrayPhase::Drawable | GrayPhase::Barred,
                    ..
                })
            );
            if !another(
                self.drawable_gray + self.cooling + self.barred,
                keep_is_evictable,
            ) {
                break;
            }
            let victim = self.pick_accepted(rng, |address, seat| {
                matches!(
                    seat,
                    Seat::Gray {
                        phase: GrayPhase::Drawable | GrayPhase::Barred,
                        ..
                    }
                ) && address != keep
            });
            self.leave(&victim);
        }
    }

    /// Demote white until it is within [`WHITE_CAP`], never `keep`.
    pub(super) fn evict_white_over_cap<R: RelayRng + ?Sized>(
        &mut self,
        keep: &NetworkAddress,
        rng: &mut R,
    ) {
        while self.white_seats > WHITE_CAP {
            let keep_is_white = matches!(self.seat_of(keep), Some(Seat::White { .. }));
            if !another(self.white_seats, keep_is_white) {
                break;
            }
            let victim = self.pick_accepted(rng, |address, seat| {
                matches!(seat, Seat::White { .. }) && address != keep
            });
            self.demote(&victim, rng);
        }
    }
}

/// Whether a kind with `kind_count` members has one that is not `keep`.
/// `keep_is_this_kind` is false when `keep` sits somewhere else, or nowhere.
fn another(kind_count: usize, keep_is_this_kind: bool) -> bool {
    match kind_count {
        0 => false,
        1 => !keep_is_this_kind,
        _ => true,
    }
}
