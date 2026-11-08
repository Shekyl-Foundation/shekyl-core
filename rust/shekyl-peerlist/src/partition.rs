// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connector's lists.
//!
//! An address has one seat in [`Partition::seats`]. Gray and white are
//! the two values, so an address cannot be on two lists. Gray carries
//! its phase — drawable, an outstanding draw, or barred — and the ladder
//! rung of consecutive failed tests. A [`SeatHold`] on a drawable gray
//! seat is cooling: the seat stays gray and is not drawn until the hold
//! ends. The same hold on white keeps that address off the white draw.
//! Every gray phase is gray to every reader outside this module
//! ([`Partition::is_gray`], the gray count, the snapshot and the file).
//! Eviction will not take an outstanding draw. Only [`crate::Peerlist::apply`]
//! moves one.
//!
//! Barring and eviction are [`ban`]. Disclosure and intake are [`disclose`].
//! Everything here is inside one partition; the connector is the caller's
//! key ([`crate::Peerlist`] derives it from the address type). No method
//! of this module sees another connector's entries.

use std::collections::BTreeMap;

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_net_address::{Host, NetworkAddress};
use shekyl_relay_privacy::ConnectionId;
use shekyl_timing_engine::Tick;

use shekyl_transport_layer::{BanSet, JitteredSpan};

use crate::index::Index;
use crate::outcome::WhiteClock;
use crate::{cooldown_nanos, Cooldown, EXPIRATION_PERIOD_NANOS};

mod ban;
mod disclose;

use disclose::Sample;
pub use disclose::{DiscloseEarly, DiscloseEarlyEnd};

/// Why a seated address is held off the draw, and until when.
///
/// Counted cooling is the ladder: thaw returns the gray seat to the draw
/// on the same rung. An excusal is the judge's hold (`OE-D6`): the next
/// sign of life clears one that carries no counted failure. A white seat's
/// hold is always an excusal — white has no rung to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeatHold {
    /// The judge excused the test.
    Excused { until: Tick },
    /// A counted failure. Gray only.
    Counted { until: Tick },
}

impl SeatHold {
    const fn until(self) -> Tick {
        match self {
            Self::Excused { until } | Self::Counted { until } => until,
        }
    }

    const fn excused(self) -> bool {
        matches!(self, Self::Excused { .. })
    }
}

/// Where a gray address is in its test.
///
/// A drawable seat is evictable whether or not a [`SeatHold`] waits on it.
/// An outstanding draw is not: the dialer has it, and eviction must not
/// cancel the test. A hold is legal only on [`Self::Drawable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrayPhase {
    /// Not drawn. A [`SeatHold`] on this phase is cooling.
    Drawable,
    /// Drawn, not yet reported.
    Outstanding,
    /// Covered by an active ban entry. Ineligible on both lists: never
    /// drawn, in no census or candidate count, refused at the door.
    /// Evictable, so a ban never holds gray over its cap. The lift of the
    /// last entry that covers it returns it as drawable gray on its rung.
    /// Barring drops any hold and keeps the rung.
    Barred,
}

/// Where one address sits. One seat, so gray and white cannot both hold it.
///
/// Gray carries its [`GrayPhase`] and the ladder rung: how many failed
/// tests in a row it has had. The rung survives a thaw and dies when the
/// seat becomes white or the address leaves. Readers outside this module
/// still call every gray phase gray. The clock on white is
/// `last_observed` (brief §4): not a sort key, not a rank. White is
/// reached only from [`Partition::confirm`], which only
/// [`crate::Peerlist::apply`] calls (brief §11.1). No `Deserialize`: the
/// file cannot carry a white entry (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seat {
    /// Unconfirmed. `failures` is the cooldown ladder's rung. `hold` waits
    /// only while the phase is [`GrayPhase::Drawable`].
    Gray {
        phase: GrayPhase,
        failures: u32,
        hold: Option<SeatHold>,
    },
    /// Confirmed by this node's own dial. `observed` is `last_observed`.
    /// `hold` keeps an excused white address off the draw: white has no
    /// counted rung, so without it an excused white address would be
    /// redrawn at once (`DIALER_OUTAGE_EVIDENCE.md` §4.1).
    White {
        observed: Tick,
        hold: Option<SeatHold>,
    },
}

/// Which counter a seat moves, and whether a draw may take it.
///
/// One classification, so the gray draw, the white draw and the counters
/// cannot disagree about a hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SeatClass {
    /// [`GrayPhase::Drawable`] with no hold.
    DrawableGray,
    /// [`GrayPhase::Drawable`] with a hold.
    Cooling,
    /// [`GrayPhase::Outstanding`].
    Outstanding,
    /// [`GrayPhase::Barred`].
    Barred,
    /// White, and not held back.
    White,
    /// White, held off the draw. Counted in the white seats as well.
    HeldWhite,
}

impl Seat {
    /// The one match of phase and hold.
    fn class(self) -> SeatClass {
        match self {
            Self::Gray {
                phase: GrayPhase::Drawable,
                hold: None,
                ..
            } => SeatClass::DrawableGray,
            Self::Gray {
                phase: GrayPhase::Drawable,
                hold: Some(_),
                ..
            } => SeatClass::Cooling,
            Self::Gray {
                phase: GrayPhase::Outstanding,
                ..
            } => SeatClass::Outstanding,
            Self::Gray {
                phase: GrayPhase::Barred,
                ..
            } => SeatClass::Barred,
            Self::White { hold: None, .. } => SeatClass::White,
            Self::White { hold: Some(_), .. } => SeatClass::HeldWhite,
        }
    }

    /// Drawable gray: the phase a draw reads, and no hold waiting on it.
    fn is_drawable_gray(self) -> bool {
        self.class() == SeatClass::DrawableGray
    }

    /// White and not held back. The white draw and the white candidate
    /// filter both read this.
    fn is_drawable_white(self) -> bool {
        self.class() == SeatClass::White
    }

    /// Gray, and a hold keeps it off the draw.
    fn is_cooling(self) -> bool {
        self.class() == SeatClass::Cooling
    }

    fn hold(self) -> Option<SeatHold> {
        match self {
            Self::Gray { hold, .. } | Self::White { hold, .. } => hold,
        }
    }
}

fn white(observed: Tick) -> Seat {
    Seat::White {
        observed,
        hold: None,
    }
}

/// White, held off the draw until `until`. The hold is an excusal.
fn excused_white(observed: Tick, until: Tick) -> Seat {
    Seat::White {
        observed,
        hold: Some(SeatHold::Excused { until }),
    }
}

fn held_gray(phase: GrayPhase, failures: u32, hold: Option<SeatHold>) -> Seat {
    debug_assert!(
        hold.is_none() || matches!(phase, GrayPhase::Drawable),
        "only a drawable gray seat waits"
    );
    Seat::Gray {
        phase,
        failures,
        hold,
    }
}

fn drawable(failures: u32) -> Seat {
    held_gray(GrayPhase::Drawable, failures, None)
}

fn outstanding(failures: u32) -> Seat {
    held_gray(GrayPhase::Outstanding, failures, None)
}

/// A drawable gray seat a hold keeps off the draw, on rung `failures`.
fn cooling(hold: SeatHold, failures: u32) -> Seat {
    held_gray(GrayPhase::Drawable, failures, Some(hold))
}

fn barred(failures: u32) -> Seat {
    held_gray(GrayPhase::Barred, failures, None)
}

/// A hold waits on a drawable gray seat, and a white hold is an excusal.
fn debug_assert_seat(seat: &Seat) {
    debug_assert!(
        match *seat {
            Seat::Gray {
                phase: GrayPhase::Outstanding | GrayPhase::Barred,
                hold,
                ..
            } => hold.is_none(),
            Seat::White {
                hold: Some(hold), ..
            } => hold.excused(),
            Seat::Gray {
                phase: GrayPhase::Drawable,
                ..
            }
            | Seat::White { hold: None, .. } => true,
        },
        "a hold waits on a drawable gray seat, and a white hold is an excusal"
    );
}

/// One connector's seats, its cached sample, and its intake ledger.
#[derive(Debug, Default)]
pub(crate) struct Partition {
    /// Every address this partition holds, each exactly once.
    seats: Index<Seat>,
    /// Drawable gray seats: [`Seat::is_drawable_gray`]. A hold on a drawable
    /// seat is cooling, counted below. Moved only by [`Self::seat_new`],
    /// [`Self::move_seat`] and [`Self::leave`].
    drawable_gray: usize,
    /// Seats whose phase is [`GrayPhase::Outstanding`]. Counted as gray,
    /// never drawn by eviction or by [`Self::draw_gray`]. Same three writers.
    outstanding_draws: usize,
    /// Seats that are white. Same three writers.
    white_seats: usize,
    /// White seats a hold keeps off the draw: counted in `white_seats` and
    /// never drawn. Same three writers. A white hold is an excusal.
    excused_white: usize,
    /// Drawable gray seats a hold keeps off the draw. Same three writers.
    cooling: usize,
    /// Seats whose phase is [`GrayPhase::Barred`]. Same three writers.
    barred: usize,
    /// The cached disclosure sample and when it was drawn (D3).
    sample: Option<Sample>,
    /// This node's own dialable address on this connector, when known: one
    /// uniform member of the disclosure population (the handshake-address
    /// ruling), never a white entry.
    own_address: Option<NetworkAddress>,
    /// Per session, the distinct addresses it has offered and when each
    /// last arrived (D-S1). Pruned to the intake span on every touch.
    intake: BTreeMap<ConnectionId, BTreeMap<NetworkAddress, Tick>>,
    /// `--p2p-disclose-early` on this connector; `None` when never set.
    disclose_early: Option<DiscloseEarly>,
}

impl Partition {
    /// Gray seats that are eligible: drawable, outstanding or cooling. An
    /// outstanding draw is counted: drawing it does not free its seat. A
    /// barred seat is in no count, though it holds a slot under the cap
    /// ([`Self::occupied_gray`]).
    pub(crate) fn gray_len(&self) -> usize {
        self.drawable_gray + self.outstanding_draws + self.cooling
    }

    pub(crate) fn white_len(&self) -> usize {
        self.white_seats
    }

    /// Seats a hold keeps off the draw: cooling gray and excused white.
    ///
    /// Cooling gray is a counted failure or an excusal. Excused white is an
    /// excusal only. Sessions are not this count.
    pub(crate) fn off_draw_len(&self) -> usize {
        self.cooling + self.excused_white
    }

    pub(crate) fn is_gray(&self, address: &NetworkAddress) -> bool {
        matches!(self.seat_of(address), Some(Seat::Gray { .. }))
    }

    /// Whether `address` is gray and cooling: seated, not drawable until
    /// its hold ends.
    pub(crate) fn is_cooling(&self, address: &NetworkAddress) -> bool {
        self.seat_of(address).is_some_and(Seat::is_cooling)
    }

    /// Consecutive counted failed tests stored on the seat: the cooldown's
    /// rung. Zero for an address that is white, unseated, or has not failed
    /// since it last became white. An excused failure leaves it as it is.
    pub(crate) fn failed_tests(&self, address: &NetworkAddress) -> u32 {
        match self.seat_of(address) {
            Some(Seat::Gray { failures, .. }) => failures,
            Some(Seat::White { .. }) | None => 0,
        }
    }

    /// Whether an excused hold waits on the seat: a gray seat cooling from
    /// an excused failure, or a white seat's excusal. A counted hold is
    /// not excused.
    pub(crate) fn is_excused(&self, address: &NetworkAddress) -> bool {
        self.seat_of(address)
            .and_then(Seat::hold)
            .is_some_and(SeatHold::excused)
    }

    pub(crate) fn is_white(&self, address: &NetworkAddress) -> bool {
        matches!(self.seat_of(address), Some(Seat::White { .. }))
    }

    /// Whether the address already has a seat. A seated address is not a
    /// new gray entry and not a new intake charge.
    pub(crate) fn is_seated(&self, address: &NetworkAddress) -> bool {
        self.seats.contains(address)
    }

    pub(crate) fn gray_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::Gray { .. } => Some(address),
            Seat::White { .. } => None,
        })
    }

    pub(crate) fn white_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::White { .. } => Some(address),
            Seat::Gray { .. } => None,
        })
    }

    /// Seat `address` on gray when it sits nowhere.
    ///
    /// Already seated — drawable, outstanding, cooling, or white: left
    /// where it is, and `false`.
    /// Over [`crate::GRAY_CAP`], a uniformly random *other* gray seat, drawable or
    /// cooling alike, is dropped, so the address just admitted stays (brief
    /// §2) and an outstanding draw is not a candidate (brief §5). When the
    /// only evictable seat is the one just admitted, gray sits over the cap
    /// by the outstanding draws rather than cancelling one.
    pub(crate) fn insert_gray<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        rng: &mut R,
    ) -> bool {
        if self.seats.contains(address) {
            return false;
        }
        self.seat_new(address.clone(), drawable(0));
        self.evict_gray_over_cap(address, rng);
        true
    }

    /// One uniform drawable gray address, moved to outstanding. `None`
    /// when every gray seat is already outstanding, or gray is empty.
    pub(crate) fn draw_gray<R: RelayRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        if self.drawable_gray == 0 {
            return None;
        }
        let chosen = self.pick_accepted(rng, |_, seat| seat.is_drawable_gray());
        self.mark_outstanding(&chosen);
        Some(chosen)
    }

    /// The dial candidates of one list, grouped by host: every address
    /// `eligible` admits, under the host it names.
    ///
    /// A host that advertises many ports is one candidate (dialer brief,
    /// "The candidate filter"), so the draw below is uniform over hosts
    /// and then uniform over that host's eligible ports. It is not "the
    /// first port in list order".
    fn candidates_by_host(
        &self,
        white: bool,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
    ) -> BTreeMap<Host, Vec<&NetworkAddress>> {
        let mut hosts: BTreeMap<Host, Vec<&NetworkAddress>> = BTreeMap::new();
        for (address, seat) in self.seats.iter() {
            let of_list = if white {
                seat.is_drawable_white()
            } else {
                seat.is_drawable_gray()
            };
            if of_list && eligible(address) {
                hosts.entry(address.host()).or_default().push(address);
            }
        }
        hosts
    }

    /// How many hosts the candidate draw could return from one list.
    pub(crate) fn candidate_hosts(
        &self,
        white: bool,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
    ) -> usize {
        self.candidates_by_host(white, eligible).len()
    }

    /// One candidate: a host uniform over the hosts with an eligible
    /// address, then that host's port uniform over its eligible ports.
    fn pick_candidate<R: RelayRng + ?Sized>(
        &self,
        white: bool,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let hosts = self.candidates_by_host(white, eligible);
        let last = u64::try_from(hosts.len().checked_sub(1)?).ok()?;
        let at = usize::try_from(bounded_uniform(rng, last)).ok()?;
        let ports = hosts.values().nth(at)?;
        let last = u64::try_from(ports.len().checked_sub(1)?).ok()?;
        let at = usize::try_from(bounded_uniform(rng, last)).ok()?;
        ports.get(at).map(|address| (*address).clone())
    }

    /// One gray candidate, remembered as an outstanding draw. `None` when
    /// no drawable gray address is eligible.
    pub(crate) fn draw_gray_candidate<R: RelayRng + ?Sized>(
        &mut self,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let chosen = self.pick_candidate(false, eligible, rng)?;
        self.mark_outstanding(&chosen);
        Some(chosen)
    }

    /// One white candidate. A re-contact draw, not a promotion.
    pub(crate) fn draw_white_candidate<R: RelayRng + ?Sized>(
        &self,
        eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        self.pick_candidate(true, eligible, rng)
    }

    /// One uniform white address. A re-contact draw, not a promotion.
    pub(crate) fn draw_white<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Option<NetworkAddress> {
        if self.white_seats == self.excused_white {
            return None;
        }
        Some(self.pick_accepted(rng, |_, seat| seat.is_drawable_white()))
    }

    /// A dial this node opened was confirmed.
    ///
    /// One read of the seat, then [`WhiteClock`] where the seat is already
    /// white (brief §5):
    ///
    /// - outstanding: the one white write. The seat becomes white, the
    ///   clock is `now`, and over [`crate::WHITE_CAP`] a uniformly random *other*
    ///   white seat is demoted to gray. `clock` is not consulted.
    /// - already white, [`WhiteClock::Move`]: `last_observed` becomes
    ///   `now`. The seat does not change.
    /// - already white, [`WhiteClock::Hold`]: nothing. A confirm-and-close
    ///   does not extend a white lifetime.
    /// - undrawn gray, or not listed: nothing. A dial of an address that
    ///   was not the draw does not write white (brief §2).
    pub(crate) fn confirm<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        now: Tick,
        bans: &BanSet,
        rng: &mut R,
        clock: WhiteClock,
    ) {
        match (self.seat_of(address), clock) {
            (
                Some(Seat::Gray {
                    phase: GrayPhase::Outstanding,
                    ..
                }),
                _,
            ) => {
                // White carries no rung. The ladder ends with the gray seat.
                self.resolve_draw(address, white(now), bans);
                self.evict_white_over_cap(address, rng);
            }
            (Some(Seat::White { .. }), WhiteClock::Move) => self.write_clock(address, now),
            // A held gray seat is still drawable in phase, and a barred seat
            // was not the draw: neither writes white.
            (Some(Seat::White { .. }), WhiteClock::Hold)
            | (
                Some(Seat::Gray {
                    phase: GrayPhase::Drawable | GrayPhase::Barred,
                    ..
                })
                | None,
                _,
            ) => {}
        }
    }

    /// Stamp `last_observed`. The address is white and answered, so an
    /// excusal it held ends with it.
    fn write_clock(&mut self, address: &NetworkAddress, now: Tick) {
        debug_assert!(
            matches!(self.seat_of(address), Some(Seat::White { .. })),
            "write_clock follows a white seat"
        );
        self.move_seat(address, white(now));
    }

    /// White to gray, on rung zero. The clock is not copied. The entry
    /// then takes the capped gray path (F3, Rick 2026-10-09): over
    /// capacity a uniformly random other gray seat, drawable or cooling,
    /// is dropped. An outstanding draw is not a candidate, so gray may
    /// sit over the cap by those draws.
    pub(crate) fn demote<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        rng: &mut R,
    ) -> bool {
        if !matches!(self.seat_of(address), Some(Seat::White { .. })) {
            return false;
        }
        self.move_seat(address, drawable(0));
        self.evict_gray_over_cap(address, rng);
        true
    }

    /// Drop a tested address: an outstanding gray draw or a white address
    /// leaves the partition. Only a test that proved misbehaviour ends here
    /// (the gray lifecycle; white is known-working, Rick 2026-10-26).
    pub(crate) fn drop_tested(&mut self, address: &NetworkAddress) -> bool {
        if !matches!(
            self.seat_of(address),
            Some(
                Seat::White { .. }
                    | Seat::Gray {
                        phase: GrayPhase::Outstanding,
                        ..
                    }
            )
        ) {
            return false;
        }
        self.leave(address);
        true
    }

    /// A counted failed test ([`crate::Verdict::Counted`]), on the
    /// connector's cooldown ladder `cooldown`. Returns whether the seat moved.
    ///
    /// - **An outstanding gray draw** returns to gray, its consecutive count
    ///   steps, and it cools until `now` plus [`cooldown_nanos`] for that
    ///   rung.
    /// - **A white address** is known-working, so a counted failure moves it
    ///   to gray, cooling at the first rung with a count of one, under the
    ///   gray cap (Rick, 2026-10-26).
    ///
    /// A cooling seat is not drawable until [`Self::thaw`] passes its tick.
    /// Anything else is left as it is.
    pub(crate) fn fail_test<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        now: Tick,
        cooldown: Cooldown,
        bans: &BanSet,
        rng: &mut R,
    ) -> bool {
        let (failures, from_white) = match self.seat_of(address) {
            Some(Seat::Gray {
                phase: GrayPhase::Outstanding,
                failures,
                ..
            }) => (failures.saturating_add(1), false),
            Some(Seat::White { .. }) => (1, true),
            Some(Seat::Gray { .. }) | None => return false,
        };
        let until = Tick::new(
            now.get()
                .saturating_add(cooldown_nanos(cooldown, failures, rng)),
        );
        self.resolve_draw(
            address,
            cooling(SeatHold::Counted { until }, failures),
            bans,
        );
        if from_white {
            self.evict_gray_over_cap(address, rng);
        }
        true
    }

    /// An excused failed test ([`crate::Verdict::Excused`]; `OE-D6`, hold
    /// the rung). Returns whether the seat moved. The count neither climbs
    /// nor descends.
    ///
    /// - **An outstanding gray draw with counted failures** cools at its
    ///   current rung on `cooldown`.
    /// - **An outstanding gray draw with none** cools for `outage_retry`.
    /// - **A white address** has no counted failure: it stays white and is
    ///   held back from the draw for `outage_retry`.
    ///
    /// Both cooling seats are marked excused, so the judge's next sign of
    /// life clears the one with no counted failure. Anything else is left
    /// as it is.
    pub(crate) fn excuse<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        now: Tick,
        cooldown: Cooldown,
        outage_retry: JitteredSpan,
        bans: &BanSet,
        rng: &mut R,
    ) -> bool {
        match self.seat_of(address) {
            Some(Seat::Gray {
                phase: GrayPhase::Outstanding,
                failures,
                ..
            }) => {
                let wait = if failures == 0 {
                    outage_retry_nanos(outage_retry, rng)
                } else {
                    cooldown_nanos(cooldown, failures, rng)
                };
                let until = Tick::new(now.get().saturating_add(wait));
                self.resolve_draw(
                    address,
                    cooling(SeatHold::Excused { until }, failures),
                    bans,
                );
                true
            }
            Some(Seat::White { observed, .. }) => {
                let until = Tick::new(
                    now.get()
                        .saturating_add(outage_retry_nanos(outage_retry, rng)),
                );
                self.move_seat(address, excused_white(observed, until));
                true
            }
            Some(Seat::Gray { .. }) | None => false,
        }
    }

    /// The judge saw the link work (`OE-D6`, clearing): every excused seat
    /// with no counted failure is drawable again at once, a white one's
    /// excusal ends with it, and nothing on the ladder is touched. Returns
    /// how many seats moved.
    pub(crate) fn clear_excused(&mut self) -> usize {
        let cleared: Vec<(NetworkAddress, Seat)> = self
            .seats
            .iter()
            .filter_map(|(address, seat)| match seat {
                Seat::Gray {
                    phase: GrayPhase::Drawable,
                    failures: 0,
                    hold: Some(SeatHold::Excused { .. }),
                } => Some((address.clone(), drawable(0))),
                Seat::White {
                    observed,
                    hold: Some(SeatHold::Excused { .. }),
                } => Some((address.clone(), white(*observed))),
                Seat::Gray { .. } | Seat::White { .. } => None,
            })
            .collect();
        for (address, seat) in &cleared {
            self.move_seat(address, *seat);
        }
        cleared.len()
    }

    /// Every cooling seat whose tick has passed returns to drawable gray,
    /// on the same ladder rung, and every white excusal that has passed
    /// ends. Returns how many seats moved.
    pub(crate) fn thaw(&mut self, now: Tick) -> usize {
        let due: Vec<(NetworkAddress, Seat)> = self
            .seats
            .iter()
            .filter_map(|(address, seat)| match seat {
                Seat::Gray {
                    phase: GrayPhase::Drawable,
                    failures,
                    hold: Some(hold),
                } if hold.until().get() <= now.get() => {
                    Some((address.clone(), drawable(*failures)))
                }
                Seat::White {
                    observed,
                    hold: Some(hold),
                } if hold.until().get() <= now.get() => Some((address.clone(), white(*observed))),
                Seat::Gray { .. } | Seat::White { .. } => None,
            })
            .collect();
        for (address, seat) in &due {
            self.move_seat(address, *seat);
        }
        due.len()
    }

    /// A kept session to `address` ended at `now`: its white clock moves to
    /// the close time, so expiry counts from the end of the connection, not
    /// from its start (the gray lifecycle, item 1). Nothing else is
    /// touched; an address that is not white is left as it is.
    pub(crate) fn session_ended(&mut self, address: &NetworkAddress, now: Tick) -> bool {
        if !matches!(self.seat_of(address), Some(Seat::White { .. })) {
            return false;
        }
        self.write_clock(address, now);
        true
    }

    /// The draw is over and the address returns to drawable gray.
    ///
    /// The gray count is unchanged, so this does not evict. Going through
    /// [`Self::insert_gray`] would: an outstanding draw can be what holds
    /// gray over the cap, and settling it must not drop someone else.
    pub(crate) fn settle_outstanding(&mut self, address: &NetworkAddress, bans: &BanSet) {
        if let Some(Seat::Gray {
            phase: GrayPhase::Outstanding,
            failures,
            ..
        }) = self.seat_of(address)
        {
            self.resolve_draw(address, drawable(failures), bans);
        }
    }

    /// Demote every white entry that has gone `EXPIRATION_PERIOD` without
    /// contact and has no live kept session (`is_live`): a connection that
    /// is up is contact, and its clock moves when it ends
    /// ([`Self::session_ended`]). Returns how many moved.
    pub(crate) fn expire<R: RelayRng + ?Sized>(
        &mut self,
        now: Tick,
        is_live: &mut dyn FnMut(&NetworkAddress) -> bool,
        rng: &mut R,
    ) -> usize {
        let expired: Vec<NetworkAddress> = self
            .white_clocks()
            .filter(|(address, observed)| {
                now.get().saturating_sub(observed.get()) >= EXPIRATION_PERIOD_NANOS
                    && !is_live(address)
            })
            .map(|(address, _)| address.clone())
            .collect();
        for address in &expired {
            self.demote(address, rng);
        }
        expired.len()
    }

    /// The earliest white expiry, if any white seat exists.
    pub(crate) fn next_expiry(&self) -> Option<Tick> {
        self.white_clocks()
            .map(|(_, observed)| Tick::new(observed.get().saturating_add(EXPIRATION_PERIOD_NANOS)))
            .min()
    }

    /// Every address this partition holds, each once, unordered: gray
    /// (outstanding included) and white together, for the file (§7).
    pub(crate) fn persistable(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.seats.iter().map(|(address, _)| address)
    }

    /// Move a gray seat to outstanding, keeping its ladder rung.
    fn mark_outstanding(&mut self, address: &NetworkAddress) {
        let failures = self.failed_tests(address);
        self.move_seat(address, outstanding(failures));
    }

    /// Every gray seat, barred ones included: the cap bounds memory, not
    /// eligibility.
    fn occupied_gray(&self) -> usize {
        self.drawable_gray + self.outstanding_draws + self.cooling + self.barred
    }

    fn seat_of(&self, address: &NetworkAddress) -> Option<Seat> {
        self.seats.get(address).copied()
    }

    fn white_clocks(&self) -> impl Iterator<Item = (&NetworkAddress, Tick)> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::White { observed, .. } => Some((address, *observed)),
            Seat::Gray { .. } => None,
        })
    }

    /// First seat for `address`. The caller has already seen it sit nowhere.
    fn seat_new(&mut self, address: NetworkAddress, seat: Seat) {
        let inserted = self.seats.insert(address, seat);
        debug_assert!(inserted, "seat_new is the first seat");
        if inserted {
            self.note_added(&seat);
        }
    }

    /// Move an address that already sits. The counts follow the value.
    fn move_seat(&mut self, address: &NetworkAddress, seat: Seat) {
        let previous = self.seat_of(address).expect("the address sits");
        self.note_removed(&previous);
        self.note_added(&seat);
        *self.seats.get_mut(address).expect("the address sits") = seat;
    }

    fn leave(&mut self, address: &NetworkAddress) -> Option<Seat> {
        let previous = self.seats.remove(address)?;
        self.note_removed(&previous);
        Some(previous)
    }

    fn note_added(&mut self, seat: &Seat) {
        debug_assert_seat(seat);
        *self.tally(seat) += 1;
        if seat.class() == SeatClass::HeldWhite {
            self.excused_white += 1;
        }
    }

    fn note_removed(&mut self, seat: &Seat) {
        let tally = self.tally(seat);
        debug_assert!(*tally > 0, "a seat count tracks the table");
        *tally -= 1;
        if seat.class() == SeatClass::HeldWhite {
            debug_assert!(self.excused_white > 0, "a seat count tracks the table");
            self.excused_white -= 1;
        }
    }

    fn tally(&mut self, seat: &Seat) -> &mut usize {
        match seat.class() {
            SeatClass::DrawableGray => &mut self.drawable_gray,
            SeatClass::Cooling => &mut self.cooling,
            SeatClass::Outstanding => &mut self.outstanding_draws,
            SeatClass::Barred => &mut self.barred,
            SeatClass::White | SeatClass::HeldWhite => &mut self.white_seats,
        }
    }

    /// A uniform member for which `accept` holds.
    ///
    /// Precondition: at least one member is acceptable, so the rejection
    /// ends. The draw is uniform over those members. A one-member table
    /// does not consume the generator ([`Index::pick`]).
    fn pick_accepted<R: RelayRng + ?Sized>(
        &self,
        rng: &mut R,
        mut accept: impl FnMut(&NetworkAddress, &Seat) -> bool,
    ) -> NetworkAddress {
        loop {
            let (address, seat) = self
                .seats
                .pick(rng)
                .expect("a seat was known to be acceptable");
            if accept(address, seat) {
                return address.clone();
            }
        }
    }
}

/// One draw of the connector's `outage_retry`: its base plus a uniform
/// jitter.
fn outage_retry_nanos<R: RelayRng + ?Sized>(outage_retry: JitteredSpan, rng: &mut R) -> u64 {
    outage_retry
        .base_nanos
        .saturating_add(bounded_uniform(rng, outage_retry.jitter_nanos))
}
