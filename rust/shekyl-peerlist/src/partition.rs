// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connector's lists.
//!
//! An address has one seat in [`Partition::seats`]. Drawable gray,
//! an outstanding draw, and white are three values of that seat, so an
//! address cannot be on two lists. Outstanding is still gray to every
//! reader outside this module — [`Partition::is_gray`], the gray count,
//! the snapshot and the file — and it is the one gray seat eviction
//! will not take. Only [`crate::Peerlist::apply`] moves it.
//!
//! Everything here is inside one partition; the connector is the caller's
//! key ([`crate::Peerlist`] derives it from the address type). No method
//! of this module sees another connector's entries.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_net_address::{Host, NetworkAddress};
use shekyl_relay_privacy::ConnectionId;
use shekyl_timing_engine::Tick;

use crate::index::Index;
use crate::outcome::WhiteClock;
use crate::sample::sample_prefix;
use crate::validity::RefusedSet;
use crate::{
    DISCLOSE_COUNT, DISCLOSE_WINDOW_NANOS, EXPIRATION_PERIOD_NANOS, GRAY_CAP, INTAKE_SPAN_NANOS,
    SESSION_INTAKE_CAP, WHITE_CAP,
};

/// The connector's cached disclosure sample (D3): drawn once, kept for the
/// window, sent unchanged to every requester in it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    drawn_at: Tick,
    addresses: Vec<NetworkAddress>,
}

/// Where one address sits. One seat, so gray and white cannot both hold it.
///
/// `Outstanding` is a gray address the dialer has drawn and not yet
/// reported. Readers outside this module still call it gray. The clock on
/// `White` is `last_observed` (brief §4): not a sort key, not a rank.
/// White is reached only from [`Partition::confirm`], which only
/// [`crate::Peerlist::apply`] calls (brief §11.1). No `Deserialize`: the
/// file cannot carry a white entry (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seat {
    /// Arrived, not drawn, not confirmed. No clock.
    Gray,
    /// Drawn, not yet reported. Still gray to every outside reader.
    Outstanding,
    /// Confirmed by this node's own dial. The value is `last_observed`.
    White(Tick),
}

/// One connector's seats, its cached sample, and its intake ledger.
#[derive(Debug, Default)]
pub(crate) struct Partition {
    /// Every address this partition holds, each exactly once.
    seats: Index<Seat>,
    /// Seats that are [`Seat::Gray`]: the drawable population. Moved only
    /// by [`Self::seat_new`], [`Self::move_seat`] and [`Self::leave`].
    drawable_gray: usize,
    /// Seats that are [`Seat::Outstanding`]. Counted as gray, never drawn
    /// by eviction or by [`Self::draw_gray`]. Same three writers.
    outstanding_draws: usize,
    /// Seats that are [`Seat::White`]. Same three writers.
    white_seats: usize,
    /// The cached disclosure sample and when it was drawn (D3).
    sample: Option<Sample>,
    /// This node's own dialable address on this connector, when known: one
    /// uniform member of the disclosure population (the handshake-address
    /// ruling), never a white entry.
    own_address: Option<NetworkAddress>,
    /// Per session, the distinct addresses it has offered and when each
    /// last arrived (D-S1). Pruned to the intake span on every touch.
    intake: BTreeMap<ConnectionId, BTreeMap<NetworkAddress, Tick>>,
}

impl Partition {
    /// Gray seats, outstanding draws included. An outstanding draw still
    /// occupies gray: drawing it does not free a cap slot.
    pub(crate) fn gray_len(&self) -> usize {
        self.occupied_gray()
    }

    pub(crate) fn white_len(&self) -> usize {
        self.white_seats
    }

    pub(crate) fn is_gray(&self, address: &NetworkAddress) -> bool {
        matches!(self.seat_of(address), Some(Seat::Gray | Seat::Outstanding))
    }

    pub(crate) fn is_white(&self, address: &NetworkAddress) -> bool {
        matches!(self.seat_of(address), Some(Seat::White(_)))
    }

    /// Whether the address already has a seat. A seated address is not a
    /// new gray entry and not a new intake charge.
    pub(crate) fn is_seated(&self, address: &NetworkAddress) -> bool {
        self.seats.contains(address)
    }

    pub(crate) fn gray_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::Gray | Seat::Outstanding => Some(address),
            Seat::White(_) => None,
        })
    }

    pub(crate) fn white_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::White(_) => Some(address),
            Seat::Gray | Seat::Outstanding => None,
        })
    }

    /// Seat `address` on gray when it sits nowhere.
    ///
    /// Already gray, outstanding, or white: left where it is, and `false`.
    /// Over [`GRAY_CAP`], a uniformly random *other drawable* gray seat is
    /// dropped, so the address just admitted stays (brief §2) and an
    /// outstanding draw is not a candidate (brief §5). When the only
    /// drawable seat is the one just admitted, gray sits over the cap by
    /// the outstanding draws rather than cancelling one.
    pub(crate) fn insert_gray<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        rng: &mut R,
    ) -> bool {
        if self.seats.contains(address) {
            return false;
        }
        self.seat_new(address.clone(), Seat::Gray);
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
        let chosen = self.pick_accepted(rng, |_, seat| matches!(seat, Seat::Gray));
        self.move_seat(&chosen, Seat::Outstanding);
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
            let of_list = match seat {
                Seat::Gray => !white,
                Seat::White(_) => white,
                Seat::Outstanding => false,
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
        self.move_seat(&chosen, Seat::Outstanding);
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
        if self.white_seats == 0 {
            return None;
        }
        Some(self.pick_accepted(rng, |_, seat| matches!(seat, Seat::White(_))))
    }

    /// A dial this node opened was confirmed.
    ///
    /// One read of the seat, then [`WhiteClock`] where the seat is already
    /// white (brief §5):
    ///
    /// - outstanding: the one white write. The seat becomes white, the
    ///   clock is `now`, and over [`WHITE_CAP`] a uniformly random *other*
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
        rng: &mut R,
        clock: WhiteClock,
    ) {
        match (self.seat_of(address), clock) {
            (Some(Seat::Outstanding), _) => {
                self.move_seat(address, Seat::White(now));
                self.evict_white_over_cap(address, rng);
            }
            (Some(Seat::White(_)), WhiteClock::Move) => self.write_clock(address, now),
            (Some(Seat::White(_)), WhiteClock::Hold) | (Some(Seat::Gray) | None, _) => {}
        }
    }

    /// Stamp `last_observed`. The address is white; this is not a seat
    /// change, so the tallies stay.
    fn write_clock(&mut self, address: &NetworkAddress, now: Tick) {
        match self.seats.get_mut(address) {
            Some(Seat::White(observed)) => *observed = now,
            _ => debug_assert!(false, "write_clock follows a white seat"),
        }
    }

    /// White to gray. The clock is not copied. The entry then takes the
    /// capped gray path (F3, Rick 2026-10-09): over capacity a uniformly
    /// random other drawable gray seat is dropped, so a mass demotion
    /// cannot push gray over its cap except by outstanding draws.
    pub(crate) fn demote<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        rng: &mut R,
    ) -> bool {
        if !matches!(self.seat_of(address), Some(Seat::White(_))) {
            return false;
        }
        self.move_seat(address, Seat::Gray);
        self.evict_gray_over_cap(address, rng);
        true
    }

    /// Drop an outstanding draw: the address leaves the partition. A white
    /// address is not outstanding, so a failed redial leaves it white.
    pub(crate) fn drop_outstanding(&mut self, address: &NetworkAddress) -> bool {
        if !matches!(self.seat_of(address), Some(Seat::Outstanding)) {
            return false;
        }
        self.leave(address);
        true
    }

    /// The draw is over and the address returns to drawable gray.
    ///
    /// The gray count is unchanged, so this does not evict. Going through
    /// [`Self::insert_gray`] would: an outstanding draw can be what holds
    /// gray over the cap, and settling it must not drop someone else.
    pub(crate) fn settle_outstanding(&mut self, address: &NetworkAddress) {
        if matches!(self.seat_of(address), Some(Seat::Outstanding)) {
            self.move_seat(address, Seat::Gray);
        }
    }

    /// Demote every white entry that has gone `EXPIRATION_PERIOD` without
    /// contact. Returns how many moved.
    pub(crate) fn expire<R: RelayRng + ?Sized>(&mut self, now: Tick, rng: &mut R) -> usize {
        let expired: Vec<NetworkAddress> = self
            .white_clocks()
            .filter(|(_, observed)| {
                now.get().saturating_sub(observed.get()) >= EXPIRATION_PERIOD_NANOS
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

    /// D4: move every white entry under an active ban to gray. The clock is
    /// not copied. Only an address with an IP can be banned (D7), so a Tor
    /// partition never demotes here. Returns how many moved.
    pub(crate) fn demote_banned<R: RelayRng + ?Sized>(
        &mut self,
        is_banned: &mut dyn FnMut(IpAddr, Tick) -> bool,
        now: Tick,
        rng: &mut R,
    ) -> usize {
        let banned: Vec<NetworkAddress> = self
            .white_clocks()
            .filter(|(address, _)| address.ip().is_some_and(|ip| is_banned(ip, now)))
            .map(|(address, _)| address.clone())
            .collect();
        for address in &banned {
            self.demote(address, rng);
        }
        banned.len()
    }

    /// D-S1: record that `session` offered `address` at `now`, for an
    /// address that is about to enter gray. `false` when the session has
    /// already offered [`SESSION_INTAKE_CAP`] other distinct addresses
    /// within the intake span — the refusal. A row already in the ledger
    /// (the address left and is entering again inside the span) counts once.
    pub(crate) fn record_intake(
        &mut self,
        session: ConnectionId,
        address: &NetworkAddress,
        now: Tick,
    ) -> bool {
        let ledger = self.intake.entry(session).or_default();
        prune_intake(ledger, now);
        if let Some(at) = ledger.get_mut(address) {
            *at = now;
            return true;
        }
        if ledger.len() >= SESSION_INTAKE_CAP {
            return false;
        }
        ledger.insert(address.clone(), now);
        true
    }

    /// A seated address offered again: refresh the ledger row when this
    /// session still has one. Does not create a row. A seated address did
    /// not newly become gray, so it is not a new charge.
    pub(crate) fn refresh_intake(
        &mut self,
        session: ConnectionId,
        address: &NetworkAddress,
        now: Tick,
    ) {
        let Some(ledger) = self.intake.get_mut(&session) else {
            return;
        };
        prune_intake(ledger, now);
        if let Some(at) = ledger.get_mut(address) {
            *at = now;
        }
    }

    /// D-S1 for a whole list (F2, Rick 2026-10-09): would seating every
    /// address in `candidates` that is not already seated take `session`
    /// past [`SESSION_INTAKE_CAP`] distinct addresses within the intake
    /// span? Counted before any entry is admitted, so a list that would
    /// cross the cap admits nothing. An address the session already
    /// offered, and an address that already sits, each count as not fresh.
    pub(crate) fn would_exceed_intake(
        &mut self,
        session: ConnectionId,
        candidates: &[&NetworkAddress],
        now: Tick,
    ) -> bool {
        // The unseated set borrows `candidates`, not `self`, so the ledger
        // prune below can take `&mut self`.
        let entering: BTreeSet<&NetworkAddress> = candidates
            .iter()
            .copied()
            .filter(|candidate| self.seat_of(candidate).is_none())
            .collect();
        let ledger = self.intake.entry(session).or_default();
        prune_intake(ledger, now);
        let fresh = entering
            .iter()
            .filter(|candidate| !ledger.contains_key(**candidate))
            .count();
        ledger.len() + fresh > SESSION_INTAKE_CAP
    }

    /// The session ended: its intake ledger goes with it.
    pub(crate) fn forget_session(&mut self, session: ConnectionId) {
        self.intake.remove(&session);
    }

    /// Distinct addresses `session` has offered within the intake span.
    pub(crate) fn intake_count(&mut self, session: ConnectionId, now: Tick) -> usize {
        match self.intake.get_mut(&session) {
            Some(ledger) => {
                prune_intake(ledger, now);
                ledger.len()
            }
            None => 0,
        }
    }

    pub(crate) fn set_own_address(&mut self, address: Option<NetworkAddress>) {
        self.own_address = address;
    }

    /// D3: the connector's cached sample. A sample, once drawn, is served
    /// unchanged until its window ends — whatever white does meanwhile
    /// (F1, Rick 2026-10-09): a demotion, an expiry or a ban in the window
    /// does not change the reply, since a reply that changed would tell
    /// the requester what changed. The floor is checked only when a
    /// sample is drawn: below `floor` (the eligible white count after
    /// demotion and expiry) nothing is drawn and the reply is empty.
    /// Otherwise a fresh uniform draw of `min(DISCLOSE_COUNT, population)`
    /// over white plus this node's own address, cached for the window.
    /// An address `refused` holds is not in the population (brief §2).
    pub(crate) fn disclose<R: RelayRng + ?Sized>(
        &mut self,
        floor: usize,
        refused: &RefusedSet,
        now: Tick,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        if let Some(sample) = &self.sample {
            if now.get().saturating_sub(sample.drawn_at.get()) < DISCLOSE_WINDOW_NANOS {
                return sample.addresses.clone();
            }
        }
        if self.white_seats < floor {
            return Vec::new();
        }
        let mut population: Vec<NetworkAddress> = self
            .white_iter()
            .filter(|address| refused.refuses(address).is_none())
            .cloned()
            .collect();
        if let Some(own) = &self.own_address {
            if refused.refuses(own).is_none() && !population.contains(own) {
                population.push(own.clone());
            }
        }
        let take = sample_prefix(&mut population, DISCLOSE_COUNT, rng);
        population.truncate(take);
        self.sample = Some(Sample {
            drawn_at: now,
            addresses: population.clone(),
        });
        population
    }

    fn occupied_gray(&self) -> usize {
        self.drawable_gray + self.outstanding_draws
    }

    fn seat_of(&self, address: &NetworkAddress) -> Option<Seat> {
        self.seats.get(address).copied()
    }

    fn white_clocks(&self) -> impl Iterator<Item = (&NetworkAddress, Tick)> {
        self.seats.iter().filter_map(|(address, seat)| match seat {
            Seat::White(observed) => Some((address, *observed)),
            Seat::Gray | Seat::Outstanding => None,
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
        *self.tally(seat) += 1;
    }

    fn note_removed(&mut self, seat: &Seat) {
        let tally = self.tally(seat);
        debug_assert!(*tally > 0, "a seat count tracks the table");
        *tally -= 1;
    }

    fn tally(&mut self, seat: &Seat) -> &mut usize {
        match seat {
            Seat::Gray => &mut self.drawable_gray,
            Seat::Outstanding => &mut self.outstanding_draws,
            Seat::White(_) => &mut self.white_seats,
        }
    }

    /// Drop drawable gray until the gray population is within [`GRAY_CAP`],
    /// never `keep` and never an outstanding draw. Stops when the only
    /// drawable seat left is `keep`: gray may then sit over the cap.
    fn evict_gray_over_cap<R: RelayRng + ?Sized>(&mut self, keep: &NetworkAddress, rng: &mut R) {
        while self.occupied_gray() > GRAY_CAP {
            let keep_is_drawable = matches!(self.seat_of(keep), Some(Seat::Gray));
            if !another(self.drawable_gray, keep_is_drawable) {
                break;
            }
            let victim = self.pick_accepted(rng, |address, seat| {
                matches!(seat, Seat::Gray) && address != keep
            });
            self.leave(&victim);
        }
    }

    /// Demote white until it is within [`WHITE_CAP`], never `keep`.
    fn evict_white_over_cap<R: RelayRng + ?Sized>(&mut self, keep: &NetworkAddress, rng: &mut R) {
        while self.white_seats > WHITE_CAP {
            let keep_is_white = matches!(self.seat_of(keep), Some(Seat::White(_)));
            if !another(self.white_seats, keep_is_white) {
                break;
            }
            let victim = self.pick_accepted(rng, |address, seat| {
                matches!(seat, Seat::White(_)) && address != keep
            });
            self.demote(&victim, rng);
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

/// Whether a kind with `kind_count` members has one that is not `keep`.
/// `keep_is_this_kind` is false when `keep` sits somewhere else, or nowhere.
fn another(kind_count: usize, keep_is_this_kind: bool) -> bool {
    match kind_count {
        0 => false,
        1 => !keep_is_this_kind,
        _ => true,
    }
}

/// Drop ledger rows whose arrival has left the intake span.
fn prune_intake(ledger: &mut BTreeMap<NetworkAddress, Tick>, now: Tick) {
    ledger.retain(|_, at| now.get().saturating_sub(at.get()) < INTAKE_SPAN_NANOS);
}
