// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One connector's lists.
//!
//! Everything here is inside one partition; the connector is the caller's
//! key ([`crate::Peerlist`] derives it from the address type). No method
//! of this module sees another connector's entries.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};
use shekyl_timing_engine::Tick;

use crate::outcome::SessionId;
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

/// A confirmed address's one clock: when this process last confirmed it on
/// a connection this node opened (brief §4). Not a sort key, not a rank.
///
/// Built in exactly one place, [`Partition::promote`], which only
/// [`crate::Peerlist::apply`] reaches (brief §11.1). No `Deserialize`: the
/// file cannot carry a white entry (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct White {
    pub(crate) last_observed: Tick,
}

/// One connector's gray and white lists and the gray draws the dialer has
/// outstanding.
#[derive(Debug, Default)]
pub(crate) struct Partition {
    /// Arrived, not confirmed. No clock.
    gray: BTreeSet<NetworkAddress>,
    /// Confirmed by this node's own dial. Keyed by address; the map's order
    /// carries no meaning.
    white: BTreeMap<NetworkAddress, White>,
    /// Gray addresses the dialer drew and has not yet reported on. A draw
    /// that was not outstanding cannot promote (§5).
    outstanding: BTreeSet<NetworkAddress>,
    /// The cached disclosure sample and when it was drawn (D3).
    sample: Option<Sample>,
    /// This node's own dialable address on this connector, when known: one
    /// uniform member of the disclosure population (the handshake-address
    /// ruling), never a white entry.
    own_address: Option<NetworkAddress>,
    /// Per session, the distinct addresses it has offered and when each
    /// last arrived (D-S1). Pruned to the intake span on every touch.
    intake: BTreeMap<SessionId, BTreeMap<NetworkAddress, Tick>>,
}

impl Partition {
    pub(crate) fn gray_len(&self) -> usize {
        self.gray.len()
    }

    pub(crate) fn white_len(&self) -> usize {
        self.white.len()
    }

    pub(crate) fn is_gray(&self, address: &NetworkAddress) -> bool {
        self.gray.contains(address)
    }

    pub(crate) fn is_white(&self, address: &NetworkAddress) -> bool {
        self.white.contains_key(address)
    }

    pub(crate) fn is_outstanding(&self, address: &NetworkAddress) -> bool {
        self.outstanding.contains(address)
    }

    pub(crate) fn gray_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.gray.iter()
    }

    pub(crate) fn white_iter(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.white.keys()
    }

    /// Insert into gray. A white entry at the address is untouched. Over
    /// capacity, a uniformly random *other* gray entry is dropped, so the
    /// address just admitted is the one that stays (§2). Returns whether
    /// the address was new to gray.
    pub(crate) fn insert_gray<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        rng: &mut R,
    ) -> bool {
        if !self.gray.insert(address.clone()) {
            return false;
        }
        while self.gray.len() > GRAY_CAP {
            let victim = self.pick_gray(rng, Some(address));
            if let Some(victim) = victim {
                self.gray.remove(&victim);
                self.outstanding.remove(&victim);
            } else {
                break;
            }
        }
        true
    }

    /// One uniform gray address, remembered as outstanding. `None` when
    /// every gray entry is already outstanding or gray is empty.
    pub(crate) fn draw_gray<R: RelayRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Option<NetworkAddress> {
        let candidates: Vec<&NetworkAddress> = self
            .gray
            .iter()
            .filter(|a| !self.outstanding.contains(*a))
            .collect();
        let chosen = pick(&candidates, rng)?.clone();
        self.outstanding.insert(chosen.clone());
        Some(chosen)
    }

    /// One uniform white address. A re-contact draw, not a promotion.
    pub(crate) fn draw_white<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Option<NetworkAddress> {
        let candidates: Vec<&NetworkAddress> = self.white.keys().collect();
        pick(&candidates, rng).map(|a| (*a).clone())
    }

    /// The one white write. Removes the address from gray and from the
    /// outstanding draws, stamps `now`, and over capacity demotes a
    /// uniformly random *other* white entry to gray.
    pub(crate) fn promote<R: RelayRng + ?Sized>(
        &mut self,
        address: &NetworkAddress,
        now: Tick,
        rng: &mut R,
    ) {
        self.gray.remove(address);
        self.outstanding.remove(address);
        self.white
            .insert(address.clone(), White { last_observed: now });
        while self.white.len() > WHITE_CAP {
            let candidates: Vec<&NetworkAddress> =
                self.white.keys().filter(|a| *a != address).collect();
            let Some(victim) = pick(&candidates, rng).map(|a| (*a).clone()) else {
                break;
            };
            self.demote(&victim);
        }
    }

    /// Move the clock of an address that is already white.
    pub(crate) fn touch(&mut self, address: &NetworkAddress, now: Tick) -> bool {
        match self.white.get_mut(address) {
            Some(white) => {
                white.last_observed = now;
                true
            }
            None => false,
        }
    }

    /// White to gray, the clock not copied across.
    pub(crate) fn demote(&mut self, address: &NetworkAddress) -> bool {
        if self.white.remove(address).is_some() {
            self.gray.insert(address.clone());
            true
        } else {
            false
        }
    }

    /// Drop an outstanding gray draw: the address leaves gray.
    pub(crate) fn drop_draw(&mut self, address: &NetworkAddress) -> bool {
        if self.outstanding.remove(address) {
            self.gray.remove(address);
            true
        } else {
            false
        }
    }

    /// The draw is resolved and the address stays gray.
    pub(crate) fn settle_draw(&mut self, address: &NetworkAddress) {
        self.outstanding.remove(address);
    }

    /// Demote every white entry that has gone `EXPIRATION_PERIOD` without
    /// contact. Returns how many moved.
    pub(crate) fn expire(&mut self, now: Tick) -> usize {
        let expired: Vec<NetworkAddress> = self
            .white
            .iter()
            .filter(|(_, w)| {
                now.get().saturating_sub(w.last_observed.get()) >= EXPIRATION_PERIOD_NANOS
            })
            .map(|(a, _)| a.clone())
            .collect();
        for address in &expired {
            self.demote(address);
        }
        expired.len()
    }

    /// The earliest white expiry, if any white entry exists.
    pub(crate) fn next_expiry(&self) -> Option<Tick> {
        self.white
            .values()
            .map(|w| {
                Tick::new(
                    w.last_observed
                        .get()
                        .saturating_add(EXPIRATION_PERIOD_NANOS),
                )
            })
            .min()
    }

    /// Every address this partition holds, unordered: gray and white
    /// together, for the file (§7).
    pub(crate) fn persistable(&self) -> impl Iterator<Item = &NetworkAddress> {
        self.gray.iter().chain(self.white.keys())
    }

    /// D4: move every white entry under an active ban to gray. The clock is
    /// not copied. Only an address with an IP can be banned (D7), so a Tor
    /// partition never demotes here. Returns how many moved.
    pub(crate) fn demote_banned(
        &mut self,
        is_banned: &mut dyn FnMut(IpAddr, Tick) -> bool,
        now: Tick,
    ) -> usize {
        let banned: Vec<NetworkAddress> = self
            .white
            .keys()
            .filter(|a| a.ip().is_some_and(|ip| is_banned(ip, now)))
            .cloned()
            .collect();
        for address in &banned {
            self.demote(address);
        }
        banned.len()
    }

    /// D-S1: record that `session` offered `address` at `now`. `false` when
    /// the session has already offered `SESSION_INTAKE_CAP` other distinct
    /// addresses within the intake span — the refusal. A re-offer of an
    /// address the session already sent counts once.
    pub(crate) fn record_intake(
        &mut self,
        session: SessionId,
        address: &NetworkAddress,
        now: Tick,
    ) -> bool {
        let ledger = self.intake.entry(session).or_default();
        ledger.retain(|_, at| now.get().saturating_sub(at.get()) < INTAKE_SPAN_NANOS);
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

    /// The session ended: its intake ledger goes with it.
    pub(crate) fn forget_session(&mut self, session: SessionId) {
        self.intake.remove(&session);
    }

    /// Distinct addresses `session` has offered within the intake span.
    pub(crate) fn intake_count(&mut self, session: SessionId, now: Tick) -> usize {
        match self.intake.get_mut(&session) {
            Some(ledger) => {
                ledger.retain(|_, at| now.get().saturating_sub(at.get()) < INTAKE_SPAN_NANOS);
                ledger.len()
            }
            None => 0,
        }
    }

    pub(crate) fn set_own_address(&mut self, address: Option<NetworkAddress>) {
        self.own_address = address;
    }

    /// D3: the connector's cached sample. `eligible` is the white count
    /// after demotion and expiry; below `floor` nothing is disclosed and
    /// no sample is drawn. Otherwise the cached sample while its window
    /// lasts, else a fresh uniform draw of `min(DISCLOSE_COUNT, population)`
    /// over white plus this node's own address, cached for the window. A
    /// ban does not rebuild the sample.
    pub(crate) fn disclose<R: RelayRng + ?Sized>(
        &mut self,
        floor: usize,
        now: Tick,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        if self.white.len() < floor {
            return Vec::new();
        }
        if let Some(sample) = &self.sample {
            if now.get().saturating_sub(sample.drawn_at.get()) < DISCLOSE_WINDOW_NANOS {
                return sample.addresses.clone();
            }
        }
        let mut population: Vec<NetworkAddress> = self.white.keys().cloned().collect();
        if let Some(own) = &self.own_address {
            if !population.contains(own) {
                population.push(own.clone());
            }
        }
        // Partial Fisher-Yates: `DISCLOSE_COUNT` distinct members, uniform,
        // in a random order.
        let take = DISCLOSE_COUNT.min(population.len());
        for i in 0..take {
            let remaining = population.len() - i;
            let pick = i + usize::try_from(bounded_uniform(rng, (remaining - 1) as u64))
                .expect("the draw is bounded by the population");
            population.swap(i, pick);
        }
        population.truncate(take);
        self.sample = Some(Sample {
            drawn_at: now,
            addresses: population.clone(),
        });
        population
    }

    fn pick_gray<R: RelayRng + ?Sized>(
        &self,
        rng: &mut R,
        keep: Option<&NetworkAddress>,
    ) -> Option<NetworkAddress> {
        let candidates: Vec<&NetworkAddress> = self
            .gray
            .iter()
            .filter(|a| keep.is_none_or(|k| *a != k))
            .collect();
        pick(&candidates, rng).map(|a| (*a).clone())
    }
}

/// One uniform element of `candidates`.
fn pick<'a, T, R: RelayRng + ?Sized>(candidates: &[&'a T], rng: &mut R) -> Option<&'a T> {
    match candidates.len() {
        0 => None,
        1 => Some(candidates[0]),
        n => {
            let index = usize::try_from(bounded_uniform(rng, (n - 1) as u64))
                .expect("the draw is bounded by the candidate count");
            Some(candidates[index])
        }
    }
}
