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

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};
use shekyl_timing_engine::Tick;

use crate::{EXPIRATION_PERIOD_NANOS, GRAY_CAP, WHITE_CAP};

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
