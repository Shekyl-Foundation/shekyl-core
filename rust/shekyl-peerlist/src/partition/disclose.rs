// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Disclosure and the intake ledger for one connector.
//!
//! The cached sample (D3), the `--p2p-disclose-early` flag, and the
//! per-session intake ledger (D-S1) read which addresses are white and
//! which are already seated. They do not move a seat.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_draw_rng::RelayRng;
use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::ConnectionId;
use shekyl_timing_engine::Tick;

use super::Partition;
use crate::sample::sample_prefix;
use crate::validity::RefusedSet;
use crate::{
    DISCLOSE_COUNT, DISCLOSE_WINDOW_NANOS, INTAKE_SPAN_NANOS, P2P_DISCLOSE_EARLY_SPAN_NANOS,
    SESSION_INTAKE_CAP,
};

/// The connector's cached disclosure sample (D3): drawn once, kept for the
/// window, sent unchanged to every requester in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sample {
    drawn_at: Tick,
    addresses: Vec<NetworkAddress>,
}

/// `--p2p-disclose-early` on one connector (brief revision 3 §2.6): while it
/// runs, the connector discloses below the floor with a fresh draw on
/// every request; it ends at the span or the first time white reaches the
/// floor, and once ended stays ended for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscloseEarly {
    /// Running since the flag reached the lists.
    Running {
        /// When the flag reached the lists; the span counts from here.
        since: Tick,
    },
    /// Ended, for this run.
    Ended,
}

/// Why a connector's `--p2p-disclose-early` flag ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscloseEarlyEnd {
    /// [`crate::P2P_DISCLOSE_EARLY_SPAN_NANOS`] ran out.
    Span,
    /// White reached the floor.
    Floor,
}

impl Partition {
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

    /// `--p2p-disclose-early` reached the lists at `now`: the flag runs on this
    /// connector from here. Set once per run; a second call keeps the first.
    pub(crate) fn set_disclose_early(&mut self, now: Tick) {
        if self.disclose_early.is_none() {
            self.disclose_early = Some(DiscloseEarly::Running { since: now });
        }
    }

    /// The flag's state on this connector.
    pub(crate) fn disclose_early(&self) -> Option<DiscloseEarly> {
        self.disclose_early
    }

    /// End the flag if it runs and `now` is at or past the span, or if
    /// white has reached `floor`. Returns why it ended, for the log; `None`
    /// when it was not running or nothing ended it. Checked at every white
    /// write and at every disclosure, so the floor ends it whenever white
    /// crosses, not only when a reply is drawn.
    pub(crate) fn end_disclose_early_if_due(
        &mut self,
        floor: usize,
        now: Tick,
    ) -> Option<DiscloseEarlyEnd> {
        let Some(DiscloseEarly::Running { since }) = self.disclose_early else {
            return None;
        };
        let reason = if self.white_seats >= floor {
            DiscloseEarlyEnd::Floor
        } else if now.get().saturating_sub(since.get()) >= P2P_DISCLOSE_EARLY_SPAN_NANOS {
            DiscloseEarlyEnd::Span
        } else {
            return None;
        };
        self.disclose_early = Some(DiscloseEarly::Ended);
        Some(reason)
    }

    /// The disclosure population: eligible white plus this node's own
    /// address, the refused set filtering both.
    fn disclosure_population(&self, refused: &RefusedSet) -> Vec<NetworkAddress> {
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
        population
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
    ///
    /// While `--p2p-disclose-early` runs on this connector (§2.6), the floor
    /// does not gate the reply and nothing is cached: every request gets
    /// a fresh draw from the same population, and a draw made under the
    /// flag is never stored as the window's sample. The caller ends the
    /// flag when it is due before calling here.
    pub(crate) fn disclose<R: RelayRng + ?Sized>(
        &mut self,
        floor: usize,
        refused: &RefusedSet,
        now: Tick,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        if matches!(self.disclose_early, Some(DiscloseEarly::Running { .. })) {
            let mut population = self.disclosure_population(refused);
            let take = sample_prefix(&mut population, DISCLOSE_COUNT, rng);
            population.truncate(take);
            return population;
        }
        if let Some(sample) = &self.sample {
            if now.get().saturating_sub(sample.drawn_at.get()) < DISCLOSE_WINDOW_NANOS {
                return sample.addresses.clone();
            }
        }
        if self.white_seats < floor {
            return Vec::new();
        }
        let mut population = self.disclosure_population(refused);
        let take = sample_prefix(&mut population, DISCLOSE_COUNT, rng);
        population.truncate(take);
        self.sample = Some(Sample {
            drawn_at: now,
            addresses: population.clone(),
        });
        population
    }
}

/// Drop ledger rows whose arrival has left the intake span.
fn prune_intake(ledger: &mut BTreeMap<NetworkAddress, Tick>, now: Tick) {
    ledger.retain(|_, at| now.get().saturating_sub(at.get()) < INTAKE_SPAN_NANOS);
}
