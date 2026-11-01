// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clock named from the consensus, and when a republish may run
//! (`TOR_SUPERVISOR.md` §4.2, §4.5; Rick, 2026-11-01).
//!
//! **The clock.** At each liveness sample the driver reads the consensus's
//! `valid-after` and this machine's wall time and passes both as values. A
//! wall time behind `valid-after` by more than the tolerance names the clock.
//! Nothing legitimate produces a consensus from the future, and a majority
//! of the directory authorities signed its `valid-after`, so only this
//! machine's clock can trip it. Only that direction counts: a consensus past
//! its `valid-until` is legitimate while a node was offline. Tor numbers each
//! descriptor from its own clock (tor 0.4.9.14 `hs_service.c:3215-3270`), so
//! with the clock behind, the directories refuse what this node uploads and
//! keep serving the copy they have. The inbound facet says so; outbound and
//! `OwnTx` are untouched (outbound carried traffic throughout the VM run of
//! 2026-11-01). It clears at the first sample inside the tolerance, and
//! nothing is done then: Tor's next rebuild takes a counter above anything the
//! directories hold, and the overdue rule covers a stalled schedule.
//!
//! **No republish while it cannot help:** while the clock is named, or while
//! more than half of the latest round's directories refused its upload. A
//! republish replaces the introduction points, and the directories would
//! keep advertising the old ones (the VM run's loop, 36 republishes).
//!
//! **The backoff.** A republish waits for its own round to end and its probe,
//! with the directory check, to judge it. A failed judgment holds the next
//! republish for a wait that doubles each time, from
//! `Policy::republish_after` up to the descriptor's lifetime; a confirmed
//! Reachable resets it. This gap stood with a correct clock as well.

use super::super::posture::{Inbound, InboundCause};
use super::announce::Cadence;
use super::{duration_ns, Action, Core, Duty, Phase};

/// The republish backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RepublishHold {
    /// The wait the next failed judgment holds for.
    wait: u64,
    /// A republish was sent and its round has not yet been judged.
    judging: bool,
    /// No republish before this; set by a failed judgment.
    until: Option<u64>,
    /// A republish was asked for while held; it runs when the hold ends.
    owed: bool,
}

impl RepublishHold {
    pub(super) const fn new(base: u64) -> Self {
        Self {
            wait: base,
            judging: false,
            until: None,
            owed: false,
        }
    }

    /// When an owed republish may run.
    pub(super) fn due(&self) -> Option<u64> {
        self.until.filter(|_| self.owed)
    }
}

impl Core {
    /// The consensus's `valid-after` against this machine's wall time, at a
    /// liveness sample, Bootstrapping or Running.
    pub(super) fn consensus_clock(&mut self, now: u64, valid_after: u64, wall: u64) -> Vec<Action> {
        if !matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        ) {
            return Vec::new();
        }
        let behind = valid_after.saturating_sub(wall);
        if behind > self.policy.clock_behind_after.as_secs() {
            let named = self.clock_behind.is_none();
            self.clock_behind = Some(behind);
            if !named {
                return Vec::new();
            }
            self.inbound_unreachable(now, InboundCause::ClockBehind);
            return self.say(now, Cadence::Due);
        }
        if self.clock_behind.take().is_none() {
            return Vec::new();
        }
        // Cleared. Refused uploads still stand if they did; otherwise the
        // facet is unknown again until a probe judges it.
        if self.uploads_refused {
            self.inbound_unreachable(now, InboundCause::UploadsRefused);
        } else {
            self.inbound = if self.onion_published_here() {
                Inbound::Publishing
            } else {
                Inbound::NotOffered
            };
        }
        self.say(now, Cadence::Due)
    }

    /// A round in which more than half of the directories refused the
    /// upload. No republish; the facet says so unless the clock, the cause
    /// behind it, already does.
    pub(super) fn uploads_refused(&mut self, now: u64) -> Vec<Action> {
        let newly = !self.uploads_refused;
        self.uploads_refused = true;
        if self.republish.judging {
            self.republish_failed(now);
        }
        if self.clock_behind.is_some() || !newly {
            return Vec::new();
        }
        self.inbound_unreachable(now, InboundCause::UploadsRefused);
        self.say(now, Cadence::Due)
    }

    /// A round that was not refused clears refused uploads. The facet is
    /// unknown again until its probe judges it.
    pub(super) fn uploads_accepted(&mut self) {
        if !std::mem::take(&mut self.uploads_refused) {
            return;
        }
        if matches!(
            self.inbound,
            Inbound::Unreachable {
                cause: InboundCause::UploadsRefused,
                ..
            }
        ) {
            self.inbound = Inbound::Publishing;
        }
    }

    /// While the clock is named, or the latest round was refused, a
    /// republish cannot help.
    pub(super) fn republish_cannot_help(&self) -> bool {
        self.clock_behind.is_some() || self.uploads_refused
    }

    /// Publish the onion again (`DEL_ONION`, then `ADD_ONION`), unless it
    /// cannot help or the backoff holds it; a held one is owed and runs when
    /// the hold ends. Refused, it is a process fault, as the Service remedy's
    /// is.
    pub(super) fn republish(&mut self, now: u64) -> Vec<Action> {
        if self.republish_cannot_help() {
            return Vec::new();
        }
        if self.republish.judging || self.republish.until.is_some_and(|until| now < until) {
            self.republish.owed = true;
            return Vec::new();
        }
        let Phase::Running { onion, .. } = &mut self.phase else {
            return Vec::new();
        };
        *onion = Duty::Owed;
        self.service_republish = true;
        self.republish.judging = true;
        self.republish.until = None;
        self.republish.owed = false;
        vec![Action::RepublishOnion]
    }

    /// The republish's round was judged unreachable, or ended with nothing
    /// to judge: hold the next for the current wait, then double it, up to
    /// the descriptor's lifetime.
    pub(super) fn republish_failed(&mut self, now: u64) {
        if !self.republish.judging {
            return;
        }
        let cap = duration_ns(self.policy.descriptor_lifetime);
        self.republish.judging = false;
        self.republish.until = Some(now.saturating_add(self.republish.wait));
        self.republish.wait = self.republish.wait.saturating_mul(2).min(cap);
    }

    /// A confirmed Reachable resets the backoff.
    pub(super) fn republish_confirmed(&mut self) {
        self.republish = RepublishHold::new(duration_ns(self.policy.republish_after));
    }

    /// The hold ended with a republish owed.
    pub(super) fn on_republish_deadline(&mut self, now: u64) -> Vec<Action> {
        self.republish.until = None;
        if !std::mem::take(&mut self.republish.owed) {
            return Vec::new();
        }
        self.republish(now)
    }

    /// A Tor reached Running: its first publish is not a republish, and
    /// nothing is owed on its behalf. The wait is kept until a Reachable.
    pub(super) fn republish_new_tor(&mut self) {
        self.republish.judging = false;
        self.republish.until = None;
        self.republish.owed = false;
    }

    fn inbound_unreachable(&mut self, now: u64, cause: InboundCause) {
        let since = match self.inbound {
            Inbound::Unreachable { since, .. } => since,
            _ => now,
        };
        self.inbound = Inbound::Unreachable { cause, since };
    }

    fn onion_published_here(&self) -> bool {
        matches!(
            self.phase,
            Phase::Running {
                onion: Duty::Done,
                ..
            }
        )
    }
}
