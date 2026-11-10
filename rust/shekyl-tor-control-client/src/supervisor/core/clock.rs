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
//! 2026-11-01). The lower bound clears at the first sample inside the
//! tolerance. Tor's own report that the clock is behind clears with it only
//! when that sample closed the gap faster than the time since the previous
//! one: a fixed consensus ages into the tolerance without the clock being
//! set, and retiring the report there makes the next report say the fault
//! again. Nothing is done on the clear besides the one recovery line: Tor's
//! next rebuild takes a counter above anything the directories hold, and the
//! overdue rule covers a stalled schedule.
//!
//! **No republish while it cannot help:** while the clock is named, or while
//! more than half of the latest round's directories refused its upload. A
//! republish replaces the introduction points, and the directories would
//! keep advertising the old ones (the VM run's loop, 36 republishes). One
//! already handed to the driver is withheld, and the lifetime it started
//! is put back.
//!
//! **The backoff.** A republish waits for its own round to end and its probe,
//! with the directory check, to judge it. A failed judgment holds the next
//! republish for a wait that doubles each time, from
//! `Policy::republish_after` up to the descriptor's lifetime; a confirmed
//! Reachable resets it. While a republish is waiting on its own round, only
//! that round's probe confirms it. This gap stood with a correct clock as well.

use std::time::Duration;

use super::super::posture::{Cause, Inbound, InboundCause, ReportedSkew};
use super::announce::Cadence;
use super::{duration_ns, Action, Core, Duty, Phase};

/// One consensus check, so the next one can tell a fixed `valid-after`
/// aging into the tolerance from the wall clock being set forward.
#[derive(Clone, Copy, Debug)]
pub(super) struct ConsensusSample {
    /// Supervisor time of the sample, in the caller's units.
    at: u64,
    /// `valid-after` minus the wall clock, in seconds. How far behind the
    /// check measured.
    gap: u64,
}

impl ConsensusSample {
    /// The gap closed by at least `tolerance` beyond the time since this
    /// sample. A fixed consensus ages one second per second. That is not
    /// the clock being set forward, and it does not retire Tor's report.
    pub(super) fn corrected(self, now: u64, gap: u64, tolerance: Duration) -> bool {
        let elapsed = Duration::from_nanos(now.saturating_sub(self.at)).as_secs();
        let closed = self.gap.saturating_sub(gap);
        // `>=` so a clock just past the tolerance, set right in one sample,
        // counts. Aging closes by `elapsed` and does not.
        closed >= elapsed.saturating_add(tolerance.as_secs())
    }
}

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

    /// When an owed republish may run. Hidden while a republish cannot help,
    /// by [`Core::republish_due`]: a past hold must not spin, and it runs
    /// once standing down clears.
    pub(super) fn due(&self) -> Option<u64> {
        self.until.filter(|_| self.owed)
    }
}

/// A remedial republish handed to the driver and not yet published. If the
/// driver withholds it, these are what the core puts back.
#[derive(Clone, Copy, Debug)]
pub(super) struct QueuedSend {
    /// `lifetime_from` before the hand-over moved it.
    anchor: Option<u64>,
    /// The hold's `until` before the hand-over cleared it.
    until: Option<u64>,
    /// The hold's `owed` before the hand-over cleared it.
    owed: bool,
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
        let gap = valid_after.saturating_sub(wall);
        let corrected = self
            .consensus_sample
            .is_some_and(|sample| sample.corrected(now, gap, self.policy.clock_behind_after));
        self.consensus_sample = Some(ConsensusSample { at: now, gap });
        if gap > self.policy.clock_behind_after.as_secs() {
            let behind = Duration::from_secs(gap);
            // Tor's report or the certificates may have named it already.
            let named = self.clock_named_already();
            let newly = self.note_clock_behind(now, behind);
            // A probe already in hand would judge the copy a republish
            // cannot replace. Drop it, including one this same deadline
            // armed before the sample was folded.
            let mut actions = self.stand_down_probe();
            if newly && !named {
                actions.extend(self.say(now, Cadence::Due));
            } else {
                // The lag moved, or this check joined a clock already named.
                // Record the key. Do not speak.
                self.note_key();
            }
            return actions;
        }
        if !self.clock_is_behind() {
            return Vec::new();
        }
        // The check no longer trips. Tor's report that the clock is behind
        // is retired only when the gap closed faster than the time since the
        // previous sample: the wall was set forward. A fixed consensus ages
        // into the tolerance one second per second, and that must not clear
        // the report or the next one says the fault again. A report that the
        // clock is ahead stands either way: this check cannot see ahead.
        // Refused uploads still stand if they did; otherwise the facet is
        // unknown again until a probe judges it.
        if corrected && matches!(self.cause, Cause::ClockSkew { skew } if skew.is_behind()) {
            self.set_cause(Cause::None);
        }
        if self.uploads_refused {
            self.inbound_unreachable(now, InboundCause::UploadsRefused);
        } else {
            self.inbound = if self.onion_published_here() {
                Inbound::Publishing
            } else {
                Inbound::NotOffered
            };
        }
        if matches!(
            self.cause,
            Cause::ClockSkew { .. } | Cause::CertificatesOutOfDate
        ) {
            self.note_key();
            return Vec::new();
        }
        self.say(now, Cadence::Due)
    }

    /// Tor reports the clock off. Said when it newly names the clock. While
    /// the clock is already named (by an earlier report, the certificates,
    /// or the consensus check) the figure is kept and the key is recorded
    /// without speaking: a clock three days behind for four minutes is said
    /// once (Rick, 2026-11-10). Tor reports it at every handshake and
    /// directory fetch, seconds apart (the macOS run of 2026-11-09).
    pub(super) fn clock_skew(&mut self, now: u64, skew: ReportedSkew) -> Vec<Action> {
        let named = self.clock_named_already();
        self.set_cause(Cause::ClockSkew { skew });
        if named {
            self.note_key();
            return Vec::new();
        }
        self.say(now, Cadence::Due)
    }

    /// The clock is named: by Tor's report, the certificates, or the
    /// consensus check beside no other cause.
    pub(super) fn clock_named_already(&self) -> bool {
        matches!(
            self.cause,
            Cause::ClockSkew { .. } | Cause::CertificatesOutOfDate
        ) || (self.cause == Cause::None && self.clock_is_behind())
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
        let mut actions = self.stand_down_probe();
        if self.clock_is_behind() || !newly {
            return actions;
        }
        self.inbound_unreachable(now, InboundCause::UploadsRefused);
        actions.extend(self.say(now, Cadence::Due));
        actions
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
        self.clock_is_behind() || self.uploads_refused
    }

    /// The republish is waiting on its own round's probe.
    pub(super) fn republish_is_judging(&self) -> bool {
        self.republish.judging
    }

    /// When an owed republish may run. None while one cannot help, so a
    /// hold that expired during standing down does not spin; the original
    /// instant is still there and fires once standing down clears.
    pub(super) fn republish_due(&self) -> Option<u64> {
        if self.republish_cannot_help() {
            None
        } else {
            self.republish.due()
        }
    }

    /// How far behind the consensus this computer's clock is, while the
    /// clock is named. The status projects this.
    pub(super) fn clock_lag(&self) -> Option<Duration> {
        match self.inbound {
            Inbound::Unreachable {
                cause: InboundCause::ClockBehind { behind },
                ..
            } => Some(behind),
            _ => None,
        }
    }

    /// The clock is named: inbound's cause carries the lag.
    pub(super) fn clock_is_behind(&self) -> bool {
        self.clock_lag().is_some()
    }

    /// Record `behind` on the standing clock cause. Returns whether this
    /// sample newly names the clock. A later sample that is still behind
    /// updates the lag and does not say the sentence again.
    fn note_clock_behind(&mut self, now: u64, behind: Duration) -> bool {
        if let Inbound::Unreachable {
            cause: InboundCause::ClockBehind { behind: named },
            ..
        } = &mut self.inbound
        {
            *named = behind;
            return false;
        }
        self.inbound_unreachable(now, InboundCause::ClockBehind { behind });
        true
    }

    /// Publish the onion again (`DEL_ONION`, then `ADD_ONION`), unless it
    /// cannot help or the backoff holds it; a held one is owed and runs when
    /// the hold ends. Refused, it is a process fault, as the Service remedy's
    /// is.
    ///
    /// The hand-over starts this republish's own lifetime and drops a probe
    /// already in hand, so that probe cannot confirm the republish. The
    /// driver may still withhold the send: a liveness sample queued ahead of
    /// it can name the clock first ([`Self::republish_withheld`]).
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
        self.queued_send = Some(QueuedSend {
            anchor: self.lifetime_from,
            until: self.republish.until,
            owed: self.republish.owed,
        });
        // The republish's own lifetime, not the remainder of the descriptor
        // the previous upload numbered (§4.5). A withhold puts `anchor` back.
        self.lifetime_from = Some(now);
        *onion = Duty::Owed;
        self.service_republish = true;
        self.republish.judging = true;
        self.republish.until = None;
        self.republish.owed = false;
        let mut actions = self.disarm_probe();
        actions.push(Action::RepublishOnion);
        actions
    }

    /// The driver did not send the remedial republish: standing down was
    /// named after the hand-over. The anchor goes back. A hold started
    /// since the hand-over (a refused round failing the judgment) stays;
    /// otherwise the hold the hand-over cleared is restored, still due when
    /// a republish can help, and not spinning while one cannot.
    pub(super) fn republish_withheld(&mut self) -> Vec<Action> {
        let Some(queued) = self.queued_send.take() else {
            return Vec::new();
        };
        self.lifetime_from = queued.anchor;
        self.service_republish = false;
        // The send did not happen, so the onion already published is still
        // the one in service. `Waiting` is that same hand-over after the
        // forward listener was absent; leaving it would publish again when
        // the listener returns.
        if let Phase::Running { onion, .. } = &mut self.phase {
            if *onion != Duty::Done {
                *onion = Duty::Done;
            }
        }
        if self.republish.until.is_none() {
            self.republish.judging = false;
            self.republish.owed = queued.owed;
            self.republish.until = queued.until;
        }
        Vec::new()
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

    /// The hold ended with a republish owed. While one cannot help the hold
    /// stays where it is (and [`Self::republish_due`] does not arm it, so
    /// this does not spin). A phase that can no longer send drops the debt
    /// rather than arming a past instant forever.
    pub(super) fn on_republish_deadline(&mut self, now: u64) -> Vec<Action> {
        if self.republish_cannot_help() {
            return Vec::new();
        }
        let actions = self.republish(now);
        if !actions
            .iter()
            .any(|action| matches!(action, Action::RepublishOnion))
            && !matches!(self.phase, Phase::Running { .. })
        {
            self.republish.until = None;
            self.republish.owed = false;
        }
        actions
    }

    /// A Tor reached Running: its first publish is not a republish, and
    /// nothing is owed on its behalf. The wait is kept until a Reachable.
    pub(super) fn republish_new_tor(&mut self) {
        self.republish.judging = false;
        self.republish.until = None;
        self.republish.owed = false;
        self.queued_send = None;
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
