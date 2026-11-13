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
//! tolerance. Tor's own report that the clock is off stands until Tor
//! reaches Running, which clears every cause: this check cannot tell the
//! clock set right from a fixed consensus aging into the tolerance, or from
//! a sleep, and retiring the report on either would make Tor's next report
//! say the fault again. The clear is that event on every OS. Supervisor time
//! counts awake time, so a sleep moves the wall and not the supervisor,
//! whether the process clock is `CLOCK_MONOTONIC`, `CLOCK_UPTIME_RAW`, or
//! the unbiased interrupt time (#1352). The clear does not let a block take
//! the line.
//!
//! What does is Tor's `CLOCK_JUMPED` after the report ([`SkewHold`]). A
//! repeat of that figure inside one handshake stretch
//! ([`super::Policy::clock_evidence_within`]) is a handshake that was
//! already open: it leaves the line where it is. A repeat after the stretch
//! means Tor still sees the figure, which a wake does too, so the report
//! owns a block again. A different figure owns it at once. Nothing else is
//! done on the clear: Tor's next rebuild takes a counter above anything the
//! directories hold, and the overdue rule covers a stalled schedule.
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

/// Whether Tor's skew report owns a bootstrap block.
///
/// [`Self::Holding`] owns one, while the cause is that report.
/// [`Self::Yielded`] is the figure a `CLOCK_JUMPED` superseded, at the
/// supervisor time of the jump. A later report of that figure inside one
/// handshake stretch is the handshake that was already open. A later report
/// past the stretch, or of another figure, owns blocks again.
///
/// The consensus check is not a writer. Its clear is an aging consensus or
/// a sleep on every OS, and [`Core::clock_is_behind`] already owns a block
/// while the check trips.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SkewHold {
    /// The standing report owns a block.
    #[default]
    Holding,
    /// `CLOCK_JUMPED` at `at` yielded `skew`.
    Yielded {
        /// The figure the jump superseded.
        skew: ReportedSkew,
        /// Supervisor time of the jump.
        at: u64,
    },
}

impl SkewHold {
    /// The standing skew report owns a block.
    pub(super) fn owns(self, cause: &Cause) -> bool {
        match (self, cause) {
            (Self::Yielded { skew: yielded, .. }, Cause::ClockSkew { skew })
                if yielded == *skew =>
            {
                false
            }
            (_, Cause::ClockSkew { .. }) => true,
            _ => false,
        }
    }

    /// Tor reported `CLOCK_JUMPED`. The standing figure, when the cause is
    /// that report, no longer owns a block. A jump with no standing report
    /// leaves the hold: the next report is a new fact.
    pub(super) fn note_jump(self, cause: &Cause, now: u64) -> Self {
        match cause {
            Cause::ClockSkew { skew } => Self::Yielded {
                skew: *skew,
                at: now,
            },
            _ => self,
        }
    }

    /// `skew` is the yielded figure, still inside `within` of the jump.
    fn is_tail(self, skew: ReportedSkew, now: u64, within: u64) -> bool {
        match self {
            Self::Yielded { skew: yielded, at } => {
                skew == yielded && now.saturating_sub(at) <= within
            }
            Self::Holding => false,
        }
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
        if gap > self.policy.clock_behind_after.as_secs() {
            let behind = Duration::from_secs(gap);
            // While Tor bootstraps a named clock is what blocks it (§4.2): a
            // blocked link or an unreachable directory named before this
            // check gives way, so the line says the clock alone and Tor's
            // next skew report finds it already named.
            let displaced = matches!(self.phase, Phase::Bootstrapping { .. })
                && matches!(
                    self.cause,
                    Cause::ExternalBlocked | Cause::DirectoryUnreachable
                );
            if displaced {
                self.set_cause(Cause::None);
            }
            // Tor's report or the certificates may have named it already.
            let named = self.clock_named_already();
            let newly = self.note_clock_behind(now, behind);
            // A probe already in hand would judge the copy a republish
            // cannot replace. Drop it, including one this same deadline
            // armed before the sample was folded.
            let mut actions = self.stand_down_probe();
            if (newly && !named) || displaced {
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
        // The check no longer trips: its lower bound clears. Tor's own report
        // stands until Tor reaches Running, which clears every cause. This
        // check cannot tell the clock being set right from a fixed consensus
        // aging into the tolerance, or from a sleep: on Linux and macOS
        // supervisor time stops in a sleep and the wall does not (`TSR-M8`),
        // so either moves the wall without moving its offset. Retiring the
        // report here would let Tor's next report say the same fault again.
        // Refused uploads still stand if they did; otherwise the facet is
        // unknown again until a probe judges it.
        if self.uploads_refused {
            self.inbound_unreachable(now, InboundCause::UploadsRefused);
        } else {
            self.inbound = if self.onion_published_here() {
                Inbound::Publishing { since: now }
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
    /// directory fetch, seconds apart (the macOS run of 2026-11-09). A
    /// repeat of the figure a jump just yielded, inside one handshake
    /// stretch, is that same report: it does not speak, and it does not
    /// replace a block named since the jump.
    pub(super) fn clock_skew(&mut self, now: u64, skew: ReportedSkew) -> Vec<Action> {
        let within = duration_ns(self.policy.clock_evidence_within);
        // A repeat of the figure the jump yielded, inside one handshake
        // stretch: the handshake that was already open. It does not replace
        // a block named since the jump, and it does not speak.
        if self.skew_hold.is_tail(skew, now, within) {
            if self.clock_named_already() {
                self.note_key();
            }
            return Vec::new();
        }
        self.skew_hold = SkewHold::Holding;
        let named = self.clock_named_already();
        self.set_cause(Cause::ClockSkew { skew });
        if named {
            self.note_key();
            return Vec::new();
        }
        self.say(now, Cadence::Due)
    }

    /// Tor reported `CLOCK_JUMPED`. The standing skew report yields a block
    /// from here ([`SkewHold::note_jump`]).
    pub(super) fn note_clock_jumped(&mut self, now: u64) {
        self.skew_hold = self.skew_hold.note_jump(&self.cause, now);
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
    pub(super) fn uploads_accepted(&mut self, now: u64) {
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
            self.inbound = Inbound::Publishing { since: now };
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
