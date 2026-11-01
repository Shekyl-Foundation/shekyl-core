// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe of this node's own onion, and the inbound facet it proves
//! (`TOR_SUPERVISOR.md` §4.1, §4.4, §4.5).
//!
//! One probe per descriptor upload round (`TSR-Q5`): the end of a round in
//! which an upload succeeded, or `Policy::round_wait` after the round's
//! first upload, whichever comes first (Rick, 2026-10-29), schedules it,
//! after a delay drawn uniformly from the policy's range, so a hostile directory does not see "upload, then an
//! immediate fetch of the same descriptor". The probe's nonce arriving at
//! this node's inbound handshake is the evidence, when the handshake took
//! the nonce before the probe's bound. The evidence time is that take.
//!
//! **Outside a round** (§4.5, "Overdue"; Rick, 2026-10-31): when no round
//! has begun within the descriptor's lifetime of the last round's first
//! upload, counted on this clock, the onion is published again, which
//! forces a fresh upload; and when Tor reports a clock jump while Running,
//! one probe, which draws its delay through the driver
//! ([`Action::ProbeAfterJump`]) and then runs as a round's probe does.
//!
//! **One miss is not a verdict** (Rick, 2026-10-29). A probe that misses its
//! bound is followed by `HSFETCH` of this node's own onion, which refreshes
//! Tor's client view of that one address, and one more probe after a fresh
//! delay. The onion is unreachable after two consecutive misses, the second
//! preceded by the refetch; that, or a round in which every upload ended
//! and every one failed, is Service-class evidence: the onion is published
//! again on the running Tor, and only a refused republish escalates to a
//! respawn.
//!
//! The probe answers one question, whether this node is reachable at its
//! own onion (`TSR-Q14`). It never sets or clears an outbound or network
//! cause, and a probe that cannot be judged (outbound left usable while it
//! was in flight) is dropped without a verdict.

use super::super::posture::{Cause, Inbound, InboundCause};
use super::announce::Cadence;
use super::{duration_ns, Action, Core, Duty, Phase, RoundEnd};

/// The probe's place in its round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Probe {
    /// None scheduled and none in flight.
    Idle,
    /// Scheduled, due at `at`.
    Scheduled { at: u64, attempt: Attempt },
    /// Asked of the driver. It has until `bound_at` to arrive. `minted_at`
    /// names it once the driver has minted its nonce.
    InFlight {
        bound_at: u64,
        minted_at: Option<u64>,
        attempt: Attempt,
    },
    /// The first probe missed; the refetch is asked and its answer awaited.
    Refetching,
}

/// The descriptor round open now (§4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RoundTrack {
    started_at: u64,
    /// When its first upload succeeded, and the draw that came with it.
    first: Option<(u64, u64)>,
    /// The round's one probe has been scheduled, or was not wanted.
    triggered: bool,
    /// The round has been counted as stuck.
    stuck: bool,
}

impl RoundTrack {
    const fn new(started_at: u64) -> Self {
        Self {
            started_at,
            first: None,
            triggered: false,
            stuck: false,
        }
    }
}

/// Which probe of a round this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Attempt {
    /// The round's probe.
    First,
    /// The probe after a miss and the refetch: its miss is the verdict.
    AfterRefetch,
}

impl Probe {
    /// The deadline the probe holds, if any.
    pub(super) const fn due(self) -> Option<u64> {
        match self {
            Self::Idle | Self::Refetching => None,
            Self::Scheduled { at, .. } => Some(at),
            Self::InFlight { bound_at, .. } => Some(bound_at),
        }
    }
}

impl Core {
    /// The delay before a probe, from a uniform `draw` over the policy's
    /// range. The driver draws it from the daemon's CSPRNG.
    fn probe_delay(&self, draw: u64) -> u64 {
        let low = duration_ns(self.policy.probe_after_min);
        let high = duration_ns(self.policy.probe_after_max).max(low);
        let span = high - low;
        if span == u64::MAX {
            return low.saturating_add(draw);
        }
        // CLIPPY: `span + 1` fits in u128 and the remainder is at most span.
        #[allow(clippy::cast_possible_truncation)]
        let offset = (u128::from(draw) % (u128::from(span) + 1)) as u64;
        low + offset
    }

    /// A round began.
    pub(super) fn round_started(&mut self, now: u64) -> Vec<Action> {
        self.round = Some(RoundTrack::new(now));
        Vec::new()
    }

    /// A round's first upload reached a directory: the probe waits for the
    /// round's end, or `Policy::round_wait` from now.
    pub(super) fn first_uploaded(&mut self, now: u64, draw: u64) -> Vec<Action> {
        let track = self.round.get_or_insert(RoundTrack::new(now));
        if track.first.is_none() {
            track.first = Some((now, draw));
            self.lifetime_from = Some(now);
        }
        Vec::new()
    }

    /// A round ended. One in which an upload succeeded confirms the onion is
    /// published, as `ADD_ONION`'s reply does, and schedules the round's one
    /// probe unless the round's wait already did; a probe already scheduled,
    /// in flight or being refetched is not doubled. One in which every upload
    /// ended, none succeeded and at least one failed is Service-class
    /// evidence: the onion is unreachable, and is published again. A round
    /// that still has an upload unfinished, or whose ends were lost, says
    /// nothing.
    pub(super) fn round_ended(&mut self, now: u64, end: RoundEnd, draw: u64) -> Vec<Action> {
        let track = self.round.take();
        match end {
            RoundEnd::Uploaded => {
                let actions = self.onion_published();
                if !track.is_some_and(|track| track.triggered) {
                    self.trigger(now, draw);
                }
                actions
            }
            RoundEnd::FailedAll if self.onion_done() => {
                self.inbound_down(now, InboundCause::DescriptorRejected)
            }
            RoundEnd::FailedAll | RoundEnd::Unknown => Vec::new(),
        }
    }

    /// The round's one probe, or the jump's: scheduled while Running with
    /// none in hand.
    fn trigger(&mut self, now: u64, draw: u64) {
        if matches!(self.phase, Phase::Running { .. }) && self.probe == Probe::Idle {
            self.schedule(now, draw, Attempt::First);
        }
    }

    /// When the open round next needs the core: its wait for the probe, or
    /// the moment it counts as stuck.
    pub(super) fn round_due(&self) -> Option<u64> {
        let track = self.round?;
        let wait = track
            .first
            .filter(|_| !track.triggered)
            .map(|(at, _)| at.saturating_add(duration_ns(self.policy.round_wait)));
        let stuck = (!track.stuck).then(|| {
            track
                .started_at
                .saturating_add(duration_ns(self.policy.round_stuck_after))
        });
        wait.into_iter().chain(stuck).min()
    }

    /// When the descriptor's lifetime runs out with no round begun: the
    /// lifetime from its anchor, while no round is open. A round that ends
    /// with no upload leaves the old anchor, so the check can be due at
    /// once: nothing shows a fresh descriptor.
    pub(super) fn overdue_due(&self) -> Option<u64> {
        if self.round.is_some() {
            return None;
        }
        self.lifetime_from
            .map(|at| at.saturating_add(duration_ns(self.policy.descriptor_lifetime)))
    }

    /// The descriptor's lifetime ran out with no round begun (§4.5,
    /// "Overdue"; Rick, 2026-10-31). Tor broke its own lifetime, and the
    /// directories drop the descriptor at their next cleanup. Publish the
    /// onion again from the held seed (`DEL_ONION`, then `ADD_ONION`), which
    /// forces a fresh upload; that round's probe judges the facet. Inbound
    /// is not marked down: nothing shows peers cannot reach the onion yet. A
    /// refused republish is a process fault, as the Service remedy's is. The
    /// next lifetime counts from now, so a republish that brings no round
    /// does not ask again at every tick.
    pub(super) fn on_overdue_deadline(&mut self, now: u64) -> Vec<Action> {
        self.lifetime_from = Some(now);
        let Phase::Running { onion, .. } = &mut self.phase else {
            return Vec::new();
        };
        if *onion != Duty::Done {
            return Vec::new();
        }
        *onion = Duty::Owed;
        self.service_republish = true;
        let mut actions = vec![Action::DescriptorOverdue];
        if matches!(self.probe, Probe::InFlight { .. }) {
            actions.push(Action::CancelProbe);
        }
        self.probe = Probe::Idle;
        actions.push(Action::RepublishOnion);
        actions
    }

    /// Tor reported a clock jump while Running: ask for one probe, with
    /// none in hand. A probe already scheduled, in flight or being
    /// refetched answers the same question.
    pub(super) fn jump_probe(&self) -> Vec<Action> {
        if matches!(self.phase, Phase::Running { .. }) && self.probe == Probe::Idle {
            vec![Action::ProbeAfterJump]
        } else {
            Vec::new()
        }
    }

    /// The jump probe's delay was drawn: it is scheduled as a round's is, so
    /// it waits at least the delay's floor and takes the same miss path
    /// (`HSFETCH`, a second probe, then a republish).
    pub(super) fn jump_probe_drawn(&mut self, now: u64, draw: u64) -> Vec<Action> {
        self.trigger(now, draw);
        Vec::new()
    }

    /// The machine slept (§5, "Resumed from suspend"). A probe in flight
    /// gets its whole bound from the wake. A scheduled probe waits at least
    /// the delay's floor, so it does not dial while Tor rebuilds the
    /// circuits it closed (7 s in the VM suspend, §7). An open round's
    /// waits, and the descriptor's lifetime, start again from the wake.
    pub(super) fn probe_resumed(&mut self, now: u64) {
        match &mut self.probe {
            Probe::InFlight { bound_at, .. } => {
                *bound_at = now.saturating_add(duration_ns(self.policy.probe_within));
            }
            Probe::Scheduled { at, .. } => {
                *at = (*at).max(now.saturating_add(duration_ns(self.policy.probe_after_min)));
            }
            Probe::Idle | Probe::Refetching => {}
        }
        if let Some(at) = &mut self.lifetime_from {
            *at = now;
        }
        if let Some(track) = &mut self.round {
            track.started_at = now;
            if let Some((first_at, _)) = &mut track.first {
                *first_at = now;
            }
        }
    }

    /// The open round's deadline fired. Its wait ran out: the probe goes
    /// ahead with the first upload's draw. It has been open too long: it is
    /// counted, and the driver says so once and ends it in the coalescer.
    pub(super) fn on_round_deadline(&mut self, now: u64) -> Vec<Action> {
        let Some(mut track) = self.round else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        if let Some((at, draw)) = track.first {
            if !track.triggered && now >= at.saturating_add(duration_ns(self.policy.round_wait)) {
                track.triggered = true;
                self.trigger(now, draw);
            }
        }
        if !track.stuck
            && now
                >= track
                    .started_at
                    .saturating_add(duration_ns(self.policy.round_stuck_after))
        {
            track.stuck = true;
            self.stuck_rounds = self.stuck_rounds.saturating_add(1);
            actions.push(Action::RoundStuck);
        }
        self.round = Some(track);
        actions
    }

    /// The refetch after a first miss was asked: the second probe is
    /// scheduled after a fresh delay.
    pub(super) fn refetched(&mut self, now: u64, draw: u64) -> Vec<Action> {
        if self.probe == Probe::Refetching && matches!(self.phase, Phase::Running { .. }) {
            self.schedule(now, draw, Attempt::AfterRefetch);
        }
        Vec::new()
    }

    fn schedule(&mut self, now: u64, draw: u64, attempt: Attempt) {
        self.probe = Probe::Scheduled {
            at: now.saturating_add(self.probe_delay(draw)),
            attempt,
        };
    }

    /// The driver minted the probe's nonce and launched the dial.
    pub(super) fn probe_dialed(&mut self, minted: u64) -> Vec<Action> {
        if let Probe::InFlight { minted_at, .. } = &mut self.probe {
            if minted_at.is_none() {
                *minted_at = Some(minted);
            }
        }
        Vec::new()
    }

    /// The driver could not dial: no route, no tip, or no onion yet. No
    /// evidence either way; the next round tries again.
    pub(super) fn probe_not_dialed(&mut self) -> Vec<Action> {
        if matches!(self.probe, Probe::InFlight { .. }) {
            self.probe = Probe::Idle;
        }
        Vec::new()
    }

    /// A probe's nonce came back through this node's onion. Only the probe
    /// in flight is evidence, and only when the handshake took the nonce
    /// before that probe's bound. `arrived_at` is that take, on this core's
    /// clock; `now` is the fold, which can be later, and it does not move
    /// the evidence. A nonce taken at or after the bound leaves the probe
    /// in flight, so the deadline still misses it. One from before a
    /// respawn, or one given up on, is stale and changes nothing.
    pub(super) fn probe_arrived(&mut self, now: u64, minted: u64, arrived_at: u64) -> Vec<Action> {
        let Probe::InFlight {
            bound_at,
            minted_at: Some(current),
            ..
        } = self.probe
        else {
            return Vec::new();
        };
        if current != minted
            || !matches!(self.phase, Phase::Running { .. })
            || arrived_at >= bound_at
        {
            return Vec::new();
        }
        self.probe = Probe::Idle;
        let recovered = matches!(self.inbound, Inbound::Unreachable { .. });
        self.inbound = Inbound::Reachable {
            evidence_at: arrived_at,
        };
        if recovered {
            self.say(now, Cadence::Now)
        } else {
            Vec::new()
        }
    }

    /// The probe's deadline fired: a scheduled probe is due, or one in
    /// flight missed its bound.
    pub(super) fn on_probe_deadline(&mut self, now: u64) -> Vec<Action> {
        match self.probe {
            Probe::Scheduled { at, attempt } if now >= at => {
                if !self.probe_may_run() {
                    // Suppressed: outbound is not usable, or the onion is
                    // owed. The next round schedules the next one.
                    self.probe = Probe::Idle;
                    return Vec::new();
                }
                self.probe = Probe::InFlight {
                    bound_at: now.saturating_add(duration_ns(self.policy.probe_within)),
                    minted_at: None,
                    attempt,
                };
                vec![Action::Probe]
            }
            Probe::InFlight {
                bound_at, attempt, ..
            } if now >= bound_at => {
                self.probe = Probe::Idle;
                let mut actions = vec![Action::CancelProbe];
                if !self.probe_may_run() {
                    return actions;
                }
                match attempt {
                    // One miss is not a verdict: refresh Tor's client view
                    // of this address, then probe once more.
                    Attempt::First => {
                        self.probe = Probe::Refetching;
                        actions.push(Action::RefetchDescriptor);
                    }
                    Attempt::AfterRefetch => {
                        actions.extend(self.inbound_down(now, InboundCause::ProbeTimedOut));
                    }
                }
                actions
            }
            _ => Vec::new(),
        }
    }

    /// Outbound is usable and the onion is published: a probe can be judged.
    fn probe_may_run(&self) -> bool {
        self.outbound_usable() && self.onion_done()
    }

    fn onion_done(&self) -> bool {
        matches!(
            self.phase,
            Phase::Running {
                onion: Duty::Done,
                ..
            }
        )
    }

    /// Service-class evidence (§4.4): the inbound facet goes down and the
    /// onion is published again on the running Tor. A probe still in
    /// flight is cancelled; the republish's own round schedules the next.
    fn inbound_down(&mut self, now: u64, cause: InboundCause) -> Vec<Action> {
        let mut actions = Vec::new();
        if matches!(self.probe, Probe::InFlight { .. }) {
            actions.push(Action::CancelProbe);
        }
        self.probe = Probe::Idle;
        let since = match self.inbound {
            Inbound::Unreachable { since, .. } => since,
            _ => now,
        };
        self.inbound = Inbound::Unreachable { cause, since };
        if let Phase::Running { onion, .. } = &mut self.phase {
            *onion = Duty::Owed;
        }
        self.service_republish = true;
        actions.push(Action::RepublishOnion);
        actions.extend(self.say(now, Cadence::Due));
        actions
    }

    /// `ADD_ONION` was refused. A republish the probe or a failed round
    /// asked for is Service-class: its control command failing is a
    /// process fault (§4.4). The first publish of a Tor keeps waiting for
    /// its endpoint, as before.
    pub(super) fn onion_refused(&mut self, now: u64) -> Vec<Action> {
        if self.service_republish && matches!(self.phase, Phase::Running { .. }) {
            self.service_republish = false;
            return self.process_fault(now, Cause::OnionRefused, false);
        }
        self.onion_rejected(now)
    }

    /// Drop the probe at a fault, a hold or a stop. The driver aborts the
    /// dial; the nonce leaves the set with it.
    pub(super) fn drop_probe(&mut self) -> Option<Action> {
        let in_flight = matches!(self.probe, Probe::InFlight { .. });
        self.probe = Probe::Idle;
        self.round = None;
        self.lifetime_from = None;
        self.service_republish = false;
        in_flight.then_some(Action::CancelProbe)
    }
}
