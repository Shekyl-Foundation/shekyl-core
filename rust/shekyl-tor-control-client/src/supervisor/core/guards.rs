// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Guard pinning (`TOR_SUPERVISOR.md` §4.4, the guard-pinning row; `TSR-W1`;
//! Rick, 2026-11-27).
//!
//! A Tor whose onion keeps its second-layer guards
//! ([`VanguardsMode::Managed`](crate::vanguard_rotation::VanguardsMode)) owes
//! one more step on entering Running: the guards are pinned before the onion
//! is published. The driver runs the guard manager's whole pipeline
//! (consensus, compute, `SETCONF`, save) as one request,
//! [`Action::PinGuards`], and reports how it ended. Until a pin is confirmed
//! on this Tor, no publish is sent: the choke point is
//! [`Core::guards_allow_publish`], which every `RepublishOnion` passes on its
//! way to the driver.
//!
//! How a pin ends, and what follows:
//!
//! - **Pinned:** the onion owed is published, and the set's expiry is armed
//!   on the pin. A set with no expiry is not rotated by the clock.
//! - **The control failed, or the reply missed its bound:** a process fault,
//!   folded as every other request's ([`super::Input::ControlEnded`], the
//!   reply bound). Tor's set and ours are in doubt, so Tor is started again.
//! - **Tor refused the pins:** the pinned Tor should accept them, so this is
//!   a defect to report. No respawn: a new Tor would refuse them again. Asked
//!   again at the cap.
//! - **Tor's view cannot fill the set:** too few eligible relays, too few
//!   entries decoded, or no consensus yet. No respawn. Asked again when
//!   Tor's consensus changes, which the sample's consensus clock already
//!   reads.
//! - **The random source refused the draw:** the driver ends the supervisor,
//!   as it does when the onion's key cannot be drawn. Nothing reaches the
//!   core.
//!
//! A first pin that fails is the onion's facet: [`InboundCause::GuardsRefused`]
//! or [`InboundCause::GuardsUnfilled`], written the way every other onion
//! cause is. A later Tor does not keep the previous offer. Until its pin is
//! confirmed the facet is not offered, unless a clock is already named, and
//! that clock keeps its cause. When the clock clears, the pin's cause stands
//! ([`Core::inbound_for_unproven`]). A rotation that fails on a Tor already
//! pinned keeps serving on the confirmed set, which Tor still holds, and says
//! so ([`Action::RotationFailed`]); unpublishing a reachable onion because one
//! guard is overdue costs more than it protects.
//!
//! Expiry is wall time and lives on the confirmed pin; this core's deadlines
//! are awake time. The pin reports the next expiry with the wall it was read
//! at, and the awake deadline is the gap between them. A sleep moves the wall
//! and not this clock, so every consensus clock the sample reads also compares
//! the wall with the expiry: a guard that expired in a sleep is replaced at
//! the sample the wake asks for. The clock does not outlive the pin. A new
//! Tor confirms its own.

use super::super::posture::{Inbound, InboundCause};
use super::{duration_ns, Action, Cadence, Core, Duty, Phase};
use crate::vanguard_rotation::VanguardsMode;

/// Why a pin did not take, where the core has a remedy for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardFault {
    /// Tor refused the `SETCONF` of the pins.
    Refused,
    /// Tor's view of the network could not fill the set, or Tor had no
    /// consensus to read it from.
    Unfilled,
}

impl GuardFault {
    fn cause(self) -> InboundCause {
        match self {
            Self::Refused => InboundCause::GuardsRefused,
            Self::Unfilled => InboundCause::GuardsUnfilled,
        }
    }
}

/// This Tor's guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Guards {
    /// Tor keeps its own second-layer guards: nothing is pinned, and the
    /// onion is published as soon as it is owed. A per-boot onion.
    TorsOwn,
    /// Not pinned on this Tor. No onion is published. `fault` is why the
    /// last pin did not take, while one has failed.
    Unpinned { fault: Option<FailedPin> },
    /// Pinned and confirmed on this Tor. `fault` is why the last rotation
    /// did not take, while one has failed; the confirmed set keeps serving.
    /// `clock` is that set's expiry, and it is absent while a rotation is
    /// in flight.
    Pinned {
        fault: Option<FailedPin>,
        clock: Option<GuardClock>,
    },
}

impl Guards {
    /// Whether a publish may go out. An unpinned set may not.
    pub(super) fn allows_publish(&self) -> bool {
        !matches!(self, Self::Unpinned { .. })
    }

    /// The open failure's retry. The same record on an unpinned set and on
    /// a rotation that did not take.
    fn open_retry(&self) -> Option<Retry> {
        match self {
            Self::Unpinned {
                fault: Some(failed),
            }
            | Self::Pinned {
                fault: Some(failed),
                ..
            } => Some(failed.retry),
            _ => None,
        }
    }

    fn open_retry_mut(&mut self) -> Option<&mut Retry> {
        match self {
            Self::Unpinned {
                fault: Some(failed),
            }
            | Self::Pinned {
                fault: Some(failed),
                ..
            } => Some(&mut failed.retry),
            _ => None,
        }
    }
}

/// A pin that did not take, and when it is asked again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FailedPin {
    fault: GuardFault,
    /// When this run of failures started, in this core's clock.
    since: u64,
    retry: Retry,
}

/// When a pin that did not take is asked again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retry {
    /// At this time, in this core's clock: one cap after a refusal.
    At(u64),
    /// When the consensus clock reads a `valid-after` other than this one
    /// (`None`: none read yet, so any).
    NextConsensus(Option<u64>),
    /// Asked; the answer decides.
    Asked,
}

/// When the pinned set next expires. It lives on the pin, so a new Tor
/// cannot see the previous set's deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GuardClock {
    /// The earliest expiry, in Unix seconds of wall time.
    wall_due: u64,
    /// The same moment in this core's clock, as of the pin.
    awake_due: u64,
}

impl Core {
    /// Whether this Tor's onion keeps its guards.
    pub(super) fn owes_guard_pin(&self) -> bool {
        matches!(self.policy.vanguards, VanguardsMode::Managed)
    }

    /// The guards a Tor entering Running owes.
    pub(super) fn guards_for_new_tor(&self) -> Guards {
        if self.owes_guard_pin() {
            Guards::Unpinned { fault: None }
        } else {
            Guards::TorsOwn
        }
    }

    /// The action a Tor entering Running sends for its guards.
    pub(super) fn pin_on_entry(&self) -> Option<Action> {
        matches!(self.guards(), Some(Guards::Unpinned { .. })).then_some(Action::PinGuards)
    }

    /// Whether a publish may go to the driver: no Tor that owes a pin
    /// publishes before it is confirmed.
    pub(super) fn guards_allow_publish(&self) -> bool {
        self.guards().is_none_or(|guards| guards.allows_publish())
    }

    fn guards(&self) -> Option<Guards> {
        match self.phase {
            Phase::Running { guards, .. } => Some(guards),
            _ => None,
        }
    }

    fn guards_mut(&mut self) -> Option<&mut Guards> {
        match &mut self.phase {
            Phase::Running { guards, .. } => Some(guards),
            _ => None,
        }
    }

    /// The open failure of an unpinned set, as the facet names it.
    fn open_guard_cause(&self) -> Option<(InboundCause, u64)> {
        match self.guards() {
            Some(Guards::Unpinned {
                fault: Some(failed),
            }) => Some((failed.fault.cause(), failed.since)),
            _ => None,
        }
    }

    /// The facet of an onion this incarnation has not proved. A withheld pin
    /// names itself. An onion already published on this Tor is publishing.
    /// Every other unproved onion is not offered.
    pub(super) fn inbound_for_unproven(&self, now: u64) -> Inbound {
        if let Some((cause, since)) = self.open_guard_cause() {
            return Inbound::Unreachable { cause, since };
        }
        if self.onion_published_here() {
            Inbound::Publishing { since: now }
        } else {
            Inbound::NotOffered
        }
    }

    /// A confirmed pin retires its own cause. A clock's cause stays.
    fn clear_guard_cause(&mut self) {
        if matches!(
            self.inbound,
            Inbound::Unreachable {
                cause: InboundCause::GuardsRefused | InboundCause::GuardsUnfilled,
                ..
            }
        ) {
            self.inbound = Inbound::NotOffered;
        }
    }

    /// The pin was confirmed at `now`. `next_expiry` is the set's earliest
    /// expiry, read beside the wall `wall` (both Unix seconds). `None` is a
    /// set the clock does not rotate.
    pub(super) fn guards_pinned(
        &mut self,
        now: u64,
        next_expiry: Option<u64>,
        wall: u64,
    ) -> Vec<Action> {
        let clock = next_expiry.map(|expiry| {
            let left = std::time::Duration::from_secs(expiry.saturating_sub(wall));
            GuardClock {
                wall_due: expiry,
                awake_due: now.saturating_add(duration_ns(left)),
            }
        });
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        let before = *guards;
        if matches!(before, Guards::TorsOwn) {
            return Vec::new();
        }
        *guards = Guards::Pinned { fault: None, clock };
        self.clear_guard_cause();
        let mut actions = Vec::new();
        if let Guards::Unpinned { fault } = before {
            // The publish this Tor has owed since it entered Running.
            if matches!(
                self.phase,
                Phase::Running {
                    onion: Duty::Owed,
                    ..
                }
            ) {
                actions.push(Action::RepublishOnion);
            }
            if fault.is_some() {
                actions.extend(self.say(now, Cadence::Due));
            }
        }
        actions
    }

    /// The pin did not take, for `fault`.
    pub(super) fn guards_failed(&mut self, now: u64, fault: GuardFault) -> Vec<Action> {
        let retry = match fault {
            GuardFault::Refused => Retry::At(now.saturating_add(self.cap())),
            GuardFault::Unfilled => Retry::NextConsensus(self.valid_after),
        };
        let unpinned = match self.guards_mut() {
            Some(Guards::Unpinned { fault: open }) => {
                let since = open.map_or(now, |held| held.since);
                *open = Some(FailedPin {
                    fault,
                    since,
                    retry,
                });
                true
            }
            Some(Guards::Pinned { fault: open, .. }) => {
                let since = open.map_or(now, |held| held.since);
                *open = Some(FailedPin {
                    fault,
                    since,
                    retry,
                });
                false
            }
            _ => return Vec::new(),
        };
        // A named clock keeps its cause. The pin's cause is written when
        // that clock clears (`inbound_for_unproven`).
        if unpinned && !self.clock_is_behind() {
            self.inbound_unreachable(now, fault.cause());
        }
        if unpinned {
            self.say(now, Cadence::Due)
        } else {
            vec![Action::RotationFailed(fault)]
        }
    }

    /// The sample read the consensus's `valid-after` and the wall (Unix
    /// seconds). A pin waiting for a new consensus is asked when it has
    /// one; a set whose expiry the wall has passed is rotated, however
    /// little awake time went by.
    pub(super) fn guards_on_consensus(&mut self, valid_after: u64, wall: u64) -> Vec<Action> {
        self.valid_after = Some(valid_after);
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        if let Some(retry) = guards.open_retry_mut() {
            if let Retry::NextConsensus(seen) = *retry {
                if seen != Some(valid_after) {
                    *retry = Retry::Asked;
                    return vec![Action::PinGuards];
                }
            }
            return Vec::new();
        }
        if let Guards::Pinned { fault: None, clock } = guards {
            if clock.is_some_and(|due| wall >= due.wall_due) {
                *clock = None;
                return vec![Action::PinGuards];
            }
        }
        Vec::new()
    }

    /// When guard work is next due in this core's clock: a refusal's retry,
    /// or the pinned set's expiry.
    pub(super) fn guards_due(&self) -> Option<u64> {
        let guards = self.guards()?;
        if let Some(Retry::At(at)) = guards.open_retry() {
            return Some(at);
        }
        match guards {
            Guards::Pinned { fault: None, clock } => clock.map(|due| due.awake_due),
            _ => None,
        }
    }

    /// The guard deadline fired: ask the pin again.
    pub(super) fn on_guards_deadline(&mut self, now: u64) -> Vec<Action> {
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        if let Some(retry) = guards.open_retry_mut() {
            if let Retry::At(at) = *retry {
                if now >= at {
                    *retry = Retry::Asked;
                    return vec![Action::PinGuards];
                }
            }
            return Vec::new();
        }
        if let Guards::Pinned { fault: None, clock } = guards {
            if clock.is_some_and(|due| now >= due.awake_due) {
                *clock = None;
                return vec![Action::PinGuards];
            }
        }
        Vec::new()
    }
}
