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
//! - **Pinned:** the onion owed is published, and the next expiry is armed.
//! - **The control failed, or the reply missed its bound:** a process fault,
//!   folded as every other request's ([`Input::ControlEnded`], the reply
//!   bound). Tor's set and ours are in doubt, so Tor is started again.
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
//! A first pin that fails withholds the onion, and the onion's facet says
//! why: [`InboundCause::GuardsRefused`] or [`InboundCause::GuardsUnfilled`]
//! where it would otherwise say no onion is offered. A rotation that fails
//! on a Tor already pinned keeps serving on the confirmed set, which Tor
//! still holds, and says so ([`Action::RotationFailed`]); unpublishing a
//! reachable onion because one guard is overdue costs more than it protects.
//!
//! Expiry is wall time; this core's deadlines are awake time. The pin
//! reports the next expiry with the wall it was read at, and the awake
//! deadline is the gap between them. A sleep moves the wall and not this
//! clock, so every consensus clock the sample reads also compares the wall
//! with the expiry: a guard that expired in a sleep is replaced at the
//! sample the wake asks for.

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
    /// Not pinned on this Tor. No onion is published. `withheld` is why the
    /// last pin did not take, while one has failed.
    Unpinned { withheld: Option<Withheld> },
    /// Pinned and confirmed on this Tor. `rotation` is why the last rotation
    /// did not take, while one has failed; the confirmed set keeps serving.
    Pinned { rotation: Option<Withheld> },
}

/// A pin that did not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Withheld {
    fault: GuardFault,
    /// When the first pin of this run failed, in this core's clock.
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

/// When the pinned set next expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GuardClock {
    /// The earliest expiry, in Unix seconds of wall time.
    wall_due: u64,
    /// The same moment in this core's clock, as of the pin.
    awake_due: u64,
}

impl Core {
    /// The guards a Tor entering Running owes.
    pub(super) fn guards_for_new_tor(&self) -> Guards {
        match self.policy.vanguards {
            VanguardsMode::Off => Guards::TorsOwn,
            VanguardsMode::Managed => Guards::Unpinned { withheld: None },
        }
    }

    /// The action a Tor entering Running sends for its guards.
    pub(super) fn pin_on_entry(&self) -> Option<Action> {
        matches!(self.guards(), Some(Guards::Unpinned { .. })).then_some(Action::PinGuards)
    }

    /// Whether a publish may go to the driver: no Tor that owes a pin
    /// publishes before it is confirmed.
    pub(super) fn guards_allow_publish(&self) -> bool {
        !matches!(self.guards(), Some(Guards::Unpinned { .. }))
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

    /// The pin was confirmed at `now`; the set's earliest expiry is
    /// `next_expiry`, read beside the wall `wall` (both Unix seconds).
    pub(super) fn guards_pinned(&mut self, now: u64, next_expiry: u64, wall: u64) -> Vec<Action> {
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        let before = *guards;
        if before == Guards::TorsOwn {
            return Vec::new();
        }
        *guards = Guards::Pinned { rotation: None };
        let left = std::time::Duration::from_secs(next_expiry.saturating_sub(wall));
        self.guard_clock = Some(GuardClock {
            wall_due: next_expiry,
            awake_due: now.saturating_add(duration_ns(left)),
        });
        let mut actions = Vec::new();
        if let Guards::Unpinned { withheld } = before {
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
            if withheld.is_some() {
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
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        match guards {
            Guards::TorsOwn => Vec::new(),
            Guards::Unpinned { withheld } => {
                let since = withheld.map_or(now, |held| held.since);
                *withheld = Some(Withheld {
                    fault,
                    since,
                    retry,
                });
                self.say(now, Cadence::Due)
            }
            Guards::Pinned { rotation } => {
                let since = rotation.map_or(now, |held| held.since);
                *rotation = Some(Withheld {
                    fault,
                    since,
                    retry,
                });
                vec![Action::RotationFailed(fault)]
            }
        }
    }

    /// The sample read the consensus's `valid-after` and the wall (Unix
    /// seconds). A pin waiting for a new consensus is asked when it has
    /// one; a set whose expiry the wall has passed is rotated, however
    /// little awake time went by.
    pub(super) fn guards_on_consensus(&mut self, valid_after: u64, wall: u64) -> Vec<Action> {
        self.valid_after = Some(valid_after);
        let clock = self.guard_clock;
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        match guards {
            Guards::Unpinned {
                withheld: Some(held),
            }
            | Guards::Pinned {
                rotation: Some(held),
            } => match held.retry {
                Retry::NextConsensus(seen) if seen != Some(valid_after) => {
                    held.retry = Retry::Asked;
                    vec![Action::PinGuards]
                }
                _ => Vec::new(),
            },
            Guards::Pinned { rotation: None } if clock.is_some_and(|c| wall >= c.wall_due) => {
                self.guard_clock = None;
                vec![Action::PinGuards]
            }
            _ => Vec::new(),
        }
    }

    /// When guard work is next due in this core's clock: a refusal's retry,
    /// or the pinned set's expiry.
    pub(super) fn guards_due(&self) -> Option<u64> {
        match self.guards()? {
            Guards::Unpinned {
                withheld: Some(held),
            }
            | Guards::Pinned {
                rotation: Some(held),
            } => match held.retry {
                Retry::At(at) => Some(at),
                _ => None,
            },
            Guards::Pinned { rotation: None } => self.guard_clock.map(|c| c.awake_due),
            _ => None,
        }
    }

    /// The guard deadline fired: ask the pin again.
    pub(super) fn on_guards_deadline(&mut self, now: u64) -> Vec<Action> {
        let clock_due = self.guard_clock.is_some_and(|c| now >= c.awake_due);
        let Some(guards) = self.guards_mut() else {
            return Vec::new();
        };
        match guards {
            Guards::Unpinned {
                withheld: Some(held),
            }
            | Guards::Pinned {
                rotation: Some(held),
            } if matches!(held.retry, Retry::At(at) if now >= at) => {
                held.retry = Retry::Asked;
                vec![Action::PinGuards]
            }
            Guards::Pinned { rotation: None } if clock_due => {
                self.guard_clock = None;
                vec![Action::PinGuards]
            }
            _ => Vec::new(),
        }
    }

    /// The onion facet as shown: why a withheld onion is not published,
    /// where the facet would otherwise say none is offered. Every other
    /// facet stands as it is, so a clock named before the first publish
    /// keeps its cause.
    pub(super) fn inbound_shown(&self) -> Inbound {
        match (self.inbound, self.guards()) {
            (
                Inbound::NotOffered,
                Some(Guards::Unpinned {
                    withheld: Some(held),
                }),
            ) => Inbound::Unreachable {
                cause: held.fault.cause(),
                since: held.since,
            },
            (inbound, _) => inbound,
        }
    }
}
