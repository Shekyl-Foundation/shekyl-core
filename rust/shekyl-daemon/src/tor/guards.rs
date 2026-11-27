// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A persistent onion's second-layer guards (`TOR_SUPERVISOR.md` §4.4, the
//! guard-pinning row; `TSR-W1`, which closes `TSR-Q15`; Rick, 2026-11-27).
//!
//! Stock Tor keeps its second-layer guards in memory, so a persistent onion
//! would draw them again at every start. The guard manager the wallet's Tor
//! uses (`shekyl_tor_control_client::vanguard_rotation`) pins and keeps them,
//! its state file in the onion's own guard directory beside Tor's `state`.
//! A per-boot onion's Tor keeps its own: nothing here runs for it.
//!
//! The pipeline (consensus, compute, `SETCONF`, save) is one request run off
//! the loop, as every request to Tor is. The manager's state goes with it
//! and comes back with the answer, whether or not the core still waits on
//! that answer: the state on disk and in memory is the manager's alone, and
//! a pin Tor confirmed after the core gave up on it still moved it. A pin
//! asked while the manager is out waits for it to come home, and the loop
//! does not. Each pass is bounded by the core's reply bound, so the manager
//! comes home within one bound of being sent.
//!
//! A confirmed pin mints the witness the onion's publish is sent through
//! ([`ControlAsker::pinned`]). It is held for the incarnation it was minted
//! on and dropped when that Tor goes, so no publish of this onion reaches a
//! Tor whose guards were never pinned. The wallet consumes its witness at
//! its one publish; this driver republishes on a running Tor (§4.4,
//! Service), so it holds the witness and lends it to each publish.

use std::time::{SystemTime, UNIX_EPOCH};

use shekyl_tor_control_client::awake;
use shekyl_tor_control_client::control::ControlError;
use shekyl_tor_control_client::directory_cache::GuardState;
use shekyl_tor_control_client::supervisor::{GuardFault, Input, REPLY_BOUND};
use shekyl_tor_control_client::vanguard_rotation::{
    RotationError, VanguardManager, VanguardsAbort, VanguardsActive, VanguardsError, VanguardsMode,
    VanguardsWarning,
};

use super::requests::Answer;
use super::{Drive, SupervisorEnd, TorAsk};

/// The manager, and what the driver keeps about it between requests.
pub(super) struct GuardSlot {
    /// The manager when it is home; `None` while a pin holds it.
    home: Option<VanguardManager>,
    /// A pin asked while the manager was out, by its request number: sent
    /// when the manager comes home, if the core still waits on it.
    waiting: Option<u64>,
    /// The warning last said, so a change is said once.
    said: Option<VanguardsWarning>,
}

impl GuardSlot {
    /// The persistent onion's manager, loaded from its guard directory. A
    /// state file that could not be used is said now: the first pin draws a
    /// new set, which is the redraw the manager exists to prevent.
    pub(super) fn load(guard_state: &GuardState) -> Self {
        if let Err(error) = guard_state.ensure() {
            tracing::warn!(
                target: "tor",
                "this onion's guard directory could not be made, so its guards cannot be kept across a restart: {error}"
            );
        }
        let manager = VanguardManager::load(VanguardsMode::Managed, guard_state.path());
        let said = manager.warning();
        if let Some(warning) = &said {
            tracing::warn!(target: "tor", "{warning}");
        }
        Self {
            home: Some(manager),
            waiting: None,
            said,
        }
    }

    /// Take the manager out, as a pin in flight holds it.
    #[cfg(all(test, unix))]
    pub(super) fn take_home(&mut self) -> Option<VanguardManager> {
        self.home.take()
    }

    /// Whether the manager is home.
    #[cfg(all(test, unix))]
    pub(super) fn is_home(&self) -> bool {
        self.home.is_some()
    }

    /// The pin waiting for the manager, by its request number.
    #[cfg(all(test, unix))]
    pub(super) fn waiting(&self) -> Option<u64> {
        self.waiting
    }

    /// Say the manager's warning when it changed.
    fn say(&mut self, now: Option<VanguardsWarning>) {
        if now == self.said {
            return;
        }
        match &now {
            Some(warning) => tracing::warn!(target: "tor", "{warning}"),
            None => tracing::info!(target: "tor", "this onion's guard state is saved again"),
        }
        self.said = now;
    }
}

/// Unix seconds of `at`; a time before the epoch is the epoch.
fn unix_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl Drive {
    fn guard_slot(&mut self) -> Result<&mut GuardSlot, SupervisorEnd> {
        self.managed
            .as_mut()
            .and_then(|boot| boot.guards.as_mut())
            .ok_or(SupervisorEnd::NoTorToRun(TorAsk::Guards))
    }

    /// Send the pin `number` names. The manager goes with it; one that is
    /// out with an earlier pin is waited for off the loop.
    pub(super) fn send_pin(&mut self, number: u64) -> Result<Option<Vec<Input>>, SupervisorEnd> {
        let asker = self.asker();
        let slot = self.guard_slot()?;
        let Some(mut manager) = slot.home.take() else {
            slot.waiting = Some(number);
            return Ok(None);
        };
        let Some(asker) = asker else {
            slot.home = Some(manager);
            return Ok(Some(vec![Input::ControlEnded]));
        };
        let actor = asker.actor().clone();
        self.answer_later(number, async move {
            let pinned = awake::timeout(
                REPLY_BOUND,
                manager.establish(&actor, REPLY_BOUND, SystemTime::now()),
            )
            .await;
            let outcome = pinned.unwrap_or(Err(VanguardsAbort::Failed(VanguardsError::Control(
                ControlError::Timeout,
            ))));
            Answer::Guards {
                manager: Box::new(manager),
                outcome,
            }
        });
        Ok(None)
    }

    /// A pin's answer: the manager comes home whatever the core still waits
    /// on. The core folds the outcome only when `number` is in flight; a
    /// stale answer's witness names a Tor the core gave up on, and is
    /// dropped.
    pub(super) fn guards_answered(
        &mut self,
        number: u64,
        manager: VanguardManager,
        outcome: Result<Option<VanguardsActive>, VanguardsAbort>,
    ) -> Vec<Input> {
        let next_expiry = manager.next_expiry();
        let warning = manager.warning();
        let waiting = match self.guard_slot() {
            Ok(slot) => {
                slot.home = Some(manager);
                slot.say(warning);
                slot.waiting.take()
            }
            // A pin's answer reaches only a driver that sent one.
            Err(_) => return Vec::new(),
        };
        if self.core.in_flight() != Some(number) {
            // A pin asked while this one was out goes now that the manager
            // is home.
            if waiting.is_some() && waiting == self.core.in_flight() {
                return match self.send(shekyl_tor_control_client::supervisor::Action::PinGuards) {
                    Ok(inputs) => inputs,
                    Err(end) => {
                        self.ending = Some(end);
                        Vec::new()
                    }
                };
            }
            return Vec::new();
        }
        self.core.begin_reply_fold();
        let mut inputs = self.pin_outcome(outcome, next_expiry);
        inputs.push(Input::Replied { number });
        inputs
    }

    /// The core's inputs for a pin's outcome, by §4.4's guard-pinning row.
    pub(super) fn pin_outcome(
        &mut self,
        outcome: Result<Option<VanguardsActive>, VanguardsAbort>,
        next_expiry: Option<SystemTime>,
    ) -> Vec<Input> {
        match outcome {
            Ok(Some(witness)) => {
                self.witness = Some(witness);
                tracing::info!(target: "tor", "this onion's second-layer guards are pinned");
                vec![Input::GuardsPinned {
                    // A confirmed pin holds a set, so it has an expiry; one
                    // without is never rotated by the clock.
                    next_expiry: next_expiry.map_or(u64::MAX, unix_seconds),
                    wall: unix_seconds(SystemTime::now()),
                }]
            }
            // The manager is loaded managed, so a pass that pins nothing is a
            // broken promise, not a condition.
            Ok(None) => {
                self.ending = Some(SupervisorEnd::NoTorToRun(TorAsk::Guards));
                Vec::new()
            }
            Err(VanguardsAbort::ActorGone) => vec![Input::ControlEnded],
            Err(VanguardsAbort::Failed(VanguardsError::Control(error))) => {
                tracing::info!(
                    target: "tor",
                    "pinning this onion's guards failed on the control connection, so Tor is started again: {error}"
                );
                vec![Input::ControlEnded]
            }
            Err(VanguardsAbort::Failed(VanguardsError::PinsRefused { status })) => {
                tracing::warn!(
                    target: "tor",
                    status,
                    "Tor refused this onion's guard pins; the onion is not published on unpinned guards, and the pin is asked again"
                );
                vec![Input::GuardsRefused]
            }
            Err(VanguardsAbort::Failed(
                error @ (VanguardsError::ConsensusRefused { .. }
                | VanguardsError::Rotation(
                    RotationError::TooFewEligible { .. } | RotationError::ConsensusUnusable { .. },
                )),
            )) => {
                tracing::info!(
                    target: "tor",
                    "this onion's guards wait for a fuller view of the network: {error}"
                );
                vec![Input::GuardsUnfilled]
            }
            Err(VanguardsAbort::Failed(VanguardsError::Rotation(
                RotationError::RngUnavailable,
            ))) => {
                self.ending = Some(SupervisorEnd::NoGuardDraw);
                Vec::new()
            }
        }
    }

    /// A rotation on a pinned Tor did not take.
    pub(super) fn rotation_failed(fault: GuardFault) {
        let why = match fault {
            GuardFault::Refused => "Tor refused the new pins",
            GuardFault::Unfilled => "Tor's view of the network could not fill the set",
        };
        tracing::warn!(
            target: "tor",
            "this onion's guards due for rotation were not replaced ({why}); it keeps serving on the guards Tor confirmed, and the rotation is asked again"
        );
    }
}
