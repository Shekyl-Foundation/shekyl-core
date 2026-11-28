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
//! ([`shekyl_tor_control_daemon::ControlAsker::pinned`]). It is held for the incarnation it was minted
//! on and dropped when that Tor goes, so no publish of this onion reaches a
//! Tor whose guards were never pinned. The wallet consumes its witness at
//! its one publish; this driver republishes on a running Tor (§4.4,
//! Service), so it holds the witness and lends it to each publish.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shekyl_timing_engine::{Clock, MonotonicClock};
use shekyl_tor_control_client::awake;
use shekyl_tor_control_client::control::ControlError;
use shekyl_tor_control_client::directory_cache::GuardState;
use shekyl_tor_control_client::supervisor::{GuardFault, Input, REPLY_BOUND};
use shekyl_tor_control_client::vanguard_rotation::{
    RotationError, VanguardManager, VanguardsAbort, VanguardsActive, VanguardsError, VanguardsMode,
    VanguardsWarning,
};

use super::requests::Answer;
use super::{Drive, SupervisorEnd};

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
            .ok_or(SupervisorEnd::NoGuardManager)
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
            let clock = MonotonicClock::new();
            let sent = clock.now();
            let pinned = awake::timeout(
                REPLY_BOUND,
                manager.pin(&actor, REPLY_BOUND, SystemTime::now()),
            )
            .await;
            let outcome = pinned.unwrap_or(Err(VanguardsAbort::Failed(VanguardsError::Control(
                ControlError::Timeout,
            ))));
            Answer::Guards {
                manager: Box::new(manager),
                outcome,
                took: Duration::from_nanos(clock.now().get().saturating_sub(sent.get())),
            }
        });
        Ok(None)
    }

    /// A pin's answer: the manager comes home whatever the core still waits
    /// on. The core folds the outcome only when `number` is in flight; a
    /// stale answer's witness names a Tor the core gave up on, and is
    /// dropped.
    ///
    /// Every answer, a stale one included, says how long the pin took. The
    /// floor device's soak counts each pin over 10 s (`TOR_SUPERVISOR.md`
    /// `TSR-M16`; Rick, 2026-11-28): the worst of 20 passes on the floor was
    /// 8.9 s against the 30 s reply bound, eleven times the typical pass.
    pub(super) fn guards_answered(
        &mut self,
        number: u64,
        manager: VanguardManager,
        outcome: Result<VanguardsActive, VanguardsAbort>,
        took: Duration,
    ) -> Vec<Input> {
        let took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
        tracing::info!(target: "tor", took_ms, "this onion's guard pin answered");
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
        outcome: Result<VanguardsActive, VanguardsAbort>,
        next_expiry: Option<SystemTime>,
    ) -> Vec<Input> {
        match outcome {
            Ok(witness) => {
                self.witness = Some(witness);
                tracing::info!(target: "tor", "this onion's second-layer guards are pinned");
                vec![Input::GuardsPinned {
                    // No expiry is a set the clock does not rotate.
                    next_expiry: next_expiry.map(unix_seconds),
                    wall: unix_seconds(SystemTime::now()),
                }]
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

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use shekyl_tor_control_client::binary::VerifiedTorBinary;
    use shekyl_tor_control_client::control::ControlError;
    use shekyl_tor_control_client::supervisor::{Action, Core, Input};
    use shekyl_tor_control_client::vanguard_rotation::{
        RotationError, VanguardsAbort, VanguardsError,
    };

    use super::super::loop_tests::{on_the_loops_runtime, persistent};
    use super::super::{Drive, OnionSource, PinSource, Supervises, SupervisorEnd};

    fn guard_slot(drive: &mut Drive) -> &mut super::GuardSlot {
        drive
            .managed
            .as_mut()
            .and_then(|boot| boot.guards.as_mut())
            .expect("a persistent onion's guard manager")
    }

    fn replied(core: &mut Core, at: u64) {
        if let Some(number) = core.in_flight() {
            core.on(Input::Replied { number }, at);
        }
    }

    /// Bring the core to Running with its pin in flight. The driver has not
    /// sent it: the manager is still home.
    fn pin_in_flight(drive: &mut Drive) -> u64 {
        let core = &mut drive.core;
        core.on(
            Input::PinAccepted {
                binary: VerifiedTorBinary::unchecked_for_test(std::path::PathBuf::from(
                    "/opt/shekyl/tor/tor",
                )),
            },
            0,
        );
        core.on(Input::Spawned, 0);
        replied(core, 0);
        replied(core, 0);
        core.on(
            Input::DirectorySample {
                progress: Some(10),
                socks: Some("127.0.0.1:9150".parse().expect("socks")),
                read: None,
            },
            0,
        );
        replied(core, 0);
        let running = core.on(Input::BootstrapComplete, 0);
        assert!(
            running.actions.contains(&Action::PinGuards),
            "entry asks the pin: {running:?}"
        );
        core.in_flight().expect("the pin is in flight")
    }

    /// **A pin's answer the core gave up on still brings the guard manager
    /// home.** The manager's state moved with the pin; dropping it with a stale
    /// answer would make the next pin draw a new set, the restart-driven
    /// rotation the manager exists to prevent. A pin asked while the manager
    /// was out waits for it, off the loop. The stale answer still says how
    /// long the pin took, since a pin past the bound is the slow one the
    /// floor's soak counts (`TSR-M16`). Red edits: return before
    /// `guards_answered` puts the manager home when the number is not in
    /// flight; or drop its `took_ms` line.
    #[test]
    fn a_pin_answer_the_core_gave_up_on_brings_the_manager_home() {
        on_the_loops_runtime(|dir| async move {
            let mut drive = persistent(dir.path());
            assert!(guard_slot(&mut drive).is_home(), "loaded at the start");
            let manager = guard_slot(&mut drive)
                .take_home()
                .expect("the manager is home");

            // The core gave up on that pin, and asked another while it was out.
            assert_eq!(drive.send_pin(9), Ok(None), "the second pin waits");
            assert_eq!(guard_slot(&mut drive).waiting(), Some(9));

            assert_eq!(
                drive.core.in_flight(),
                None,
                "the first pin is not in flight"
            );
            let mut folded = Vec::new();
            let log = crate::logged(|| {
                folded = drive.guards_answered(
                    5,
                    manager,
                    Err(VanguardsAbort::ActorGone),
                    Duration::from_millis(12_345),
                );
            });
            assert!(
                log.contains("took_ms=12345"),
                "a stale answer still says how long the pin took: {log}"
            );
            assert!(
                folded.is_empty(),
                "a stale answer folds nothing: {folded:?}"
            );
            assert!(guard_slot(&mut drive).is_home(), "the manager came home");
            assert!(drive.witness.is_none());
            assert!(drive.ending.is_none());
            tokio::task::spawn_blocking(move || drop(drive))
                .await
                .expect("the driver drops");
        });
    }

    /// **A pin asked while the manager is out is sent when the manager comes
    /// home.** The core still waits on that later pin. The stale answer is
    /// not folded. With no control connection the send answers at once.
    /// Red edit: drop the waiting pin in `guards_answered`, and this answer
    /// folds nothing.
    #[test]
    fn a_pin_asked_while_the_manager_is_out_is_sent_when_it_comes_home() {
        on_the_loops_runtime(|dir| async move {
            let mut drive = persistent(dir.path());
            let number = pin_in_flight(&mut drive);
            let manager = guard_slot(&mut drive)
                .take_home()
                .expect("the manager is home");
            assert_eq!(drive.send_pin(number), Ok(None), "the pin waits");
            assert_eq!(guard_slot(&mut drive).waiting(), Some(number));

            let folded = drive.guards_answered(
                number.wrapping_sub(1),
                manager,
                Err(VanguardsAbort::Failed(VanguardsError::PinsRefused {
                    status: 552,
                })),
                Duration::ZERO,
            );
            assert!(
                folded
                    .iter()
                    .any(|input| matches!(input, Input::ControlEnded)),
                "the waiting pin is sent: {folded:?}"
            );
            assert!(
                !folded
                    .iter()
                    .any(|input| matches!(input, Input::GuardsRefused)),
                "the stale refusal is not folded: {folded:?}"
            );
            assert!(
                guard_slot(&mut drive).is_home(),
                "no control, so it came back"
            );
            assert_eq!(guard_slot(&mut drive).waiting(), None);
            assert!(drive.ending.is_none());
            tokio::task::spawn_blocking(move || drop(drive))
                .await
                .expect("the driver drops");
        });
    }

    /// **Each way a pin ends reaches the core as its remedy** (§4.4, the
    /// guard-pinning row). A control failure is a process fault; Tor refusing
    /// the pins and a view that cannot fill the set are their own inputs and
    /// respawn nothing; a refused random source ends the supervisor. Red edit:
    /// fold a refused pin as `ControlEnded`, and a Tor that refuses its
    /// options is respawned forever.
    #[test]
    fn each_pin_outcome_reaches_the_core_as_its_remedy() {
        on_the_loops_runtime(|dir| async move {
            let mut drive = persistent(dir.path());
            let failed = |error| Err(VanguardsAbort::Failed(error));
            let cases = [
                (Err(VanguardsAbort::ActorGone), vec![Input::ControlEnded]),
                (
                    failed(VanguardsError::Control(ControlError::Timeout)),
                    vec![Input::ControlEnded],
                ),
                (
                    failed(VanguardsError::PinsRefused { status: 552 }),
                    vec![Input::GuardsRefused],
                ),
                (
                    failed(VanguardsError::ConsensusRefused { status: 551 }),
                    vec![Input::GuardsUnfilled],
                ),
                (
                    failed(VanguardsError::Rotation(RotationError::TooFewEligible {
                        available: 3,
                        needed: 12,
                    })),
                    vec![Input::GuardsUnfilled],
                ),
                (
                    failed(VanguardsError::Rotation(RotationError::ConsensusUnusable {
                        decoded: 10,
                        announced: 7_000,
                    })),
                    vec![Input::GuardsUnfilled],
                ),
            ];
            for (outcome, expected) in cases {
                let label = format!("{outcome:?}");
                assert_eq!(drive.pin_outcome(outcome, None), expected, "{label}");
                assert!(drive.ending.is_none(), "{label}: no end");
            }
            assert!(drive
                .pin_outcome(
                    failed(VanguardsError::Rotation(RotationError::RngUnavailable)),
                    None
                )
                .is_empty());
            assert_eq!(drive.ending.take(), Some(SupervisorEnd::NoGuardDraw));
            tokio::task::spawn_blocking(move || drop(drive))
                .await
                .expect("the driver drops");
        });
    }

    /// **A persistent onion is published only through the pin confirmed on its
    /// Tor.** With no witness held, the publish is the supervisor's end, never
    /// a send on the plain control: the core withholds it, so reaching here is
    /// a broken promise. A per-boot onion's Tor keeps its own guards and needs
    /// none; asking it for a pin is the same kind of broken promise. Red edit:
    /// publish a persistent onion through `self.asker()`, or report a missing
    /// manager as `NoTorToRun`.
    #[test]
    fn a_persistent_onion_is_not_published_without_its_pin() {
        on_the_loops_runtime(|dir| async move {
            let mut drive = persistent(dir.path());
            drive.forward = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18_022)));
            assert_eq!(drive.send_add(1), Err(SupervisorEnd::UnpinnedPublish));
            tokio::task::spawn_blocking(move || drop(drive))
                .await
                .expect("the driver drops");

            let data_dir = dir.path().join("per-boot");
            std::fs::create_dir_all(&data_dir).expect("the data directory");
            let (_owner, inbox, feeds) = super::super::inbox::inbox();
            let network = super::super::loop_tests::network(dir.path(), feeds);
            let mut per_boot = Drive::start(
                Supervises::Managed {
                    pin: PinSource::Discover(None),
                    onion: OnionSource::PerBoot,
                },
                super::super::policy(),
                true,
                18_021,
                data_dir,
                inbox,
                network,
            )
            .expect("the driver");
            assert!(
                per_boot
                    .managed
                    .as_ref()
                    .is_some_and(|boot| boot.guards.is_none()),
                "a per-boot onion has no guard manager"
            );
            assert_eq!(
                per_boot.send_pin(1),
                Err(SupervisorEnd::NoGuardManager),
                "a pin with no manager is its own end"
            );
            assert_eq!(
                per_boot.send_add(1),
                Ok(Some(vec![Input::ControlEnded])),
                "with no Tor, a per-boot publish answers at once"
            );
            tokio::task::spawn_blocking(move || drop(per_boot))
                .await
                .expect("the driver drops");
        });
    }
}
