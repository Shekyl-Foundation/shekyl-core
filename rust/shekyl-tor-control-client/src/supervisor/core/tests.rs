// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The phase machine against the waits and the remedies it claims.

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_timing_engine::{Clock, ManualClock, Tick};

use super::super::posture::{
    render, Cause, Connectors, ManagedTorFix, OriginVerdict, OwnTx, Shown, Status, TorSetting,
};
use super::{duration_ns, Action, Core, DialTally, Input, Policy, Step};

fn policy() -> Policy {
    Policy {
        base: Duration::from_secs(1),
        cap: Duration::from_secs(8),
        sample_every: Duration::from_secs(1),
        alive_every: Duration::from_secs(4),
        fresh_directory_after: 3,
        quiet_after: Duration::from_secs(20),
    }
}

fn managed(clearnet_on: bool) -> Connectors {
    Connectors {
        tor: TorSetting::Managed,
        clearnet_on,
    }
}

fn clock() -> ManualClock {
    ManualClock::new(Tick::new(0))
}

fn ns(clock: &ManualClock) -> u64 {
    clock.now().get()
}

fn socks() -> SocketAddr {
    "127.0.0.1:9150".parse().expect("socks")
}

/// [`OriginVerdict::Routable`]: a session hides the address and the origin leaves.
fn carrying() -> Input {
    Input::AddressHidingOrigin(OriginVerdict::Routable)
}

/// [`OriginVerdict::Absent`]: nothing hides the address.
fn held() -> Input {
    Input::AddressHidingOrigin(OriginVerdict::Absent)
}

/// [`OriginVerdict::Connected`]: a session hides the address, and the origin
/// does not leave.
fn connected() -> Input {
    Input::AddressHidingOrigin(OriginVerdict::Connected)
}

fn announces(step: &Step) -> usize {
    step.actions
        .iter()
        .filter(|action| matches!(action, Action::Announce))
        .count()
}

fn spawns(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::Spawn { .. }))
}

fn publishes(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::Publish(_)))
}

fn takes_down(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::TakeDown))
}

fn fresh_directory(step: &Step) -> bool {
    step.actions
        .iter()
        .find_map(|action| match action {
            Action::Spawn { fresh_directory } => Some(*fresh_directory),
            _ => None,
        })
        .expect("a passed pin spawns")
}

/// Pin, spawn, name the listener, and pass the ready gate. The route is
/// owed, not installed: health stays false until [`Input::RouteInstalled`].
fn bring_up(core: &mut Core) -> Step {
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some(socks()),
            read: None,
            network: None,
            circuits: None,
        },
        0,
    );
    let step = core.on(Input::BootstrapComplete, 0);
    assert!(publishes(&step), "running publishes the route");
    assert!(!core.status().health, "no verdict yet: health is false");
    step
}

/// The link reaches Usable, and then the relay's verdict arrives. Between
/// the two the send is held (`GS-F3`): the link is not the fact.
fn reach_usable(core: &mut Core) {
    bring_up(core);
    let step = core.on(Input::RouteInstalled, 0);
    assert_eq!(announces(&step), 1, "recovery is said once the route is in");
    core.on(Input::OnionPublished, 0);
    let status = core.status();
    assert_eq!(status.shown, Shown::Usable);
    assert!(
        !status.health,
        "the link is usable; no address-hiding peer yet"
    );
    assert_eq!(
        status.own_tx,
        OwnTx::Held,
        "held until the relay can originate"
    );
    assert!(status.sync.tor, "the link is what the node syncs over");
    let step = core.on(carrying(), 0);
    assert_eq!(
        announces(&step),
        1,
        "the verdict's recovery is said at once"
    );
    let status = core.status();
    assert!(status.health);
    assert_eq!(status.shown, Shown::Usable);
    assert_eq!(status.own_tx, OwnTx::AddressHiding);
}

/// Backoff doubles until the cap, and the failure is said at the first
/// fault and then once per cap. An announcement deadline is not a spawn.
#[test]
fn a_respawn_backs_off_and_announces_once_per_cap() {
    let clock = clock();
    let (mut core, step) = Core::start(policy(), managed(true), ns(&clock));
    assert!(matches!(step.actions[0], Action::CheckPin));
    let mut step = core.on(Input::PinAccepted, ns(&clock));
    assert!(matches!(
        step.actions[0],
        Action::Spawn {
            fresh_directory: false
        }
    ));
    step = core.on(Input::SpawnFailed, ns(&clock));
    assert_eq!(announces(&step), 1);
    let mut said = 1usize;
    let mut pin_at = Vec::new();
    let mut fresh = Vec::new();
    while pin_at.len() < 4 {
        let due = step.deadline.expect("a retry is armed");
        clock.set(Tick::new(due));
        step = core.on_deadline(ns(&clock));
        said += announces(&step);
        if step
            .actions
            .iter()
            .any(|action| matches!(action, Action::CheckPin))
        {
            pin_at.push(due);
            step = core.on(Input::PinAccepted, ns(&clock));
            fresh.push(fresh_directory(&step));
            step = core.on(Input::SpawnFailed, ns(&clock));
            said += announces(&step);
        }
    }
    assert_eq!(
        pin_at,
        vec![1_000_000_000, 3_000_000_000, 7_000_000_000, 15_000_000_000],
        "the wait doubles, then the cap, and an announcement does not spawn"
    );
    assert_eq!(fresh, vec![false, false, true, true]);
    assert_eq!(
        said, 2,
        "the first fault and one more at the cap, not each retry"
    );
    let text = render(&core.status());
    assert!(
        text.contains(
            "waiting for Tor and holding its own transactions. It is syncing over clearnet."
        ),
        "{text}"
    );
    assert!(!text.contains("clearnet-only"), "{text}");
}

/// A bootstrap that answers inside the bound never respawns. A missing
/// listener field leaves one already recorded, and a missing progress
/// leaves the percent. A reply past the bound is a process fault, and it
/// does not withdraw a route that was never installed.
#[test]
fn a_sample_keeps_what_the_reply_omits_and_a_late_reply_restarts() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let bound = socks();
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some(bound),
            read: None,
            network: None,
            circuits: None,
        },
        0,
    );
    for step in [1_u64, 60, 3_600, 86_400] {
        let now = step * 1_000_000_000;
        let step = core.on(
            Input::DirectorySample {
                progress: Some(10),
                socks: None,
                read: None,
                network: None,
                circuits: None,
            },
            now,
        );
        assert!(!spawns(&step), "standing progress is not a fault at {now}");
        assert!(!takes_down(&step), "a timely reply is not a death at {now}");
        assert_eq!(core.status().shown, Shown::Bootstrapping);
        assert_eq!(core.status().progress, 10);
    }
    let kept = core.on(
        Input::DirectorySample {
            progress: Some(40),
            socks: None,
            read: None,
            network: None,
            circuits: None,
        },
        90_000 * 1_000_000_000,
    );
    assert_eq!(core.status().progress, 40);
    assert!(!publishes(&kept), "progress alone is not the ready gate");
    let running = core.on(Input::BootstrapComplete, 90_000 * 1_000_000_000);
    assert!(
        publishes(&running),
        "the listener survived the samples that omitted it"
    );
    assert_eq!(core.status().fixes, Vec::<ManagedTorFix>::new());

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let step = core.on(Input::ReplyLate, 90_000 * 1_000_000_000);
    assert!(!takes_down(&step), "no route was installed");
    assert_eq!(core.status().shown, Shown::Restarting);
    assert_eq!(core.status().cause, Cause::ReplyLate);
    assert!(core.status().fixes.is_empty());
}

/// The open-file limit is a facet, not a death. The process and the route
/// stay, the pin is not retried, and the line repeats at the cap.
#[test]
fn an_open_file_limit_degrades_without_a_respawn() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    // The route is in and the directory is settled, so the deadlines left
    // are the liveness sample and the facet's own announcement.
    core.on(Input::StateFileAppeared, 0);
    let at = duration_ns(policy().cap);
    let step = core.on(Input::TooManyFiles { open: 1024 }, at);
    assert!(!takes_down(&step));
    assert!(!spawns(&step));
    assert_eq!(announces(&step), 1);
    assert_eq!(core.status().shown, Shown::Degraded);
    assert_eq!(core.status().cause, Cause::TooManyFiles { open: 1024 });
    assert!(
        core.status().health,
        "degraded is the link's facet; the relay's verdict still carries"
    );
    // Answer each liveness sample until the announcement comes due.
    let mut due = step.deadline.expect("the facet is said again");
    let step = loop {
        let step = core.on_deadline(due);
        if step.actions.contains(&Action::Sample) {
            core.on(
                Input::DirectorySample {
                    progress: Some(100),
                    socks: None,
                    read: None,
                    network: None,
                    circuits: None,
                },
                due,
            );
        }
        if announces(&step) > 0 {
            break step;
        }
        due = core.deadline().expect("something is waiting");
    };
    assert_eq!(due, at + duration_ns(policy().cap));
    assert_eq!(announces(&step), 1);
    assert!(!takes_down(&step));
    assert!(!step
        .actions
        .iter()
        .any(|action| matches!(action, Action::CheckPin)));
    assert!(!spawns(&step));
    assert_eq!(core.status().shown, Shown::Degraded);
    let text = render(&core.status());
    assert!(text.contains("open-file limit (1024 open)"), "{text}");
}

/// A clock jump is one sample now. The next reply restores the usable line
/// when the route is still in and the cause is not a degraded facet.
#[test]
fn a_clock_jump_is_one_sample_and_the_reply_restores_the_line() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let jumped = core.on(Input::ClockJumped, 5_000);
    assert!(jumped
        .actions
        .iter()
        .any(|action| matches!(action, Action::Sample)));
    assert_eq!(core.status().shown, Shown::Bootstrapping);
    assert_eq!(core.status().since, 5_000);
    let restored = core.on(
        Input::DirectorySample {
            progress: None,
            socks: None,
            read: None,
            network: None,
            circuits: None,
        },
        6_000,
    );
    assert!(restored.actions.is_empty());
    assert_eq!(core.status().shown, Shown::Usable);
    assert_eq!(core.status().since, 6_000);
    assert!(core.status().health);
}

/// A refused pin is not executed. The hold waits out the cap, then checks
/// the pin again. The fixes are the install row.
#[test]
fn a_pin_failure_does_not_spawn_and_retries_at_the_cap() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let step = core.on(Input::ProcessEnded { exit_code: Some(9) }, 5_000_000_000);
    assert!(takes_down(&step));
    // The sessions over the dead Tor close, and the relay withdraws its
    // verdict: that, not the death, is what moves Health and `OwnTx`.
    core.on(held(), 5_000_000_000);
    let text = render(&core.status());
    assert!(
        !text.contains("exit code"),
        "the first stop names no code: {text}"
    );
    let due = step.deadline.expect("backoff");
    let step = core.on_deadline(due);
    assert!(matches!(step.actions.first(), Some(Action::CheckPin)));
    let step = core.on(Input::PinRefused, due);
    assert!(!spawns(&step), "a refused pin is not executed");
    let status = core.status();
    assert_eq!(status.shown, Shown::RestartingHeld);
    assert_eq!(status.cause, Cause::PinRefused);
    let mut step = step;
    let mut retried = false;
    for _ in 0..4 {
        let next = step.deadline.expect("the hold stays armed");
        step = core.on_deadline(next);
        assert!(!spawns(&step), "the hold never executes the binary");
        if step
            .actions
            .iter()
            .any(|action| matches!(action, Action::CheckPin))
        {
            assert_eq!(next, due + duration_ns(policy().cap));
            retried = true;
            break;
        }
        assert_eq!(announces(&step), 1, "the hold is said once per cap");
    }
    assert!(retried, "the pin is retried when the cap elapses");
    let text = render(&status);
    assert!(text.contains("failed its check"), "{text}");
    assert!(text.contains("holding its own transactions"), "{text}");
    assert!(!text.contains("clearnet-only"), "{text}");
    assert_eq!(
        status.fixes,
        vec![
            ManagedTorFix::RestoreManaged,
            ManagedTorFix::Operator,
            ManagedTorFix::ClearnetOnly,
        ]
    );
}

/// Unavailable is fixed. It is said once per cap and it never checks a pin.
#[test]
fn an_unavailable_platform_is_fixed_and_announced_once_per_cap() {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    let step = core.on(Input::Unavailable, 0);
    assert!(!spawns(&step));
    assert_eq!(announces(&step), 1);
    let text = render(&core.status());
    assert!(
        text.contains("This release has no Tor for this platform yet"),
        "{text}"
    );
    assert!(text.contains("waiting for Tor"), "{text}");
    assert!(!text.contains("clearnet-only"), "{text}");
    let mut said = 1usize;
    let mut now = 0u64;
    for _ in 0..3 {
        let due = core.deadline().expect("the cap is armed");
        let early = core.on_deadline(due - 1);
        assert_eq!(announces(&early), 0, "inside the cap says nothing");
        let step = core.on_deadline(core.deadline().expect("still armed"));
        said += announces(&step);
        assert!(!spawns(&step));
        assert!(
            !step
                .actions
                .iter()
                .any(|action| matches!(action, Action::CheckPin)),
            "nothing at runtime changes an unavailable platform"
        );
        now = due;
    }
    assert_eq!(said, 4, "the first announcement plus one per cap");
    assert_eq!(core.status().own_tx, OwnTx::Held);
    assert_eq!(now, 3 * duration_ns(policy().cap));
    assert!(core.status().fixes.contains(&ManagedTorFix::ClearnetOn));
}

/// A directory the spawn could not use is held, and it offers no install fix.
#[test]
fn a_missing_directory_is_held_without_an_install_fix() {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    let path = std::path::PathBuf::from("/var/lib/shekyl");
    let step = core.on(
        Input::DirectoryUnusable {
            path: path.clone(),
            space: None,
        },
        0,
    );
    assert!(!spawns(&step));
    assert_eq!(core.status().shown, Shown::RestartingHeld);
    assert_eq!(
        core.status().cause,
        Cause::DirectoryUnusable { path, space: None }
    );
    assert!(core.status().fixes.is_empty());
}

/// The route is owed until the driver reports it. A host that is absent
/// waits. The endpoint, once present, publishes again. A second ready
/// signal does not. A fault before the route is in withdraws nothing; a
/// fault after it does.
#[test]
fn a_route_waits_for_its_host_and_a_fault_withdraws_only_an_installed_one() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    assert!(
        core.status().fixes.is_empty(),
        "bootstrapping offers no fix"
    );
    let absent = core.on(Input::HostAbsent, 1);
    assert!(!publishes(&absent));
    let ready = core.on(Input::EndpointReady, 2);
    assert_eq!(
        ready
            .actions
            .iter()
            .filter(|action| matches!(action, Action::Publish(_)))
            .count(),
        1
    );
    let installed = core.on(Input::RouteInstalled, 3);
    assert_eq!(announces(&installed), 1);
    assert_eq!(core.status().shown, Shown::Usable);
    assert!(!core.status().health, "usable is not the verdict");
    let again = core.on(Input::EndpointReady, 4);
    assert!(!publishes(&again));

    let fault = core.on(Input::ProcessEnded { exit_code: Some(9) }, 5);
    assert!(takes_down(&fault));

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::HostAbsent, 1);
    let fault = core.on(Input::ProcessEnded { exit_code: None }, 2);
    assert!(!takes_down(&fault));
    assert_eq!(core.status().shown, Shown::Restarting);
    assert!(core.status().fixes.is_empty());
}

/// The second death names the exit code. One death does not.
#[test]
fn a_repeated_death_names_the_last_exit_code() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::ProcessEnded { exit_code: Some(9) }, 1);
    let first = render(&core.status());
    assert!(!first.contains("exit code"), "{first}");
    let due = core.deadline().expect("backoff");
    let step = core.on_deadline(due);
    assert!(matches!(step.actions.first(), Some(Action::CheckPin)));
    core.on(Input::PinAccepted, due);
    core.on(Input::Spawned, due);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
            network: None,
            circuits: None,
        },
        due,
    );
    core.on(Input::BootstrapComplete, due);
    core.on(Input::RouteInstalled, due);
    core.on(Input::ProcessEnded { exit_code: Some(9) }, due + 1);
    let text = render(&core.status());
    assert!(text.contains("The last exit code was 9"), "{text}");
    assert!(text.contains("stopped 2 times"), "{text}");

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::ProcessEnded { exit_code: None }, 0);
    core.on(Input::ProcessEnded { exit_code: None }, 1);
    let text = render(&core.status());
    assert!(text.contains("stopped 2 times"), "{text}");
    assert!(!text.contains("exit code"), "{text}");
}

/// A rejected onion retries on the sample, not in a loop. A descriptor
/// that fails after a success republishes once; a second failure while
/// that republish is still owed does not stack another.
#[test]
fn an_onion_retries_on_the_sample_and_a_descriptor_failure_does_not_stack() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    let rejected = core.on(Input::OnionRejected, 0);
    assert!(!rejected
        .actions
        .iter()
        .any(|action| matches!(action, Action::RepublishOnion)));
    let due = core.deadline().expect("the sample is armed");
    let step = core.on_deadline(due);
    assert_eq!(
        step.actions
            .iter()
            .filter(|action| matches!(action, Action::RepublishOnion))
            .count(),
        1
    );
    core.on(Input::OnionPublished, due);
    let failed = core.on(Input::DescriptorFailed, due);
    assert_eq!(
        failed
            .actions
            .iter()
            .filter(|action| matches!(action, Action::RepublishOnion))
            .count(),
        1
    );
    let stacked = core.on(Input::DescriptorFailed, due);
    assert!(!stacked
        .actions
        .iter()
        .any(|action| matches!(action, Action::RepublishOnion)));
}

/// The first `state` file defers disk writes. Once the route and the onion
/// are in, the core stops sampling.
#[test]
fn a_state_file_defers_writes_and_ends_the_sample() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    core.on(Input::OnionPublished, 0);
    let step = core.on(Input::StateFileAppeared, 1);
    assert!(step
        .actions
        .iter()
        .any(|action| matches!(action, Action::SetConfAvoidDiskWrites)));
    assert_eq!(
        core.deadline(),
        Some(duration_ns(Duration::from_secs(4))),
        "only the liveness sample is waiting"
    );
    let again = core.on(Input::StateFileAppeared, 2);
    assert!(again.actions.is_empty());
}

/// The ready gate with no listener asks once. The reply that still omits
/// it waits out the sample interval instead of asking again immediately.
#[test]
fn a_ready_gate_without_a_listener_waits_for_the_sample() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let asked = core.on(Input::BootstrapComplete, 0);
    assert_eq!(
        asked
            .actions
            .iter()
            .filter(|action| matches!(action, Action::Sample))
            .count(),
        1
    );
    assert!(!publishes(&asked));
    let waited = core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: None,
            read: None,
            network: None,
            circuits: None,
        },
        0,
    );
    assert!(!waited
        .actions
        .iter()
        .any(|action| matches!(action, Action::Sample)));
    let due = waited.deadline.expect("the next sample is armed");
    assert_eq!(due, duration_ns(policy().sample_every));
    let step = core.on_deadline(due);
    assert!(step
        .actions
        .iter()
        .any(|action| matches!(action, Action::Sample)));
}

/// Shutdown takes an installed route down and says nothing. The child is
/// stopped, not reaped. With no route installed, only the stop is asked.
#[test]
fn a_shutdown_stops_an_installed_route_and_says_nothing() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let step = core.on(Input::Shutdown, 1_000);
    assert_eq!(step.actions, vec![Action::StopRoute, Action::StopChild]);
    assert!(step.deadline.is_none());
    assert_eq!(announces(&step), 0);

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    let step = core.on(Input::Shutdown, 1_000);
    assert_eq!(step.actions, vec![Action::StopChild]);
    assert_eq!(announces(&step), 0);
}

#[path = "live_tests.rs"]
mod live;

/// A death right after a recovery is a state change and is said at once
/// (`TSR-F11`). The cap limits repeats of one cause, not every message: in
/// the Linux run (2026-10-24, case D) "Tor is carrying this node's traffic"
/// stood for a minute after Tor died. Dropping the `changed` key fails this.
#[test]
fn a_death_right_after_a_recovery_is_said_at_once() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let step = core.on(Input::ProcessEnded { exit_code: None }, 1);
    assert_eq!(announces(&step), 1, "the death is said inside the cap");
}

/// While held, a repeat of the same cause waits for the cap, and a new cause
/// is said at once (case E: a refused binary waited two minutes).
#[test]
fn a_new_cause_is_said_at_once_and_a_repeat_waits_for_the_cap() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    assert_eq!(announces(&core.on(Input::PinRefused, 0)), 1);
    let second = duration_ns(Duration::from_secs(1));
    assert_eq!(
        announces(&core.on(Input::PinRefused, second)),
        0,
        "a repeat waits"
    );
    let unusable = Input::DirectoryUnusable {
        path: std::path::PathBuf::from("/var/lib/shekyl"),
        space: None,
    };
    assert_eq!(
        announces(&core.on(unusable, 2 * second)),
        1,
        "a new cause does not"
    );
}

/// The key is the cause's kind, not its detail (Rick, 2026-10-24): the
/// directory found short of space after it was found unusable is still "fix
/// the directory", so it waits for the cap; the repeat carries the new
/// detail. Keying on the payload fails this.
#[test]
fn a_new_detail_of_the_same_cause_is_a_repeat() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let path = std::path::PathBuf::from("/var/lib/shekyl");
    let unusable = Input::DirectoryUnusable {
        path: path.clone(),
        space: None,
    };
    assert_eq!(announces(&core.on(unusable, 0)), 1);
    let short = Input::DirectoryUnusable {
        path,
        space: Some(super::Space {
            available: 0,
            needed: 35_000_000,
        }),
    };
    let second = duration_ns(Duration::from_secs(1));
    assert_eq!(
        announces(&core.on(short, second)),
        0,
        "the same kind with new detail waits for the cap"
    );
    assert!(
        matches!(
            core.status().cause,
            Cause::DirectoryUnusable { space: Some(_), .. }
        ),
        "the status carries the new detail at once"
    );
}

/// The held state's repeat belongs to the held state. When the pin check is
/// due in the same tick, the check speaks, not a repeat of the old cause
/// (case E); and once Tor has spawned no repeat is left armed to fire into
/// the bootstrap (case C2's stale line).
#[test]
fn a_held_repeat_yields_to_its_pin_check_and_ends_with_the_spawn() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let unusable = Input::DirectoryUnusable {
        path: std::path::PathBuf::from("/var/lib/shekyl"),
        space: None,
    };
    assert_eq!(announces(&core.on(unusable, 0)), 1);
    let cap = duration_ns(policy().cap);
    let step = core.on_deadline(cap);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
    assert_eq!(announces(&step), 0, "the check speaks for itself");
    core.on(Input::PinAccepted, cap);
    core.on(Input::Spawned, cap);
    assert!(
        core.announcements.pending().is_none(),
        "pin dropped the repeat"
    );
}

/// Three launch failures arm the repeat at the cap and the pin sooner.
/// Spawning first must not let that repeat be said into the bootstrap.
#[test]
fn a_repeat_armed_before_spawn_is_not_said_into_the_bootstrap() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    for _ in 0..3 {
        core.on(Input::PinAccepted, 0);
        core.on(Input::SpawnFailed, 0);
    }
    let pin_at = core.pin_at.expect("the third fault arms a pin");
    let cap = duration_ns(policy().cap);
    assert!(pin_at < cap, "pin and repeat are different ticks");
    let step = core.on_deadline(pin_at);
    assert!(step.actions.contains(&Action::CheckPin), "{step:?}");
    assert_eq!(announces(&step), 0);
    core.on(Input::PinAccepted, pin_at);
    core.on(Input::Spawned, pin_at);
    assert_eq!(announces(&core.on_deadline(cap)), 0);
}

/// Backoff after faults, then a recovery at `usable_at`, then a death at
/// `death_at`: the retry wait the death arms (the pin check, not the next
/// deadline, which may be an announcement).
fn wait_after_death(usable_at: u64, degraded_at: Option<u64>, death_at: u64) -> u64 {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    for _ in 0..3 {
        core.on(Input::PinAccepted, 0);
        core.on(Input::SpawnFailed, 0);
    }
    core.on(Input::PinAccepted, usable_at);
    core.on(Input::Spawned, usable_at);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
            network: None,
            circuits: None,
        },
        usable_at,
    );
    core.on(Input::BootstrapComplete, usable_at);
    core.on(Input::RouteInstalled, usable_at);
    core.on(Input::OnionPublished, usable_at);
    assert_eq!(core.status().shown, Shown::Usable);
    if let Some(at) = degraded_at {
        core.on(Input::ExternalBlocked, at);
    }
    core.on(Input::ProcessEnded { exit_code: None }, death_at);
    core.pin_at.expect("a retry is armed") - death_at
}

/// A full cap of usable outbound resets the backoff (§4.4, Rick
/// 2026-10-24); less than a cap, or a cap spent degraded, does not. Removing
/// the reset makes the first assertion read the cap.
#[test]
fn the_backoff_starts_again_only_after_a_cap_of_usable_outbound() {
    let base = duration_ns(policy().base);
    let cap = duration_ns(policy().cap);
    let up = duration_ns(Duration::from_secs(20));
    assert_eq!(
        wait_after_death(up, None, up + cap),
        base,
        "a cap of health resets"
    );
    assert_eq!(
        wait_after_death(up, None, up + cap / 2),
        cap,
        "half a cap does not"
    );
    assert_eq!(
        wait_after_death(up, Some(up + 1), up + cap + 1),
        cap,
        "a cap spent with outbound blocked is not health"
    );
    assert_eq!(
        wait_after_death(up, Some(up + cap), up + cap + cap),
        base,
        "a served cap survives a later block"
    );
}

/// The §5 row names the path and the shortfall.
#[test]
fn a_space_shortfall_names_the_path_and_both_sizes() {
    let status = Status {
        cause: Cause::DirectoryUnusable {
            path: std::path::PathBuf::from("/var/lib/shekyl"),
            space: Some(super::Space {
                available: 0,
                needed: 35_000_000,
            }),
        },
        ..held_status()
    };
    let text = render(&status);
    assert!(text.contains("/var/lib/shekyl"), "{text}");
    assert!(text.contains("0 bytes free"), "{text}");
    assert!(text.contains("35.0 MB"), "{text}");
}

fn held_status() -> Status {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinRefused, 0);
    core.status()
}

/// `GS-Q3`: `OwnTx` and Health are the relay's verdict. The same value again
/// changes nothing; a loss is said under the cap, not at once; a recovery is
/// said at once.
#[test]
fn the_relays_verdict_decides_own_tx_and_health_and_is_said_under_the_cap() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let cap = duration_ns(policy().cap);
    let text = render(&core.status());
    assert!(
        text.starts_with("Tor is carrying this node's traffic."),
        "{text}"
    );

    let again = core.on(carrying(), 1);
    assert!(again.actions.is_empty(), "the same verdict is not a change");

    let lost = core.on(held(), 2);
    assert_eq!(
        announces(&lost),
        0,
        "a loss inside the cap is not said at once"
    );
    let status = core.status();
    assert!(!status.health);
    assert_eq!(status.own_tx, OwnTx::Held);
    assert_eq!(status.shown, Shown::Usable, "the link did not move");
    assert!(status.sync.tor, "the node still syncs over the link");
    let text = render(&status);
    assert!(
        text.starts_with(
            "This node is holding its own transactions. It is syncing over Tor and clearnet."
        ),
        "{text}"
    );
    // The running link samples every second, so the step's deadline is the
    // sample's; the announcement is armed one cap after the recovery at 0.
    assert!(lost.deadline.is_some_and(|due| due <= cap));
    let said = core.on_deadline(cap);
    assert_eq!(announces(&said), 1, "the loss is said at the cap");
    let later = core.on_deadline(cap * 2);
    assert_eq!(
        announces(&later),
        0,
        "said once; a lost verdict does not repeat"
    );

    let flapped = core.on(held(), cap * 2 + 1);
    assert!(flapped.actions.is_empty());

    let back = core.on(carrying(), cap * 2 + 2);
    assert_eq!(announces(&back), 1, "a recovery is said at once");
    assert!(core.status().health);
    assert_eq!(core.status().own_tx, OwnTx::AddressHiding);
}

/// A loss after the cap has passed is said at once: the warning is not held
/// for a second cap.
#[test]
fn a_lost_verdict_past_the_cap_is_said_at_once() {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    reach_usable(&mut core);
    let cap = duration_ns(policy().cap);
    let lost = core.on(held(), cap + 1);
    assert_eq!(announces(&lost), 1);
    // R1: the link is usable, so the node is not waiting for Tor and is
    // syncing over it; the hold's reason is GS-C2's typed value.
    let text = render(&core.status());
    assert!(
        text.starts_with("This node is holding its own transactions. It is syncing over Tor."),
        "{text}"
    );
    assert!(!text.contains("waiting for Tor"), "{text}");
    assert!(!text.contains("not syncing"), "{text}");
}

/// `Held` while the link is down: waiting for Tor, and syncing over
/// nothing when clearnet is off.
#[test]
fn a_held_origin_under_a_down_link_waits_for_tor() {
    let (core, _) = Core::start(policy(), managed(false), 0);
    assert_eq!(core.status().own_tx, OwnTx::Held);
    let text = render(&core.status());
    assert!(
        text.starts_with(
            "This node is waiting for Tor and holding its own transactions. It is not syncing."
        ),
        "{text}"
    );
}

/// Health is the relay's fact alone (`GS-Q3`): a verdict before the link is
/// usable still makes Health, and `Tor::Off` keeps `ClearnetOnly` whatever
/// the verdict says.
#[test]
fn health_is_the_verdict_whatever_the_link_shows() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    assert_eq!(core.status().shown, Shown::Bootstrapping);
    core.on(carrying(), 0);
    assert!(core.status().health);
    assert_eq!(core.status().own_tx, OwnTx::AddressHiding);
    assert!(!core.status().sync.tor, "the link is still bootstrapping");
}

/// `RPC_CHANNEL.md` §6.1: Health carries the class part of the verdict only.
/// An exhausted origin pin with address-hiding sessions live is `Held` with
/// Health still true, and said as a change of `OwnTx`; the class part moving
/// alone changes no sentence and says nothing.
#[test]
fn an_exhausted_pin_holds_the_origin_while_health_stays_true() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let cap = duration_ns(policy().cap);
    let exhausted = core.on(connected(), cap + 1);
    assert_eq!(announces(&exhausted), 1, "the sentence flipped to holding");
    let status = core.status();
    assert!(status.health, "a session still hides the address");
    assert_eq!(status.own_tx, OwnTx::Held, "but the pin is exhausted: held");
    assert_eq!(status.shown, Shown::Usable);

    let class_only = core.on(held(), cap + 2);
    assert!(
        class_only.actions.is_empty(),
        "the class emptying changes no sentence: already held"
    );
    assert!(!core.status().health);
    assert_eq!(core.status().own_tx, OwnTx::Held);

    let session = core.on(connected(), cap + 3);
    assert!(
        session.actions.is_empty(),
        "a session arriving under an exhausted pin: still held"
    );
    assert!(core.status().health);
    assert_eq!(core.status().own_tx, OwnTx::Held);
}

/// A tally of `unopened` failed Tor dials since the `opened`-th opened one,
/// with `held` sessions.
fn dials(opened: u64, unopened: u32, held: u32) -> Input {
    Input::DialEvidence(DialTally {
        opened,
        unopened,
        held,
    })
}

/// A sample while Running that carries Tor's own view.
fn tor_says(network: Option<bool>, circuits: Option<bool>) -> Input {
    Input::DirectorySample {
        progress: Some(100),
        socks: None,
        read: None,
        network,
        circuits,
    }
}

/// Run every deadline up to and including `until`, answering each liveness
/// sample as a healthy Tor would, so nothing but the evidence under test can
/// move the core. Returns every step taken.
fn run_until(core: &mut Core, until: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some(due) = core.deadline().filter(|due| *due <= until) {
        let step = core.on_deadline(due);
        if step.actions.contains(&Action::Sample) {
            steps.push(core.on(tor_says(None, None), due));
        }
        steps.push(step);
    }
    steps
}

fn faults(steps: &[Step]) -> bool {
    steps.iter().any(|step| {
        spawns(step)
            || takes_down(step)
            || step
                .actions
                .iter()
                .any(|action| matches!(action, Action::CheckPin))
    })
}

fn says_progress(steps: &[Step]) -> usize {
    steps
        .iter()
        .flat_map(|step| &step.actions)
        .filter(|action| matches!(action, Action::SayProgress))
        .count()
}

/// `TSR-Q14` (Rick, 2026-10-25): this node's own dial replies are never a
/// link verdict. Ten minutes of failed Tor dials, with no session held and
/// Tor saying nothing about its network, is a neutral line said once, and
/// no cause, no announcement, no respawn. A planted onion answers `0x01` at
/// will and a blackholing one `0x06` (shekyl-dev
/// `data/tsr-acceptance/2026-10-25-socks-reply-sources`), so a cause from
/// dials would let anyone make the node tell its operator it cannot reach
/// Tor. Routing the tally to a cause fails the first half; dropping it
/// fails the line. Every deadline runs; all 150 samples are answered.
#[test]
fn ten_minutes_of_failed_dials_are_a_neutral_line_never_a_cause() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let mut steps = Vec::new();
    let mut unopened = 0;
    let mut at = 0;
    while at < duration_ns(Duration::from_secs(600)) {
        at += duration_ns(Duration::from_secs(5));
        steps.extend(run_until(&mut core, at));
        unopened += 1;
        steps.push(core.on(dials(0, unopened, 0), at));
    }
    let samples = steps
        .iter()
        .filter(|step| step.actions.contains(&Action::Sample))
        .count();
    // One liveness sample per `alive_every` while Running: 600 s / 4 s.
    assert_eq!(samples, 150, "the liveness samples ran");
    assert!(!faults(&steps), "no respawn, no takedown, no pin check");
    assert_eq!(
        steps.iter().map(announces).sum::<usize>(),
        0,
        "nothing announced"
    );
    assert_eq!(says_progress(&steps), 1, "the line is said once");
    let status = core.status();
    assert_eq!(status.cause, Cause::None);
    assert_eq!(status.shown, Shown::Usable);
    assert_eq!(status.respawn_count, 0);
    assert!(status.tor_quiet.is_some());
    let text = render(&status);
    assert!(text.contains("No connection through Tor is open"), "{text}");
    assert!(!text.contains("cannot reach"), "{text}");
}

/// A held Tor session means Tor carries this node's traffic: no line, however
/// many dials to dead or refusing onions fail (the testnet case: two live
/// seeds held, four dead ones redialed). An opened dial starts the stretch
/// again.
#[test]
fn a_held_session_or_an_opened_dial_keeps_the_line_away() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let late = duration_ns(Duration::from_secs(60));
    core.on(dials(0, 40, 1), late);
    run_until(&mut core, late);
    assert_eq!(core.status().tor_quiet, None, "a session is held");
    core.on(dials(0, 41, 0), late + 1);
    assert!(core.status().tor_quiet.is_some(), "none held, none opened");
    core.on(dials(1, 0, 0), late + 2);
    let step = core.on(dials(1, 1, 0), late + 3);
    assert_eq!(says_progress(&[step]), 0);
    assert_eq!(core.status().tor_quiet, None, "the stretch began again");
}

/// The stretch starts when a Tor reaches Running: failures from before do
/// not make the line stand for the new Tor at once.
#[test]
fn the_quiet_stretch_starts_when_a_tor_reaches_running() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(dials(0, 9, 0), duration_ns(Duration::from_secs(100)));
    let at = duration_ns(Duration::from_secs(100));
    core.on(Input::PinAccepted, at);
    core.on(Input::Spawned, at);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
            network: None,
            circuits: None,
        },
        at,
    );
    core.on(Input::BootstrapComplete, at);
    core.on(Input::RouteInstalled, at);
    core.on(dials(0, 10, 0), at + 1);
    assert_eq!(core.status().tor_quiet, None);
    core.on(dials(0, 11, 0), at + duration_ns(policy().quiet_after));
    assert!(core.status().tor_quiet.is_some());
}

/// Tor's own view, read with every sample (`TSR-Q14`), governs even when Tor
/// sends no event: down or no circuit names the blocked link at once; up
/// with a circuit clears it at once. Unknown says nothing. During a
/// bootstrap no circuit is built yet, and that is not a statement.
#[test]
fn tors_sampled_view_names_and_clears_a_blocked_link_only_while_running() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let step = core.on(
        Input::DirectorySample {
            progress: Some(40),
            socks: None,
            read: None,
            network: Some(true),
            circuits: Some(false),
        },
        1,
    );
    assert_eq!(announces(&step), 0);
    assert_eq!(
        core.status().cause,
        Cause::None,
        "bootstrapping: no circuit yet"
    );

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    assert_eq!(announces(&core.on(tor_says(None, None), 1)), 0);
    let step = core.on(tor_says(Some(false), None), 2);
    assert_eq!(announces(&step), 1, "said at once");
    assert_eq!(core.status().cause, Cause::ExternalBlocked);
    assert_eq!(core.status().shown, Shown::Degraded);
    assert_eq!(announces(&core.on(tor_says(Some(true), None), 3)), 0);
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "a circuit too");
    let step = core.on(tor_says(Some(true), Some(true)), 4);
    assert_eq!(announces(&step), 1, "the recovery is said at once");
    assert_eq!(core.status().cause, Cause::None);
    core.on(tor_says(Some(true), Some(false)), 5);
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "no circuit");
}

/// "Process only when the control connection also fails" (Rick): a blocked
/// link does not stop a control failure from being a process fault.
#[test]
fn a_blocked_link_still_respawns_when_the_control_connection_fails() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::ExternalBlocked, 1);
    core.on(Input::ControlEnded, 2);
    assert!(matches!(core.status().cause, Cause::Died { .. }));
    assert_eq!(core.status().shown, Shown::Restarting);
    let due = core.deadline().expect("the respawn wait");
    let step = core.on_deadline(due);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
}

/// Tor saying it reaches its network clears what is about reaching the
/// network, which nothing did while Tor ran: a blocked link and an
/// unreachable directory. The open-file limit and a clock report are not
/// the network and keep their own evidence.
#[test]
fn tor_reaching_its_network_clears_the_network_causes_only() {
    for named in [Input::ExternalBlocked, Input::DirectoryUnreachable] {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_usable(&mut core);
        core.on(named, 1);
        assert_eq!(core.status().shown, Shown::Degraded);
        let step = core.on(Input::ExternalCleared, 2);
        assert_eq!(announces(&step), 1, "the recovery is said at once");
        assert_eq!(core.status().cause, Cause::None);
        assert_eq!(core.status().shown, Shown::Usable);
    }
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::TooManyFiles { open: 1024 }, 3);
    let step = core.on(Input::ExternalCleared, 4);
    assert_eq!(announces(&step), 0);
    assert_eq!(core.status().cause, Cause::TooManyFiles { open: 1024 });
}
