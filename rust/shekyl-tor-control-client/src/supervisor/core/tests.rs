// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The phase machine against the waits and the remedies it claims.

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_timing_engine::{Clock, ManualClock, Tick};

use super::super::posture::{
    Cause, Connectors, ManagedTorFix, OriginVerdict, OwnTx, Sessions, Shown, Status, Syncing,
    TorSetting,
};
use super::{duration_ns, Action, Core, DirectoryPlan, Input, LaunchDirectory, Policy, Step};

impl Input {
    /// The pin's acceptance, carrying a witness no test spawns: the core
    /// hands it to the launch and never reads it.
    pub(in crate::supervisor::core) fn accepted() -> Self {
        Self::PinAccepted {
            binary: crate::binary::VerifiedTorBinary::unchecked_for_test(std::path::PathBuf::from(
                "/opt/shekyl/tor/tor",
            )),
        }
    }
}

fn policy() -> Policy {
    Policy {
        base: Duration::from_secs(1),
        cap: Duration::from_secs(8),
        sample_every: Duration::from_secs(1),
        alive_every: Duration::from_secs(4),
        fresh_directory_after: 3,
        quiet_after: Duration::from_secs(20),
        probe_after_min: Duration::from_secs(15),
        probe_after_max: super::PROBE_AFTER_MAX,
        probe_within: super::PROBE_WITHIN,
        round_wait: super::ROUND_WAIT,
        round_stuck_after: Duration::from_secs(300),
        jump_stall_after: Duration::from_secs(300),
        clock_evidence_within: Duration::from_secs(60),
        descriptor_lifetime: super::DESCRIPTOR_LIFETIME,
        clock_behind_after: super::CLOCK_BEHIND_AFTER,
        republish_after: super::REPUBLISH_AFTER,
        reply_bound: super::REPLY_BOUND,
    }
}

/// The status in words, as the daemon's log says it: the core's snapshot
/// through the one renderer (`shekyl_tor_status::render`). Read late
/// enough that no age is negative. The one age the renderer speaks is the
/// quiet line's; a test that reads it asks at its own time ([`said_at`]).
fn said(core: &Core) -> String {
    said_at(core, u64::MAX)
}

/// The status in words, asked at `now`.
fn said_at(core: &Core, now: u64) -> String {
    shekyl_tor_status::render(&core.view(now), Some("/data"))
}

/// A hand-built status in words, under a managed Tor.
fn said_of(status: &Status) -> String {
    shekyl_tor_status::render(
        &super::super::snapshot(status, managed(false), u64::MAX),
        Some("/data"),
    )
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
        .any(|action| matches!(action, Action::Spawn(_)))
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

/// **The directory policy read against what is held.** Fresh with a
/// directory retires it. Kept with a directory reuses it. Either with
/// nothing held creates one. Fails if a retire can be planned when nothing
/// is held, or a kept directory is dropped.
#[test]
fn a_launch_directory_plans_against_what_is_held() {
    assert_eq!(
        LaunchDirectory::Fresh.plan(Some(7)),
        DirectoryPlan::Retire(7)
    );
    assert_eq!(LaunchDirectory::Fresh.plan(None::<u8>), DirectoryPlan::New);
    assert_eq!(LaunchDirectory::Kept.plan(None::<u8>), DirectoryPlan::New);
    assert_eq!(LaunchDirectory::Kept.plan(Some(7)), DirectoryPlan::Reuse(7));
}

fn launch_directory(step: &Step) -> LaunchDirectory {
    step.actions
        .iter()
        .find_map(|action| match action {
            Action::Spawn(launch) => Some(launch.directory),
            _ => None,
        })
        .expect("a passed pin spawns")
}

/// **A launch is of the binary its own pin accepted** (Rick, 2026-11-12):
/// the witness the pin hands the core is the one the spawn carries, and a
/// re-pin's witness replaces it. The driver holds no binary, so no launch
/// can be asked for without one. Fails if the core drops the witness, or a
/// later launch carries an earlier pin's.
#[test]
fn a_launch_carries_the_binary_its_pin_accepted() {
    use crate::binary::VerifiedTorBinary;
    let launched = |step: &Step| {
        step.actions.iter().find_map(|action| match action {
            Action::Spawn(launch) => Some(launch.binary.clone()),
            _ => None,
        })
    };
    let first = VerifiedTorBinary::unchecked_for_test(std::path::PathBuf::from("/opt/a/tor"));
    let second = VerifiedTorBinary::unchecked_for_test(std::path::PathBuf::from("/opt/b/tor"));
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    let step = core.on(
        Input::PinAccepted {
            binary: first.clone(),
        },
        0,
    );
    assert_eq!(launched(&step), Some(first));
    let mut step = core.on(Input::SpawnFailed, 0);
    let mut now = 0;
    while !step
        .actions
        .iter()
        .any(|action| matches!(action, Action::CheckPin))
    {
        now = step.deadline.expect("a retry is armed");
        step = core.on_deadline(now);
    }
    let step = core.on(
        Input::PinAccepted {
            binary: second.clone(),
        },
        now,
    );
    assert_eq!(launched(&step), Some(second));
}

/// The last input of a reply, as the driver folds it: [`Input::Replied`]
/// for the request in flight. With none in flight it answers nothing.
fn replied(core: &mut Core, at: u64) -> Step {
    match core.in_flight() {
        Some(number) => core.on(Input::Replied { number }, at),
        None => Step {
            actions: Vec::new(),
            deadline: core.deadline(),
        },
    }
}

/// Pin, spawn, name the listener, and pass the ready gate. The route is
/// owed, not installed: health stays false until [`Input::RouteInstalled`].
/// Each request is answered as the driver answers it: the launch, then the
/// event subscription, then the first sample.
fn bring_up(core: &mut Core) -> Step {
    core.on(Input::accepted(), 0);
    core.on(Input::Spawned, 0);
    replied(core, 0);
    let subscribed = replied(core, 0);
    assert!(
        subscribed.actions.contains(&Action::Sample),
        "the first sample follows the subscription: {subscribed:?}"
    );
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some(socks()),
            read: None,
        },
        0,
    );
    replied(core, 0);
    let step = core.on(Input::BootstrapComplete, 0);
    assert!(publishes(&step), "running publishes the route");
    assert!(!core.status().health, "no verdict yet: health is false");
    step
}

/// The session layer reports one Tor session: the first peer the dialer
/// kept over the link.
fn tor_session() -> Input {
    Input::Sessions(Sessions {
        clearnet: 0,
        tor: 1,
    })
}

/// The link reaches Usable, and then the relay's verdict arrives. Between
/// the two the send is held (`GS-F3`): the link is not the fact.
fn reach_usable(core: &mut Core) {
    bring_up(core);
    let step = core.on(Input::RouteInstalled, 0);
    assert_eq!(announces(&step), 1, "recovery is said once the route is in");
    // The publish's `DEL_ONION`, then its `ADD_ONION`.
    let deleted = replied(core, 0);
    assert!(
        deleted.actions.contains(&Action::AddOnion),
        "the add follows the delete: {deleted:?}"
    );
    core.on(Input::OnionPublished, 0);
    replied(core, 0);
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
    assert_eq!(
        status.sync,
        Syncing::default(),
        "a usable link with no session syncs nothing (alpha.11 finding 9)"
    );
    core.on(tor_session(), 0);
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
    let mut step = core.on(Input::accepted(), ns(&clock));
    assert_eq!(launch_directory(&step), LaunchDirectory::Kept);
    step = core.on(Input::SpawnFailed, ns(&clock));
    assert_eq!(announces(&step), 1);
    let mut told = 1usize;
    let mut pin_at = Vec::new();
    let mut directories = Vec::new();
    while pin_at.len() < 4 {
        let due = step.deadline.expect("a retry is armed");
        clock.set(Tick::new(due));
        step = core.on_deadline(ns(&clock));
        told += announces(&step);
        if step
            .actions
            .iter()
            .any(|action| matches!(action, Action::CheckPin))
        {
            pin_at.push(due);
            step = core.on(Input::accepted(), ns(&clock));
            directories.push(launch_directory(&step));
            step = core.on(Input::SpawnFailed, ns(&clock));
            told += announces(&step);
        }
    }
    assert_eq!(
        pin_at,
        vec![1_000_000_000, 3_000_000_000, 7_000_000_000, 15_000_000_000],
        "the wait doubles, then the cap, and an announcement does not spawn"
    );
    use LaunchDirectory::{Fresh, Kept};
    assert_eq!(directories, vec![Kept, Kept, Fresh, Fresh]);
    assert_eq!(
        told, 2,
        "the first fault and one more at the cap, not each retry"
    );
    core.on(
        Input::Sessions(Sessions {
            clearnet: 2,
            tor: 0,
        }),
        ns(&clock),
    );
    let text = said(&core);
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
    core.on(Input::accepted(), 0);
    core.on(Input::Spawned, 0);
    // The launch, then its subscription. The sample is what the directory
    // replies answer.
    replied(&mut core, 0);
    replied(&mut core, 0);
    let bound = socks();
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some(bound),
            read: None,
        },
        0,
    );
    replied(&mut core, 0);
    for step in [1_u64, 60, 3_600, 86_400] {
        let now = step * 1_000_000_000;
        let step = core.on(
            Input::DirectorySample {
                progress: Some(10),
                socks: None,
                read: None,
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
    core.on(Input::accepted(), 0);
    core.on(Input::Spawned, 0);
    // The launch is in flight and Tor never answers: one bound later.
    let step = core.on_deadline(duration_ns(policy().reply_bound));
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
    let text = said(&core);
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
    let text = said(&core);
    assert!(
        !text.contains("exit code"),
        "the first stop names no code: {text}"
    );
    let due = step.deadline.expect("backoff");
    // The reap is still in flight: the pin check is the next launch's, so
    // it waits until that reap is answered.
    let during = core.on_deadline(due);
    assert!(
        !during
            .actions
            .iter()
            .any(|action| matches!(action, Action::CheckPin)),
        "the pin waits for the reap: {during:?}"
    );
    let step = replied(&mut core, due);
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
    let text = said_of(&status);
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
    let text = said(&core);
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
    let step = core.on(Input::DirectoryUnusable { space: None }, 0);
    assert!(!spawns(&step));
    assert_eq!(core.status().shown, Shown::RestartingHeld);
    assert_eq!(
        core.status().cause,
        Cause::DirectoryUnusable { space: None }
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
    // The onion's delete is still in flight. Answer it, and the add, before
    // the endpoint asks for the route: a publish waits behind that request.
    replied(&mut core, 1);
    core.on(Input::OnionPublished, 1);
    replied(&mut core, 1);
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
    let first = said(&core);
    assert!(!first.contains("exit code"), "{first}");
    let due = core.deadline().expect("backoff");
    let during = core.on_deadline(due);
    assert!(
        !during
            .actions
            .iter()
            .any(|action| matches!(action, Action::CheckPin)),
        "the pin waits for the reap: {during:?}"
    );
    let step = replied(&mut core, due);
    assert!(matches!(step.actions.first(), Some(Action::CheckPin)));
    core.on(Input::accepted(), due);
    core.on(Input::Spawned, due);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
        },
        due,
    );
    core.on(Input::BootstrapComplete, due);
    core.on(Input::RouteInstalled, due);
    core.on(Input::ProcessEnded { exit_code: Some(9) }, due + 1);
    let text = said(&core);
    assert!(text.contains("The last exit code was 9"), "{text}");
    assert!(text.contains("stopped 2 times"), "{text}");

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::ProcessEnded { exit_code: None }, 0);
    core.on(Input::ProcessEnded { exit_code: None }, 1);
    let text = said(&core);
    assert!(text.contains("stopped 2 times"), "{text}");
    assert!(!text.contains("exit code"), "{text}");
}

/// A rejected onion retries on the sample, not in a loop.
#[test]
fn an_onion_retries_on_the_sample() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    // The publish's `DEL_ONION` is answered; its `ADD_ONION` is refused.
    let deleted = replied(&mut core, 0);
    assert!(deleted.actions.contains(&Action::AddOnion));
    let mut rejected = core.on(Input::OnionRejected, 0);
    rejected.actions.extend(replied(&mut core, 0).actions);
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
}

/// The first `state` file defers disk writes. Once the route and the onion
/// are in, the core stops sampling.
#[test]
fn a_state_file_defers_writes_and_ends_the_sample() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    // The publish's `DEL_ONION`, then its `ADD_ONION`.
    replied(&mut core, 0);
    core.on(Input::OnionPublished, 0);
    replied(&mut core, 0);
    let step = core.on(Input::StateFileAppeared, 1);
    assert!(step
        .actions
        .iter()
        .any(|action| matches!(action, Action::SetConfAvoidDiskWrites)));
    replied(&mut core, 1);
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
    core.on(Input::accepted(), 0);
    core.on(Input::Spawned, 0);
    // The launch, the subscription, and the first sample are answered
    // before the bootstrap ends; that sample names no listener yet.
    replied(&mut core, 0);
    replied(&mut core, 0);
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: None,
            read: None,
        },
        0,
    );
    replied(&mut core, 0);
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
        },
        0,
    );
    assert!(!waited
        .actions
        .iter()
        .any(|action| matches!(action, Action::Sample)));
    let due = waited.deadline.expect("the next sample is armed");
    assert_eq!(due, duration_ns(policy().sample_every));
    let answered = replied(&mut core, 0);
    assert!(!answered
        .actions
        .iter()
        .any(|action| matches!(action, Action::Sample)));
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
    let unusable = Input::DirectoryUnusable { space: None };
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
    let unusable = Input::DirectoryUnusable { space: None };
    assert_eq!(announces(&core.on(unusable, 0)), 1);
    let short = Input::DirectoryUnusable {
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
    let unusable = Input::DirectoryUnusable { space: None };
    assert_eq!(announces(&core.on(unusable, 0)), 1);
    let cap = duration_ns(policy().cap);
    let step = core.on_deadline(cap);
    assert!(
        step.actions.contains(&Action::CheckPin),
        "{:?}",
        step.actions
    );
    assert_eq!(announces(&step), 0, "the check speaks for itself");
    core.on(Input::accepted(), cap);
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
        core.on(Input::accepted(), 0);
        core.on(Input::SpawnFailed, 0);
    }
    let pin_at = core.pin_at.expect("the third fault arms a pin");
    let cap = duration_ns(policy().cap);
    assert!(pin_at < cap, "pin and repeat are different ticks");
    let step = core.on_deadline(pin_at);
    assert!(step.actions.contains(&Action::CheckPin), "{step:?}");
    assert_eq!(announces(&step), 0);
    core.on(Input::accepted(), pin_at);
    core.on(Input::Spawned, pin_at);
    assert_eq!(announces(&core.on_deadline(cap)), 0);
}

/// Backoff after faults, then a recovery at `usable_at`, then a death at
/// `death_at`: the retry wait the death arms (the pin check, not the next
/// deadline, which may be an announcement).
fn wait_after_death(usable_at: u64, degraded_at: Option<u64>, death_at: u64) -> u64 {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    for _ in 0..3 {
        core.on(Input::accepted(), 0);
        core.on(Input::SpawnFailed, 0);
    }
    core.on(Input::accepted(), usable_at);
    core.on(Input::Spawned, usable_at);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
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

/// The §5 row names the path the caller passes and the shortfall.
#[test]
fn a_space_shortfall_names_the_path_and_both_sizes() {
    let status = Status {
        cause: Cause::DirectoryUnusable {
            space: Some(super::Space {
                available: 0,
                needed: 35_000_000,
            }),
        },
        ..held_status()
    };
    let text = said_of(&status);
    assert!(text.contains("/data has 0 bytes free"), "{text}");
    assert!(text.contains("0 bytes free"), "{text}");
    assert!(text.contains("35.0 MB"), "{text}");
}

/// The snapshot's ages are `now` less the clock readings it holds: a status
/// read twice, 10 s apart, reports every age 10 s larger: `tor.age`, the
/// onion's in each state that has one, and the quiet line's (Rick,
/// 2026-11-12; `TOR_STATUS_CRATE.md` §5). Fails if an age is a reading taken
/// before the ask, or if the onion's age reads another state's start.
#[test]
fn every_age_on_the_wire_grows_with_the_asking_clock() {
    use super::super::posture::{Inbound, InboundCause, TorQuiet};
    use shekyl_tor_status::TorQuiet as WireQuiet;
    let second = duration_ns(Duration::from_secs(1));
    let ten = 10 * second;
    for inbound in [
        Inbound::Publishing { since: 7 * second },
        Inbound::Reachable {
            evidence_at: 7 * second,
        },
        Inbound::Unreachable {
            cause: InboundCause::ProbeTimedOut,
            since: 7 * second,
        },
    ] {
        let status = Status {
            since: 3 * second,
            inbound,
            tor_quiet: Some(TorQuiet::Unanswered { since: 5 * second }),
            ..held_status()
        };
        let ask = 100 * second;
        let first = super::super::snapshot(&status, managed(false), ask);
        let later = super::super::snapshot(&status, managed(false), ask + ten);
        assert_eq!(first.tor_quiet, Some(WireQuiet::Failing { age: 95 }));
        assert_eq!(later.tor_quiet, Some(WireQuiet::Failing { age: 105 }));
        let (first, later) = (first.tor.expect("managed"), later.tor.expect("managed"));
        assert_eq!(first.age, 97, "{inbound:?}");
        assert_eq!(later.age, first.age + 10, "{inbound:?}");
        let (first, later) = (first.onion.expect("offered"), later.onion.expect("offered"));
        assert_eq!(first.age, 93, "{inbound:?}");
        assert_eq!(later.age, first.age + 10, "{inbound:?}");
    }
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
    core.on(
        Input::Sessions(Sessions {
            clearnet: 1,
            tor: 1,
        }),
        0,
    );
    let cap = duration_ns(policy().cap);
    let text = said(&core);
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
    assert!(status.sync.tor, "the node still holds its Tor session");
    let text = said_of(&status);
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

/// **Churn with no announced loss says nothing** (Rick, 2026-11-08). The
/// relay's verdict flips to held and back inside the cap, as session churn
/// does: the loss was never said, so the recovery says nothing, and the
/// loss's owed sentence is forgiven rather than said at the cap. The floor
/// device's soak said "Tor is carrying this node's traffic." 19,352 times
/// under churn. Red edits: say every recovery at once (the recovery
/// assertion fails); keep the owed sentence (the deadline assertion fails).
#[test]
fn churn_with_no_announced_loss_says_nothing() {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    reach_usable(&mut core);
    let cap = duration_ns(policy().cap);
    for flip in 0..5 {
        let at = 1 + flip * 2;
        assert_eq!(announces(&core.on(held(), at)), 0, "a loss inside the cap");
        assert_eq!(
            announces(&core.on(carrying(), at + 1)),
            0,
            "a recovery from a loss the operator never saw"
        );
    }
    assert_eq!(
        announces(&core.on_deadline(cap)),
        0,
        "the forgiven loss is not said at the cap"
    );
    assert_eq!(core.status().own_tx, OwnTx::AddressHiding);
}

/// **An announced loss followed by a recovery says the recovery once.** The
/// loss is said at the cap; the recovery is said at once, and a second
/// routable verdict is not a change.
#[test]
fn an_announced_loss_is_paired_with_one_recovery() {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    reach_usable(&mut core);
    let cap = duration_ns(policy().cap);
    core.on(held(), 1);
    assert_eq!(announces(&core.on_deadline(cap)), 1, "the loss is said");
    assert_eq!(
        announces(&core.on(carrying(), cap + 1)),
        1,
        "then the recovery"
    );
    assert!(core.on(carrying(), cap + 2).actions.is_empty());
    assert_eq!(announces(&core.on_deadline(cap * 2 + 1)), 0);
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
    let text = said(&core);
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
    let text = said(&core);
    assert!(
        text.starts_with(
            "This node is waiting for Tor and holding its own transactions. It is not syncing."
        ),
        "{text}"
    );
}

/// **What the node syncs over is the sessions it holds** (alpha.11 finding
/// 9): a default node with clearnet on and no clearnet peer said "syncing
/// over Tor and clearnet". The line follows the session layer's counts:
/// a connector is named while it holds a session, and not while it holds
/// none, whatever the configuration. Building `Syncing` from the
/// configured connector again fails the first assertion.
#[test]
fn the_node_syncs_over_the_connectors_that_hold_a_session() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(held(), 1);
    let line = |core: &Core| said(core);
    let sessions = |clearnet, tor| Input::Sessions(Sessions { clearnet, tor });
    core.on(sessions(0, 3), 2);
    assert!(
        line(&core).contains("It is syncing over Tor.") && !line(&core).contains("clearnet"),
        "clearnet is on and holds nothing: {}",
        line(&core)
    );
    core.on(sessions(1, 3), 3);
    assert!(
        line(&core).contains("It is syncing over Tor and clearnet."),
        "{}",
        line(&core)
    );
    core.on(sessions(1, 0), 4);
    assert!(
        line(&core).contains("It is syncing over clearnet."),
        "the Tor link is up and holds nothing: {}",
        line(&core)
    );
    assert!(
        !line(&core).contains("waiting for Tor"),
        "the link is up, so the node is not waiting for it: {}",
        line(&core)
    );
    core.on(sessions(0, 0), 5);
    assert!(
        line(&core).contains("It is not syncing."),
        "{}",
        line(&core)
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

mod clock;
mod clock_evidence;
mod clock_jump;
mod clock_line;
mod directories;
mod overdue;
mod pace;
mod probe;
mod quiet;
mod render;
mod requests;
mod resume;
mod unmanaged;
