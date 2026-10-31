// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Windows count awake time on every platform (§5, "Resumed from suspend";
//! Rick, 2026-10-30). On Windows `Instant` counts through a sleep
//! (`TSR-M8`): these tests jump the clock ten minutes, as a wake does there,
//! and check that no window that included the sleep fires.

use std::time::Duration;

use super::super::super::posture::{Cause, Inbound};
use super::super::{duration_ns, Action, Core, Input, Policy, RoundEnd, Step};
use super::{managed, policy, reach_usable};
use crate::control::RESUMED_AFTER;

const SLEEP: u64 = 600;

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

/// The test policy with the daemon's resume threshold.
fn resuming() -> Policy {
    Policy {
        resumed_after: RESUMED_AFTER,
        ..policy()
    }
}

fn sample(percent: u8, read: u64) -> Input {
    Input::DirectorySample {
        progress: Some(percent),
        socks: None,
        read: Some(read),
    }
}

/// Fire every deadline up to `to` on time, answering each sample with
/// `percent` and `read`. True if Tor was started again on the way: during
/// a bootstrap no route is installed, so a respawn takes nothing down.
fn run(core: &mut Core, to: u64, percent: u8, read: u64) -> bool {
    let before = core.status().respawn_count;
    while let Some(due) = core.deadline().filter(|due| *due <= to) {
        let step = core.on_deadline(due);
        if step.actions.contains(&Action::Sample) {
            core.on(sample(percent, read), due);
        }
    }
    core.status().respawn_count > before
}

fn respawns(core: &Core) -> u32 {
    core.status().respawn_count
}

fn resumed(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::Resumed { .. }))
}

/// A bootstrap whose jump is held from earlier, flat for 15 s before the
/// sleep: without the resume, the first look after a ten-minute sleep sees
/// the percent and the bytes still for ten minutes.
fn stalled_before_a_sleep() -> Core {
    let (mut core, _) = Core::start(resuming(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    assert!(!run(&mut core, secs(5), 14, 1_000));
    core.on(Input::ClockJumped, secs(5));
    assert!(!run(&mut core, secs(20), 14, 1_000));
    core
}

/// The wake's first look is the timer: the deadline is found ten minutes
/// late, the windows start again, and a sample is asked at once. No
/// respawn at the wake; a stall of five awake minutes after it still is
/// one. Judging the windows on the raw clock fails the first half;
/// restarting the jump itself, or never judging again, fails the second.
#[test]
fn a_sleep_in_a_bootstrap_is_not_a_stall_and_an_awake_stall_still_is() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on_deadline(wake);
    assert!(resumed(&step), "{:?}", step.actions);
    assert!(step.actions.contains(&Action::Sample), "re-evaluate now");
    core.on(sample(14, 1_000), wake);
    assert_eq!(respawns(&core), 0, "no respawn at the wake");
    assert!(
        !run(&mut core, wake + secs(299), 14, 1_000),
        "inside the bound"
    );
    assert!(
        run(&mut core, wake + secs(301), 14, 1_000),
        "five awake minutes"
    );
    assert_eq!(core.status().cause, Cause::StrandedAfterClockJump);
    assert_eq!(core.status().respawn_count, 1);
}

/// The wake's first look is a reply: the sample asked before the sleep
/// answers after it, ahead of the timer. It is judged after the resume,
/// not against windows that include the sleep. Detecting the resume only
/// at a deadline fails this.
#[test]
fn a_reply_that_arrives_first_after_a_wake_is_judged_after_the_resume() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on(sample(14, 1_000), wake);
    assert!(resumed(&step), "{:?}", step.actions);
    assert_eq!(respawns(&core), 0);
}

/// A probe in flight through the sleep gets its whole bound from the wake:
/// no miss, no refetch, and an arrival inside the new bound is the
/// evidence. Leaving the bound where it was fails this.
#[test]
fn a_probe_in_flight_through_a_sleep_keeps_a_whole_bound() {
    let (mut core, _) = Core::start(resuming(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Uploaded,
            draw: 0,
        },
        0,
    );
    let mut at = 0;
    while let Some(due) = core.deadline().filter(|due| *due <= secs(15)) {
        at = due;
        let step = core.on_deadline(due);
        if step.actions.contains(&Action::Probe) {
            break;
        }
        if step.actions.contains(&Action::Sample) {
            core.on(sample(100, 1_000), due);
        }
    }
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let wake = at + secs(SLEEP);
    let step = core.on_deadline(wake);
    assert!(resumed(&step), "{:?}", step.actions);
    assert!(
        !step
            .actions
            .iter()
            .any(|action| matches!(action, Action::CancelProbe | Action::RefetchDescriptor)),
        "no miss at the wake: {:?}",
        step.actions
    );
    let taken = wake + secs(5);
    core.on(
        Input::ProbeArrived {
            minted_at: at,
            arrived_at: taken,
        },
        taken,
    );
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable { evidence_at: taken }
    );
}

/// The quiet stretch counts awake time: a sleep is not ten minutes in which
/// no Tor connection opened. After the wake the stretch runs again. Leaving
/// the stretch's start where it was fails this.
#[test]
fn the_quiet_stretch_counts_awake_time() {
    let (mut core, _) = Core::start(resuming(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    let quiet = super::super::DialTally {
        opened: 0,
        unopened: 1,
        held: 0,
    };
    core.on(Input::DialEvidence(quiet), secs(1));
    run(&mut core, secs(15), 100, 1_000);
    assert_eq!(core.status().tor_quiet, None);
    let wake = secs(15 + SLEEP);
    let step = core.on_deadline(wake);
    assert!(resumed(&step), "{:?}", step.actions);
    // The next liveness deadline judges the stretch: the sleep is not in it.
    run(
        &mut core,
        wake + duration_ns(policy().alive_every) + secs(1),
        100,
        1_000,
    );
    assert_eq!(core.status().tor_quiet, None, "the sleep is not quiet");
    let after = policy().quiet_after;
    run(&mut core, wake + duration_ns(after) + secs(4), 100, 1_000);
    assert!(core.status().tor_quiet.is_some(), "awake and still quiet");
}
