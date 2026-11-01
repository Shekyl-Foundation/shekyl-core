// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Windows count awake time (§5, "Resumed from suspend"; Rick, 2026-10-30).
//!
//! The core does not decide that the machine slept. The driver says so
//! with [`Input::Resumed`], and only then do the windows start again.
//! These tests jump the clock ten minutes, as a wake does on Windows
//! (`TSR-M8`), and check both halves: the resume pardons the sleep, and
//! the same jump with no resume is a stall.

use std::time::Duration;

use super::super::super::posture::{Cause, Inbound};
use super::super::{duration_ns, Action, Core, Input, Step};
use super::{managed, policy, reach_usable};

const SLEEP: u64 = 600;

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

fn sample(percent: u8, read: u64) -> Input {
    Input::DirectorySample {
        progress: Some(percent),
        socks: None,
        read: Some(read),
    }
}

fn slept(late_by: Duration) -> Input {
    Input::Resumed { late_by }
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

fn cancels_probe(step: &Step) -> bool {
    step.actions
        .iter()
        .any(|action| matches!(action, Action::CancelProbe | Action::RefetchDescriptor))
}

/// A bootstrap whose jump is held from earlier, flat for 15 s before the
/// sleep: without the resume, the first look after a ten-minute sleep sees
/// the percent and the bytes still for ten minutes.
fn stalled_before_a_sleep() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    assert!(!run(&mut core, secs(5), 14, 1_000));
    core.on(Input::ClockJumped, secs(5));
    assert!(!run(&mut core, secs(20), 14, 1_000));
    core
}

/// The wake's first look is the timer: the driver reports the sleep, the
/// windows start again, and a sample is asked at once. No respawn at the
/// wake; a stall of five awake minutes after it still is one. Judging the
/// windows on the raw clock fails the first half; restarting the jump
/// itself, or never judging again, fails the second.
#[test]
fn a_sleep_in_a_bootstrap_is_not_a_stall_and_an_awake_stall_still_is() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on(slept(Duration::from_secs(SLEEP)), wake);
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

/// The reply that was in flight is folded after the resume, so it is
/// judged on the new windows. Folding it on the raw clock fails this.
#[test]
fn a_reply_that_arrives_first_after_a_wake_is_judged_after_the_resume() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on(slept(Duration::from_secs(SLEEP)), wake);
    assert!(resumed(&step), "{:?}", step.actions);
    core.on(sample(14, 1_000), wake);
    assert_eq!(respawns(&core), 0);
}

/// The same reply, with no resume, is a stall. The core does not hide a
/// sleep the driver did not report.
#[test]
fn a_jumped_sample_without_a_resume_is_a_stall() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on(sample(14, 1_000), wake);
    assert!(!resumed(&step), "{:?}", step.actions);
    assert_eq!(core.status().cause, Cause::StrandedAfterClockJump);
    assert_eq!(respawns(&core), 1);
}

/// A deadline found late is not itself a resume. The select classifies the
/// wait; `on_deadline` only runs the work that is due.
#[test]
fn a_late_deadline_does_not_infer_a_sleep() {
    let mut core = stalled_before_a_sleep();
    let wake = secs(20 + SLEEP);
    let step = core.on_deadline(wake);
    assert!(!resumed(&step), "{:?}", step.actions);
}

/// A probe in flight through the sleep gets its whole bound from the wake:
/// no miss, no refetch, and an arrival inside the new bound is the
/// evidence. Leaving the bound where it was fails this.
#[test]
fn a_probe_in_flight_through_a_sleep_keeps_a_whole_bound() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    core.on(
        Input::UploadRoundEnded {
            end: super::super::RoundEnd::Uploaded,
            uploads: 16,
            refused: 0,
            draw: 0,
        },
        0,
    );
    // The driver folds the directory list in that same turn. This round
    // reached none, so the probe alone decides.
    core.on(
        Input::DirectoriesDrawn {
            fetches: Vec::new(),
            ours: None,
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
    let step = core.on(slept(Duration::from_secs(SLEEP)), wake);
    assert!(resumed(&step), "{:?}", step.actions);
    assert!(
        !cancels_probe(&step),
        "no miss at the wake: {:?}",
        step.actions
    );
    let due = core.on_deadline(wake);
    assert!(
        !cancels_probe(&due),
        "the bound was re-armed: {:?}",
        due.actions
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
    let (mut core, _) = Core::start(policy(), managed(true), 0);
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
    let step = core.on(slept(Duration::from_secs(SLEEP)), wake);
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
