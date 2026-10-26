// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The live check and the progress line.
//!
//! Split from the phase-machine tests: a running Tor is sampled, a
//! bootstrap says how it is going, and a percent notice is not a sample.

use std::time::Duration;

use super::super::super::posture::BootstrapPace;
use super::{
    announces, carrying, duration_ns, held, managed, policy, reach_usable, render, socks,
    takes_down, Action, Core, Input, Shown,
};

fn says_progress(step: &super::Step) -> usize {
    step.actions
        .iter()
        .filter(|action| matches!(action, Action::SayProgress))
        .count()
}

/// A running Tor that nothing else asks is sampled every `alive_every`, so a
/// wedged Tor meets the reply bound: a late reply is a process fault that
/// takes the route down. Without the liveness sample a steady Running core
/// has no deadline, and a stopped Tor is never noticed (Linux acceptance,
/// 2026-10-23).
#[test]
fn a_running_tor_is_sampled_and_a_late_reply_restarts_it() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    let alive = duration_ns(Duration::from_secs(4));
    assert_eq!(core.deadline(), Some(alive), "the liveness sample is armed");

    // An answer re-arms it.
    let step = core.on_deadline(alive);
    assert!(step.actions.contains(&Action::Sample), "{:?}", step.actions);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: None,
            read: None,
        },
        alive,
    );
    assert_eq!(core.deadline(), Some(2 * alive), "the next sample is armed");
    assert_eq!(
        core.status().shown,
        Shown::Usable,
        "an answer changes nothing"
    );

    // A wedged Tor: the next sample's reply misses the bound.
    let step = core.on_deadline(2 * alive);
    assert!(step.actions.contains(&Action::Sample));
    let fault = core.on(Input::ReplyLate, 2 * alive);
    assert!(takes_down(&fault), "a late reply withdraws the route");
    // Health is the relay's verdict (`GS-Q3`), reported by the relay, not
    // by this fault; the link's own state is what the fault moves.
    assert_eq!(core.status().shown, Shown::Restarting);
}

/// The liveness sample belongs to a running Tor only: a fault or a shutdown
/// clears it, so an absent or stopping Tor is never asked.
#[test]
fn the_liveness_sample_ends_with_the_running_phase() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    core.on(Input::ProcessEnded { exit_code: Some(1) }, 1);
    let step = core.on_deadline(duration_ns(Duration::from_secs(4)));
    assert!(
        !step.actions.contains(&Action::Sample),
        "{:?}",
        step.actions
    );

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::Shutdown, 1);
    assert!(
        core.deadline().is_none(),
        "a stopping Tor has nothing waiting"
    );
}

/// A bootstrap says its progress line every `alive_every`: the percent, how
/// long it has held, and the bytes Tor read in the window, measured from the
/// first sample that carried a count. Without the line a 314 s cold start
/// said nothing (Linux acceptance, 2026-10-23).
#[test]
fn a_bootstrap_says_its_progress_and_whether_bytes_are_moving() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let sample = |progress, read| Input::DirectorySample {
        progress: Some(progress),
        socks: Some(socks()),
        read: Some(read),
    };
    core.on(sample(55, 1_000), 0);
    core.on(sample(55, 3_201_000), duration_ns(Duration::from_secs(3)));

    let window = duration_ns(Duration::from_secs(4));
    let step = core.on_deadline(window);
    assert_eq!(says_progress(&step), 1, "the progress line is said");
    assert_eq!(announces(&step), 0, "the line is not a posture warning");
    let line = core.status().bootstrap.expect("a line while bootstrapping");
    assert_eq!(line.received, Some(3_200_000));
    assert_eq!(line.window, Duration::from_secs(4));
    let text = render(&core.status());
    assert!(text.contains("55%"), "{text}");
    assert!(text.contains("3.2 MB arrived in the last 4 s"), "{text}");

    // Nothing moved in the next window: the line says so. The window opens
    // on the newest sample at least a window old, the one at 3 s, and runs
    // to the deadline at 8 s: five measured seconds, not a mark moved to
    // the deadline as if a sample had been taken there.
    let step = core.on_deadline(2 * window);
    assert_eq!(says_progress(&step), 1);
    assert_eq!(announces(&step), 0);
    assert_eq!(core.status().pace, Some(BootstrapPace::Stalled));
    let text = render(&core.status());
    assert!(text.contains("Nothing arrived in the last 5 s"), "{text}");
    assert!(text.contains("unchanged for 8 s"), "{text}");

    // Running ends the line: the deadline is a liveness sample again.
    core.on(Input::BootstrapComplete, 2 * window);
    assert_eq!(core.status().bootstrap, None);
}

/// A sample without a count leaves the window unknown, never zero: the line
/// does not claim a stall it did not measure.
#[test]
fn a_bootstrap_without_a_count_does_not_claim_a_stall() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(
        Input::DirectorySample {
            progress: Some(30),
            socks: None,
            read: None,
        },
        1,
    );
    core.on_deadline(duration_ns(Duration::from_secs(4)));
    let text = render(&core.status());
    assert!(text.contains("30%"), "{text}");
    assert!(!text.contains("Nothing arrived"), "{text}");
}

/// A bootstrap with a named cause does not say the progress line: the cause
/// repeats on its own events at most once per cap. Saying it on the
/// progress deadline too doubled the outbound-blocked warning (Linux
/// acceptance, 2026-10-24). Dropping the cause check fails this.
#[test]
fn a_blocked_bootstrap_is_said_by_its_cause_not_by_the_progress_line() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let first = core.on(Input::ExternalBlocked, 1);
    assert_eq!(
        announces(&first),
        1,
        "the cause is said when it first appears"
    );
    let window = duration_ns(Duration::from_secs(4));
    let step = core.on_deadline(window);
    assert_eq!(
        says_progress(&step),
        0,
        "the progress deadline says nothing over a cause"
    );
    assert_eq!(announces(&step), 0, "and it does not repeat the cause");
    let again = core.on(Input::ExternalBlocked, window + 1);
    assert_eq!(
        announces(&again),
        0,
        "inside the cap the cause is not said again"
    );
    let later = core.on(Input::ExternalBlocked, duration_ns(policy().cap) + 2);
    assert_eq!(announces(&later), 1, "after the cap it is");
    assert_eq!(says_progress(&later), 0);
}

/// The line names the span it measured. The first count arrived a second
/// into the incarnation, and the driver said the line two seconds after the
/// deadline because an ask held it. The window is those five seconds, not
/// `alive_every`. Assigning the policy interval fails this.
#[test]
fn the_progress_line_measures_the_span_it_names() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let count_at = duration_ns(Duration::from_secs(1));
    core.on(
        Input::DirectorySample {
            progress: Some(20),
            socks: None,
            read: Some(100),
        },
        count_at,
    );
    core.on(
        Input::DirectorySample {
            progress: Some(20),
            socks: None,
            read: Some(5_000_100),
        },
        duration_ns(Duration::from_secs(5)),
    );
    let said_at = duration_ns(Duration::from_secs(6));
    let step = core.on_deadline(said_at);
    assert_eq!(says_progress(&step), 1);
    let line = core.status().bootstrap.expect("a line");
    assert_eq!(line.received, Some(5_000_000));
    assert_eq!(line.window, Duration::from_secs(5));
    assert_ne!(line.window, policy().alive_every);
    let text = render(&core.status());
    assert!(text.contains("5.0 MB arrived in the last 5 s"), "{text}");
    assert!(text.contains("unchanged for 5 s"), "{text}");
}

/// The actor's bootstrap poll is a percent notice, not a directory sample.
/// A notice that arrives strictly between the arm and the sample deadline
/// must leave that deadline where the directory sample armed it. Resetting
/// the sample on each notice says "Nothing arrived" through a download the
/// sample never counted. Dropping the phase guard in `note_bootstrap`, or
/// folding the notice back into `DirectorySample`, fails this.
#[test]
fn a_bootstrap_notice_leaves_the_traffic_sample_where_it_was_armed() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(
        Input::DirectorySample {
            progress: Some(40),
            socks: None,
            read: Some(1_000),
        },
        0,
    );
    let sample_due = duration_ns(policy().sample_every);
    // Halfway is the actor's poll shape: earlier than the sample, later
    // than the arm. The core does not import the actor's interval.
    let notice_at = sample_due / 2;
    let notice = core.on(Input::BootstrapNoted { progress: 40 }, notice_at);
    assert!(notice.actions.is_empty(), "{:?}", notice.actions);
    assert_eq!(
        core.deadline(),
        Some(sample_due),
        "a notice does not postpone the sample"
    );

    let asked = core.on_deadline(sample_due);
    assert!(asked.actions.contains(&Action::Sample));
    core.on(
        Input::DirectorySample {
            progress: Some(40),
            socks: None,
            read: Some(9_000),
        },
        sample_due,
    );
    let between = core.on(
        Input::BootstrapNoted { progress: 40 },
        sample_due + notice_at,
    );
    assert!(between.actions.is_empty());
    assert_eq!(
        core.deadline(),
        Some(sample_due + duration_ns(policy().sample_every))
    );

    let alive = duration_ns(policy().alive_every);
    let said = core.on_deadline(alive);
    assert_eq!(says_progress(&said), 1);
    assert_eq!(announces(&said), 0);
    let line = core.status().bootstrap.expect("the download was counted");
    assert_eq!(line.received, Some(8_000));
    assert_ne!(line.received, Some(0));
}

/// An origin-hold while Tor is still bootstrapping is a posture
/// announcement. The progress line is a different action, so the hold is
/// not logged as news.
#[test]
fn an_origin_hold_during_bootstrap_is_announced_not_said_as_progress() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let up = core.on(carrying(), 0);
    assert_eq!(announces(&up), 1, "a recovery is the posture line");
    assert_eq!(says_progress(&up), 0);
    let lost = core.on(held(), duration_ns(policy().cap) + 1);
    assert_eq!(announces(&lost), 1, "a hold is the posture warning");
    assert_eq!(says_progress(&lost), 0);
    assert_eq!(core.status().shown, Shown::Bootstrapping);
}
