// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet line and Tor's sampled network view (`TSR-Q14`).
//!
//! Dial replies are display. Tor's own statements name the cause.

use std::time::Duration;

use super::super::super::posture::{render, Cause, Shown};
use super::super::{duration_ns, Action, Core, DialTally, Input, Step};
use super::{announces, managed, policy, reach_usable, socks, spawns, takes_down};
use crate::control::{NetworkView, Reported};

/// A tally of `unopened` failed Tor dials since the `opened`-th opened one,
/// with `held` sessions.
fn dials(opened: u64, unopened: u32, held: u32) -> Input {
    Input::DialEvidence(DialTally {
        opened,
        unopened,
        held,
    })
}

/// A sampled view. Unknown is not a negative.
fn tor_says(liveness: Reported, circuits: Reported) -> Input {
    Input::NetworkView(NetworkView { liveness, circuits })
}

/// Run every deadline up to and including `until`, answering each liveness
/// sample as a Tor that has not reported its network, so nothing but the
/// evidence under test can move the core. Returns every step taken.
fn run_until(core: &mut Core, until: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some(due) = core.deadline().filter(|due| *due <= until) {
        let step = core.on_deadline(due);
        if step.actions.contains(&Action::Sample) {
            steps.push(core.on(tor_says(Reported::Unknown, Reported::Unknown), due));
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

/// Dials counted before this supervisor watched are the baseline, not an
/// open. Seeding them after Running, at a later instant, leaves the stretch
/// clock on the transition into Running. Folding that same tally as evidence
/// would move the clock to the seed and the line would not stand yet.
#[test]
fn a_tally_from_before_this_tor_does_not_count_as_an_open() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    let quiet = duration_ns(policy().quiet_after);
    core.on(
        Input::DialBaseline(DialTally {
            opened: 4,
            unopened: 2,
            held: 0,
        }),
        1,
    );
    let step = core.on(dials(4, 3, 0), quiet);
    assert_eq!(
        says_progress(&[step]),
        1,
        "no new open, so the stretch stands"
    );
    assert!(core.status().tor_quiet.is_some());
    core.on(dials(5, 1, 0), quiet + 1);
    assert_eq!(
        core.status().tor_quiet,
        None,
        "an open on this Tor starts the stretch again"
    );
}

/// Tor's own view (`TSR-Q14`) governs even when Tor sends no event: a
/// negative answer names the blocked link at once; both affirmative answers
/// clear it at once. Unknown says nothing. During a bootstrap no circuit is
/// built yet, and a view folded then is not a statement.
#[test]
fn tors_sampled_view_names_and_clears_a_blocked_link_only_while_running() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    let step = core.on(tor_says(Reported::Yes, Reported::No), 1);
    assert_eq!(announces(&step), 0);
    assert_eq!(
        core.status().cause,
        Cause::None,
        "bootstrapping: no circuit yet"
    );

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    assert_eq!(
        announces(&core.on(tor_says(Reported::Unknown, Reported::Unknown), 1)),
        0
    );
    let step = core.on(tor_says(Reported::No, Reported::Unknown), 2);
    assert_eq!(announces(&step), 1, "said at once");
    assert_eq!(core.status().cause, Cause::ExternalBlocked);
    assert_eq!(core.status().shown, Shown::Degraded);
    assert_eq!(
        announces(&core.on(tor_says(Reported::Yes, Reported::Unknown), 3)),
        0
    );
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "a circuit too");
    let step = core.on(tor_says(Reported::Yes, Reported::Yes), 4);
    assert_eq!(announces(&step), 1, "the recovery is said at once");
    assert_eq!(core.status().cause, Cause::None);
    core.on(tor_says(Reported::Yes, Reported::No), 5);
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

/// The line reads whether dials failed, never how many (the dialer lane's
/// #1190 keeps up to five Tor dials in flight): five failures landing at
/// once leave the posture exactly where one does, and the count reaches no
/// one, since Status carries only the stretch.
#[test]
fn the_line_reads_whether_dials_failed_not_how_many() {
    let late = duration_ns(policy().quiet_after) + 1;
    let mut seen = Vec::new();
    for unopened in [1, 5] {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_usable(&mut core);
        let step = core.on(dials(0, unopened, 0), late);
        seen.push((says_progress(&[step]), core.status()));
    }
    assert_eq!(
        seen[0], seen[1],
        "one failure and five are the same posture"
    );
    assert!(seen[0].1.tor_quiet.is_some());
}
