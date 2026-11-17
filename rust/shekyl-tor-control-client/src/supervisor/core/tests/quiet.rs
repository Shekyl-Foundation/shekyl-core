// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quiet line and Tor's sampled network view (`TSR-Q14`).
//!
//! The line stands only when the Tor Manager's onion-path reading is
//! impaired, peers are known, and a Tor dial launched since failed (Rick,
//! 2026-11-15). Dial replies are display. Tor's own statements name the
//! cause, and a named cause says the line instead.

use super::super::super::posture::{Cause, Shown, TorQuiet};
use super::super::{Action, Core, DialTally, Input, OnionPath, Step, TorCensus};
use super::probe::{misses_twice, published, run_to, secs, uploaded};
use super::said;
use super::{announces, managed, policy, reach_usable, replied, spawns, takes_down};
use crate::control::{NetworkView, Reported};

/// The Tor connector's tally: one peer held since the clock's origin, and
/// the latest failed dial launched at `began`.
pub(super) fn held_failing(began: Option<u64>) -> Input {
    tally(TorCensus::Held { seats: 1, since: 0 }, began)
}

fn tally(census: TorCensus, began: Option<u64>) -> Input {
    Input::DialEvidence(DialTally {
        failed_attempt_began: began,
        census,
    })
}

/// A published core whose round's check missed twice: the manager's
/// reading is impaired, learned at the returned instant, and Tor names no
/// cause of its own.
pub(super) fn impaired() -> (Core, u64) {
    let mut core = published();
    core.on(uploaded(0), secs(100));
    run_to(&mut core, secs(115));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(115),
        },
        secs(115),
    );
    let (verdict_at, missed) = misses_twice(&mut core, secs(115));
    assert!(
        missed.actions.iter().any(|action| matches!(
            action,
            Action::PathReading(reading) if reading.path == OnionPath::Impaired
        )),
        "the two-miss verdict is an impaired reading"
    );
    (core, verdict_at)
}

/// A sampled view. Unknown is not a negative.
fn tor_says(liveness: Reported, circuits: Reported) -> Input {
    Input::NetworkView(NetworkView { liveness, circuits })
}

/// Run every deadline up to and including `until`, answering each liveness
/// sample as a Tor that has not reported its network, so nothing but the
/// evidence under test can move the core, and then with
/// [`Input::Replied`]. Returns every step taken, the `Replied` steps among
/// them: a request queued behind a sample is sent there.
fn run_until(core: &mut Core, until: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some(due) = core.deadline().filter(|due| *due <= until) {
        let step = core.on_deadline(due);
        let mut sampled = step.actions.contains(&Action::Sample);
        steps.push(step);
        while sampled {
            steps.push(core.on(tor_says(Reported::Unknown, Reported::Unknown), due));
            let next = replied(core, due);
            sampled = next.actions.contains(&Action::Sample);
            steps.push(next);
        }
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

/// **The line stands on an impaired reading, with peers known and a dial
/// failed since**, said once, as a neutral fact: no cause, no respawn
/// (`TSR-Q14`). The line carries the reading's instant. The edits that
/// make this red: standing it on failed dials alone, routing it to a cause,
/// or saying it again on every tally.
#[test]
fn the_line_stands_on_an_impaired_reading_with_peers_and_a_failed_dial() {
    let (mut core, verdict_at) = impaired();
    let failed = verdict_at + secs(5);
    let first = core.on(held_failing(Some(failed)), failed);
    assert_eq!(
        core.status().tor_quiet,
        Some(TorQuiet::Unreached { since: verdict_at })
    );
    assert_eq!(says_progress(&[first]), 1, "said when it begins");
    let again = core.on(held_failing(Some(failed + secs(9))), failed + secs(9));
    assert_eq!(says_progress(&[again]), 0, "not said again");
    assert_eq!(core.status().cause, Cause::None, "a fact, never a cause");
    assert!(
        said(&core).contains("Peers are known, but Tor has not been able to reach them for"),
        "{}",
        said(&core)
    );
}

/// **Failed dials alone never stand the line** (`TSR-Q14`, Rick
/// 2026-10-25): with no impaired reading, failures with peers known say
/// nothing, name no cause and respawn nothing. A planted onion answers
/// failures at will, so a line from dials would let anyone make the node
/// say it. The edit that makes this red is standing the line without the
/// manager's reading.
#[test]
fn failed_dials_alone_never_stand_the_line() {
    let mut core = published();
    let mut steps = Vec::new();
    for at in (1..=600).step_by(30) {
        steps.push(core.on(held_failing(Some(secs(at))), secs(at)));
    }
    steps.extend(run_until(&mut core, secs(600)));
    assert_eq!(core.status().tor_quiet, None);
    assert_eq!(core.status().cause, Cause::None);
    assert!(!faults(&steps), "no respawn from dials");
}

/// **The line needs a dial launched since the reading**: a failure
/// launched before the impaired reading did not test the path since. The
/// edit that makes this red is reading the failure by when it was counted.
#[test]
fn the_line_needs_a_dial_launched_since_the_reading() {
    let (mut core, verdict_at) = impaired();
    core.on(
        held_failing(Some(verdict_at - secs(1))),
        verdict_at + secs(1),
    );
    assert_eq!(core.status().tor_quiet, None);
    core.on(held_failing(Some(verdict_at)), verdict_at + secs(2));
    assert!(core.status().tor_quiet.is_some(), "launched at the reading");
}

/// **No line while no peer is known** (Rick, 2026-11-15: the line stands
/// only when peers are known): an empty or pending census says nothing,
/// whatever the reading. The edit that makes this red is standing the line
/// on an empty census.
#[test]
fn no_line_while_no_peer_is_known() {
    let (mut core, verdict_at) = impaired();
    for census in [TorCensus::Pending, TorCensus::Empty] {
        core.on(
            tally(census, Some(verdict_at + secs(1))),
            verdict_at + secs(1),
        );
        assert_eq!(core.status().tor_quiet, None, "{census:?}");
    }
}

/// **A working fact takes the line down**: a completed onion dial after
/// the impaired reading is the manager's reading now. The edit that makes
/// this red is keeping the line on a superseded reading.
#[test]
fn a_working_fact_takes_the_line_down() {
    let (mut core, verdict_at) = impaired();
    let failed = verdict_at + secs(5);
    core.on(held_failing(Some(failed)), failed);
    assert!(core.status().tor_quiet.is_some());
    core.on(
        Input::OnionDialOpened {
            at: failed + secs(1),
        },
        failed + secs(1),
    );
    assert_eq!(core.status().tor_quiet, None);
}

/// Tor's own view (`TSR-Q14`) governs even when Tor sends no event: its
/// liveness verdict `down` names the blocked link at once; both affirmative
/// answers clear it at once. Unknown says nothing, and neither does "no
/// circuit established", which is display only. During a bootstrap no
/// circuit is built yet, and a view folded then is not a statement.
/// *Changed by the VM clock findings (2026-10-30):* "no circuit" named the
/// blocked link, and after a resume, when Tor drops its circuits on
/// purpose, that was a false alarm.
#[test]
fn tors_sampled_view_names_and_clears_a_blocked_link_only_while_running() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::accepted(), 0);
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
    let step = core.on(tor_says(Reported::Yes, Reported::No), 5);
    assert_eq!(announces(&step), 0);
    assert_eq!(
        core.status().cause,
        Cause::None,
        "no circuit is not Tor saying its network is down"
    );
}

/// **After a resume, no circuit is not a block** (the VM suspend of
/// 2026-10-30). Tor drops its circuits on a clock jump and says so; the
/// sample after it reads `circuit-established=0` with liveness up. That
/// named the blocked link and said "cannot reach the Tor network" for the
/// seconds Tor took to rebuild. Reading "no circuit" as "blocked" again
/// fails this.
#[test]
fn the_sample_after_a_clock_jump_names_no_block() {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::ClockJumped, 10);
    let step = core.on(tor_says(Reported::Yes, Reported::No), 11);
    assert_eq!(announces(&step), 0, "nothing is said");
    assert_eq!(core.status().cause, Cause::None);
    assert!(!said(&core).contains("cannot reach"));
    core.on(tor_says(Reported::Yes, Reported::Yes), 18);
    assert_eq!(core.status().cause, Cause::None);
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
    let during = core.on_deadline(due);
    assert!(
        !during.actions.contains(&Action::CheckPin),
        "the pin waits for the reap: {during:?}"
    );
    let step = replied(&mut core, due);
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
