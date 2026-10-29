// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe and the inbound facet (`TOR_SUPERVISOR.md` §4.1, §4.5; the
//! probe brief's tests 1 to 4).
//!
//! A round's first upload schedules one probe inside the jitter range. Its
//! arrival is the evidence; its bound, and a round in which every upload
//! failed, are the Service-class remedy. The probe never moves an outbound
//! cause (`TSR-Q14`).

use std::time::Duration;

use super::super::super::posture::{render, Cause, Inbound, InboundCause, Shown};
use super::super::{duration_ns, Action, Core, Input, Step};
use super::{announces, bring_up, managed, policy, reach_usable, socks, takes_down};

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

fn count(step: &Step, wanted: fn(&Action) -> bool) -> usize {
    step.actions.iter().filter(|action| wanted(action)).count()
}

fn probes(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::Probe))
}

fn cancels(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::CancelProbe))
}

fn republishes(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::RepublishOnion))
}

fn publishes_inbound(step: &Step) -> Vec<Inbound> {
    step.actions
        .iter()
        .filter_map(|action| match action {
            Action::PublishInbound(inbound) => Some(*inbound),
            _ => None,
        })
        .collect()
}

/// A Running, usable core whose onion is published, at time 0. The state
/// file has appeared, so the only deadlines are the liveness sample and
/// what the probe arms.
fn published() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    assert_eq!(core.status().inbound, Inbound::Publishing);
    core
}

/// Run deadlines up to `at`, answering each liveness sample, and stop at
/// the first step that starts or drops a probe. Returns that step, or the
/// last one taken.
fn run_to(core: &mut Core, at: u64) -> Step {
    run_timed(core, at).1
}

/// [`run_to`], with the time of the step it returns.
fn run_timed(core: &mut Core, at: u64) -> (u64, Step) {
    let mut last = Step {
        actions: Vec::new(),
        deadline: None,
    };
    let mut when = 0;
    while let Some(due) = core.deadline().filter(|due| *due <= at) {
        when = due;
        let step = core.on_deadline(due);
        let sampled = step.actions.contains(&Action::Sample);
        last = Step {
            actions: step.actions,
            deadline: step.deadline,
        };
        if sampled {
            core.on(
                Input::DirectorySample {
                    progress: Some(100),
                    socks: None,
                    read: None,
                },
                due,
            );
        }
        if probes(&last) > 0 || cancels(&last) > 0 {
            return (when, last);
        }
    }
    (when, last)
}

/// **Test 1.** A round's first upload schedules exactly one probe, inside
/// the jitter range, at the delay the draw names. A second round while one
/// is scheduled or in flight schedules none. Dropping the `Idle` check in
/// `round_uploaded`, or mapping the draw outside the range, fails this.
#[test]
fn a_first_upload_schedules_one_probe_inside_the_jitter_range() {
    let low = secs(15);
    let high = secs(60);
    for (draw, expect) in [
        (0_u64, low),
        (high - low, high),
        (high - low + 1, low),
        (u64::MAX, low + u64::MAX % (high - low + 1)),
    ] {
        let mut core = published();
        core.on(Input::FirstUploaded { draw }, 0);
        let (at, step) = run_timed(&mut core, high);
        assert_eq!(probes(&step), 1, "draw {draw}");
        assert!((low..=high).contains(&expect));
        assert_eq!(at, expect, "the delay the draw names");
        core.on(Input::ProbeDialed { minted_at: at }, at);
        let (bound, missed) = run_timed(&mut core, at + secs(60));
        assert_eq!(cancels(&missed), 1);
        assert_eq!(bound, at + secs(60), "the bound is 60 s after the probe");
    }

    let mut core = published();
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    let again = core.on(Input::FirstUploaded { draw: 7 }, secs(1));
    assert_eq!(probes(&again), 0);
    let step = run_to(&mut core, low);
    assert_eq!(probes(&step), 1, "the first round's one probe");
    core.on(Input::ProbeDialed { minted_at: low }, low);
    let in_flight = core.on(Input::FirstUploaded { draw: 0 }, low + 1);
    assert_eq!(probes(&in_flight), 0, "none while one is in flight");
    let step = run_to(&mut core, low + secs(59));
    assert_eq!(
        probes(&step),
        0,
        "the round that came mid-flight added none"
    );
}

/// **Test 2.** An arrival is `Reachable`, published on the link. A probe
/// past its bound is `Unreachable` with a republish, and Degraded with the
/// inbound sentence; the next arrival recovers it and says so. A refused
/// republish is a process fault. Setting a cause from the probe, or
/// treating a refused Service republish as the first publish's retry,
/// fails this.
#[test]
fn an_arrival_is_reachable_a_miss_republishes_and_a_refusal_respawns() {
    let mut core = published();
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let arrived = core.on(
        Input::ProbeArrived {
            minted_at: secs(15),
        },
        secs(20),
    );
    let reachable = Inbound::Reachable {
        evidence_at: secs(20),
    };
    assert_eq!(core.status().inbound, reachable);
    assert_eq!(publishes_inbound(&arrived), [reachable]);
    assert_eq!(core.status().shown, Shown::Usable);
    assert_eq!(cancels(&arrived), 0, "an arrival ends the dial itself");

    // The next round's probe misses its bound.
    core.on(Input::FirstUploaded { draw: 0 }, secs(100));
    run_to(&mut core, secs(115));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(115),
        },
        secs(115),
    );
    let missed = run_to(&mut core, secs(175));
    assert_eq!(cancels(&missed), 1);
    assert_eq!(republishes(&missed), 1);
    assert_eq!(announces(&missed), 1, "the facet going down is said");
    let down = Inbound::Unreachable {
        cause: InboundCause::ProbeTimedOut,
        since: secs(175),
    };
    assert_eq!(publishes_inbound(&missed), [down]);
    let status = core.status();
    assert_eq!(status.inbound, down);
    assert_eq!(status.shown, Shown::Degraded);
    assert_eq!(status.cause, Cause::None, "never an outbound cause");
    assert!(status.sync.tor, "the outbound facet still carries the sync");
    let text = render(&status);
    assert!(
        text.contains("Peers cannot reach this node through Tor right now"),
        "{text}"
    );
    assert!(!text.contains("cannot reach the Tor network"), "{text}");

    // The republish succeeds; the next round's probe arrives and recovers.
    core.on(Input::OnionPublished, secs(176));
    assert_eq!(
        core.status().inbound,
        down,
        "unreachable until a probe says"
    );
    core.on(Input::FirstUploaded { draw: 0 }, secs(180));
    run_to(&mut core, secs(195));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(195),
        },
        secs(195),
    );
    let recovered = core.on(
        Input::ProbeArrived {
            minted_at: secs(195),
        },
        secs(200),
    );
    assert_eq!(announces(&recovered), 1, "a recovery is said at once");
    assert_eq!(core.status().shown, Shown::Usable);

    // A miss whose republish Tor refuses escalates to a respawn.
    core.on(Input::FirstUploaded { draw: 0 }, secs(300));
    run_to(&mut core, secs(315));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(315),
        },
        secs(315),
    );
    let missed = run_to(&mut core, secs(375));
    assert_eq!(republishes(&missed), 1);
    let refused = core.on(Input::OnionRejected, secs(376));
    assert!(
        takes_down(&refused),
        "a refused republish is a process fault"
    );
    let status = core.status();
    assert_eq!(status.cause, Cause::OnionRefused);
    assert_eq!(status.shown, Shown::Restarting);
}

/// **Test 2, the round.** A round in which every upload failed is the same
/// Service evidence, and cancels a probe in flight: the republish's own
/// round schedules the next.
#[test]
fn a_round_with_every_upload_failed_is_unreachable_and_republishes() {
    let mut core = published();
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let failed = core.on(Input::UploadRoundEnded { failed_all: true }, secs(16));
    assert_eq!(cancels(&failed), 1);
    assert_eq!(republishes(&failed), 1);
    assert_eq!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::DescriptorRejected,
            since: secs(16),
        }
    );
    let late = core.on(
        Input::ProbeArrived {
            minted_at: secs(15),
        },
        secs(17),
    );
    assert!(
        publishes_inbound(&late).is_empty(),
        "the cancelled probe's arrival is stale"
    );
}

/// **Test 3.** A respawn resets the inbound facet to `Publishing` (the onion
/// is the same; the evidence was the old Tor's), cancels the probe in
/// flight, and an arrival from before it is ignored. Keeping `Reachable`
/// across the respawn, or matching any arrival, fails this.
#[test]
fn a_respawn_resets_inbound_and_a_stale_arrival_is_ignored() {
    let mut core = published();
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    core.on(
        Input::ProbeArrived {
            minted_at: secs(15),
        },
        secs(16),
    );
    core.on(Input::FirstUploaded { draw: 0 }, secs(100));
    run_to(&mut core, secs(115));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(115),
        },
        secs(115),
    );
    let died = core.on(Input::ProcessEnded { exit_code: None }, secs(116));
    assert_eq!(cancels(&died), 1, "the fault drops the probe");
    assert!(takes_down(&died));

    // The respawn reaches Running again; the onion is republished.
    let due = core.deadline().expect("the pin check");
    core.on_deadline(due);
    core.on(Input::PinAccepted, due);
    core.on(Input::Spawned, due);
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: Some(socks()),
            read: None,
        },
        due,
    );
    let running = core.on(Input::BootstrapComplete, due);
    assert!(running.actions.contains(&Action::RepublishOnion));
    assert_eq!(core.status().inbound, Inbound::Publishing);
    core.on(Input::RouteInstalled, due);
    core.on(Input::OnionPublished, due);
    let stale = core.on(
        Input::ProbeArrived {
            minted_at: secs(115),
        },
        due + 1,
    );
    assert!(publishes_inbound(&stale).is_empty());
    assert_eq!(core.status().inbound, Inbound::Publishing);

    // The new Tor's probe is in flight when the old one's arrival comes: it
    // names another probe and changes nothing. Only the current one counts.
    core.on(Input::FirstUploaded { draw: 0 }, due + 2);
    let (at, step) = run_timed(&mut core, due + 2 + secs(15));
    assert_eq!(probes(&step), 1);
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let stale = core.on(
        Input::ProbeArrived {
            minted_at: secs(115),
        },
        at + 1,
    );
    assert!(publishes_inbound(&stale).is_empty());
    assert_eq!(core.status().inbound, Inbound::Publishing);
    core.on(Input::ProbeArrived { minted_at: at }, at + 2);
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: at + 2
        }
    );
}

/// **Test 4.** No probe while the outbound facet is not usable: a probe due
/// under a blocked link is skipped, and one in flight when the link is
/// blocked ends at its bound with no verdict. The outbound cause is Tor's
/// alone; the probe neither sets nor clears it. Dropping the suppression
/// check fails this.
#[test]
fn no_probe_runs_or_judges_while_outbound_is_not_usable() {
    let mut core = published();
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    core.on(Input::ExternalBlocked, secs(1));
    let step = run_to(&mut core, secs(15));
    assert_eq!(probes(&step), 0, "suppressed under a blocked link");
    assert_eq!(core.status().inbound, Inbound::Publishing);

    core.on(Input::ExternalCleared, secs(20));
    core.on(Input::FirstUploaded { draw: 0 }, secs(30));
    let step = run_to(&mut core, secs(45));
    assert_eq!(probes(&step), 1);
    core.on(
        Input::ProbeDialed {
            minted_at: secs(45),
        },
        secs(45),
    );
    core.on(Input::ExternalBlocked, secs(50));
    let bound = run_to(&mut core, secs(105));
    assert_eq!(cancels(&bound), 1, "the dial is dropped");
    assert_eq!(republishes(&bound), 0, "a blocked link judges nothing");
    let status = core.status();
    assert_eq!(status.inbound, Inbound::Publishing);
    assert_eq!(status.cause, Cause::ExternalBlocked, "Tor's cause stands");

    // A probe due while the onion is owed again (a republish in progress)
    // is skipped: its round's descriptor is the one being replaced.
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    bring_up(&mut core);
    core.on(Input::RouteInstalled, 0);
    core.on(Input::FirstUploaded { draw: 0 }, 0);
    core.on(Input::OnionRejected, secs(1));
    let step = run_to(&mut core, secs(15));
    assert_eq!(probes(&step), 0);
}
