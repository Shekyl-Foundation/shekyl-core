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
use super::super::{
    duration_ns, Action, Core, DirectoryAnswer, DirectoryFetch, Input, Policy, RoundEnd, Step,
    DESCRIPTOR_LIFETIME,
};
use super::{announces, bring_up, managed, policy, reach_usable, socks, takes_down};
use crate::control::RelayFingerprint;

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

fn refetches(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::RefetchDescriptor))
}

/// A round ended with an upload that succeeded: the probe's trigger.
fn uploaded(draw: u64) -> Input {
    Input::UploadRoundEnded {
        end: RoundEnd::Uploaded,
        draw,
    }
}

/// The probe minted at `minted_at` was taken by the handshake at `arrived_at`.
/// Successes here pass the fold's time as the take, so the evidence time
/// stays that instant.
fn arrival(minted_at: u64, arrived_at: u64) -> Input {
    Input::ProbeArrived {
        minted_at,
        arrived_at,
    }
}

/// The probe minted at `minted` misses its bound. One miss is not a verdict:
/// the core refetches the descriptor and judges nothing. The second probe,
/// after the refetch and a fresh delay, misses too. Returns that verdict
/// step and its time.
fn misses_twice(core: &mut Core, minted: u64) -> (u64, Step) {
    let (at, first) = run_timed(core, minted + secs(60));
    assert_eq!(at, minted + secs(60));
    assert_eq!(cancels(&first), 1);
    assert_eq!(refetches(&first), 1, "a first miss refetches");
    assert_eq!(republishes(&first), 0, "and does not republish");
    assert!(
        publishes_inbound(&first).is_empty(),
        "one miss is not a verdict"
    );
    core.on(Input::DescriptorRefetched { draw: 0 }, at);
    let (probe_at, step) = run_timed(core, at + secs(15));
    assert_eq!(
        probes(&step),
        1,
        "the second probe, a fresh delay after the refetch"
    );
    assert_eq!(probe_at, at + secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    run_timed(core, probe_at + secs(60))
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
        core.on(uploaded(draw), 0);
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
    core.on(uploaded(0), 0);
    let again = core.on(uploaded(7), secs(1));
    assert_eq!(probes(&again), 0);
    let step = run_to(&mut core, low);
    assert_eq!(probes(&step), 1, "the first round's one probe");
    core.on(Input::ProbeDialed { minted_at: low }, low);
    let in_flight = core.on(uploaded(0), low + 1);
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
    core.on(uploaded(0), 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let arrived = core.on(arrival(secs(15), secs(20)), secs(20));
    let reachable = Inbound::Reachable {
        evidence_at: secs(20),
    };
    assert_eq!(core.status().inbound, reachable);
    assert_eq!(publishes_inbound(&arrived), [reachable]);
    assert_eq!(core.status().shown, Shown::Usable);
    assert_eq!(cancels(&arrived), 0, "an arrival ends the dial itself");

    // The next round's probe misses its bound.
    core.on(uploaded(0), secs(100));
    run_to(&mut core, secs(115));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(115),
        },
        secs(115),
    );
    let before = core.status().inbound;
    let (verdict_at, missed) = misses_twice(&mut core, secs(115));
    assert_eq!(
        before,
        Inbound::Reachable {
            evidence_at: secs(20)
        }
    );
    assert_eq!(verdict_at, secs(250));
    assert_eq!(cancels(&missed), 1);
    assert_eq!(refetches(&missed), 0, "the second miss is the verdict");
    assert_eq!(republishes(&missed), 1);
    assert_eq!(announces(&missed), 1, "the facet going down is said");
    let down = Inbound::Unreachable {
        cause: InboundCause::ProbeTimedOut,
        since: secs(250),
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
    core.on(Input::OnionPublished, secs(251));
    assert_eq!(
        core.status().inbound,
        down,
        "unreachable until a probe says"
    );
    core.on(uploaded(0), secs(255));
    run_to(&mut core, secs(270));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(270),
        },
        secs(270),
    );
    let recovered = core.on(arrival(secs(270), secs(275)), secs(275));
    assert_eq!(announces(&recovered), 1, "a recovery is said at once");
    assert_eq!(core.status().shown, Shown::Usable);

    // A miss whose republish Tor refuses escalates to a respawn.
    core.on(uploaded(0), secs(300));
    run_to(&mut core, secs(315));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(315),
        },
        secs(315),
    );
    let (at, missed) = misses_twice(&mut core, secs(315));
    assert_eq!(republishes(&missed), 1);
    let refused = core.on(Input::OnionRejected, at + 1);
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
    let succeeded = core.on(uploaded(0), 0);
    assert_eq!(
        republishes(&succeeded),
        0,
        "an upload that succeeded, even beside a failure, is not evidence"
    );
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let failed = core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::FailedAll,
            draw: 0,
        },
        secs(16),
    );
    assert_eq!(cancels(&failed), 1);
    assert_eq!(republishes(&failed), 1);
    assert_eq!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::DescriptorRejected,
            since: secs(16),
        }
    );
    let stacked = core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::FailedAll,
            draw: 0,
        },
        secs(16),
    );
    assert_eq!(
        republishes(&stacked),
        0,
        "a republish already owed does not stack"
    );
    let unfinished = core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Unknown,
            draw: 0,
        },
        secs(16),
    );
    assert_eq!(
        republishes(&unfinished),
        0,
        "an upload still unfinished is not evidence"
    );
    let late = core.on(arrival(secs(15), secs(17)), secs(17));
    assert!(
        publishes_inbound(&late).is_empty(),
        "the cancelled probe's arrival is stale"
    );
}

/// **The arrival's own time.** The handshake stamps when it took the nonce.
/// A fold that runs after the bound still counts a take from before the
/// bound, and the evidence time is that stamp. A take at or after the bound
/// is not evidence: the probe stays in flight and the deadline still misses
/// it. Judging by the fold's clock, or accepting a late nonce, fails this.
#[test]
fn a_timely_arrival_folded_late_is_reachable_and_a_late_one_still_misses() {
    let mut core = published();
    core.on(uploaded(0), 0);
    let (at, step) = run_timed(&mut core, secs(15));
    assert_eq!(probes(&step), 1);
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let bound = at + secs(60);
    let taken = at + secs(10);
    let arrived = core.on(arrival(at, taken), bound + secs(5));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable { evidence_at: taken }
    );
    assert_eq!(publishes_inbound(&arrived).len(), 1);
    let later = core.on_deadline(bound + secs(5));
    assert_eq!(cancels(&later), 0, "the probe already arrived");
    assert_eq!(republishes(&later), 0);

    let mut core = published();
    core.on(uploaded(0), 0);
    let (at, _) = run_timed(&mut core, secs(15));
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let bound = at + secs(60);
    let late = core.on(arrival(at, bound), bound);
    assert!(publishes_inbound(&late).is_empty());
    assert_eq!(core.status().inbound, Inbound::Publishing);
    let missed = core.on_deadline(bound);
    assert_eq!(cancels(&missed), 1);
    assert_eq!(
        refetches(&missed),
        1,
        "the deadline still misses a late take"
    );
}

/// **Test 3.** A respawn resets the inbound facet to `Publishing` (the onion
/// is the same; the evidence was the old Tor's), cancels the probe in
/// flight, and an arrival from before it is ignored. Keeping `Reachable`
/// across the respawn, or matching any arrival, fails this.
#[test]
fn a_respawn_resets_inbound_and_a_stale_arrival_is_ignored() {
    let mut core = published();
    core.on(uploaded(0), 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    core.on(arrival(secs(15), secs(16)), secs(16));
    core.on(uploaded(0), secs(100));
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
    let stale = core.on(arrival(secs(115), due + 1), due + 1);
    assert!(publishes_inbound(&stale).is_empty());
    assert_eq!(core.status().inbound, Inbound::Publishing);

    // The new Tor's probe is in flight when the old one's arrival comes: it
    // names another probe and changes nothing. Only the current one counts.
    core.on(uploaded(0), due + 2);
    let (at, step) = run_timed(&mut core, due + 2 + secs(15));
    assert_eq!(probes(&step), 1);
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let stale = core.on(arrival(secs(115), at + 1), at + 1);
    assert!(publishes_inbound(&stale).is_empty());
    assert_eq!(core.status().inbound, Inbound::Publishing);
    core.on(arrival(at, at + 2), at + 2);
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
    core.on(uploaded(0), 0);
    core.on(Input::ExternalBlocked, secs(1));
    let step = run_to(&mut core, secs(15));
    assert_eq!(probes(&step), 0, "suppressed under a blocked link");
    assert_eq!(core.status().inbound, Inbound::Publishing);

    core.on(Input::ExternalCleared, secs(20));
    core.on(uploaded(0), secs(30));
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
    core.on(uploaded(0), 0);
    core.on(Input::OnionRejected, secs(1));
    let step = run_to(&mut core, secs(15));
    assert_eq!(probes(&step), 0);
}

/// **One miss is not a verdict** (Rick, 2026-10-29). A first probe that
/// misses is followed by the refetch and a second probe; a round that ends
/// meanwhile schedules nothing more; the second probe arriving is
/// `Reachable`, and the facet was never down and nothing was republished.
/// Judging on the first miss, or letting the round add a probe during the
/// refetch, fails this.
#[test]
fn a_single_miss_refetches_and_an_arrival_after_it_is_reachable() {
    let mut core = published();
    core.on(uploaded(0), 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let (at, first) = run_timed(&mut core, secs(75));
    assert_eq!(refetches(&first), 1);
    assert_eq!(republishes(&first), 0);
    assert_eq!(core.status().inbound, Inbound::Publishing);
    assert_eq!(core.status().shown, Shown::Usable, "nothing is said down");
    let round = core.on(uploaded(0), at + 1);
    assert_eq!(probes(&round), 0);
    core.on(Input::DescriptorRefetched { draw: 0 }, at + 2);
    let (probe_at, step) = run_timed(&mut core, at + 2 + secs(15));
    assert_eq!(probes(&step), 1, "exactly the refetch's probe");
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    let arrived = core.on(arrival(probe_at, probe_at + 1), probe_at + 1);
    assert_eq!(republishes(&arrived), 0);
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: probe_at + 1
        }
    );
    // The next round's probe is a first attempt again.
    core.on(uploaded(0), probe_at + secs(100));
    let (_, step) = run_timed(&mut core, probe_at + secs(115));
    assert_eq!(probes(&step), 1);
}

fn stucks(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::RoundStuck))
}

/// **The round's wait** (Rick, 2026-10-29). A round still open 60 s after
/// its first upload does not hold the probe: it goes ahead with the first
/// upload's draw, and the round's late end schedules no second one. A round
/// that ends sooner triggers at its end with the end's draw, and the wait
/// then does nothing. Dropping the wait, or letting the end trigger again,
/// fails this.
#[test]
fn the_probe_follows_the_rounds_end_or_its_wait_whichever_is_first() {
    // The round hangs: the wait runs out at 60 s after its first upload.
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, secs(5));
    let (at, step) = run_timed(&mut core, secs(5 + 60 + 15));
    assert_eq!(probes(&step), 1, "the wait's probe");
    assert_eq!(
        at,
        secs(5 + 60 + 15),
        "60 s after the first upload, then the delay"
    );
    core.on(Input::ProbeDialed { minted_at: at }, at);
    core.on(arrival(at, at + 1), at + 1);
    let late = core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Uploaded,
            draw: 0,
        },
        at + 2,
    );
    assert_eq!(probes(&late), 0);
    let (_, rest) = run_timed(&mut core, at + secs(120));
    assert_eq!(probes(&rest), 0, "the late end schedules no second probe");

    // The round ends at 9 s: the probe follows its end, and the wait is gone.
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, secs(5));
    core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Uploaded,
            draw: 0,
        },
        secs(9),
    );
    let (at, step) = run_timed(&mut core, secs(5 + 60 + 15));
    assert_eq!(probes(&step), 1);
    assert_eq!(at, secs(9 + 15), "the end's probe, not the wait's");
    core.on(Input::ProbeDialed { minted_at: at }, at);
    let (_, rest) = run_timed(&mut core, secs(5 + 60 + 15));
    assert_eq!(probes(&rest), 0, "the wait added nothing");
}

/// **A round that never ends is counted, said once, and ended** (Rick,
/// 2026-10-29). At 300 s open it is counted in Status and the driver is told
/// once ([`Action::RoundStuck`]: a debug line, and the coalescer's open round
/// ended so the next round is seen). It is never a cause, and the probe's
/// wait has already gone ahead. Counting it twice, or never, fails this.
#[test]
fn a_round_open_for_five_minutes_is_counted_once_and_never_a_cause() {
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, secs(5));
    let mut said = 0;
    let mut probed = 0;
    let mut now = 0;
    let mut turns = 0;
    while let Some(due) = core.deadline().filter(|due| *due <= secs(400)) {
        turns += 1;
        assert!(turns < 1_000, "a deadline that never moves");
        now = due;
        let step = core.on_deadline(due);
        said += stucks(&step);
        probed += probes(&step);
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
        if probes(&step) > 0 {
            core.on(Input::ProbeDialed { minted_at: due }, due);
            core.on(arrival(due, due), due);
        }
    }
    assert!(now >= secs(300));
    assert_eq!(said, 1, "said once");
    assert_eq!(probed, 1, "the wait's probe went ahead long before");
    let status = core.status();
    assert_eq!(status.stuck_upload_rounds, 1);
    assert_eq!(status.cause, Cause::None);
    assert_eq!(status.shown, Shown::Usable);
    // The coalescer's resync ends it; the next round counts from nothing.
    core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Uploaded,
            draw: 0,
        },
        secs(401),
    );
    core.on(Input::UploadRoundStarted, secs(402));
    assert_eq!(core.status().stuck_upload_rounds, 1);
}

// The overdue upload and the clock jump (§4.5, "Overdue"; Rick, 2026-10-31).

/// The policy's descriptor lifetime: three hours.
fn lifetime() -> u64 {
    secs(3 * 60 * 60)
}

fn overdue(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::DescriptorOverdue))
}

fn jump_probes(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::ProbeAfterJump))
}

/// Run every deadline up to `at`, answering each liveness sample, and keep
/// the times at which the overdue republish was asked. A deadline that
/// does not move after it is served fails here, rather than looping.
fn overdue_to(core: &mut Core, at: u64) -> Vec<u64> {
    let mut asked = Vec::new();
    let mut served = None;
    while let Some(due) = core.deadline().filter(|due| *due <= at) {
        assert_ne!(served, Some(due), "the deadline at {due} did not move");
        served = Some(due);
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
        if overdue(&step) > 0 {
            assert_eq!(republishes(&step), 1, "the overdue republish");
            asked.push(due);
        }
    }
    asked
}

/// A published core whose round began at `round_at`, with its first upload
/// then and its probe arrived. Returns the core and the first upload, from
/// which the next lifetime counts.
fn reached(round_at: u64) -> (Core, u64) {
    let mut core = published();
    core.on(Input::UploadRoundStarted, round_at);
    core.on(Input::FirstUploaded { draw: 0 }, round_at);
    core.on(uploaded(0), round_at + secs(5));
    let (probe_at, step) = run_timed(&mut core, round_at + secs(20));
    assert_eq!(probes(&step), 1, "the round's probe");
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    let arrived = probe_at + secs(5);
    core.on(arrival(probe_at, arrived), arrived);
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    (core, round_at)
}

/// Tor's `HS_DESC_DEFAULT_LIFETIME` at the pinned tor 0.4.9.14
/// (`src/feature/hs/hs_descriptor.h:30`) is 3 hours, and the daemon's policy
/// uses it. A re-pin that changes it fails here until the policy follows
/// (`RELEASE_CHECKLIST.md`, "Bundled Tor pin current").
#[test]
fn the_descriptor_lifetime_is_tors_three_hours() {
    assert_eq!(DESCRIPTOR_LIFETIME, Duration::from_secs(3 * 60 * 60));
    assert_eq!(
        Policy::provisional(Duration::from_secs(1)).descriptor_lifetime,
        DESCRIPTOR_LIFETIME
    );
}

/// No round begins within the descriptor's lifetime of the last round's
/// first upload (the round's probe arriving does not move it): the onion is
/// published again, once, with no probe and no claim that peers cannot
/// reach it; the next lifetime counts from the republish. Fails if the
/// check probes instead (`on_overdue_deadline` emitting no republish), or
/// if it does not re-anchor (the deadline does not move).
#[test]
fn an_overdue_upload_republishes_once() {
    let (mut core, uploaded_at) = reached(0);
    let before = core.status().inbound;
    let due = uploaded_at + lifetime();
    let mut asked = core.on_deadline(due);
    while overdue(&asked) == 0 {
        let next = core.deadline().expect("the overdue check is armed");
        assert!(next <= due, "nothing past the lifetime before the check");
        asked = core.on_deadline(next);
    }
    assert_eq!(republishes(&asked), 1);
    assert_eq!(probes(&asked), 0, "a republish, not a probe");
    assert_eq!(
        core.status().inbound,
        before,
        "nothing shows peers cannot reach it"
    );
    assert_eq!(
        overdue_to(&mut core, due + secs(1)),
        [],
        "none again while the republish is owed"
    );
    core.on(Input::OnionPublished, due + secs(1));
    assert_eq!(overdue_to(&mut core, due + lifetime() - secs(1)), []);
    assert_eq!(overdue_to(&mut core, due + lifetime()), [due + lifetime()]);
}

/// The overdue republish is Service-class: refused, it is a process fault,
/// as a republish after two misses is. Fails if `on_overdue_deadline` does
/// not set `service_republish`.
#[test]
fn a_refused_overdue_republish_takes_tor_down() {
    let (mut core, uploaded_at) = reached(0);
    assert_eq!(
        overdue_to(&mut core, uploaded_at + lifetime()),
        [uploaded_at + lifetime()]
    );
    let refused = core.on(Input::OnionRejected, uploaded_at + lifetime() + secs(1));
    assert!(
        takes_down(&refused),
        "a refused republish is a process fault"
    );
}

/// A round that begins just inside the lifetime is not overdue, while it is
/// open. Fails if `overdue_due` stays armed while a round is open.
#[test]
fn a_round_just_inside_the_lifetime_gives_no_republish() {
    let (mut core, uploaded_at) = reached(0);
    assert_eq!(
        overdue_to(&mut core, uploaded_at + lifetime() - secs(1)),
        []
    );
    core.on(
        Input::UploadRoundStarted,
        uploaded_at + lifetime() - secs(1),
    );
    assert_eq!(
        overdue_to(&mut core, uploaded_at + lifetime() + secs(120)),
        [],
        "an open round is the upload"
    );
}

/// A round that ends with no upload leaves the old anchor standing:
/// nothing shows a fresh descriptor, so the republish is due at once.
#[test]
fn a_round_that_ends_with_no_upload_leaves_the_upload_overdue() {
    let (mut core, uploaded_at) = reached(0);
    let started = uploaded_at + lifetime() - secs(60);
    assert_eq!(overdue_to(&mut core, started), []);
    core.on(Input::UploadRoundStarted, started);
    let ended = uploaded_at + lifetime() + secs(60);
    assert_eq!(overdue_to(&mut core, ended), []);
    core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::Unknown,
            draw: 0,
        },
        ended,
    );
    assert!(
        core.deadline().is_some_and(|due| due <= ended),
        "due at once"
    );
    let step = core.on_deadline(ended);
    assert_eq!(overdue(&step), 1);
    assert_eq!(republishes(&step), 1);
}

/// `CLOCK_JUMPED` while Running asks one probe, a jittered delay later; with
/// a probe already in flight it asks none. During a bootstrap it asks none.
/// The jump probe arriving does not move the descriptor's lifetime: only an
/// upload shows the descriptor's age. Fails if `clock_jumped` asks no probe,
/// if `jump_probe` ignores a probe in hand, or if an arrival re-anchors.
#[test]
fn a_clock_jump_gives_one_probe_or_none_with_one_in_flight() {
    let (mut core, uploaded_at) = reached(0);
    let jumped = uploaded_at + secs(3600);
    let step = core.on(Input::ClockJumped, jumped);
    assert!(step.actions.contains(&Action::Sample), "re-evaluate now");
    assert_eq!(jump_probes(&step), 1);
    core.on(Input::JumpProbeDrawn { draw: 0 }, jumped);
    let (probe_at, step) = run_timed(&mut core, jumped + secs(15));
    assert_eq!(
        probes(&step),
        1,
        "one probe, a jittered delay after the jump"
    );
    assert_eq!(probe_at, jumped + secs(15), "at least the delay's floor");
    core.on(
        Input::ProbeDialed {
            minted_at: probe_at,
        },
        probe_at,
    );
    let again = core.on(Input::ClockJumped, probe_at + secs(1));
    assert_eq!(jump_probes(&again), 0, "the probe in flight answers it");
    core.on(arrival(probe_at, probe_at + secs(5)), probe_at + secs(5));
    assert_eq!(
        overdue_to(&mut core, uploaded_at + lifetime()),
        [uploaded_at + lifetime()],
        "the jump probe's arrival does not move the lifetime"
    );

    let (mut booting, _) = Core::start(policy(), managed(true), 0);
    booting.on(Input::PinAccepted, 0);
    booting.on(Input::Spawned, 0);
    let during = booting.on(Input::ClockJumped, secs(1));
    assert_eq!(
        jump_probes(&during),
        0,
        "no onion to probe while bootstrapping"
    );
}

// The directory check (§4.5; Rick, 2026-10-31).

fn hsdir(n: u8) -> RelayFingerprint {
    RelayFingerprint::from_bytes([n; 20])
}

/// Directories `1..=n`, each sent `descriptor`, each drawing `draw`.
fn sent(range: std::ops::RangeInclusive<u8>, descriptor: &str, draw: u64) -> Vec<DirectoryFetch> {
    range
        .map(|n| DirectoryFetch {
            hsdir: hsdir(n),
            descriptor_id: descriptor.to_owned(),
            draw,
        })
        .collect()
}

fn fetched(step: &Step) -> Vec<RelayFingerprint> {
    step.actions
        .iter()
        .filter_map(|action| match action {
            Action::FetchFromDirectory { hsdir } => Some(*hsdir),
            _ => None,
        })
        .collect()
}

fn answered(n: u8, descriptor: &str, answer: DirectoryAnswer) -> Input {
    Input::DirectoryAnswered {
        hsdir: hsdir(n),
        descriptor_id: Some(descriptor.to_owned()),
        answer,
    }
}

/// A published core whose round just ended, its check's directories drawn
/// (`fetches`), and the probe and the fetches due at the delay's floor run:
/// the probe is in flight, minted at 15 s. Returns the core and the fetches
/// asked at 15 s.
fn checking(fetches: Vec<DirectoryFetch>) -> (Core, Vec<RelayFingerprint>) {
    let mut core = published();
    let ended = core.on(uploaded(0), 0);
    assert!(
        ended.actions.contains(&Action::CheckDirectories),
        "each probe's check asks for the directories"
    );
    core.on(Input::DirectoriesDrawn { fetches }, 0);
    let step = core.on_deadline(secs(15));
    assert_eq!(probes(&step), 1, "the probe at the delay's floor");
    let asked = fetched(&step);
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    (core, asked)
}

/// **Found at every directory, the probe arrives: Reachable.** The verdict
/// waits for both halves: an arrival before the answers leaves the facet
/// where it was. Fails if `probe_arrived` judges at once (Reachable before
/// the answers), or if `judge` ignores a complete check.
#[test]
fn found_at_every_directory_and_the_probe_arrives_is_reachable() {
    let (mut core, asked) = checking(sent(1..=8, "cur", 0));
    assert_eq!(asked.len(), 8, "every directory the round reached is asked");
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Publishing,
        "the directories are still out"
    );
    core.on(
        Input::DirectoryAsked {
            descriptor_id: "cur".to_owned(),
        },
        secs(19),
    );
    for n in 1..=7 {
        core.on(answered(n, "cur", DirectoryAnswer::Received), secs(20));
    }
    assert_eq!(core.status().inbound, Inbound::Publishing);
    let last = core.on(answered(8, "cur", DirectoryAnswer::Received), secs(21));
    let reachable = Inbound::Reachable {
        evidence_at: secs(18),
    };
    assert_eq!(core.status().inbound, reachable);
    assert_eq!(publishes_inbound(&last), [reachable]);
}

/// **Our cache still holds the descriptor, the directories report
/// `NOT_FOUND`: a miss.** The probe arrives, as it does from this node's own
/// copy, and the check is still a miss: the first refetches, and a second
/// check the same way republishes, with the directories' cause. Fails if
/// the verdict takes the probe alone (`judge` treating `Lost` as held).
#[test]
fn the_probe_arriving_from_our_cache_with_the_directories_empty_is_a_miss() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    let first = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&first), 1, "a first miss refetches");
    assert_eq!(
        core.status().inbound,
        Inbound::Publishing,
        "one miss is not a verdict"
    );
    let again = core.on(Input::DescriptorRefetched { draw: 0 }, secs(20));
    assert!(
        again.actions.contains(&Action::CheckDirectories),
        "a new check"
    );
    core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=8, "cur", 0),
        },
        secs(20),
    );
    let launched = core.on_deadline(secs(35));
    assert_eq!(probes(&launched), 1);
    assert_eq!(fetched(&launched).len(), 8);
    core.on(
        Input::ProbeDialed {
            minted_at: secs(35),
        },
        secs(35),
    );
    for n in 1..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(36));
    }
    let verdict = core.on(arrival(secs(35), secs(37)), secs(37));
    assert_eq!(republishes(&verdict), 1);
    assert_eq!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::DescriptorNotFound,
            since: secs(37),
        }
    );
}

/// **One directory withholds: still Reachable above the threshold.** A
/// directory that never answers counts as missing at the check's bound
/// (the last fetch's due plus the probe's bound); seven of eight is more
/// than half. Fails if a missing answer blocks the verdict (no bound), or
/// if the threshold is "every directory".
#[test]
fn one_directory_withholding_is_still_reachable() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=7 {
        core.on(answered(n, "cur", DirectoryAnswer::Received), secs(16));
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Publishing,
        "directory 8 is still out"
    );
    let bound = core.on_deadline(secs(75));
    let reachable = Inbound::Reachable {
        evidence_at: secs(18),
    };
    assert_eq!(core.status().inbound, reachable);
    assert_eq!(publishes_inbound(&bound), [reachable]);
}

/// The threshold is more than half of the counted directories: four of
/// eight is a miss. Fails if `found * 2 > counted` becomes `>=`.
#[test]
fn half_of_the_directories_is_not_enough() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=4 {
        core.on(answered(n, "cur", DirectoryAnswer::Received), secs(16));
    }
    for n in 5..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    let step = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&step), 1, "a miss");
}

/// A round sends the current descriptor to some directories and the next
/// period's to others, and a fetch asks for the current one. Once a fetch
/// names it, a directory sent the other descriptor is excluded: not asked
/// if not yet asked, and not counted if it answers. Fails if `learn` keeps
/// mismatched directories (they would count missing and make this a miss).
#[test]
fn a_directory_sent_the_other_descriptor_is_not_counted() {
    let mut fetches = sent(1..=4, "cur", 0);
    // Directories 5 to 8 got the next period's descriptor, and draw later.
    fetches.extend(sent(5..=8, "next", u64::MAX));
    let (mut core, asked) = checking(fetches);
    assert_eq!(asked, [hsdir(1), hsdir(2), hsdir(3), hsdir(4)]);
    core.on(
        Input::DirectoryAsked {
            descriptor_id: "cur".to_owned(),
        },
        secs(16),
    );
    for n in 1..=4 {
        core.on(answered(n, "cur", DirectoryAnswer::Received), secs(17));
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    let later = core.on_deadline(secs(60));
    assert!(
        fetched(&later).is_empty(),
        "the excluded directories are never asked"
    );
}

/// A check that counts no directory (no directory the round reached holds
/// the descriptor Tor asks for) is decided by the probe alone, and says so
/// once. Fails if `Unmatched` is a miss (a node whose uploads land under the
/// wrong key would republish in a loop), or if it is not said.
#[test]
fn a_check_that_counts_no_directory_is_decided_by_the_probe() {
    let (mut core, _) = checking(sent(1..=4, "next", 0));
    core.on(
        Input::DirectoryAsked {
            descriptor_id: "cur".to_owned(),
        },
        secs(16),
    );
    let step = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        count(&step, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        1
    );
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
}

/// Each fetch takes its own delay from the probe's range, so the fetches do
/// not all land straight after an upload. Fails if one draw times them all.
#[test]
fn each_directory_fetch_has_its_own_delay() {
    let mut core = published();
    core.on(uploaded(0), 0);
    let mut fetches = sent(1..=1, "cur", 0);
    fetches.extend(sent(2..=2, "cur", u64::MAX));
    core.on(Input::DirectoriesDrawn { fetches }, 0);
    let at_floor = core.on_deadline(secs(15));
    assert_eq!(fetched(&at_floor), [hsdir(1)]);
    let at_top = core.on_deadline(secs(60));
    assert_eq!(fetched(&at_top), [hsdir(2)]);
}
