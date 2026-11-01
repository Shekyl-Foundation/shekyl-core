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
use super::super::{duration_ns, Action, Core, Input, RoundEnd, Step};
use super::{announces, bring_up, managed, policy, reach_usable, socks, takes_down};

pub(super) fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

pub(super) fn count(step: &Step, wanted: fn(&Action) -> bool) -> usize {
    step.actions.iter().filter(|action| wanted(action)).count()
}

pub(super) fn probes(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::Probe))
}

pub(super) fn cancels(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::CancelProbe))
}

pub(super) fn refetches(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::RefetchDescriptor))
}

/// A round ended with an upload that succeeded: the probe's trigger.
pub(super) fn uploaded(draw: u64) -> Input {
    Input::UploadRoundEnded {
        end: RoundEnd::Uploaded,
        uploads: 16,
        refused: 0,
        draw,
    }
}

/// The probe minted at `minted_at` was taken by the handshake at `arrived_at`.
/// Successes here pass the fold's time as the take, so the evidence time
/// stays that instant.
pub(super) fn arrival(minted_at: u64, arrived_at: u64) -> Input {
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

pub(super) fn republishes(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::RepublishOnion))
}

pub(super) fn publishes_inbound(step: &Step) -> Vec<Inbound> {
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
pub(super) fn published() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    reach_usable(&mut core);
    core.on(Input::StateFileAppeared, 0);
    assert_eq!(core.status().inbound, Inbound::Publishing);
    core
}

/// Run deadlines up to `at`, answering each liveness sample, and stop at
/// the first step that starts or drops a probe. Returns that step, or the
/// last one taken.
pub(super) fn run_to(core: &mut Core, at: u64) -> Step {
    run_timed(core, at).1
}

/// The driver folds the directory list in the same turn the check is
/// asked. A list still outstanding is one this test did not name: the
/// round reached no directory, and the probe alone decides. Folding once
/// the probe is already being judged would hide that verdict inside the
/// wait, so it is refused.
fn fold_unnamed_directories(core: &mut Core, at: u64) {
    let drawn = core.on(
        Input::DirectoriesDrawn {
            fetches: Vec::new(),
            ours: None,
        },
        at,
    );
    assert!(
        drawn.actions.is_empty(),
        "the list was folded after the probe was already being judged: {drawn:?}"
    );
}

/// [`run_to`], with the time of the step it returns.
pub(super) fn run_timed(core: &mut Core, at: u64) -> (u64, Step) {
    // A check asked before this wait, by a round ending.
    fold_unnamed_directories(core, at);
    let mut last = Step {
        actions: Vec::new(),
        deadline: None,
    };
    let mut when = 0;
    while let Some(due) = core.deadline().filter(|due| *due <= at) {
        when = due;
        let step = core.on_deadline(due);
        let sampled = step.actions.contains(&Action::Sample);
        // A check asked by this deadline, the round's wait among them.
        // Fold it before the next deadline, as the driver does.
        if step.actions.contains(&Action::CheckDirectories) {
            fold_unnamed_directories(core, due);
        }
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

/// **Test 2, the round.** A round in which no upload succeeded is not
/// Service evidence, and republishes nothing: Tor retries its own failed
/// uploads, and a refused round is the clock's, which a republish cannot get
/// past (Rick, 2026-11-01, reversing increment 4's rule). The probe in
/// flight stays. Fails if `round_ended` maps `NotUploaded` to `inbound_down`
/// again.
#[test]
fn a_round_with_every_upload_failed_republishes_nothing() {
    let mut core = published();
    core.on(uploaded(0), 0);
    run_to(&mut core, secs(15));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let failed = core.on(
        Input::UploadRoundEnded {
            end: RoundEnd::NotUploaded,
            uploads: 16,
            refused: 0,
            draw: 0,
        },
        secs(16),
    );
    assert_eq!(cancels(&failed), 0, "the probe in flight stays");
    assert_eq!(republishes(&failed), 0, "no republish");
    assert_eq!(core.status().inbound, Inbound::Publishing);
    let landed = core.on(arrival(secs(15), secs(17)), secs(17));
    assert_eq!(
        publishes_inbound(&landed),
        [Inbound::Reachable {
            evidence_at: secs(17)
        }],
        "the probe still judges"
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
            uploads: 16,
            refused: 0,
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
            uploads: 16,
            refused: 0,
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
            uploads: 16,
            refused: 0,
            draw: 0,
        },
        secs(401),
    );
    core.on(Input::UploadRoundStarted, secs(402));
    assert_eq!(core.status().stuck_upload_rounds, 1);
}
