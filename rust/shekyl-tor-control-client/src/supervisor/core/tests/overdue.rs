// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The overdue upload and the clock jump (`TOR_SUPERVISOR.md` §4.5, "Overdue").
//!
//! No round within the descriptor's lifetime of the last round's first
//! upload publishes the onion again. `CLOCK_JUMPED` while Running, with no
//! probe in hand, asks one probe. Neither moves the inbound facet on its own.

use std::time::Duration;

use super::super::super::posture::Inbound;
use super::super::{Action, Core, Input, Policy, RoundEnd, Step, DESCRIPTOR_LIFETIME};
use super::probe::{arrival, count, probes, published, republishes, run_timed, secs, uploaded};
use super::{managed, policy, takes_down};

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
/// the times at which the overdue check fired. A deadline that does not
/// move after it is served fails here, rather than looping.
fn overdue_to(core: &mut Core, at: u64) -> Vec<u64> {
    served_to(core, at).0
}

/// [`overdue_to`], with the times a republish went out beside.
fn served_to(core: &mut Core, at: u64) -> (Vec<u64>, Vec<u64>) {
    let mut asked = Vec::new();
    let mut republished = Vec::new();
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
            asked.push(due);
        }
        if republishes(&step) > 0 {
            republished.push(due);
        }
    }
    (asked, republished)
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
/// reach it; the next lifetime counts from the republish. A republish that
/// brought no round in a whole lifetime failed its judgment: the next
/// waits out the backoff's base (Rick, 2026-11-01). Fails if the check
/// probes instead (`on_overdue_deadline` emitting no republish), if it does
/// not re-anchor (the deadline does not move), or if a roundless republish
/// is never judged (`republish_failed` dropped from the overdue check: the
/// second is owed forever).
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
    let again = due + lifetime();
    let base = secs(300);
    assert_eq!(
        served_to(&mut core, again + base),
        (vec![again], vec![again + base]),
        "the second overdue waits the base, then republishes"
    );
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
            end: RoundEnd::NotUploaded,
            uploads: 16,
            refused: 0,
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
