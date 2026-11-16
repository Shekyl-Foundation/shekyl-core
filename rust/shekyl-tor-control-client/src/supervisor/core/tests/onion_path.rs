// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor Manager's onion-path reading (`TOR_SUPERVISOR.md` §4.5a; Rick,
//! 2026-11-15): wants, facts, the on-demand check and its spacing, on the
//! core's own pathways. The check's verdicts as facts are the directory
//! check's tests (`directories.rs`). Each test names the edit that makes it
//! fail.

use super::super::super::posture::Cause;
use super::super::{duration_ns, Action, Input, OnionPath, PathReading, Step};
use super::super::{CHECK_LONGEST, CHECK_SPACING};
use super::probe::{count, published, run_to, secs};

fn checks(step: &Step) -> usize {
    count(step, |action| matches!(action, Action::CheckDirectories))
}

fn readings(step: &Step) -> Vec<PathReading> {
    step.actions
        .iter()
        .filter_map(|action| match action {
            Action::PathReading(reading) => Some(*reading),
            _ => None,
        })
        .collect()
}

fn want(after: u64) -> Input {
    Input::PathWanted { after, draw: 0 }
}

fn working(at: u64) -> PathReading {
    PathReading {
        path: OnionPath::Working,
        at,
    }
}

/// **A want with no reading after it starts a check** at once when none
/// began before. The edit that makes this red is waiting for a round.
#[test]
fn a_want_with_no_reading_starts_a_check() {
    let mut core = published();
    let step = core.on(want(secs(1)), secs(2));
    assert_eq!(checks(&step), 1, "the check began on the want");
}

/// **A completed onion dial and a new inbound Tor session are working
/// facts**, each at its own instant, and a want before such a fact is
/// already answered: no check runs. The edits that make this red: ignoring
/// either fact, dating it at the fold, or checking anyway.
#[test]
fn a_completed_dial_or_a_new_inbound_session_reads_working() {
    let mut core = published();
    let opened = core.on(Input::OnionDialOpened { at: secs(5) }, secs(6));
    assert_eq!(readings(&opened), [working(secs(5))]);
    let answered = core.on(want(secs(3)), secs(7));
    assert_eq!(
        checks(&answered),
        0,
        "the dial after the failure answers it"
    );
    let inbound = core.on(Input::InboundTorSession { at: secs(9) }, secs(9));
    assert_eq!(readings(&inbound), [working(secs(9))]);
    let older = core.on(Input::OnionDialOpened { at: secs(8) }, secs(10));
    assert!(readings(&older).is_empty(), "an older fact changes nothing");
}

/// **While Tor says it cannot reach its network, a want is answered
/// impaired at once and no check runs.** Tor's own statement is an impaired
/// reading the moment it is folded. The edits that make this red: running
/// the check, or waiting for one.
#[test]
fn while_tor_says_it_cannot_reach_its_network_no_check_runs() {
    let mut core = published();
    let blocked = core.on(Input::ExternalBlocked, secs(10));
    assert_eq!(core.status().cause, Cause::ExternalBlocked);
    assert_eq!(
        readings(&blocked),
        [PathReading {
            path: OnionPath::Impaired,
            at: secs(10),
        }],
        "Tor's statement is an impaired reading"
    );
    let asked = core.on(want(secs(11)), secs(12));
    assert_eq!(checks(&asked), 0, "no check while Tor says so");
    assert_eq!(
        readings(&asked),
        [PathReading {
            path: OnionPath::Impaired,
            at: secs(12),
        }],
        "the want is answered at once"
    );
}

/// **Checks never run closer together than the spacing, however many
/// dials fail.** A first want starts a check; while it runs, and after its
/// verdict, a want every 30 s starts nothing until the spacing has passed
/// from the check's start, and then exactly one check starts. The edits
/// that make this red: spacing from the verdict instead of the start, a
/// want starting a check inside the spacing, or no check at the spacing.
#[test]
fn checks_never_run_closer_together_than_the_spacing() {
    let mut core = published();
    let start = secs(1);
    assert_eq!(checks(&core.on(want(start), start)), 1, "the first check");
    let spacing = duration_ns(CHECK_SPACING);
    assert!(
        CHECK_LONGEST < CHECK_SPACING,
        "a check ends inside the spacing"
    );
    let mut at = start;
    let mut started = Vec::new();
    while at < start + spacing + secs(30) {
        at += secs(30);
        let step = run_to(&mut core, at);
        // The driver answers a first miss's refetch, as it does in the
        // daemon, so the check goes on to its second probe.
        if step.actions.contains(&Action::RefetchDescriptor) {
            core.on(Input::DescriptorRefetched { draw: 0 }, at);
        }
        let asked = core.on(want(at - secs(1)), at);
        if checks(&step) + checks(&asked) > 0 && at < start + spacing {
            // The first check's own second probe, after its refetch, is the
            // same check: it begins no new one.
            assert!(
                at <= start + duration_ns(CHECK_LONGEST) + secs(30),
                "a check began inside the spacing at {at}"
            );
        }
        if at >= start + spacing && checks(&step) + checks(&asked) > 0 {
            started.push(at);
        }
    }
    assert_eq!(
        started.len(),
        1,
        "exactly one check once the spacing passed: {started:?}"
    );
    assert!(started[0] >= start + spacing);
}

/// **The Tor connector's declared wait is the spacing plus one check**
/// (Rick, 2026-11-15): 15 minutes, then the two-miss rule's two probes at
/// their longest delay and bound, 240 s, so 19 minutes. A failure just
/// after a check began waits out the spacing, then a check. The edit that
/// makes this red is a wait shorter than a spaced check can answer.
#[test]
fn the_tor_wait_is_the_spacing_plus_one_check() {
    use std::time::Duration;
    assert_eq!(CHECK_SPACING, Duration::from_secs(15 * 60));
    assert_eq!(CHECK_LONGEST, Duration::from_secs(240));
    assert_eq!(super::super::READING_WAIT, CHECK_SPACING + CHECK_LONGEST);
    assert_eq!(super::super::READING_WAIT, Duration::from_secs(19 * 60));
}

/// **A want during a check that ends without a fact is asked again at the
/// spacing** (the Tor lane's review of #1404, F1). A failure arrives while
/// a round's check is in hand; that check is decided by the probe alone,
/// which is no fact; once the spacing from its start has passed, a check
/// runs for the waiting want, not the reading wait's end. The edit that
/// makes this red is leaving a want deferred by a check in hand with
/// nothing due.
#[test]
fn a_want_during_a_check_that_ends_without_a_fact_is_asked_again() {
    use super::probe::{arrival, uploaded};
    let mut core = published();
    let ended = core.on(uploaded(0), secs(100));
    assert_eq!(checks(&ended), 1, "the round's check began at 100 s");
    let asked = core.on(want(secs(101)), secs(102));
    assert_eq!(checks(&asked), 0, "the round's check is in hand");
    run_to(&mut core, secs(115));
    core.on(
        Input::ProbeDialed {
            minted_at: secs(115),
        },
        secs(115),
    );
    let arrived = core.on(arrival(secs(115), secs(118)), secs(118));
    assert!(
        readings(&arrived).is_empty(),
        "the probe alone decided: no fact, so the want still waits"
    );
    let due = secs(100) + duration_ns(CHECK_SPACING);
    let step = run_to(&mut core, due);
    assert_eq!(checks(&step), 1, "asked again once the spacing passed");
}

/// **While the check's gates refuse it, a want is asked again one check's
/// span later** (F2). With the clock named the probe stands down (§4.5), so
/// the manager cannot answer from a check; a completed dial still answers,
/// and once the clock clears a check runs for the waiting want. The edits
/// that make this red: a want left with nothing due, or one retried at an
/// instant already past.
#[test]
fn while_the_check_stands_down_a_want_is_asked_again() {
    const VALID_AFTER: u64 = 1_800_000_000;
    let mut core = published();
    core.on(
        Input::ConsensusClock {
            valid_after: VALID_AFTER,
            wall: VALID_AFTER - 86_400,
        },
        secs(5),
    );
    let asked = core.on(want(secs(6)), secs(7));
    assert_eq!(checks(&asked), 0, "no check while the clock is named");
    assert!(readings(&asked).is_empty(), "and no impaired reading");
    core.on(
        Input::ConsensusClock {
            valid_after: VALID_AFTER,
            wall: VALID_AFTER,
        },
        secs(8),
    );
    let retry = secs(7) + duration_ns(CHECK_LONGEST);
    let step = run_to(&mut core, retry);
    assert_eq!(checks(&step), 1, "a check once the clock has cleared");
}
