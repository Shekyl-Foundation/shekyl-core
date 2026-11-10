// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clock is said once (`TOR_SUPERVISOR.md` §4.4, §5; Rick, 2026-11-10).
//!
//! The Windows and macOS runs of 2026-11-08 and 2026-11-09 said the clock
//! line 11 times in 3.5 min and 18 times in 4 min with the clock three days
//! behind. Two things made each say new. The consensus check rewrote the lag
//! it carries at every liveness sample, and the key compared that value, so
//! the first Tor report after a sample was a change. And a bootstrap problem
//! with another reason named the blocked link over Tor's skew, and the next
//! skew report named the clock again.
//!
//! Each test drives the core as the driver does: Tor's statements at their
//! times, every deadline served, each liveness sample answered with the
//! bootstrap's progress and the consensus clock read at it. Every line the
//! core asks to say (an announcement or a progress line) is rendered, and
//! the lines that name the clock are counted.

use super::super::super::posture::{render, ReportedSkew};
use super::super::{Action, Core, Input};
use super::{managed, policy};

const SECOND: u64 = 1_000_000_000;
const DAY: u64 = 86_400;

/// This machine's wall clock at the test's 0, three days behind.
const WALL_AT_START: u64 = 1_793_491_200;

/// The consensus Tor fetched at 2 s: published 14 min before the true time.
const VALID_AFTER: u64 = WALL_AT_START + 3 * DAY - 14 * 60;

/// The cached consensus Tor started with, an hour older.
const VALID_AFTER_CACHED: u64 = VALID_AFTER - 3_600;

fn ms(milliseconds: u64) -> u64 {
    milliseconds * 1_000_000
}

/// One of Tor's statements, at a time in the run.
#[derive(Clone, Copy)]
enum Tor {
    Skew(i64),
    Blocked,
    Cleared,
    Jumped,
}

impl Tor {
    fn input(self) -> Input {
        match self {
            Self::Skew(seconds) => Input::ClockSkew {
                skew: ReportedSkew::Measured(seconds),
            },
            Self::Blocked => Input::ExternalBlocked,
            Self::Cleared => Input::ExternalCleared,
            Self::Jumped => Input::ClockJumped,
        }
    }
}

/// A Bootstrapping core: the pin passed, Tor spawned at 0.
fn bootstrapping() -> Core {
    let (mut core, _) = Core::start(policy(), managed(false), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core
}

/// What a run said: every rendered line, in order, and the announcements
/// among them (the rest are progress lines).
struct Said {
    lines: Vec<String>,
    announced: Vec<String>,
}

impl Said {
    fn naming_the_clock(&self) -> Vec<&String> {
        self.lines
            .iter()
            .filter(|line| line.contains("clock") || line.contains("date or time"))
            .collect()
    }
}

/// Drive `core` to `until`: each of `events` at its time, every deadline up
/// to it served, each sample answered with `progress` and the consensus
/// clock `wall_at` reads then (the time is the test's, in
/// nanoseconds; the wall clock and `valid-after` are seconds).
fn run(
    core: &mut Core,
    from: u64,
    until: u64,
    events: &[(u64, Tor)],
    progress: u8,
    wall_at: impl Fn(u64) -> (u64, u64),
) -> Said {
    let mut lines = Vec::new();
    let mut announced = Vec::new();
    let mut said = |core: &Core, actions: &[Action]| {
        for action in actions {
            if matches!(action, Action::Announce | Action::SayProgress) {
                let line = render(&core.status());
                if matches!(action, Action::Announce) {
                    announced.push(line.clone());
                }
                lines.push(line);
            }
        }
    };
    let mut next_event = 0;
    let mut now = from;
    loop {
        let event_at = events.get(next_event).map(|(at, _)| *at);
        let deadline = core.deadline().filter(|due| *due <= until);
        let at = match (event_at, deadline) {
            (Some(event), Some(due)) => event.min(due),
            (Some(event), None) => event,
            (None, Some(due)) => due,
            (None, None) => break,
        };
        if at > until {
            break;
        }
        assert!(at >= now, "time went back from {now} to {at}");
        now = at;
        if event_at == Some(at) {
            let step = core.on(events[next_event].1.input(), at);
            said(core, &step.actions);
            next_event += 1;
            continue;
        }
        let step = core.on_deadline(at);
        said(core, &step.actions);
        if step.actions.contains(&Action::Sample) {
            let folded = core.on(
                Input::DirectorySample {
                    progress: Some(progress),
                    socks: None,
                    read: None,
                },
                at,
            );
            said(core, &folded.actions);
            let (valid_after, wall) = wall_at(at);
            let read = core.on(Input::ConsensusClock { valid_after, wall }, at);
            said(core, &read.actions);
        }
    }
    Said { lines, announced }
}

/// The wall clock `at` the test's time, three days behind, and the consensus
/// Tor holds then: the cached one until the fetch at 2 s.
fn three_days_behind(at: u64) -> (u64, u64) {
    let valid_after = if at < 2 * SECOND {
        VALID_AFTER_CACHED
    } else {
        VALID_AFTER
    };
    (valid_after, WALL_AT_START + at / SECOND)
}

/// **Three days behind for four minutes says it once.** Tor reports the
/// skew every 6 s, from a relay's handshake and from a directory a moment
/// later, a second apart; the consensus check reads the lag at every
/// sample, and the lag falls by a second each time. Fails if the say key
/// compares the lag (a line after every sample), or if Tor's report and the
/// consensus check are two kinds (a second line when Tor's report joins).
#[test]
fn three_days_behind_for_four_minutes_says_it_once() {
    let mut core = bootstrapping();
    let mut events = Vec::new();
    let mut at = ms(2_000);
    while at < 240 * SECOND {
        events.push((at, Tor::Skew(-259_201)));
        events.push((at + ms(300), Tor::Skew(-259_202)));
        at += 6 * SECOND;
    }
    let said = run(&mut core, 0, 240 * SECOND, &events, 30, three_days_behind);
    let clock = said.naming_the_clock();
    assert_eq!(clock.len(), 1, "said: {:#?}", said.lines);
}

/// **The run's alternation, replayed, says it once.** The macOS run of
/// 2026-11-09 (`s4-skew-3`), from its log: the cached consensus names the
/// clock at the start, Tor's skew reports arrive in relay-then-directory
/// pairs, and four bootstrap problems with `NOROUTE` and `TIMEOUT` (Tor's
/// `warn`, so the blocked link) fall between them. Fails if a bootstrap
/// problem names the blocked link over a standing clock (the alternation),
/// or for either reason above.
#[test]
fn the_runs_alternation_replayed_says_it_once() {
    let mut core = bootstrapping();
    let events = vec![
        (ms(1_243), Tor::Cleared),
        (ms(2_045), Tor::Skew(-258_357)),
        (ms(7_637), Tor::Skew(-259_201)),
        (ms(7_999), Tor::Skew(-259_202)),
        (ms(13_542), Tor::Skew(-259_201)),
        (ms(13_781), Tor::Skew(-259_202)),
        (ms(27_665), Tor::Skew(-259_201)),
        (ms(28_002), Tor::Skew(-259_202)),
        (ms(45_645), Tor::Skew(-259_201)),
        (ms(45_861), Tor::Skew(-259_202)),
        (ms(67_799), Tor::Skew(-259_201)),
        (ms(68_060), Tor::Skew(-259_203)),
        (ms(74_604), Tor::Blocked),
        (ms(74_696), Tor::Skew(-259_201)),
        (ms(74_776), Tor::Skew(-259_201)),
        (ms(79_056), Tor::Blocked),
        (ms(87_699), Tor::Skew(-259_201)),
        (ms(88_000), Tor::Skew(-259_202)),
        (ms(99_439), Tor::Skew(-259_201)),
        (ms(99_521), Tor::Skew(-259_201)),
        (ms(108_383), Tor::Skew(-259_201)),
        (ms(132_581), Tor::Skew(-259_201)),
        (ms(152_319), Tor::Blocked),
        (ms(193_330), Tor::Blocked),
        (ms(235_666), Tor::Skew(-259_201)),
        (ms(238_441), Tor::Blocked),
    ];
    let said = run(&mut core, 0, 240 * SECOND, &events, 30, three_days_behind);
    let clock = said.naming_the_clock();
    assert_eq!(clock.len(), 1, "said: {:#?}", said.lines);
    assert!(
        !said
            .lines
            .iter()
            .any(|line| line.contains("cannot reach the Tor network")),
        "a bootstrap problem named the blocked link over the clock: {:#?}",
        said.lines
    );
}

/// **Correcting the clock says the recovery once.** Three days behind for a
/// minute, then the clock is set right: Tor reports the jump, and the next
/// sample reads the wall clock past `valid-after`. One line follows, and it
/// no longer names the clock; nothing names it again before Tor is up.
/// Fails if Tor's skew outlives the correction (a line that still says
/// "behind"), or if the two clearings are said apart.
#[test]
fn correcting_the_clock_says_the_recovery_once() {
    let mut core = bootstrapping();
    let named = run(
        &mut core,
        0,
        60 * SECOND,
        &[
            (ms(2_045), Tor::Skew(-258_357)),
            (ms(7_637), Tor::Skew(-259_201)),
        ],
        30,
        three_days_behind,
    );
    assert_eq!(
        named.naming_the_clock().len(),
        1,
        "said: {:#?}",
        named.lines
    );
    let corrected_at = 60 * SECOND + ms(500);
    let right = |at: u64| (VALID_AFTER, VALID_AFTER + 14 * 60 + at / SECOND - 60);
    let after = run(
        &mut core,
        corrected_at,
        120 * SECOND,
        &[(corrected_at, Tor::Jumped)],
        30,
        right,
    );
    assert_eq!(
        after.announced.len(),
        1,
        "the recovery, once: {:#?}",
        after.lines
    );
    assert!(
        after.naming_the_clock().is_empty(),
        "the clock is right: {:#?}",
        after.lines
    );
}

/// A status degraded by the clock: `cause`, and the consensus check's lower
/// bound when `ours` gives one.
fn clock_status(
    cause: super::super::super::posture::Cause,
    ours: Option<u64>,
) -> super::super::super::posture::Status {
    use super::super::super::posture::{Inbound, InboundCause, Shown, Status};
    let behind = ours.map(std::time::Duration::from_secs);
    Status {
        cause,
        shown: Shown::Degraded,
        inbound: match behind {
            Some(behind) => Inbound::Unreachable {
                cause: InboundCause::ClockBehind { behind },
                since: 0,
            },
            None => Inbound::NotOffered,
        },
        clock_behind: behind,
        ..super::held_status()
    }
}

/// **One clock sentence** (Rick, 2026-11-10). With Tor's report and the
/// consensus check both standing, the line carries Tor's figure once, in
/// days and hours, ends with the check, and has neither the raw signed
/// seconds nor "Check time sync". Fails on the sentence of 2026-11-09 ("The
/// clock is off by -259201 seconds. Check time sync." beside "at least
/// 2 d 23 h behind").
#[test]
fn tors_figure_and_the_lower_bound_are_one_sentence() {
    use super::super::super::posture::Cause;
    let text = render(&clock_status(
        Cause::ClockSkew {
            skew: ReportedSkew::Measured(-259_201),
        },
        Some(258_357),
    ));
    assert!(
        text.contains(
            "This computer's clock is 3 d 0 h behind the Tor network's. Others may not be able to reach this node. Check this computer's date and time."
        ),
        "{text}"
    );
    assert_eq!(text.matches("clock").count(), 1, "{text}");
    assert_eq!(text.matches("date and time").count(), 1, "{text}");
    for gone in ["259201", "259_201", "seconds", "time sync"] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
}

/// **Ahead, and Tor's lower bound.** A clock ahead is said "ahead of", and
/// only Tor can see it: no reachability clause without the consensus check.
/// `MIN_SKEW` is said "at least". Fails if the sign is dropped, or if a
/// lower bound is said as a measure.
#[test]
fn ahead_and_at_least_are_said_as_tor_gave_them() {
    use super::super::super::posture::Cause;
    let ahead = render(&clock_status(
        Cause::ClockSkew {
            skew: ReportedSkew::Measured(2 * 86_400 + 5 * 3_600),
        },
        None,
    ));
    assert!(
        ahead.contains(
            "This computer's clock is 2 d 5 h ahead of the Tor network's. Check this computer's date and time."
        ),
        "{ahead}"
    );
    let bound = render(&clock_status(
        Cause::ClockSkew {
            skew: ReportedSkew::AtLeast(-7_200),
        },
        None,
    ));
    assert!(
        bound.contains("This computer's clock is at least 2 h 0 min behind the Tor network's."),
        "{bound}"
    );
}

/// **Our lower bound, when Tor gave no figure.** The consensus check alone,
/// or beside the certificates' verdict (which carries none): one sentence,
/// "at least". Fails if the certificates' sentence and the bound's both
/// stand.
#[test]
fn the_lower_bound_stands_in_for_a_figure_tor_did_not_give() {
    use super::super::super::posture::Cause;
    for cause in [Cause::None, Cause::CertificatesOutOfDate] {
        let text = render(&clock_status(cause.clone(), Some(3 * 86_400 - 3_600)));
        assert!(
            text.contains(
                "This computer's clock is at least 2 d 23 h behind the Tor network's. Others may not be able to reach this node. Check this computer's date and time."
            ),
            "{cause:?}: {text}"
        );
        assert_eq!(
            text.matches("date and time").count(),
            1,
            "{cause:?}: {text}"
        );
    }
    let line = render(&clock_status(Cause::CertificatesOutOfDate, None));
    assert!(
        line.contains("Tor reports that this computer's date or time looks wrong"),
        "{line}"
    );
}

/// **A lag the sample rewrites is not a change** (§4.4: detail within a
/// kind is a repeat). Running with the clock a day behind and the blocked
/// link named, each sample reads the lag a second smaller, and Tor repeats
/// the blocked link every second inside the cap. Nothing is said again
/// until the cap. Fails if the say key compares the inbound cause's value:
/// the key of 2026-11-09, which made the first statement after every
/// sample new.
#[test]
fn a_lag_the_sample_rewrites_is_not_a_change() {
    use super::probe::{published, secs};
    let mut core = published();
    let valid_after = WALL_AT_START + DAY;
    let clock = |wall| Input::ConsensusClock { valid_after, wall };
    let named = core.on(clock(WALL_AT_START), secs(5));
    assert!(
        named.actions.contains(&Action::Announce),
        "the clock, named"
    );
    let blocked = core.on(Input::ExternalBlocked, secs(6));
    assert!(
        blocked.actions.contains(&Action::Announce),
        "the block, named"
    );
    let mut said = Vec::new();
    for second in 7..13 {
        for input in [clock(WALL_AT_START + second), Input::ExternalBlocked] {
            let step = core.on(input, secs(second));
            if step.actions.contains(&Action::Announce) {
                said.push((second, render(&core.status())));
            }
        }
    }
    assert!(said.is_empty(), "said inside the cap: {said:#?}");
}

/// **The consensus check alone is said once too.** Tor reports nothing (its
/// own check fires only at a fetch), so no cause is set and the bootstrap's
/// progress line runs; it carries the posture, and the clock with it.
/// Fails if the progress line is said while the clock is named.
#[test]
fn the_consensus_check_alone_is_said_once() {
    let mut core = bootstrapping();
    let said = run(&mut core, 0, 240 * SECOND, &[], 30, three_days_behind);
    assert_eq!(said.naming_the_clock().len(), 1, "said: {:#?}", said.lines);
}

/// **No directory answering is the clock's too, while Tor bootstraps.**
/// With Tor's skew named, `DIR_ALL_UNREACHABLE` leaves the clock standing
/// and says nothing; past the bootstrap it is named. Fails if the
/// directories' statement takes over a named clock.
#[test]
fn unreachable_directories_leave_a_named_clock() {
    use super::super::super::posture::Cause;
    let mut core = bootstrapping();
    core.on(Tor::Skew(-259_201).input(), SECOND);
    let step = core.on(Input::DirectoryUnreachable, 2 * SECOND);
    assert!(
        !step.actions.contains(&Action::Announce),
        "said: {}",
        render(&core.status())
    );
    assert!(matches!(core.status().cause, Cause::ClockSkew { .. }));
}

/// **A kept figure is the same kind.** The consensus check names the clock,
/// then Tor's report replaces the cause. The key is recorded, so a say
/// inside the cap does not treat that as a change. Fails if the report
/// returns without recording the key.
#[test]
fn a_kept_figure_is_the_same_kind() {
    use super::super::announce::Cadence;
    let mut core = bootstrapping();
    core.on(
        Input::ConsensusClock {
            valid_after: VALID_AFTER,
            wall: WALL_AT_START,
        },
        SECOND,
    );
    let kept = core.on(
        Input::ClockSkew {
            skew: ReportedSkew::Measured(-259_201),
        },
        2 * SECOND,
    );
    assert!(
        !kept.actions.contains(&Action::Announce),
        "the figure was said again"
    );
    let again = core.say(3 * SECOND, Cadence::Due);
    assert!(again.is_empty(), "a kept figure was a new kind: {again:?}");
}

/// **A fixed consensus aging into the tolerance does not retire Tor's
/// report.** The gap starts at 900 s and the wall advances with the
/// supervisor clock, one second per second, until the gap is inside 360 s.
/// The report stays, nothing is said, and Tor repeating it says nothing.
/// Fails if aging is read as the clock being set right.
#[test]
fn an_aging_consensus_does_not_retire_tors_report() {
    use super::super::super::posture::Cause;
    use super::super::CLOCK_BEHIND_AFTER;
    let mut core = bootstrapping();
    let tolerance = CLOCK_BEHIND_AFTER.as_secs();
    // Twice the tolerance: one second of wall per second of supervisor time
    // walks the gap from named, through the window.
    let start_gap = tolerance.saturating_mul(2);
    let valid_after = start_gap.saturating_mul(2);
    let start_gap_i = i64::try_from(start_gap).expect("the gap fits in i64");
    let report = ReportedSkew::Measured(-start_gap_i);
    let skew = core.on(Input::ClockSkew { skew: report }, SECOND);
    assert!(skew.actions.contains(&Action::Announce), "the report");
    let mut said = Vec::new();
    let last = start_gap - tolerance;
    for step in 0..=last {
        let at = (2 + step) * SECOND;
        let wall = valid_after - start_gap + step;
        let sample = core.on(Input::ConsensusClock { valid_after, wall }, at);
        if sample.actions.contains(&Action::Announce) {
            said.push((step, render(&core.status())));
        }
    }
    assert!(said.is_empty(), "aging said the clock: {said:#?}");
    assert!(
        matches!(core.status().cause, Cause::ClockSkew { skew } if skew == report),
        "the report was retired: {:?}",
        core.status().cause
    );
    assert_eq!(core.status().clock_behind, None, "the bound did age out");
    let repeated = core.on(Input::ClockSkew { skew: report }, (3 + last) * SECOND);
    assert!(
        !repeated.actions.contains(&Action::Announce),
        "the same report was a new line"
    );
}
