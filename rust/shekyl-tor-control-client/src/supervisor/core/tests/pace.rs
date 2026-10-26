// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bootstrap's pace (Rick, 2026-10-24): a typed word beside the cause,
//! never instead of it, kept current at every sample.

use std::time::Duration;

use super::super::super::posture::{render, BootstrapLine, BootstrapPace, Cause};
use super::super::{duration_ns, Core, Input};
use super::{managed, policy, socks};

fn secs(n: u64) -> u64 {
    duration_ns(Duration::from_secs(n))
}

fn sample(progress: u8, read: Option<u64>) -> Input {
    Input::DirectorySample {
        progress: Some(progress),
        socks: None,
        read,
    }
}

/// A core bootstrapping since 0, with a first count at 0.
fn bootstrapping() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(sample(10, Some(0)), 0);
    core
}

/// After the first progress deadline the line is current at every sample:
/// a client polling Status sees the bytes move within one sample, not one
/// `alive_every` later. Refreshing only at the deadline fails this.
#[test]
fn the_line_is_current_at_every_sample_once_it_has_begun() {
    let mut core = bootstrapping();
    assert_eq!(
        core.status().bootstrap,
        None,
        "not before the first deadline"
    );
    assert_eq!(core.status().pace, None);
    core.on(sample(10, Some(1_000)), secs(2));
    core.on_deadline(secs(4));
    let first = core.status().bootstrap.expect("begun at the deadline");
    assert_eq!(first.received, Some(1_000));
    core.on(sample(10, Some(9_000)), secs(5));
    let line = core.status().bootstrap.expect("a line");
    assert_eq!(
        line.received,
        Some(9_000),
        "the sample at 5 s is read at once"
    );
    assert_eq!(line.window, Duration::from_secs(5));
    core.on(sample(10, Some(9_500)), secs(9));
    let line = core.status().bootstrap.expect("a line");
    assert_eq!(line.received, Some(500), "the window slid: it opens at 5 s");
    assert_eq!(line.window, Duration::from_secs(4));
}

/// The three words. Advancing: the percent moved within the window. Slow
/// but normal: it held through the window and bytes arrived. Stalled: a
/// full window of samples with nothing. A window too short to say, or no
/// count, is no word: unknown is never stalled.
#[test]
fn the_pace_reads_advancing_slow_and_stalled() {
    let mut core = bootstrapping();
    core.on(sample(20, Some(100)), secs(3));
    core.on_deadline(secs(4));
    let advancing = core.status();
    assert_eq!(advancing.pace, Some(BootstrapPace::Advancing));
    assert_eq!(
        advancing.pace,
        advancing.bootstrap.and_then(BootstrapLine::pace)
    );
    let text = render(&advancing);
    assert!(
        text.contains(
            "Tor is fetching the network directory (20%). 100 bytes arrived in the last 4 s."
        ),
        "{text}"
    );
    assert!(!text.contains("unchanged"), "{text}");

    core.on(sample(20, Some(5_000)), secs(8));
    assert_eq!(core.status().pace, Some(BootstrapPace::SlowButNormal));
    let text = render(&core.status());
    assert!(text.contains("unchanged for 5 s"), "{text}");
    assert!(
        text.contains(
            "4.9 kB arrived in the last 5 s; a slow directory mirror can hold this for minutes."
        ),
        "{text}"
    );

    core.on(sample(20, Some(5_000)), secs(10));
    assert_eq!(
        core.status().pace,
        Some(BootstrapPace::SlowButNormal),
        "the window still holds bytes from 3 s to 8 s"
    );
    core.on(sample(20, Some(5_000)), secs(12));
    assert_eq!(core.status().pace, Some(BootstrapPace::Stalled));
    let text = render(&core.status());
    assert!(text.contains("Nothing arrived in the last 4 s"), "{text}");

    core.on(sample(21, Some(5_000)), secs(13));
    assert_eq!(core.status().pace, Some(BootstrapPace::Advancing));
    let text = render(&core.status());
    assert!(
        text.contains("Tor is fetching the network directory (21%)."),
        "{text}"
    );
    assert!(!text.contains("Nothing arrived"), "{text}");
    assert!(!text.contains("unchanged"), "{text}");
    assert!(
        !text.contains("arrived"),
        "a percent that moved with no new bytes does not claim a transfer: {text}"
    );

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    core.on(sample(30, None), 1);
    core.on_deadline(secs(4));
    core.on(sample(30, None), secs(9));
    assert_eq!(core.status().pace, None, "no count: unknown, never stalled");

    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::PinAccepted, 0);
    core.on(Input::Spawned, 0);
    // The percent stays at the incarnation's 0, so only the window decides.
    core.on(sample(0, Some(0)), secs(2));
    core.on_deadline(secs(4));
    assert_eq!(
        core.status().pace,
        None,
        "two measured seconds of nothing are not a stalled window"
    );
    core.on(sample(0, Some(0)), secs(6));
    assert_eq!(
        core.status().pace,
        Some(BootstrapPace::Stalled),
        "a full window"
    );
}

/// The pace stands beside a cause: a bootstrap that stalls while Tor
/// reports the network blocked shows the cause and its fix, and the stall.
/// A client that read only the pace would hide the fix; one that read only
/// the cause would hide the stall. `render` composes both.
#[test]
fn a_cause_and_the_pace_are_said_together() {
    let mut core = bootstrapping();
    core.on_deadline(secs(4));
    core.on(Input::ExternalBlocked, secs(5));
    core.on(sample(10, Some(0)), secs(9));
    let status = core.status();
    assert_eq!(status.cause, Cause::ExternalBlocked);
    assert_eq!(status.pace, Some(BootstrapPace::Stalled));
    let text = render(&status);
    let cause = text
        .find("cannot reach the Tor network")
        .expect("the cause");
    let fix = text.find("Check the firewall").expect("the fix");
    let stall = text.find("Nothing arrived").expect("the stall");
    assert!(
        cause < fix && fix < stall,
        "the cause, its fix, then the stall: {text}"
    );
}

/// The pace is the bootstrap's: Running clears it, and a count that went
/// backwards (a new Tor's counter) starts the window again instead of
/// reading as a wrap.
#[test]
fn the_pace_ends_with_the_bootstrap_and_a_backward_count_starts_again() {
    let mut core = bootstrapping();
    core.on(sample(10, Some(50_000)), secs(3));
    core.on_deadline(secs(4));
    core.on(
        Input::DirectorySample {
            progress: Some(10),
            socks: Some(socks()),
            read: Some(10),
        },
        secs(6),
    );
    let line = core.status().bootstrap.expect("a line");
    assert_eq!(line.received, Some(0), "one mark after the reset");
    core.on(Input::BootstrapComplete, secs(6));
    assert_eq!(core.status().pace, None);
    assert_eq!(core.status().bootstrap, None);
}
