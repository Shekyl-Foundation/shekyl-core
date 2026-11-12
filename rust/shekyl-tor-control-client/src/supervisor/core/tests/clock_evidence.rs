// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clock named from relays' certificates (§4.2; Rick, 2026-10-30): at
//! least three certificate lines and three distinct relays' closed
//! handshakes within the window, during a bootstrap.

use std::time::Duration;

use super::super::super::posture::{render, Cause, ReportedSkew, Shown};
use super::super::{duration_ns, Action, Core, Input};
use super::{managed, policy};
use crate::control::RelayFingerprint;

fn secs(seconds: u64) -> u64 {
    duration_ns(Duration::from_secs(seconds))
}

fn relay(n: u8) -> RelayFingerprint {
    RelayFingerprint::from_bytes([n; 20])
}

fn bootstrapping() -> Core {
    let (mut core, _) = Core::start(policy(), managed(true), 0);
    core.on(Input::accepted(), 0);
    core.on(Input::Spawned, 0);
    core
}

fn closed(core: &mut Core, n: u8, at: u64) {
    core.on(Input::HandshakeClosed { relay: relay(n) }, at);
}

/// The clock-ahead run's shape: certificate lines, then handshakes closed
/// with three distinct relays, then the tenth problem's blocked link. The
/// clock is named at the third relay, and the blocked link that follows
/// does not overwrite it while the evidence stands. Mapping the problem's
/// `warn` over the clock, as `REASON=CLOCK_SKEW` once did, fails this.
#[test]
fn three_lines_and_three_relays_name_the_clock_and_hold_it() {
    let mut core = bootstrapping();
    for _ in 0..3 {
        core.on(Input::CertificateOutOfDate, secs(1));
    }
    closed(&mut core, 1, secs(2));
    closed(&mut core, 2, secs(3));
    assert_eq!(core.status().cause, Cause::None, "two relays");
    closed(&mut core, 3, secs(4));
    assert_eq!(core.status().cause, Cause::CertificatesOutOfDate);
    core.on(Input::ExternalBlocked, secs(10));
    let status = core.status();
    assert_eq!(
        status.cause,
        Cause::CertificatesOutOfDate,
        "not overwritten"
    );
    assert_eq!(status.shown, Shown::Degraded);
    assert_eq!(status.respawn_count, 0, "the clock is never a respawn");
    let text = render(&status);
    assert!(text.contains("date or time looks wrong"), "{text}");
}

/// One hostile relay presenting an expired certificate is one relay,
/// however often it repeats; two lines are not three. Either leaves the
/// blocked link's wording, which names the clock first. Counting lines
/// alone, or relays alone, fails this.
#[test]
fn one_relay_or_two_lines_leave_the_blocked_wording() {
    let mut core = bootstrapping();
    for i in 0..10 {
        core.on(Input::CertificateOutOfDate, secs(1 + i));
        closed(&mut core, 7, secs(1 + i));
    }
    core.on(Input::ExternalBlocked, secs(12));
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "one relay");

    let mut core = bootstrapping();
    core.on(Input::CertificateOutOfDate, secs(1));
    core.on(Input::CertificateOutOfDate, secs(1));
    for n in 1..=5 {
        closed(&mut core, n, secs(2));
    }
    core.on(Input::ExternalBlocked, secs(3));
    let status = core.status();
    assert_eq!(status.cause, Cause::ExternalBlocked, "two lines");
    assert!(render(&status).contains("Check this computer's date and time, then"));
}

/// The evidence must stand inside one window: lines from one stretch do not
/// pair with relays from another, and evidence that ages out lets the
/// blocked link speak again. Holding evidence for the whole bootstrap fails
/// this.
#[test]
fn evidence_pairs_only_inside_the_window() {
    let window = policy().clock_evidence_within;
    let mut core = bootstrapping();
    for _ in 0..3 {
        core.on(Input::CertificateOutOfDate, secs(1));
    }
    let late = secs(2) + duration_ns(window);
    for n in 1..=3 {
        closed(&mut core, n, late);
    }
    assert_eq!(core.status().cause, Cause::None, "the lines aged out");

    let mut core = bootstrapping();
    for _ in 0..3 {
        core.on(Input::CertificateOutOfDate, secs(1));
    }
    for n in 1..=3 {
        closed(&mut core, n, secs(2));
    }
    assert_eq!(core.status().cause, Cause::CertificatesOutOfDate);
    core.on(Input::ExternalBlocked, late);
    assert_eq!(core.status().cause, Cause::ExternalBlocked, "aged out");
}

/// Tor's own `CLOCK_SKEW` carries the offset; the certificates' evidence
/// does not replace it.
#[test]
fn a_measured_skew_is_not_replaced() {
    let mut core = bootstrapping();
    core.on(
        Input::ClockSkew {
            skew: ReportedSkew::Measured(259_200),
        },
        secs(1),
    );
    for _ in 0..3 {
        core.on(Input::CertificateOutOfDate, secs(1));
    }
    for n in 1..=3 {
        closed(&mut core, n, secs(2));
    }
    core.on(Input::ExternalBlocked, secs(3));
    assert_eq!(
        core.status().cause,
        Cause::ClockSkew {
            skew: ReportedSkew::Measured(259_200),
        }
    );
}

/// An unreachable directory is the same problem as a blocked link. Inside
/// the window it leaves the verdict standing and says nothing. Fails if
/// that input takes its own path around the window.
#[test]
fn an_unreachable_directory_leaves_the_verdict() {
    let mut core = bootstrapping();
    for _ in 0..3 {
        core.on(Input::CertificateOutOfDate, secs(1));
    }
    for n in 1..=3 {
        closed(&mut core, n, secs(2));
    }
    let step = core.on(Input::DirectoryUnreachable, secs(10));
    assert!(
        !step.actions.contains(&Action::Announce),
        "said: {}",
        render(&core.status())
    );
    assert_eq!(core.status().cause, Cause::CertificatesOutOfDate);
}

/// The consensus check already named the clock. Completing the count does
/// not set the verdict and does not say the line again. Fails if the count
/// calls `external` over a clock the check has spoken.
#[test]
fn the_count_does_not_say_a_clock_the_check_named() {
    let mut core = bootstrapping();
    let named = core.on(
        Input::ConsensusClock {
            valid_after: 1_000_000,
            wall: 1_000_000 - 86_400,
        },
        secs(1),
    );
    assert!(
        named.actions.contains(&Action::Announce),
        "the check names it"
    );
    let mut said = Vec::new();
    for i in 0..3 {
        let step = core.on(Input::CertificateOutOfDate, secs(2 + i));
        if step.actions.contains(&Action::Announce) {
            said.push(render(&core.status()));
        }
    }
    for n in 1..=3 {
        let step = closed_step(&mut core, n, secs(6));
        if step.actions.contains(&Action::Announce) {
            said.push(render(&core.status()));
        }
    }
    assert!(said.is_empty(), "said again: {said:#?}");
    assert_eq!(
        core.status().cause,
        Cause::None,
        "the check stays the cause"
    );
}

fn closed_step(core: &mut Core, n: u8, at: u64) -> super::super::Step {
    core.on(Input::HandshakeClosed { relay: relay(n) }, at)
}
