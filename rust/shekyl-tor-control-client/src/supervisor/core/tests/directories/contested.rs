// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Another publisher (`TOR_SUPERVISOR.md` §4.5, "Another publisher").
//!
//! One directory holding this onion's descriptor at a counter above ours
//! names another holder of the key. The overdue check stays hidden and its
//! anchor stays; the probe and the directory check keep running, so a later
//! check can clear the cause.

use super::super::super::super::posture::{Inbound, InboundCause};
use super::super::super::{Action, Counted, DirectoryAnswer, Exclusion, Input};
use super::super::probe::{arrival, count, probes, refetches, republishes, secs, uploaded};
use super::super::said_of;
use super::{answered, checking, checking_with, drive, fetched, ours, sent, OURS};

/// **A newer copy this node did not publish names another publisher, and
/// nothing is sent** (Rick, 2026-11-21). One directory of eight holds our
/// descriptor at a counter above ours, the other seven ours: another Tor
/// holding this onion's key published it. Inbound goes down as
/// `PublishedElsewhere` at once, the probe in or not: no refetch, no
/// republish, which would only race it. Hours on, the overdue check stays
/// hidden and its anchor stays: the directories have not broken a lifetime
/// this node owns. Fails if a newer copy counts as missing (a refetch, then
/// a republish fight), or as found, or if the overdue check fires and slides
/// its anchor while the other publisher is still named.
#[test]
fn a_newer_copy_names_another_publisher_and_sends_nothing() {
    let copy = |counter| DirectoryAnswer::Received {
        revision_counter: Some(counter),
    };
    for probe_in in [true, false] {
        let (mut core, _) = checking(sent(1..=8, "cur", 0));
        for n in 1..=7 {
            core.on(answered(n, "cur", copy(OURS)), secs(16));
        }
        core.on(answered(8, "cur", copy(OURS + 1)), secs(16));
        let judged = if probe_in {
            core.on(arrival(secs(15), secs(18)), secs(18))
        } else {
            super::super::probe::run_timed(&mut core, secs(15) + secs(60)).1
        };
        assert_eq!(refetches(&judged), 0, "probe in: {probe_in}");
        assert_eq!(republishes(&judged), 0, "probe in: {probe_in}");
        let status = core.status();
        assert!(
            matches!(
                status.inbound,
                Inbound::Unreachable {
                    cause: InboundCause::PublishedElsewhere,
                    ..
                }
            ),
            "probe in: {probe_in}: {:?}",
            status.inbound
        );
        assert!(
            said_of(&status).contains("Another computer is using this node's Tor address"),
            "{}",
            said_of(&status)
        );
        // Hours on, every deadline served, still nothing sent: no overdue
        // republish, and the check itself stays hidden. The anchor the first
        // upload set is the one a later recovery still counts from.
        // `checking` feeds the round's end, not its first upload, which is
        // what sets the overdue anchor. Without one the check could never
        // come due, and the assertions below would hold whatever the hold
        // does (rule 47). This is the anchor that first upload would set;
        // within the four hours the check comes due and only the hold
        // keeps it hidden.
        core.lifetime_from = Some(secs(15));
        let anchor = core.lifetime_from;
        assert!(core.overdue_due().is_none() && anchor.is_some());
        let later = drive(&mut core, secs(4 * 3_600), &mut None, &ours());
        assert_eq!(republishes(&later), 0, "probe in: {probe_in}");
        assert_eq!(
            count(&later, |action| matches!(action, Action::DescriptorOverdue)),
            0,
            "probe in: {probe_in}"
        );
        assert_eq!(
            core.lifetime_from, anchor,
            "another publisher leaves the overdue anchor"
        );
        assert_eq!(core.overdue_due(), None, "the overdue check stays hidden");
    }
}

/// **A newer copy after this node's own new round names no one** (§4.5,
/// "Another publisher"). Our counter is read for the check; a round of the same
/// descriptor that begins after the check was asked may upload a newer
/// revision of this node's own, and a directory may answer with it. Seven
/// directories hold ours, one a copy above it, and the round began either
/// while the counter was being read or while the fetches were out: the
/// copy is excluded as republished, the seven hold it, and the probe's
/// arrival is reachable. Fails if the copy names another publisher, which
/// would hold this node's republish off over its own upload.
#[test]
fn a_newer_copy_after_our_own_round_names_no_one() {
    let newer = DirectoryAnswer::Received {
        revision_counter: Some(OURS + 1),
    };
    let round = || Input::UploadRoundStarted {
        descriptor: super::super::D0,
    };
    for while_drawn in [true, false] {
        let (mut core, _) = if while_drawn {
            checking_with(sent(1..=8, "cur", 0), vec![round()])
        } else {
            let (mut core, asked) = checking(sent(1..=8, "cur", 0));
            core.on(round(), secs(16));
            (core, asked)
        };
        for n in 1..=7 {
            core.on(
                answered(
                    n,
                    "cur",
                    DirectoryAnswer::Received {
                        revision_counter: Some(OURS),
                    },
                ),
                secs(16),
            );
        }
        core.on(answered(8, "cur", newer), secs(16));
        let judged = core.on(arrival(secs(15), secs(18)), secs(18));
        assert_eq!(republishes(&judged), 0, "while drawn: {while_drawn}");
        assert!(
            matches!(core.status().inbound, Inbound::Reachable { .. }),
            "while drawn: {while_drawn}: {:?}",
            core.status().inbound
        );
        let report: Vec<Counted> = judged
            .actions
            .iter()
            .filter_map(|action| match action {
                Action::DirectoriesSettled(report) => Some(report),
                _ => None,
            })
            .flatten()
            .map(|line| line.counted)
            .collect();
        assert_eq!(
            report
                .iter()
                .filter(|counted| **counted == Counted::Excluded(Exclusion::Republished))
                .count(),
            1,
            "while drawn: {while_drawn}: {report:?}"
        );
        assert_eq!(
            report
                .iter()
                .filter(|counted| **counted == Counted::Found)
                .count(),
            7,
            "while drawn: {while_drawn}: {report:?}"
        );
    }
}

/// **A refused round names itself over another publisher** (Rick,
/// 2026-11-21: the new cause never swallows the clock case). A clock that
/// went back leaves this node's own earlier copy above its counter, and the
/// directories refuse its uploads: the refused-upload path names that. A
/// node shown `PublishedElsewhere` whose next round is refused says
/// `UploadsRefused`, and still publishes nothing. Fails if
/// `uploads_refused` leaves `PublishedElsewhere` standing.
#[test]
fn a_refused_round_names_itself_over_another_publisher() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS + 1),
                },
            ),
            secs(16),
        );
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::PublishedElsewhere,
            ..
        }
    ));
    let refused = core.on(super::super::probe::round_tally(0, 16, 16, 0), secs(30));
    assert_eq!(republishes(&refused), 0);
    assert!(
        matches!(
            core.status().inbound,
            Inbound::Unreachable {
                cause: InboundCause::UploadsRefused,
                ..
            }
        ),
        "{:?}",
        core.status().inbound
    );
}

/// **Another publisher, once gone, leaves at the next held check.** A check
/// that finds our copy at more than half and no newer one, with the probe
/// in, is `Reachable` again. Fails if `PublishedElsewhere` outlives the
/// evidence that named it.
#[test]
fn another_publisher_gone_is_reachable_at_the_next_held_check() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS + 1),
                },
            ),
            secs(16),
        );
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::PublishedElsewhere,
            ..
        }
    ));
    // Tor's next round brings the next check: our copy everywhere.
    let round = secs(600);
    core.on(uploaded(0), round);
    let at = round + secs(15);
    let launched = drive(&mut core, at, &mut Some(sent(1..=8, "cur", 0)), &ours());
    assert_eq!(probes(&launched), 1, "{launched:?}");
    assert_eq!(fetched(&launched).len(), 8, "{launched:?}");
    core.on(Input::ProbeDialed { minted_at: at }, at);
    for n in 1..=8 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS),
                },
            ),
            at + secs(1),
        );
    }
    core.on(arrival(at, at + secs(3)), at + secs(3));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: at + secs(3)
        }
    );
}
