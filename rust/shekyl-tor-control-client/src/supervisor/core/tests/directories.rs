// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The directory check (`TOR_SUPERVISOR.md` §4.5).
//!
//! Each probe asks the directories the latest upload round reached. A line
//! counts only for a fetch this check has already sent, and the verdict
//! waits until the driver's list is folded.

use super::super::super::posture::{Cause, Inbound, InboundCause};
use super::super::{
    Action, Core, Counted, DirectoryAnswer, DirectoryFetch, DirectoryReport, Exclusion, Input, Step,
};
use super::probe::{
    arrival, count, probes, published, publishes_inbound, refetches, republishes, secs, served,
    uploaded,
};
use super::replied;
use crate::control::{RelayFingerprint, RoundUpload, ServiceDescriptor, UploadEnd};

/// This service's revision counter in these tests: a directory's copy carrying it
/// is the current one.
const OURS: u64 = 7;

/// This service's `desc_current` in these tests: the descriptor `"cur"`,
/// the one each check's fetches ask for, at [`OURS`].
fn ours() -> ServiceDescriptor {
    ServiceDescriptor {
        descriptor_id: "cur".to_owned(),
        revision_counter: OURS,
    }
}

fn hsdir(n: u8) -> RelayFingerprint {
    RelayFingerprint::from_bytes([n; 20])
}

/// Directories in `range`, each confirmed holding `descriptor`, each drawing
/// `draw`.
fn sent(range: std::ops::RangeInclusive<u8>, descriptor: &str, draw: u64) -> Vec<DirectoryFetch> {
    sent_ended(range, descriptor, UploadEnd::Uploaded, draw)
}

/// Directories in `range`, each sent `descriptor`, each upload ending as
/// `ended`, each drawing `draw`.
fn sent_ended(
    range: std::ops::RangeInclusive<u8>,
    descriptor: &str,
    ended: UploadEnd,
    draw: u64,
) -> Vec<DirectoryFetch> {
    range
        .map(|n| DirectoryFetch {
            upload: RoundUpload {
                hsdir: hsdir(n),
                descriptor_id: descriptor.to_owned(),
                ended,
            },
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
/// (`fetches`) and the check's `Replied` folded, and the deadline at the
/// delay's floor run: the probe and the fetches are due there. That step's
/// liveness sample is answered, and its `Replied` sends the first fetch,
/// which is left in flight. Returns the core and the 15 s step, with the
/// sample's `Replied` step joined to it.
fn checking_in_flight(fetches: Vec<DirectoryFetch>) -> (Core, Step) {
    let mut core = published();
    let ended = core.on(uploaded(0), 0);
    assert!(
        ended.actions.contains(&Action::CheckDirectories),
        "each probe's check asks for the directories"
    );
    core.on(
        Input::DirectoriesDrawn {
            fetches,
            ours: Some(ours()),
        },
        0,
    );
    replied(&mut core, 0);
    let mut step = core.on_deadline(secs(15));
    assert!(
        step.actions.contains(&Action::Sample),
        "the liveness sample goes first"
    );
    core.on(
        Input::DirectorySample {
            progress: Some(100),
            socks: None,
            read: None,
        },
        secs(15),
    );
    step.actions.extend(replied(&mut core, secs(15)).actions);
    assert_eq!(probes(&step), 1, "the probe at the delay's floor");
    (core, step)
}

/// [`checking_in_flight`], with every fetch sent and answered at 15 s, one
/// after another as the queue sends them: each with `Replied` alone (these
/// tests fold no acceptance, so each window runs from the send), and the
/// probe in flight, minted at 15 s. Returns the core and the fetches asked
/// at 15 s.
fn checking(fetches: Vec<DirectoryFetch>) -> (Core, Vec<RelayFingerprint>) {
    let (mut core, step) = checking_in_flight(fetches);
    // The sample is answered already: what is left in flight is fetches.
    let mut asked = fetched(&step);
    let rest = served(
        &mut core,
        Step {
            actions: Vec::new(),
            deadline: None,
        },
        secs(15),
    );
    asked.extend(fetched(&rest));
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
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "the directories are still out"
    );
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(1),
            descriptor_id: "cur".to_owned(),
        },
        secs(19),
    );
    for n in 1..=7 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS),
                },
            ),
            secs(20),
        );
    }
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
    let last = core.on(
        answered(
            8,
            "cur",
            DirectoryAnswer::Received {
                revision_counter: Some(OURS),
            },
        ),
        secs(21),
    );
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
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "one miss is not a verdict"
    );
    // The refetch's reply, then its `Replied`, which sends the new check.
    let mut again = core.on(Input::DescriptorRefetched { draw: 0 }, secs(20));
    again.actions.extend(replied(&mut core, secs(20)).actions);
    assert!(
        again.actions.contains(&Action::CheckDirectories),
        "a new check"
    );
    core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=8, "cur", 0),
            ours: Some(ours()),
        },
        secs(20),
    );
    replied(&mut core, secs(20));
    let launched = core.on_deadline(secs(35));
    let launched = served(&mut core, launched, secs(35));
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
/// directory that never answers counts as missing when its answer window
/// elapses: `probe_within` after the send, since this test never folds
/// Tor's acceptance. Seven of eight is more than half. Fails if a missing
/// answer blocks the verdict, or if the threshold is "every directory".
#[test]
fn one_directory_withholding_is_still_reachable() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
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
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
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
            hsdir: hsdir(1),
            descriptor_id: "cur".to_owned(),
        },
        secs(16),
    );
    for n in 1..=4 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS),
                },
            ),
            secs(17),
        );
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    // The step's liveness sample is answered: a fetch queued behind it
    // would be sent by its `Replied`, and is looked for there too.
    let later = core.on_deadline(secs(60));
    let later = served(&mut core, later, secs(60));
    assert!(
        fetched(&later).is_empty(),
        "the excluded directories are never asked"
    );
}

/// A `REQUESTED` this check did not cause does not choose the descriptor:
/// not one from a directory outside the check (the unscoped refetch, or
/// the probe's own fetch, can name another), and not one from a directory
/// in the check whose fetch has not been sent. Only a sent fetch's
/// `REQUESTED` excludes the directories sent the other descriptor. Fails if
/// `requested` drops its sent-fetch guard: the stray `next` would exclude
/// the four directories holding `cur`, and the check would count none.
#[test]
fn a_requested_this_check_did_not_send_chooses_nothing() {
    let mut fetches = sent(1..=4, "cur", 0);
    // Directories 5 to 8 got the next period's descriptor, and draw later.
    fetches.extend(sent(5..=8, "next", u64::MAX));
    let (mut core, asked) = checking(fetches);
    assert_eq!(asked, [hsdir(1), hsdir(2), hsdir(3), hsdir(4)]);
    for stray in [hsdir(9), hsdir(5)] {
        core.on(
            Input::DirectoryAsked {
                hsdir: stray,
                descriptor_id: "next".to_owned(),
            },
            secs(16),
        );
    }
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(1),
            descriptor_id: "cur".to_owned(),
        },
        secs(16),
    );
    for n in 1..=4 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(OURS),
                },
            ),
            secs(17),
        );
    }
    let step = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        count(&step, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        0,
        "the four directories holding the asked-for descriptor are counted"
    );
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
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
            hsdir: hsdir(1),
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
    core.on(
        Input::DirectoriesDrawn {
            fetches,
            ours: Some(ours()),
        },
        0,
    );
    replied(&mut core, 0);
    let at_floor = core.on_deadline(secs(15));
    let at_floor = served(&mut core, at_floor, secs(15));
    assert_eq!(fetched(&at_floor), [hsdir(1)]);
    let at_top = core.on_deadline(secs(60));
    let at_top = served(&mut core, at_top, secs(60));
    assert_eq!(fetched(&at_top), [hsdir(2)]);
}

/// A line from a directory this check has not sent is not evidence, and
/// that directory is still fetched when its own delay comes due. An answer
/// before the send, and a `REQUESTED` from any other directory, do not
/// choose the descriptor. Fails if `answered` or `requested` count a fetch
/// that is not open.
#[test]
fn an_answer_before_the_send_is_not_evidence() {
    let mut core = published();
    core.on(uploaded(0), 0);
    core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=1, "cur", u64::MAX),
            ours: Some(ours()),
        },
        0,
    );
    replied(&mut core, 0);
    core.on(answered(1, "cur", DirectoryAnswer::NotFound), secs(1));
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(1),
            descriptor_id: "cur".to_owned(),
        },
        secs(1),
    );
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(9),
            descriptor_id: "other".to_owned(),
        },
        secs(1),
    );
    core.on(
        answered(
            9,
            "other",
            DirectoryAnswer::Received {
                revision_counter: Some(OURS),
            },
        ),
        secs(1),
    );
    let at_floor = core.on_deadline(secs(15));
    let at_floor = served(&mut core, at_floor, secs(15));
    assert!(fetched(&at_floor).is_empty(), "its delay has not come due");
    let at_top = core.on_deadline(secs(60));
    let at_top = served(&mut core, at_top, secs(60));
    assert_eq!(fetched(&at_top), [hsdir(1)], "still asked, at its own time");
}

/// The driver's list can arrive after the probe is already being judged.
/// Until it does, the arrival is not a verdict, and no list is not an empty
/// one. Fails if `directories_drawn` drops a draw once the probe is
/// `Judging`, or if `judge` treats a missing draw as unmatched.
#[test]
fn a_draw_that_arrives_while_judging_still_installs() {
    let mut core = published();
    core.on(uploaded(0), 0);
    let mut step = core.on_deadline(secs(15));
    // The directory check, then the liveness sample, then the dial.
    if core.in_flight().is_some() {
        step.actions.extend(replied(&mut core, secs(15)).actions);
    }
    if step.actions.contains(&Action::Sample) {
        core.on(
            Input::DirectorySample {
                progress: Some(100),
                socks: None,
                read: None,
            },
            secs(15),
        );
        step.actions.extend(replied(&mut core, secs(15)).actions);
    }
    assert_eq!(probes(&step), 1, "the dial follows the sample: {step:?}");
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let arrived = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        count(&arrived, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        0,
        "the draw is still outstanding"
    );
    assert!(publishes_inbound(&arrived).is_empty());
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
    let drawn = core.on(
        Input::DirectoriesDrawn {
            fetches: Vec::new(),
            ours: Some(ours()),
        },
        secs(19),
    );
    assert_eq!(
        count(&drawn, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        1
    );
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
}

/// Outbound dropping while the check is open discards it. The probe can
/// already be in hand and the directories can then finish: no refetch, and
/// no inbound verdict. Tor's outbound cause stands. Fails if `judge`
/// consumes a verdict after `probe_may_run` is false.
#[test]
fn a_check_open_when_outbound_drops_is_discarded() {
    let (mut core, _) = checking(sent(1..=4, "cur", 0));
    core.on(arrival(secs(15), secs(18)), secs(18));
    for n in 1..=3 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(19));
    }
    core.on(Input::ExternalBlocked, secs(20));
    let last = core.on(answered(4, "cur", DirectoryAnswer::NotFound), secs(21));
    assert_eq!(refetches(&last), 0);
    assert_eq!(republishes(&last), 0);
    assert!(publishes_inbound(&last).is_empty());
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
    assert_eq!(core.status().cause, Cause::ExternalBlocked);
}

/// Tor accepting a fetch starts that fetch's answer window from the
/// acceptance. A sibling due in the same breath keeps the provisional window
/// the check's deadline gave it, though the queue sends it only once the
/// first fetch is answered. Fails if acceptance leaves the provisional
/// window, or if it moves every open fetch.
#[test]
fn a_fetch_waits_from_when_tor_accepts_it() {
    // Both fetches come due at 15 s; the queue sends the first, and the
    // second waits for the first's reply.
    let (mut core, step) = checking_in_flight(sent(1..=2, "cur", 0));
    let mut asked = fetched(&step);
    assert_eq!(asked, [hsdir(1)], "the first fetch is sent");
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    core.on(arrival(secs(15), secs(18)), secs(18));
    // The first fetch's reply: Tor accepted it at 40 s. Its `Replied` sends
    // the sibling, whose acceptance is never folded: its window runs from
    // that send.
    core.on(Input::DirectoryFetchAccepted { hsdir: hsdir(1) }, secs(40));
    asked.extend(fetched(&replied(&mut core, secs(40))));
    assert_eq!(asked, [hsdir(1), hsdir(2)]);
    replied(&mut core, secs(40));
    let early = core.on_deadline(secs(75));
    let early = served(&mut core, early, secs(75));
    assert_eq!(refetches(&early), 0, "the accepted fetch is still out");
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
    let bound = core.on_deadline(secs(100));
    let bound = served(&mut core, bound, secs(100));
    assert_eq!(refetches(&bound), 1, "both missing, and the probe arrived");
}

/// **A fetch waiting in the queue is not sent yet.** Both fetches come due
/// at 15 s; the queue sends the first, and the second waits for its reply
/// at 40 s. Until then a line about the second directory is not this
/// check's, and its answer window runs from its own send: its copy at 80 s,
/// more than 60 s after it came due and less than 60 s after it was sent,
/// counts. Both directories hold our copy and the probe arrived:
/// Reachable. Fails if the check opens a fetch when it comes due rather
/// than when it is sent: the early line, or a window run out before the
/// send, makes the second directory a miss, and one of two is Lost.
#[test]
fn a_queued_fetch_is_not_open_and_its_window_runs_from_its_send() {
    let ours_copy = || DirectoryAnswer::Received {
        revision_counter: Some(OURS),
    };
    let (mut core, step) = checking_in_flight(sent(1..=2, "cur", 0));
    assert_eq!(fetched(&step), [hsdir(1)], "the second waits in the queue");
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    core.on(arrival(secs(15), secs(18)), secs(18));
    core.on(answered(2, "cur", DirectoryAnswer::NotFound), secs(20));
    core.on(Input::DirectoryFetchAccepted { hsdir: hsdir(1) }, secs(40));
    let sibling = replied(&mut core, secs(40));
    assert_eq!(fetched(&sibling), [hsdir(2)], "sent at 40 s");
    replied(&mut core, secs(40));
    core.on(answered(1, "cur", ours_copy()), secs(41));
    while let Some(due) = core.deadline().filter(|due| *due <= secs(80)) {
        let step = core.on_deadline(due);
        served(&mut core, step, due);
    }
    core.on(answered(2, "cur", ours_copy()), secs(80));
    assert!(
        matches!(core.status().inbound, Inbound::Reachable { .. }),
        "{:?}",
        core.status().inbound
    );
}

/// **A stale copy is a miss for that directory** (Rick, 2026-11-01). The
/// directory check compares each directory's copy with this service's
/// current counter: a copy numbered below ours is one a later upload never
/// reached, and one numbered above ours is the clock run's, a copy uploaded
/// before the clock went back that the directory keeps serving. Reachable
/// needs our copy at more than half. Fails if `answered` counts any
/// `Received` as found, whatever its counter.
#[test]
fn a_stale_directory_copy_is_a_miss() {
    let stale = |counter| DirectoryAnswer::Received {
        revision_counter: Some(counter),
    };
    // Every copy stale, below and above ours: a miss, with the probe in.
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=4 {
        core.on(answered(n, "cur", stale(OURS - 1)), secs(16));
    }
    for n in 5..=8 {
        core.on(answered(n, "cur", stale(OURS + 1)), secs(16));
    }
    let first = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&first), 1, "every copy stale: a miss");
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );

    // Ours at exactly half: still a miss.
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        let answer = if n <= 4 { stale(OURS) } else { stale(OURS - 1) };
        core.on(answered(n, "cur", answer), secs(16));
    }
    let half = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&half), 1, "ours at half is not more than half");

    // Ours at five of eight: Reachable.
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        let answer = if n <= 5 { stale(OURS) } else { stale(OURS + 1) };
        core.on(answered(n, "cur", answer), secs(16));
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(18)
        }
    );
}

/// **A copy of a descriptor ours does not name counts by being there**
/// (found live, 2026-11-01 17:00Z). From 12:00 to 00:00 UTC the service's
/// `desc_current`, the only one `GETINFO hs/service/desc/id` gives, is the
/// previous time period's, and clients ask for `desc_next`
/// (`hs_service.c:2127-2139`). Comparing those copies with
/// `desc_current`'s counter made a healthy node miss twice and republish.
/// Fails if `answered` compares every copy with ours whatever descriptor
/// ours names.
#[test]
fn a_copy_of_a_descriptor_ours_does_not_name_counts_by_being_there() {
    let mut core = published();
    core.on(uploaded(0), 0);
    core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=8, "cur", 0),
            ours: Some(ServiceDescriptor {
                descriptor_id: "prev".to_owned(),
                revision_counter: OURS,
            }),
        },
        0,
    );
    replied(&mut core, 0);
    // The probe and the fetches, sent as the queue sends them.
    let due = core.on_deadline(secs(15));
    let launched = served(&mut core, due, secs(15));
    assert_eq!(probes(&launched), 1);
    assert_eq!(fetched(&launched).len(), 8, "{launched:?}");
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    for n in 1..=8 {
        core.on(
            answered(
                n,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: Some(2_008_251_960),
                },
            ),
            secs(16),
        );
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(18)
        }
    );
}

/// **Without our counter the check counts nothing** (§4.5). Tor gave no
/// descriptor, so no fetch is sent and the probe alone decides. Counting
/// the copies as found would call the node Reachable on directories it
/// cannot compare, and waiting out their answer windows would hold the
/// probe for a check that counts nothing.
#[test]
fn without_our_counter_the_check_counts_nothing_and_the_probe_decides() {
    let mut core = published();
    core.on(uploaded(0), 0);
    let drawn = core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=8, "cur", 0),
            ours: None,
        },
        0,
    );
    assert!(fetched(&drawn).is_empty(), "no fetch goes out");
    let mut launched = core.on_deadline(secs(15));
    if core.in_flight().is_some() {
        launched
            .actions
            .extend(replied(&mut core, secs(15)).actions);
    }
    if launched.actions.contains(&Action::Sample) {
        core.on(
            Input::DirectorySample {
                progress: Some(100),
                socks: None,
                read: None,
            },
            secs(15),
        );
        launched
            .actions
            .extend(replied(&mut core, secs(15)).actions);
    }
    assert_eq!(
        probes(&launched),
        1,
        "the dial follows the sample: {launched:?}"
    );
    assert!(
        fetched(&launched).is_empty(),
        "the answer windows are not waited"
    );
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    let step = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        count(&step, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        1,
        "the probe alone decides"
    );
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
}

/// The round of SO-D12's run 4 (2026-11-14): directories 1 to 4 confirmed
/// holding `"cur"`, and directories 5 to 8 sent `"cur"` with no end ever
/// reported, as Tor reports an upload whose connection failed.
fn run_four() -> Vec<DirectoryFetch> {
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Unfinished, 0));
    fetches
}

fn ours_held() -> DirectoryAnswer {
    DirectoryAnswer::Received {
        revision_counter: Some(OURS),
    }
}

/// The lines a judged check said, from the step that judged it.
fn settled(step: &Step) -> Vec<DirectoryReport> {
    step.actions
        .iter()
        .find_map(|action| match action {
            Action::DirectoriesSettled(report) => Some(report.clone()),
            _ => None,
        })
        .expect("a judged check says its directories")
}

/// **An upload Tor never confirmed counts missing unless its directory
/// returns our copy** (SO-D12's run 4; Rick, 2026-11-15). C's round left four
/// of its eight current-period uploads unfinished, and the check asked only
/// the four that confirmed: Reachable, while peers dialling C gave up
/// waiting for its descriptor. Every directory is now asked, and for an unconfirmed upload
/// an answer that says nothing (`Other`, an unreadable counter, silence) is
/// missing: four of eight, a miss. The same answers after confirmed uploads
/// are not counted, as before: four of five, Reachable. An unconfirmed
/// upload whose directory returns our copy is found. Fails if `send_check`
/// asks confirmed uploads only (four asked), or if `hold` excludes an
/// unconfirmed upload's `Other` (Reachable).
#[test]
fn an_unconfirmed_upload_counts_missing_unless_its_copy_matches() {
    let says_nothing = |core: &mut Core| {
        for n in 1..=4 {
            core.on(answered(n, "cur", ours_held()), secs(16));
        }
        for n in 5..=6 {
            core.on(answered(n, "cur", DirectoryAnswer::Other), secs(16));
        }
        core.on(
            answered(
                7,
                "cur",
                DirectoryAnswer::Received {
                    revision_counter: None,
                },
            ),
            secs(16),
        );
        // Directory 8 is silent: its window decides. The liveness sample due
        // then is answered, and the refetch queued behind it goes out.
        core.on(arrival(secs(15), secs(18)), secs(18));
        let window = core.on_deadline(secs(75));
        served(core, window, secs(75))
    };

    let (mut core, asked) = checking(run_four());
    assert_eq!(asked.len(), 8, "the unconfirmed uploads are asked too");
    let window = says_nothing(&mut core);
    assert_eq!(refetches(&window), 1, "four of eight: a miss");
    let report = settled(&window);
    assert_eq!(report.len(), 8);
    for line in &report[4..] {
        assert_eq!(line.upload, UploadEnd::Unfinished);
        assert_eq!(line.counted, Counted::Missing, "{line:?}");
    }
    assert_eq!(report[4].answer, Some(DirectoryAnswer::Other));
    assert_eq!(report[7].answer, None, "silent");

    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    let window = says_nothing(&mut core);
    assert_eq!(refetches(&window), 0);
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(18)
        },
        "confirmed uploads saying nothing are not counted: four of five"
    );
    let report = settled(&window);
    assert_eq!(report[4].counted, Counted::Excluded(Exclusion::SaidNothing));
    assert_eq!(report[7].counted, Counted::Missing, "silence still misses");

    let (mut core, _) = checking(run_four());
    for n in 1..=5 {
        core.on(answered(n, "cur", ours_held()), secs(16));
    }
    for n in 6..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(18)
        },
        "an unconfirmed upload holding our copy is found: five of eight"
    );
}

/// **Our failure to ask is not counted, whatever the upload.** A fetch Tor
/// refused (`Unusable`) says nothing about the directory: counting it
/// missing would republish on a control hiccup. Four of four, Reachable.
/// Fails if `hold` lets the unconfirmed rule reach `Unusable`.
#[test]
fn our_failure_to_ask_is_not_counted_whatever_the_upload() {
    let (mut core, _) = checking(run_four());
    for n in 1..=4 {
        core.on(answered(n, "cur", ours_held()), secs(16));
    }
    for n in 5..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::Unusable), secs(16));
    }
    let step = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(18)
        }
    );
    assert!(settled(&step)[4..]
        .iter()
        .all(|line| line.counted == Counted::Excluded(Exclusion::NotAsked)));
}

/// **A second probe drawn just after a new round began leaves that round's
/// uploads in flight alone** (Rick, 2026-11-15). The first check misses and
/// the descriptor is refetched; a round starts and its first upload lands a
/// second before the second check is drawn. Its four uploads still open are
/// neither asked nor counted, so they cannot read missing: the four that
/// landed decide, and the node is Reachable. Fails if `directories_drawn`
/// asks open uploads whatever the round's age (eight asked, a second miss,
/// a republish).
#[test]
fn a_second_probe_does_not_ask_a_new_rounds_uploads_in_flight() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    let first = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&first), 1, "a first miss refetches");
    core.on(Input::UploadRoundStarted, secs(19));
    core.on(Input::FirstUploaded { draw: 0 }, secs(19));
    let mut again = core.on(Input::DescriptorRefetched { draw: 0 }, secs(20));
    again.actions.extend(replied(&mut core, secs(20)).actions);
    assert!(again.actions.contains(&Action::CheckDirectories));
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Open, 0));
    core.on(
        Input::DirectoriesDrawn {
            fetches,
            ours: Some(ours()),
        },
        secs(20),
    );
    replied(&mut core, secs(20));
    let launched = core.on_deadline(secs(35));
    let launched = served(&mut core, launched, secs(35));
    assert_eq!(probes(&launched), 1);
    assert_eq!(
        fetched(&launched),
        (1..=4).map(hsdir).collect::<Vec<_>>(),
        "the uploads in flight are not asked"
    );
    core.on(
        Input::ProbeDialed {
            minted_at: secs(35),
        },
        secs(35),
    );
    for n in 1..=4 {
        core.on(answered(n, "cur", ours_held()), secs(36));
    }
    let verdict = core.on(arrival(secs(35), secs(37)), secs(37));
    assert_eq!(republishes(&verdict), 0);
    assert_eq!(
        core.status().inbound,
        Inbound::Reachable {
            evidence_at: secs(37)
        }
    );
    let report = settled(&verdict);
    assert!(report[4..].iter().all(|line| line.upload == UploadEnd::Open
        && line.answer.is_none()
        && line.counted == Counted::Excluded(Exclusion::UploadInFlight)));
}

/// Serve every deadline up to `until` as the driver does: each liveness
/// sample answered with a full bootstrap, the first check asked folded with
/// `list` and `ours`, and `Replied` after each request so the queue sends
/// what waits. Returns every action taken.
fn drive(
    core: &mut Core,
    until: u64,
    list: &mut Option<Vec<DirectoryFetch>>,
    ours: &ServiceDescriptor,
) -> Step {
    let mut taken = Vec::new();
    let mut served_at = None;
    while let Some(due) = core.deadline().filter(|due| *due <= until) {
        assert_ne!(served_at, Some(due), "the deadline at {due} did not move");
        served_at = Some(due);
        let mut actions = core.on_deadline(due).actions;
        loop {
            if actions.contains(&Action::Sample) {
                core.on(
                    Input::DirectorySample {
                        progress: Some(100),
                        socks: None,
                        read: None,
                    },
                    due,
                );
            }
            if actions.contains(&Action::CheckDirectories) {
                core.on(
                    Input::DirectoriesDrawn {
                        fetches: list.take().expect("one check"),
                        ours: Some(ours.clone()),
                    },
                    due,
                );
            }
            taken.extend(actions);
            if core.in_flight().is_none() {
                break;
            }
            actions = replied(core, due).actions;
        }
    }
    Step {
        actions: taken,
        deadline: core.deadline(),
    }
}

/// **The round's own probe asks its uploads still open**: it goes ahead
/// `Policy::round_wait` after the first upload, so an upload open then is
/// hung (§4.5) and its directory is asked. Fails if `directories_drawn`
/// measures the round's age from anything later than its start, or never
/// asks open uploads.
#[test]
fn the_rounds_own_probe_asks_its_uploads_still_open() {
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, secs(5));
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Open, 0));
    let mut list = Some(fetches);
    let taken = drive(&mut core, secs(5 + 60 + 15), &mut list, &ours());
    assert!(list.is_none(), "the wait's check drew the list");
    assert_eq!(probes(&taken), 1, "the wait's probe");
    assert_eq!(
        fetched(&taken).len(),
        8,
        "every upload's directory is asked"
    );
}

/// **A republish the directory check drives waits out the backoff** (Rick,
/// 2026-11-15). Asking unconfirmed uploads can turn a slow link's uploads
/// into misses, and two misses republish, which restarts every upload. The
/// check's republish takes the same backoff as the probe's: the first goes
/// out; the second, judged while the first was being judged, is held for
/// `Policy::republish_after` and runs when that ends. Fails if
/// `inbound_down` stops failing the judgment, or `republish` stops holding.
#[test]
fn a_republish_the_check_drives_waits_out_the_backoff() {
    let mut core = published();
    let first = core.on(uploaded(0), 0);
    assert!(first.actions.contains(&Action::CheckDirectories));
    let (at, verdict) = missed_twice_by_directories(&mut core, 0);
    assert_eq!(republishes(&verdict), 1, "the first republish goes out");
    let deleted = replied(&mut core, at);
    assert!(deleted.actions.contains(&Action::AddOnion));
    core.on(Input::OnionPublished, at);
    replied(&mut core, at);

    // The republish's own round, judged the same way.
    let round = at + secs(10);
    let ended = core.on(uploaded(0), round);
    assert!(ended.actions.contains(&Action::CheckDirectories));
    let (judged_at, verdict) = missed_twice_by_directories(&mut core, round);
    assert_eq!(republishes(&verdict), 0, "held by the backoff");
    assert!(matches!(
        core.status().inbound,
        Inbound::Unreachable {
            cause: InboundCause::DescriptorNotFound,
            ..
        }
    ));
    let due = core.republish.due().expect("the held republish is owed");
    assert_eq!(due, judged_at + secs(300), "republish_after, the base wait");
    let step = core.on_deadline(due);
    let step = served(&mut core, step, due);
    assert_eq!(republishes(&step), 1, "runs when the hold ends");
}

/// From a step at `at` that asked for the check: two probes, each arriving,
/// and two checks over [`run_four`] whose unconfirmed uploads say nothing,
/// so each is a miss. Returns the verdict's time and step.
fn missed_twice_by_directories(core: &mut Core, at: u64) -> (u64, Step) {
    let check = |core: &mut Core, at: u64| {
        core.on(
            Input::DirectoriesDrawn {
                fetches: run_four(),
                ours: Some(ours()),
            },
            at,
        );
        replied(core, at);
        let probe_at = at + secs(15);
        let launched = core.on_deadline(probe_at);
        let launched = served(core, launched, probe_at);
        assert_eq!(probes(&launched), 1);
        assert_eq!(fetched(&launched).len(), 8);
        core.on(
            Input::ProbeDialed {
                minted_at: probe_at,
            },
            probe_at,
        );
        for n in 1..=4 {
            core.on(answered(n, "cur", ours_held()), probe_at + secs(1));
        }
        for n in 5..=8 {
            core.on(
                answered(n, "cur", DirectoryAnswer::Other),
                probe_at + secs(1),
            );
        }
        let arrived = probe_at + secs(2);
        (arrived, core.on(arrival(probe_at, arrived), arrived))
    };
    let (missed_at, first) = check(core, at);
    assert_eq!(refetches(&first), 1, "a first miss refetches");
    let refetched = missed_at + secs(1);
    let mut again = core.on(Input::DescriptorRefetched { draw: 0 }, refetched);
    again.actions.extend(replied(core, refetched).actions);
    assert!(again.actions.contains(&Action::CheckDirectories));
    check(core, refetched)
}

/// Run 4's onion C (SO-D12's walk, 2026-11-14), replayed from the daemon's
/// debug log (`shekyl-dev` `data/so-d12-walk-2026-11-14/run4/`). The
/// directories are public relays; the descriptor ids are the blinded keys
/// of an onion whose key went with its data directory. `CURRENT` is the
/// descriptor the check's fetches asked for, at the counter Tor gave.
mod run_four_replay {
    pub(super) const CURRENT: &str = "yGAaT2++/TpMdKEcKS4NepKxJvJJppM6r+9rxyIH+bE";
    pub(super) const NEXT: &str = "mfKW5uetKPkYB2B0rT82YX3GMUxdY0b0BV/o1s3+XAI";
    pub(super) const COUNTER: u64 = 3_763_297_149;
    /// `CURRENT`'s eight directories, in upload order. The first four never
    /// reported an end.
    pub(super) const CURRENT_DIRS: [&str; 8] = [
        "602A20F90E20D1B9EA4DD87AE948B590C61F8A94",
        "33728FB7DDB105FB0C2F67A871F094E3EDB671CC",
        "F2FAB7031B66F7CF09AF7BE6D104A3B72D352AE1",
        "2739C3580FE65466FE93721EADA1D47478EE718C",
        "0FF228E319AC2350BCCA4E0345E73430B8E4CC79",
        "7175B61349B26D68DBAC0298EBBBE1C0B9DAB457",
        "82A09305C8D771663E070D8D5D479BCD48EA58A8",
        "E495F147FDFA263C5DC21AE1A105B9EFFDBE2467",
    ];
    /// `NEXT`'s eight directories, in upload order. Every one confirmed.
    pub(super) const NEXT_DIRS: [&str; 8] = [
        "FA01576E6B5CB77DF2330DEC999A7259BA3A48A3",
        "99CBE9E61E65D65DFFB23CE35C541F375FB3652D",
        "92E90B9CDE0FA37937BFA4788D7C96277A1953CB",
        "1A88A34C7E4842AA658F8437436BDE6462967A64",
        "2CBB483A11A71E55A2BEB16A0C41703E61968309",
        "4C2686B7FF7AEF0478EEC7EBE53F7CEA705679E7",
        "9A70CF244A22A0B5AC67B327420F8BECB8A4522F",
        "587AC6D887F7054B63ACC683803A7B4C5FE1C8CE",
    ];
    /// The `UPLOADED`s, in the order they arrived (07:55:48.99Z to 07:55:50.36Z).
    pub(super) const UPLOADED: [&str; 12] = [
        "82A09305C8D771663E070D8D5D479BCD48EA58A8",
        "7175B61349B26D68DBAC0298EBBBE1C0B9DAB457",
        "E495F147FDFA263C5DC21AE1A105B9EFFDBE2467",
        "0FF228E319AC2350BCCA4E0345E73430B8E4CC79",
        "92E90B9CDE0FA37937BFA4788D7C96277A1953CB",
        "FA01576E6B5CB77DF2330DEC999A7259BA3A48A3",
        "587AC6D887F7054B63ACC683803A7B4C5FE1C8CE",
        "1A88A34C7E4842AA658F8437436BDE6462967A64",
        "99CBE9E61E65D65DFFB23CE35C541F375FB3652D",
        "9A70CF244A22A0B5AC67B327420F8BECB8A4522F",
        "4C2686B7FF7AEF0478EEC7EBE53F7CEA705679E7",
        "2CBB483A11A71E55A2BEB16A0C41703E61968309",
    ];
}

fn relay(hex: &str) -> RelayFingerprint {
    let mut bytes = [0u8; 20];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).expect("hex");
    }
    RelayFingerprint::from_bytes(bytes)
}

/// **Run 4, replayed: the check now reads C's round as a miss.** C's round
/// uploaded `CURRENT` to eight directories and four never reported an end.
/// Its probe went ahead at the round's wait (07:56:48Z, 60 s after the first
/// `UPLOADED`), asked only the four that confirmed, found our copy at each,
/// and C read Reachable at 07:57:44Z; from 07:59:40Z to 08:04:23Z peers
/// dialling C gave up three times after 105 s waiting for its descriptor.
/// Tor's own refetch asked one of the four, 602A20F9, which never answered. Replayed through the coalescer and the core: all eight are
/// asked, the four silent ones are missing when their windows pass, and
/// four of eight is a first miss. Fails if `UploadRounds` drops uploads
/// still open, or `directories_drawn` leaves the round's hung uploads
/// unasked.
#[test]
fn run_four_replayed_is_a_miss() {
    use crate::control::{HsDescAction, HsDescEvent, ServiceId, UploadRounds};
    use run_four_replay::{COUNTER, CURRENT, CURRENT_DIRS, NEXT, NEXT_DIRS, UPLOADED};
    let address = ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
        .expect("a test address");
    let event = |action, hsdir: &str, descriptor: Option<&str>| HsDescEvent {
        action,
        address: Some(address.clone()),
        hsdir: Some(relay(hsdir)),
        descriptor_id: descriptor.map(str::to_owned),
        reason: None,
    };
    let mut rounds = UploadRounds::new(address.clone());
    for hsdir in CURRENT_DIRS {
        rounds.observe(&event(HsDescAction::Upload, hsdir, Some(CURRENT)));
    }
    for hsdir in NEXT_DIRS {
        rounds.observe(&event(HsDescAction::Upload, hsdir, Some(NEXT)));
    }
    for hsdir in UPLOADED {
        rounds.observe(&event(HsDescAction::Uploaded, hsdir, None));
    }
    assert!(rounds.in_round(), "four uploads never reported");
    let unconfirmed: Vec<_> = rounds
        .directories()
        .iter()
        .filter(|upload| !upload.ended.confirmed())
        .map(|upload| upload.hsdir)
        .collect();
    assert_eq!(
        unconfirmed,
        CURRENT_DIRS[..4]
            .iter()
            .map(|hex| relay(hex))
            .collect::<Vec<_>>()
    );

    // The core: the round began at 0, its first upload landed at 2 s, and
    // its wait draws the check at 62 s, while the four are still open.
    let mut core = published();
    core.on(Input::UploadRoundStarted, 0);
    core.on(Input::FirstUploaded { draw: 0 }, secs(2));
    let fetches = rounds
        .directories()
        .iter()
        .map(|upload| DirectoryFetch {
            upload: upload.clone(),
            draw: 0,
        })
        .collect();
    let ours = ServiceDescriptor {
        descriptor_id: CURRENT.to_owned(),
        revision_counter: COUNTER,
    };
    let sent_at = secs(62 + 15);
    let launched = drive(&mut core, sent_at, &mut Some(fetches), &ours);
    assert_eq!(probes(&launched), 1);
    assert_eq!(fetched(&launched).len(), 16, "every upload's directory");
    core.on(Input::ProbeDialed { minted_at: sent_at }, sent_at);
    // The first fetch answered names `CURRENT`: the `NEXT` directories leave.
    core.on(
        Input::DirectoryAsked {
            hsdir: relay(CURRENT_DIRS[4]),
            descriptor_id: CURRENT.to_owned(),
        },
        sent_at + secs(1),
    );
    for hsdir in &CURRENT_DIRS[4..] {
        core.on(
            Input::DirectoryAnswered {
                hsdir: relay(hsdir),
                descriptor_id: Some(CURRENT.to_owned()),
                answer: DirectoryAnswer::Received {
                    revision_counter: Some(COUNTER),
                },
            },
            sent_at + secs(2),
        );
    }
    let arrived = core.on(arrival(sent_at, sent_at + secs(3)), sent_at + secs(3));
    assert_eq!(refetches(&arrived), 0, "the four silent windows still run");
    let window = core.on_deadline(sent_at + secs(60));
    let window = served(&mut core, window, sent_at + secs(60));
    assert_eq!(refetches(&window), 1, "four of eight: a first miss");
    let report = settled(&window);
    let missing: Vec<_> = report
        .iter()
        .filter(|line| line.counted == Counted::Missing)
        .map(|line| line.hsdir)
        .collect();
    assert_eq!(
        missing,
        CURRENT_DIRS[..4]
            .iter()
            .map(|hex| relay(hex))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report
            .iter()
            .filter(|line| line.counted == Counted::Excluded(Exclusion::OtherDescriptor))
            .count(),
        8
    );
}
