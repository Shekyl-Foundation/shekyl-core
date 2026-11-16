// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The directory check (`TOR_SUPERVISOR.md` §4.5).
//!
//! Each probe asks the directories the latest upload round reached. A line
//! counts only for a fetch this check has already sent, and the verdict
//! waits until the driver's list is folded. What an upload's end counts
//! for, and the captured rounds, are [`super::directory_uploads`].

use super::super::super::posture::{Cause, Inbound, InboundCause};
use super::super::{Action, Core, DirectoryAnswer, DirectoryFetch, Input, OpenUploads, Step};
use super::probe::{
    arrival, count, probes, published, publishes_inbound, refetches, republishes, secs, served,
    uploaded,
};
use super::replied;
use crate::control::{RelayFingerprint, RoundUpload, ServiceDescriptor, UploadEnd};

/// This service's revision counter in these tests: a directory's copy carrying it
/// is the current one.
pub(super) const OURS: u64 = 7;

/// This service's `desc_current` in these tests: the descriptor `"cur"`,
/// the one each check's fetches ask for, at [`OURS`].
pub(super) fn ours() -> ServiceDescriptor {
    ServiceDescriptor {
        descriptor_id: "cur".to_owned(),
        revision_counter: OURS,
    }
}

pub(super) fn hsdir(n: u8) -> RelayFingerprint {
    RelayFingerprint::from_bytes([n; 20])
}

/// Directories in `range`, each confirmed holding `descriptor`, each drawing
/// `draw`.
pub(super) fn sent(
    range: std::ops::RangeInclusive<u8>,
    descriptor: &str,
    draw: u64,
) -> Vec<DirectoryFetch> {
    sent_ended(range, descriptor, UploadEnd::Uploaded, draw)
}

/// Directories in `range`, each sent `descriptor`, each upload ending as
/// `ended`, each drawing `draw`.
pub(super) fn sent_ended(
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
                descriptor: super::D0,
                ended,
            },
            draw,
        })
        .collect()
}

pub(super) fn fetched(step: &Step) -> Vec<RelayFingerprint> {
    step.actions
        .iter()
        .filter_map(|action| match action {
            Action::FetchFromDirectory { hsdir } => Some(*hsdir),
            _ => None,
        })
        .collect()
}

pub(super) fn answered(n: u8, descriptor: &str, answer: DirectoryAnswer) -> Input {
    Input::DirectoryAnswered {
        hsdir: hsdir(n),
        descriptor_id: Some(descriptor.to_owned()),
        answer,
    }
}

/// A published core whose round just ended, run to the delay's floor: the
/// liveness sample due there is answered, the probe goes out and asks for
/// its check's list, the list (`fetches`) is folded, and the check's
/// `Replied` sends the first fetch, which is left in flight. The fetches are
/// due at the floor too: their delays count from the round's end. Returns
/// the core and the 15 s step, every request's actions joined to it.
fn checking_in_flight(fetches: Vec<DirectoryFetch>) -> (Core, Step) {
    let mut core = published();
    let ended = core.on(uploaded(0), 0);
    assert!(
        !ended.actions.contains(&Action::CheckDirectories),
        "the check's list waits for the probe"
    );
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
    let fired = replied(&mut core, secs(15));
    assert!(
        fired.actions.contains(&Action::CheckDirectories),
        "the probe asks for its check's list as it goes out"
    );
    step.actions.extend(fired.actions);
    let drawn = core.on(
        Input::DirectoriesDrawn {
            fetches,
            ours: Some(ours()),
            open_uploads: OpenUploads::in_flight(vec![super::D0]),
        },
        secs(15),
    );
    step.actions.extend(drawn.actions);
    step.actions.extend(replied(&mut core, secs(15)).actions);
    assert_eq!(probes(&step), 1, "the probe at the delay's floor");
    (core, step)
}

/// Serve every deadline up to `until` as the driver does: each liveness
/// sample answered with a full bootstrap, the first check asked folded with
/// `list` and `ours`, and `Replied` after each request so the queue sends
/// what waits. Returns every action taken.
pub(super) fn drive(
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
                        open_uploads: core.open_uploads(due),
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

/// [`checking_in_flight`], with every fetch sent and answered at 15 s, one
/// after another as the queue sends them: each with `Replied` alone (these
/// tests fold no acceptance, so each window runs from the send), and the
/// probe in flight, minted at 15 s. Returns the core and the fetches asked
/// at 15 s.
pub(super) fn checking(fetches: Vec<DirectoryFetch>) -> (Core, Vec<RelayFingerprint>) {
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
    // The refetch's reply, then its `Replied`; the second probe draws a new
    // check as it goes out.
    core.on(Input::DescriptorRefetched { draw: 0 }, secs(20));
    replied(&mut core, secs(20));
    let launched = drive(
        &mut core,
        secs(35),
        &mut Some(sent(1..=8, "cur", 0)),
        &ours(),
    );
    assert!(
        launched.actions.contains(&Action::CheckDirectories),
        "a new check"
    );
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
    let at_floor = drive(&mut core, secs(15), &mut Some(fetches), &ours());
    assert_eq!(fetched(&at_floor), [hsdir(1)]);
    let at_top = drive(&mut core, secs(60), &mut None, &ours());
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
    let at_floor = drive(
        &mut core,
        secs(15),
        &mut Some(sent(1..=1, "cur", u64::MAX)),
        &ours(),
    );
    assert!(fetched(&at_floor).is_empty(), "its delay has not come due");
    core.on(answered(1, "cur", DirectoryAnswer::NotFound), secs(16));
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(1),
            descriptor_id: "cur".to_owned(),
        },
        secs(16),
    );
    core.on(
        Input::DirectoryAsked {
            hsdir: hsdir(9),
            descriptor_id: "other".to_owned(),
        },
        secs(16),
    );
    core.on(
        answered(
            9,
            "other",
            DirectoryAnswer::Received {
                revision_counter: Some(OURS),
            },
        ),
        secs(16),
    );
    let at_top = drive(&mut core, secs(60), &mut None, &ours());
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
            open_uploads: OpenUploads::in_flight(vec![super::D0]),
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
/// first fetch is answered. The check settles only when the accepted
/// fetch's window ends; both were silent, and with no confirmed directory
/// answering, their silence does not count: the probe, which arrived,
/// decides. Fails if acceptance leaves the provisional window (the check
/// settles at 75 s), or if it moves every open fetch.
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
    assert!(
        !early
            .actions
            .iter()
            .any(|action| matches!(action, Action::DirectoriesSettled(_))),
        "the accepted fetch is still out"
    );
    assert!(
        matches!(core.status().inbound, Inbound::Publishing { .. }),
        "{:?}",
        core.status().inbound
    );
    let bound = core.on_deadline(secs(100));
    let bound = served(&mut core, bound, secs(100));
    assert_eq!(
        count(&bound, |action| matches!(
            action,
            Action::DirectoriesUnmatched
        )),
        1,
        "both silent, and no confirmed directory answered"
    );
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
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
    // The probe and the fetches, sent as the queue sends them.
    let launched = drive(
        &mut core,
        secs(15),
        &mut Some(sent(1..=8, "cur", 0)),
        &ServiceDescriptor {
            descriptor_id: "prev".to_owned(),
            revision_counter: OURS,
        },
    );
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
    let mut launched = core.on_deadline(secs(15));
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
    assert!(launched.actions.contains(&Action::CheckDirectories));
    let drawn = core.on(
        Input::DirectoriesDrawn {
            fetches: sent(1..=8, "cur", 0),
            ours: None,
            open_uploads: OpenUploads::in_flight(vec![super::D0]),
        },
        secs(15),
    );
    launched.actions.extend(drawn.actions);
    launched
        .actions
        .extend(replied(&mut core, secs(15)).actions);
    assert_eq!(
        probes(&launched),
        1,
        "the dial follows the sample: {launched:?}"
    );
    assert!(
        fetched(&launched).is_empty(),
        "no fetch goes out, and the answer windows are not waited"
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
