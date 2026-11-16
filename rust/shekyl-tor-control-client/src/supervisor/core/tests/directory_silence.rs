// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! When a fetch with no answer counts as missing (`TOR_SUPERVISOR.md` §4.5;
//! Rick, 2026-11-16).
//!
//! The directories whose upload Tor confirmed are the control group: silence
//! counts only when more than half of this check's fetches of those were
//! answered. Each test is a row of the ruling's table, or one of its edges.
//! Every check here fires at 15 s with its fetches sent then; answers come at
//! 16 s, the probe arrives at 18 s, and the windows end at 75 s.

use super::super::super::posture::Inbound;
use super::super::{Action, Counted, DirectoryAnswer, DirectoryFetch, Exclusion, Input, Step};
use super::directories::{answered, checking, drive, fetched, hsdir, sent, sent_ended};
use super::directory_uploads::{logged, ours_held, settled, Logged};
use super::probe::{arrival, count, published, refetches, secs, served};
use crate::control::{
    HsDescAction, HsDescContent, RelayFingerprint, ServiceId, UploadEnd, UploadRounds,
};
use crate::supervisor::{directory_content_input_of, directory_input_of};

/// Confirmed uploads to directories `confirmed`, and uploads that never
/// reported an end to `unfinished`, all of `"cur"`, the descriptor each
/// check's fetches ask for.
fn round(
    confirmed: std::ops::RangeInclusive<u8>,
    unfinished: std::ops::RangeInclusive<u8>,
) -> Vec<DirectoryFetch> {
    let mut fetches = sent(confirmed, "cur", 0);
    fetches.extend(sent_ended(unfinished, "cur", UploadEnd::Unfinished, 0));
    fetches
}

/// The check over `fetches`: `found` return our copy and `not_found` answer
/// `NOT_FOUND` at 16 s; every other directory is silent. The probe arrives
/// at 18 s and the windows end at 75 s. Returns the step that judged.
fn judged(fetches: Vec<DirectoryFetch>, found: &[u8], not_found: &[u8]) -> Step {
    let (mut core, asked) = checking(fetches);
    assert!(!asked.is_empty());
    for &n in found {
        core.on(answered(n, "cur", ours_held()), secs(16));
    }
    for &n in not_found {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    core.on(arrival(secs(15), secs(18)), secs(18));
    let window = core.on_deadline(secs(75));
    served(&mut core, window, secs(75))
}

fn counted(step: &Step, wanted: Counted) -> Vec<RelayFingerprint> {
    settled(step)
        .iter()
        .filter(|line| line.counted == wanted)
        .map(|line| line.hsdir)
        .collect()
}

fn unmatched(step: &Step) -> bool {
    count(step, |action| {
        matches!(action, Action::DirectoriesUnmatched)
    }) == 1
}

/// **Run 4: the confirmed directories answer, so silence counts** (the
/// table's first row). Four confirmed uploads hold our copy and four that
/// never reported are silent: the fetch path is shown working, the four are
/// missing, and four of eight is a miss. Fails if `silence_counts` requires
/// answers from every fetch rather than from the confirmed ones.
#[test]
fn run_four_silence_counts_when_the_confirmed_directories_answer() {
    let step = judged(round(1..=4, 5..=8), &[1, 2, 3, 4], &[]);
    assert_eq!(refetches(&step), 1, "four of eight: a miss");
    assert_eq!(
        counted(&step, Counted::Missing),
        (5..=8).map(hsdir).collect::<Vec<_>>()
    );
}

/// **Worse than run 4 is still a miss** (the table's second row). Three
/// confirmed uploads hold our copy and five never reported, all silent:
/// three of eight. Under "answered at least as many as silent" this read
/// three of three, Held, and the more directories lacked the descriptor the
/// less the check saw it (Rick, 2026-11-16). Fails if `silence_counts`
/// weighs answers against all silent fetches.
#[test]
fn worse_than_run_four_is_still_a_miss() {
    let step = judged(round(1..=3, 4..=8), &[1, 2, 3], &[]);
    assert_eq!(refetches(&step), 1, "three of eight: a miss");
    assert_eq!(counted(&step, Counted::Missing).len(), 5);
}

/// **The control node's check: no confirmed directory answers, so nothing
/// silent counts** (the table's third row; the floor device's control node,
/// 2026-11-15, start 2). Three confirmed uploads and five that never
/// reported, every fetch silent: this node's own fetch path is the likeliest
/// fault. The check counts nothing and the probe, which arrived, decides:
/// Reachable. Fails if `expire` decides silence as missing at once (Lost,
/// and a refetch).
#[test]
fn with_no_confirmed_directory_answering_silence_counts_for_nothing() {
    let step = judged(round(1..=3, 4..=8), &[], &[]);
    assert_eq!(refetches(&step), 0);
    assert!(unmatched(&step), "the probe alone decides");
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        8,
        "confirmed or not"
    );
}

/// **One guard failing: silence still counts, and the check usually holds**
/// (the table's fourth row). Of six confirmed uploads four answer and two
/// are silent, and of two that never reported one answers: more than half of
/// the confirmed directories answered, so the three silent ones are
/// missing. Five of eight hold our copy: Held. Fails if `silence_counts`
/// needs every confirmed directory to answer.
#[test]
fn one_failing_guard_lets_silence_count_and_the_check_holds() {
    let step = judged(round(1..=6, 7..=8), &[1, 2, 3, 4, 7], &[]);
    assert_eq!(refetches(&step), 0, "five of eight: Held");
    assert_eq!(
        counted(&step, Counted::Missing),
        [hsdir(5), hsdir(6), hsdir(8)]
    );
}

/// **An attacker who silences every fetch leaves the probe to decide** (the
/// table's fifth row). Eight confirmed uploads, every fetch silent: nothing
/// is counted, as before the directory check existed. Fails if silence
/// counts with no answer at all.
#[test]
fn every_fetch_silenced_leaves_the_probe_to_decide() {
    let step = judged(sent(1..=8, "cur", 0), &[], &[]);
    assert!(unmatched(&step));
    assert_eq!(refetches(&step), 0, "the probe arrived");
}

/// **A minority of the confirmed directories answering does not make
/// silence count** (the table's sixth row). A hostile directory answers
/// `NOT_FOUND` while the three other confirmed ones are silent: one of four
/// answered, so the silent fetches are excluded, and only the hostile
/// directory's own answer counts, as it already could. Fails if
/// `silence_counts` takes one answer as proof (the brief's rule C).
#[test]
fn a_hostile_minority_answering_does_not_make_silence_count() {
    let step = judged(round(1..=4, 5..=8), &[], &[1]);
    assert_eq!(counted(&step, Counted::Missing), [hsdir(1)]);
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        7
    );
}

/// **Exactly half of the confirmed directories answering is not more than
/// half.** Two of four confirmed answer with our copy; the rest are silent
/// and excluded: two of two, Held. Fails if `silence_counts` takes half as
/// enough (two of eight, a miss).
#[test]
fn half_of_the_confirmed_directories_answering_is_not_enough() {
    let step = judged(round(1..=4, 5..=8), &[1, 2], &[]);
    assert_eq!(refetches(&step), 0);
    assert_eq!(counted(&step, Counted::Found).len(), 2);
    assert!(counted(&step, Counted::Missing).is_empty());
}

/// **With no confirmed upload of the asked descriptor, only an explicit
/// `NOT_FOUND` counts.** Eight uploads that never reported: two answer
/// `NOT_FOUND`, six are silent. The silent six are excluded, and the two
/// are missing: a miss. Fails if silence counts with an empty control group.
#[test]
fn with_no_confirmed_upload_only_not_found_counts() {
    let step = judged(
        sent_ended(1..=8, "cur", UploadEnd::Unfinished, 0),
        &[],
        &[1, 2],
    );
    assert_eq!(counted(&step, Counted::Missing), [hsdir(1), hsdir(2)]);
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        6
    );
    assert_eq!(refetches(&step), 1);
}

/// **An answer from a directory of the other descriptor proves nothing**
/// (Rick, 2026-11-16; the control node's check). A fetch of a directory that
/// took the next descriptor names the current one, which that directory
/// never held, and gets `NOT_FOUND`, as at the control node's start 2; it
/// arrives with no `REQUESTED` before it, so it is recorded and its
/// directory excluded. Of the current descriptor's two confirmed
/// directories one answers with our copy and one is silent: one of two is
/// not more than half, so the silent ones are excluded and one of one holds
/// our copy. Fails if `silence_counts` takes the other descriptor's
/// directories into the control group (two of three answered: the seven
/// silent ones would count, one of eight, a miss).
#[test]
fn an_answer_from_the_other_descriptors_directory_proves_nothing() {
    let mut fetches = sent(9..=9, "next", 0);
    fetches.extend(round(1..=2, 3..=8));
    let (mut core, asked) = checking(fetches);
    assert_eq!(asked.len(), 9);
    core.on(answered(9, "cur", DirectoryAnswer::NotFound), secs(16));
    core.on(answered(1, "cur", ours_held()), secs(16));
    core.on(arrival(secs(15), secs(18)), secs(18));
    let window = core.on_deadline(secs(75));
    let step = served(&mut core, window, secs(75));
    assert_eq!(refetches(&step), 0, "{:?}", settled(&step));
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::OtherDescriptor)),
        [hsdir(9)]
    );
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        7
    );
}

/// **A late answer counts for the earlier silent ones** (the brief's test 7).
/// The fourth confirmed directory's fetch is drawn last: it goes out at 60 s
/// and answers at 80 s, after the other windows passed at 75 s. The check
/// settles only once every directory is decided, so by then three of the
/// four confirmed directories have answered, and the silent ones are
/// missing. Fails if `expire` decides each silent fetch when its own window
/// passes (two of four confirmed had answered then, and the silent ones
/// would be excluded).
#[test]
fn a_late_answer_counts_for_the_earlier_silent_ones() {
    let mut fetches = sent(1..=3, "cur", 0);
    fetches.extend(sent(4..=4, "cur", u64::MAX));
    fetches.extend(sent_ended(5..=6, "cur", UploadEnd::Unfinished, 0));
    let (mut core, asked) = checking(fetches);
    assert_eq!(asked.len(), 5, "the fourth waits for its own delay");
    core.on(answered(1, "cur", ours_held()), secs(16));
    core.on(answered(2, "cur", ours_held()), secs(16));
    core.on(arrival(secs(15), secs(18)), secs(18));
    let sent_late = core.on_deadline(secs(60));
    let sent_late = served(&mut core, sent_late, secs(60));
    assert_eq!(fetched(&sent_late), [hsdir(4)]);
    let window = core.on_deadline(secs(75));
    let window = served(&mut core, window, secs(75));
    assert!(
        !window
            .actions
            .iter()
            .any(|action| matches!(action, Action::DirectoriesSettled(_))),
        "the fourth is still out"
    );
    let step = core.on(answered(4, "cur", ours_held()), secs(80));
    let step = served(&mut core, step, secs(80));
    assert_eq!(
        counted(&step, Counted::Missing),
        [hsdir(3), hsdir(5), hsdir(6)],
        "three of four confirmed answered: the silent ones count"
    );
    assert_eq!(refetches(&step), 1, "three of six: a miss");
}

/// The control node's start 2 on the floor device (2026-11-15): its lines
/// (the fixture's header says where they came from).
const CONTROL_START_TWO: &str =
    include_str!("../../../control/testdata/tsr_pi_2026_11_15_control_start2_daemon_debug.txt");

/// **The control node's `Lost`, replayed from its own lines, reads no
/// directory.** At start 2 the probe arrived, Tor warned a guard was failing
/// a large share of its circuits, one fetch at a directory of the other
/// descriptor got `NOT_FOUND`, and the eight fetches of the asked
/// descriptor's directories were silent, three confirmed among them: the
/// check read Lost (0 of 8) and the probe was refetched. Fed as the driver
/// feeds Tor's lines, with the check drawn where that run drew it, the
/// silent eight are now excluded and the probe decides: Reachable. The one
/// other-descriptor answer came after its `REQUESTED` had excluded that
/// directory, so it is not recorded at all. Fails if a silent fetch is
/// decided as missing when its window passes (0 of 8, Lost).
#[test]
fn the_control_nodes_lost_check_replayed_reads_no_directory() {
    let address = ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
        .expect("a test address");
    let lines: Vec<Logged> = CONTROL_START_TWO
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| logged(line, &address))
        .collect();
    let drawn_at = lines
        .iter()
        .position(|line| matches!(line, Logged::Ours(_)))
        .expect("the check's own descriptor");
    let mut rounds = UploadRounds::new(address.clone());
    for line in &lines[..drawn_at] {
        if let Logged::Event(event) = line {
            rounds.observe(event);
        }
    }
    let Logged::Ours(ours_then) = &lines[drawn_at] else {
        unreachable!("found above");
    };
    let asked_for = lines[drawn_at + 1..]
        .iter()
        .find_map(|line| match line {
            Logged::Event(event) if event.action == HsDescAction::Requested => {
                event.descriptor_id.clone()
            }
            _ => None,
        })
        .expect("a fetch names the descriptor clients ask for");
    let fetches: Vec<DirectoryFetch> = rounds
        .directories(&[])
        .into_iter()
        .map(|upload| DirectoryFetch { upload, draw: 0 })
        .collect();
    assert_eq!(fetches.len(), 16, "both descriptors, each in its own round");
    let confirmed_asked = fetches
        .iter()
        .filter(|fetch| fetch.upload.descriptor_id == asked_for)
        .filter(|fetch| fetch.upload.ended.confirmed())
        .count();
    assert_eq!(
        confirmed_asked, 3,
        "the asked descriptor's confirmed uploads"
    );

    let (mut core, asked) = checking_with(fetches, ours_then);
    assert_eq!(asked.len(), 16);
    let mut at = secs(15);
    for line in &lines[drawn_at + 1..] {
        at += secs(1);
        let input = match line {
            Logged::Event(event) if rounds.owns_line(event) => continue,
            Logged::Event(event) => directory_input_of(event),
            Logged::Copy {
                hsdir,
                descriptor_id,
                revision_counter,
            } => directory_content_input_of(&HsDescContent {
                address: Some(address.clone()),
                descriptor_id: Some(descriptor_id.clone()),
                hsdir: Some(*hsdir),
                revision_counter: *revision_counter,
            }),
            Logged::Ours(_) => panic!("one check"),
        };
        if let Some(input) = input {
            core.on(input, at);
        }
    }
    core.on(arrival(secs(15), at), at);
    let window = core.on_deadline(secs(75));
    let step = served(&mut core, window, secs(75));
    assert!(unmatched(&step), "{:?}", settled(&step));
    assert_eq!(refetches(&step), 0);
    assert!(matches!(core.status().inbound, Inbound::Reachable { .. }));
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        8
    );
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::OtherDescriptor)).len(),
        8
    );
}

/// [`checking`] with this service's own descriptor given.
fn checking_with(
    fetches: Vec<DirectoryFetch>,
    ours_then: &crate::control::ServiceDescriptor,
) -> (super::super::Core, Vec<RelayFingerprint>) {
    let mut core = published();
    core.on(super::probe::uploaded(0), 0);
    let taken = drive(&mut core, secs(15), &mut Some(fetches), ours_then);
    core.on(
        Input::ProbeDialed {
            minted_at: secs(15),
        },
        secs(15),
    );
    (core, fetched(&taken))
}

/// The slow node's start 3 on the floor device (2026-11-16): its lines (the
/// fixture's header says where they came from).
const SLOW_START_THREE: &str =
    include_str!("../../../control/testdata/tsr_pi_2026_11_16_slow_start3_daemon_debug.txt");

/// **The slow node's blind check, replayed: the asked descriptor's round is
/// listed** (Rick, 2026-11-16). Tor uploaded the descriptor clients do not
/// ask for, every upload confirmed, then began the one they ask for, and on
/// the 48 kbit link none of its eight uploads reported an end. The check
/// listed only the first descriptor's directories and counted nothing.
/// Fed through the tracker to the probe at 04:45:09Z, when the asked
/// descriptor's round was 60 s old (the core's reading: no round young), the
/// list now holds its eight directories, every upload open, beside the other
/// descriptor's eight. With no confirmed directory of the asked descriptor,
/// their silence is excluded: the check reports it heard nothing from them
/// (`Exclusion::Silent`) instead of having no directory of theirs at all,
/// and the probe, which missed, decides. Fails if `Descriptor::directories`
/// lists an open round only once it has a success (the list holds only the
/// other descriptor's eight, as the run's did).
#[test]
fn the_slow_nodes_blind_check_replayed_lists_the_asked_descriptor() {
    let address = ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
        .expect("a test address");
    let lines: Vec<Logged> = SLOW_START_THREE
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| logged(line, &address))
        .collect();
    let drawn_at = lines
        .iter()
        .position(|line| matches!(line, Logged::Ours(_)))
        .expect("the check's own descriptor");
    let mut rounds = UploadRounds::new(address.clone());
    for line in &lines[..drawn_at] {
        if let Logged::Event(event) = line {
            rounds.observe(event);
        }
    }
    let Logged::Ours(ours_then) = &lines[drawn_at] else {
        unreachable!("found above");
    };
    let asked_for = lines[drawn_at + 1..]
        .iter()
        .find_map(|line| match line {
            Logged::Event(event) if event.action == HsDescAction::Requested => {
                event.descriptor_id.clone()
            }
            _ => None,
        })
        .expect("a fetch names the descriptor clients ask for");
    let list = rounds.directories(&[]);
    let asked: Vec<_> = list
        .iter()
        .filter(|upload| upload.descriptor_id == asked_for)
        .collect();
    assert_eq!(asked.len(), 8, "the asked descriptor's round is listed");
    assert!(asked.iter().all(|upload| upload.ended == UploadEnd::Open));
    let other = list.len() - asked.len();
    assert_eq!(other, 8);
    let first_asked = asked[0].hsdir;

    let fetches: Vec<DirectoryFetch> = list
        .into_iter()
        .map(|upload| DirectoryFetch { upload, draw: 0 })
        .collect();
    let (mut core, sent) = checking_with(fetches, ours_then);
    assert_eq!(sent.len(), 16, "every listed directory is asked");
    core.on(
        Input::DirectoryAsked {
            hsdir: first_asked,
            descriptor_id: asked_for.clone(),
        },
        secs(16),
    );
    let window = core.on_deadline(secs(75));
    let step = served(&mut core, window, secs(75));
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::Silent)).len(),
        8,
        "the asked descriptor's directories, asked and silent"
    );
    assert_eq!(
        counted(&step, Counted::Excluded(Exclusion::OtherDescriptor)).len(),
        8
    );
}

/// The control node's start 4 on the floor device (2026-11-15): its lines
/// (the fixture's header says where they came from).
const CONTROL_START_FOUR: &str =
    include_str!("../../../control/testdata/tsr_pi_2026_11_15_control_start4_daemon_debug.txt");

/// **A blind check, replayed from its own lines, now holds the descriptor
/// clients ask for** (the brief's test 2). Tor uploaded the current
/// descriptor at 18:28:59Z and the next one at 18:29:06Z, and its client
/// asked for the next one. Coalesced as one round, the next descriptor's
/// first `UPLOAD` ended the current one's round with three uploads still
/// open, and the check drawn then held only the current descriptor's
/// directories: it counted nothing. Kept per descriptor, the list drawn
/// once both rounds are 60 s old holds the asked descriptor's eight
/// directories, seven of them confirmed, and the current descriptor's late end at
/// 18:29:06Z closes its own upload instead of being lost. Fails if an
/// `UPLOAD` of one descriptor ends the other's round.
#[test]
fn a_blind_check_replayed_now_holds_the_asked_descriptor() {
    let address = ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
        .expect("a test address");
    let mut rounds = UploadRounds::new(address.clone());
    let mut asked_for = None;
    for line in CONTROL_START_FOUR
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        if let Some(Logged::Event(event)) = logged(line, &address) {
            if event.action == HsDescAction::Requested && asked_for.is_none() {
                asked_for = event.descriptor_id.clone();
            }
            rounds.observe(&event);
        }
    }
    let asked_for = asked_for.expect("Tor's client named the descriptor it asks for");
    let list = rounds.directories(&[]);
    let asked: Vec<_> = list
        .iter()
        .filter(|upload| upload.descriptor_id == asked_for)
        .collect();
    assert_eq!(asked.len(), 8, "the asked descriptor's directories");
    assert_eq!(
        asked
            .iter()
            .filter(|upload| upload.ended.confirmed())
            .count(),
        7,
        "seven confirmed by then; one never reported"
    );
    let other: Vec<_> = list
        .iter()
        .filter(|upload| upload.descriptor_id != asked_for)
        .collect();
    assert_eq!(other.len(), 8);
    assert_eq!(
        other
            .iter()
            .filter(|upload| upload.ended.confirmed())
            .count(),
        6,
        "the current descriptor's late end closed its own upload"
    );
    assert_eq!(
        other
            .iter()
            .filter(|upload| upload.ended == UploadEnd::Open)
            .count(),
        2
    );
}
