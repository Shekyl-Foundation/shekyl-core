// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The directory check's upload-end rules (`TOR_SUPERVISOR.md` §4.5).
//!
//! The check asks every directory a round sent an upload to. What an answer
//! counts for depends on how that upload ended, and an upload still open is
//! asked from the reading taken with the list.

use super::super::super::posture::{Inbound, InboundCause};
use super::super::{
    Action, Core, Counted, DirectoryAnswer, DirectoryFetch, DirectoryReport, Exclusion, Input,
    OpenUploads, Step,
};
use super::directories::{answered, checking, drive, fetched, ours, sent, sent_ended, OURS};
use super::probe::{arrival, probes, published, refetches, republishes, secs, served, uploaded};
use super::replied;
use crate::control::{
    parse_event, parse_service_descriptor, ControlReply, HsDescAction, HsDescContent, HsDescEvent,
    RelayFingerprint, ReplyFramer, ServiceDescriptor, ServiceId, TorEvent, UploadEnd, UploadRounds,
};
use crate::supervisor::{directory_content_input_of, directory_input_of};

/// The round of SO-D12's run 4 (2026-11-14): directories 1 to 4 confirmed
/// holding `"cur"`, and directories 5 to 8 sent `"cur"` with no end ever
/// reported, as Tor reports an upload whose connection failed.
fn run_four() -> Vec<DirectoryFetch> {
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Unfinished, 0));
    fetches
}

pub(super) fn ours_held() -> DirectoryAnswer {
    DirectoryAnswer::Received {
        revision_counter: Some(OURS),
    }
}

/// The lines a judged check said, from the step that judged it.
pub(super) fn settled(step: &Step) -> Vec<DirectoryReport> {
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

/// **A second probe waits out a new round's wait, then asks its uploads**
/// (Rick, 2026-11-15; the brief's B1). The first check misses and the
/// descriptor is refetched; a round starts, and its first upload lands, a
/// second before the second probe is scheduled. That probe is due at 35 s,
/// but it goes out only once the round is `Policy::round_wait` old, at 79 s,
/// and only then is its list drawn: the round's four uploads still open are
/// hung, and asked. Fails if `on_probe_deadline` sends a probe while a round
/// is younger than its wait (the probe at 35 s), or draws the list when the
/// probe is scheduled.
#[test]
fn a_second_probe_waits_out_a_new_rounds_wait() {
    let (mut core, _) = checking(sent(1..=8, "cur", 0));
    for n in 1..=8 {
        core.on(answered(n, "cur", DirectoryAnswer::NotFound), secs(16));
    }
    let first = core.on(arrival(secs(15), secs(18)), secs(18));
    assert_eq!(refetches(&first), 1, "a first miss refetches");
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D0,
        },
        secs(19),
    );
    core.on(
        Input::FirstUploaded {
            descriptor: super::D0,
            draw: 0,
        },
        secs(19),
    );
    let mut again = core.on(Input::DescriptorRefetched { draw: 0 }, secs(20));
    again.actions.extend(replied(&mut core, secs(20)).actions);
    assert!(
        !again.actions.contains(&Action::CheckDirectories),
        "the list waits for the probe"
    );
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Open, 0));
    let mut list = Some(fetches);
    let held = drive(&mut core, secs(78), &mut list, &ours());
    assert_eq!(probes(&held), 0, "held while the round is young: {held:?}");
    assert!(list.is_some(), "no list drawn yet");
    let launched = drive(&mut core, secs(79), &mut list, &ours());
    assert!(list.is_none(), "the list is drawn as the probe goes out");
    assert_eq!(probes(&launched), 1);
    assert_eq!(
        fetched(&launched).len(),
        8,
        "the round's wait has run: its open uploads are asked"
    );
}

/// **The round's own probe asks its uploads still open**: it goes ahead
/// `Policy::round_wait` after the first upload, so an upload open then is
/// hung (§4.5) and its directory is asked. Fails if `directories_drawn`
/// measures the round's age from anything later than its start, or never
/// asks open uploads.
#[test]
fn the_rounds_own_probe_asks_its_uploads_still_open() {
    let mut core = published();
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D0,
        },
        0,
    );
    core.on(
        Input::FirstUploaded {
            descriptor: super::D0,
            draw: 0,
        },
        secs(5),
    );
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
    core.on(uploaded(0), 0);
    let (at, verdict) = missed_twice_by_directories(&mut core, 0);
    assert_eq!(republishes(&verdict), 1, "the first republish goes out");
    let deleted = replied(&mut core, at);
    assert!(deleted.actions.contains(&Action::AddOnion));
    core.on(Input::OnionPublished, at);
    replied(&mut core, at);

    // The republish's own round, judged the same way.
    let round = at + secs(10);
    core.on(uploaded(0), round);
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

/// **`ADD_ONION` forgets the rounds open then.** The driver starts the next
/// publication's rounds afresh, so a round open when the add is sent never
/// ends in this core: kept, it would hold the overdue rule off and be
/// counted stuck. Fails if `route_requests` sends the add without
/// forgetting the open rounds.
#[test]
fn an_add_onion_forgets_the_rounds_open_then() {
    let mut core = published();
    core.on(uploaded(0), 0);
    let (at, verdict) = missed_twice_by_directories(&mut core, 0);
    assert_eq!(republishes(&verdict), 1);
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D1,
        },
        at,
    );
    assert!(!core.rounds.is_empty());
    let deleted = replied(&mut core, at);
    assert!(deleted.actions.contains(&Action::AddOnion));
    assert!(core.rounds.is_empty());
}

/// From a round that ended at `at` with its probe scheduled: two probes,
/// each arriving, and two checks over [`run_four`] whose unconfirmed uploads
/// say nothing, so each is a miss. Returns the verdict's time and step.
fn missed_twice_by_directories(core: &mut Core, at: u64) -> (u64, Step) {
    let check = |core: &mut Core, at: u64| {
        let probe_at = at + secs(15);
        let launched = drive(core, probe_at, &mut Some(run_four()), &ours());
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
    core.on(Input::DescriptorRefetched { draw: 0 }, refetched);
    replied(core, refetched);
    check(core, refetched)
}

/// SO-D12's run 4, onion C: the daemon's own debug lines, verbatim (the
/// fixture's header says where they came from). The run kept no raw `HS_DESC`
/// lines, only these.
const RUN_FOUR: &str =
    include_str!("../../../control/testdata/so_d12_run4_onion_c_daemon_debug.txt");

/// One line of [`RUN_FOUR`], read back from the daemon's Debug form.
pub(super) enum Logged {
    Event(HsDescEvent),
    Ours(ServiceDescriptor),
    /// `HS_DESC_CONTENT`. After a `NOT_FOUND` Tor sends an empty one
    /// (`hs_client.c:1719-1722`), logged with no counter.
    Copy {
        hsdir: RelayFingerprint,
        descriptor_id: String,
        revision_counter: Option<u64>,
    },
}

/// The value after `key=`, up to the next space.
fn logged_field<'a>(line: &'a str, key: &str) -> &'a str {
    let at = line.find(&format!(" {key}=")).expect(key) + key.len() + 2;
    line[at..].split(' ').next().expect(key)
}

/// `None`, `Some("text")` or `Some(RelayFingerprint($HEX))`, as Debug prints them.
fn logged_option(value: &str) -> Option<String> {
    let inner = value.strip_prefix("Some(")?.strip_suffix(')')?;
    let inner = inner
        .strip_prefix("RelayFingerprint($")
        .and_then(|hex| hex.strip_suffix(')'))
        .unwrap_or(inner);
    Some(inner.trim_matches('"').to_owned())
}

pub(super) fn logged(line: &str, address: &ServiceId) -> Option<Logged> {
    let relay = |value: &str| {
        logged_option(value).map(|hex| RelayFingerprint::parse(&hex).expect("a fingerprint"))
    };
    if line.contains("Tor's descriptor event") {
        let action = match logged_field(line, "action") {
            "Created" => HsDescAction::Created,
            "Upload" => HsDescAction::Upload,
            "Uploaded" => HsDescAction::Uploaded,
            "Requested" => HsDescAction::Requested,
            "Received" => HsDescAction::Received,
            "Failed" => HsDescAction::Failed,
            other => panic!("an action this fixture does not hold: {other}"),
        };
        return Some(Logged::Event(HsDescEvent {
            action,
            address: Some(address.clone()),
            hsdir: relay(logged_field(line, "hsdir")),
            descriptor_id: logged_option(logged_field(line, "descriptor_id")),
            reason: logged_option(logged_field(line, "reason")),
        }));
    }
    if line.contains("this onion's current descriptor") {
        return Some(Logged::Ours(ServiceDescriptor {
            descriptor_id: logged_field(line, "descriptor_id").to_owned(),
            revision_counter: logged_field(line, "revision_counter")
                .parse()
                .expect("a counter"),
        }));
    }
    if line.contains("a directory's copy") {
        return Some(Logged::Copy {
            hsdir: relay(logged_field(line, "hsdir")).expect("a directory"),
            descriptor_id: logged_option(logged_field(line, "descriptor_id")).expect("an id"),
            revision_counter: logged_option(logged_field(line, "revision_counter"))
                .map(|counter| counter.parse().expect("a counter")),
        });
    }
    None
}

/// **Run 4, replayed from its own lines: the check now reads C's round as a
/// miss.** C's round uploaded its current descriptor to eight directories,
/// and four never reported an end. Its probe went ahead at the round's wait
/// (07:56:48Z, 60 s after the first `UPLOADED`), asked only the four that
/// confirmed, found our copy at each, and C read Reachable at 07:57:44Z;
/// from 07:59:40Z to 08:04:23Z peers dialling C gave up three times after
/// 105 s waiting for its descriptor. Tor's own refetch asked one of the four,
/// 602A20F9, which never answered.
///
/// The fixture's lines are fed as the driver feeds Tor's: each event to the
/// coalescer when it owns the line, else through `directory_input_of` to
/// the core, and each copy as `directory_content_input_of` makes it, the
/// empty one after a `NOT_FOUND` included. The check draws
/// at the round's wait, as C's did, with the four still open. It now asks
/// all sixteen directories; the four silent ones are missing when their
/// windows pass, the next period's eight are excluded once a fetch names
/// the current descriptor, and four of eight is a first miss. Fails if
/// `UploadRounds` drops uploads still open, or `directories_drawn` leaves
/// the round's hung uploads unasked.
#[test]
fn run_four_replayed_from_its_own_lines_is_a_miss() {
    let address = ServiceId::parse("url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid")
        .expect("a test address");
    let lines: Vec<Logged> = RUN_FOUR
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| logged(line, &address))
        .collect();
    let drawn_at = lines
        .iter()
        .position(|line| matches!(line, Logged::Ours(_)))
        .expect("the check's own descriptor");

    // The round, up to the check.
    let mut rounds = UploadRounds::new(address.clone());
    for line in &lines[..drawn_at] {
        let Logged::Event(event) = line else {
            panic!("the round holds events only");
        };
        assert!(
            rounds.owns_line(event) || event.action == HsDescAction::Created,
            "{event:?}"
        );
        rounds.observe(event);
    }
    assert!(rounds.in_round(), "four uploads never reported");
    let Logged::Ours(ours) = &lines[drawn_at] else {
        unreachable!("found above");
    };
    let unconfirmed: Vec<_> = rounds
        .directories()
        .iter()
        .filter(|upload| upload.descriptor_id == ours.descriptor_id && !upload.ended.confirmed())
        .map(|upload| upload.hsdir)
        .collect();
    assert_eq!(unconfirmed.len(), 4);

    // The core: the round began at 0, its first upload landed at 2 s, and
    // its wait draws the check at 62 s, while the four are still open.
    let mut core = published();
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D0,
        },
        0,
    );
    core.on(
        Input::FirstUploaded {
            descriptor: super::D0,
            draw: 0,
        },
        secs(2),
    );
    let fetches = rounds
        .directories()
        .into_iter()
        .map(|upload| DirectoryFetch { upload, draw: 0 })
        .collect();
    let sent_at = secs(62 + 15);
    let launched = drive(&mut core, sent_at, &mut Some(fetches), ours);
    assert_eq!(probes(&launched), 1);
    assert_eq!(fetched(&launched).len(), 16, "every upload's directory");
    core.on(Input::ProbeDialed { minted_at: sent_at }, sent_at);

    // The answers, in the order C's daemon logged them.
    let mut at = sent_at;
    for line in &lines[drawn_at + 1..] {
        at += secs(1);
        let input = match line {
            Logged::Event(event) if rounds.owns_line(event) => {
                panic!("an upload's line after the round: {event:?}")
            }
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
    let arrived = core.on(arrival(sent_at, at), at);
    assert_eq!(refetches(&arrived), 0, "the silent windows still run");
    let window = core.on_deadline(sent_at + secs(60));
    let window = served(&mut core, window, sent_at + secs(60));
    assert_eq!(refetches(&window), 1, "four of eight: a first miss");
    let report = settled(&window);
    let counted = |wanted: Counted| -> Vec<RelayFingerprint> {
        report
            .iter()
            .filter(|line| line.counted == wanted)
            .map(|line| line.hsdir)
            .collect()
    };
    assert_eq!(counted(Counted::Missing), unconfirmed);
    assert_eq!(counted(Counted::Found).len(), 4);
    assert_eq!(
        counted(Counted::Excluded(Exclusion::OtherDescriptor)).len(),
        8
    );
}

/// A cut round captured from tor 0.4.9.14 (the fixture's header says how):
/// four uploads of each descriptor left unfinished, then a directed fetch of
/// every directory. Verbatim bytes, as tor wrote them to the controller.
const UPLOAD_CUT: &str =
    include_str!("../../../control/testdata/hs_desc_upload_cut_tor_0_4_9_14.txt");

/// [`UPLOAD_CUT`]'s replies after its header, framed as the control client
/// frames them.
fn upload_cut_replies() -> Vec<ControlReply> {
    let mut rest = UPLOAD_CUT;
    while rest.starts_with('#') {
        rest = &rest[rest.find('\n').expect("a header line ends") + 1..];
    }
    let mut framer = ReplyFramer::default();
    framer.push_bytes(rest.as_bytes());
    let mut replies = Vec::new();
    while let Some(reply) = framer.next_reply().expect("tor's own framing") {
        replies.push(reply);
    }
    replies
}

/// **A cut round, from tor's own bytes through the real parser, is a miss.**
/// The capture is run 4's condition made on purpose: a second controller
/// closed the upload circuits to four of each descriptor's eight
/// directories, so those uploads never report an end, and a directed fetch
/// then asked all sixteen. Fed as the driver feeds them (the framer,
/// `parse_event`, the coalescer when it owns the line, else
/// `directory_input_of`; `HS_DESC_CONTENT` through
/// `directory_content_input_of`; our descriptor through
/// `parse_service_descriptor`), with the check drawn at the round's wait
/// while the four are open: the four that confirmed hold our copy, the four
/// cut ones answer `NOT_FOUND` or nothing, and four of eight is a first
/// miss. The capture was taken between 12:00 and 00:00 UTC, when clients
/// ask for `desc_next`. Fails if a cut upload's directory is not asked, or
/// if its `NOT_FOUND` or silence is not counted missing.
#[test]
fn a_cut_round_from_tors_own_bytes_is_a_miss() {
    let replies = upload_cut_replies();
    let address = replies
        .iter()
        .find_map(|reply| {
            reply
                .lines()
                .iter()
                .find_map(|line| line.strip_prefix("ServiceID="))
        })
        .and_then(ServiceId::parse)
        .expect("ADD_ONION's reply names the onion");
    let drawn_at = replies
        .iter()
        .position(|reply| parse_service_descriptor(reply).is_some())
        .expect("the check's own descriptor");
    let ours = parse_service_descriptor(&replies[drawn_at]).expect("found above");

    let mut rounds = UploadRounds::new(address.clone());
    for reply in &replies[..drawn_at] {
        if let Some(TorEvent::HsDesc(event)) = parse_event(reply) {
            rounds.observe(&event);
        }
    }
    assert!(rounds.in_round(), "the cut uploads never report");
    let unconfirmed: Vec<_> = rounds
        .directories()
        .into_iter()
        .filter(|upload| !upload.ended.confirmed())
        .collect();
    assert_eq!(unconfirmed.len(), 8, "four of each descriptor");

    let mut core = published();
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D0,
        },
        0,
    );
    core.on(
        Input::FirstUploaded {
            descriptor: super::D0,
            draw: 0,
        },
        secs(2),
    );
    let fetches = rounds
        .directories()
        .into_iter()
        .map(|upload| DirectoryFetch { upload, draw: 0 })
        .collect();
    let sent_at = secs(62 + 15);
    let launched = drive(&mut core, sent_at, &mut Some(fetches), &ours);
    assert_eq!(fetched(&launched).len(), 16, "every upload's directory");
    core.on(Input::ProbeDialed { minted_at: sent_at }, sent_at);

    let mut at = sent_at;
    let mut asked_for = None;
    for reply in &replies[drawn_at + 1..] {
        at += secs(1) / 10;
        let input = match parse_event(reply) {
            Some(TorEvent::HsDesc(event)) if rounds.owns_line(&event) => {
                panic!("an upload's line after the round: {event:?}")
            }
            Some(TorEvent::HsDesc(event)) => {
                if event.action == HsDescAction::Requested && asked_for.is_none() {
                    asked_for = event.descriptor_id.clone();
                }
                directory_input_of(&event)
            }
            Some(TorEvent::HsDescContent(content)) => directory_content_input_of(&content),
            _ => None,
        };
        if let Some(input) = input {
            core.on(input, at);
        }
    }
    let asked_for = asked_for.expect("a fetch names the descriptor clients ask for");
    core.on(arrival(sent_at, at), at);
    let window = core.on_deadline(sent_at + secs(60));
    let window = served(&mut core, window, sent_at + secs(60));
    assert_eq!(refetches(&window), 1, "four of eight: a first miss");
    let report = settled(&window);
    let cut: Vec<_> = unconfirmed
        .iter()
        .filter(|upload| upload.descriptor_id == asked_for)
        .map(|upload| upload.hsdir)
        .collect();
    let missing: Vec<_> = report
        .iter()
        .filter(|line| line.counted == Counted::Missing)
        .map(|line| line.hsdir)
        .collect();
    assert_eq!(missing, cut, "the cut directories, and only those");
    assert_eq!(
        report
            .iter()
            .filter(|line| line.counted == Counted::Found)
            .count(),
        4
    );
}

/// **An upload still open is asked from the reading taken with the list.**
/// The round's wait schedules the probe, which goes out with four uploads
/// still open, so they are hung. The list's request can queue behind
/// another, and here the descriptor's next pass begins before the list is
/// folded: the live reading now has that descriptor in flight. The list
/// still says those four are open, and it carries the reading taken when it
/// was read. They are asked. Fails if `directories_drawn` reads the live
/// rounds (the four are left in flight, and four directories are asked).
#[test]
fn an_open_upload_is_asked_from_the_reading_taken_with_the_list() {
    let mut core = published();
    core.on(
        Input::UploadRoundStarted {
            descriptor: super::D0,
        },
        0,
    );
    core.on(
        Input::FirstUploaded {
            descriptor: super::D0,
            draw: 0,
        },
        secs(5),
    );
    let mut fetches = sent(1..=4, "cur", 0);
    fetches.extend(sent_ended(5..=8, "cur", UploadEnd::Open, 0));
    let until = secs(5 + 60 + 15);
    let mut taken = Vec::new();
    let mut saw_check = false;
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
                let reading = core.open_uploads(due);
                assert_eq!(reading, OpenUploads::default(), "the round's wait has run");
                // The descriptor read is still out. The descriptor's next
                // pass begins in that gap.
                let next = core.on(
                    Input::UploadRoundStarted {
                        descriptor: super::D0,
                    },
                    due,
                );
                assert!(
                    next.actions.is_empty(),
                    "a round's start sends nothing ahead of the list: {:?}",
                    next.actions
                );
                assert_eq!(
                    core.open_uploads(due),
                    OpenUploads::in_flight(vec![super::D0])
                );
                core.on(
                    Input::DirectoriesDrawn {
                        fetches: fetches.clone(),
                        ours: Some(ours()),
                        open_uploads: reading,
                    },
                    due,
                );
                saw_check = true;
            }
            taken.extend(std::mem::take(&mut actions));
            if core.in_flight().is_none() {
                break;
            }
            actions = replied(&mut core, due).actions;
        }
    }
    assert!(saw_check, "the wait's check drew the list");
    let step = Step {
        actions: taken,
        deadline: core.deadline(),
    };
    assert_eq!(
        fetched(&step).len(),
        8,
        "the hung uploads are asked from the reading taken with the list"
    );
}
