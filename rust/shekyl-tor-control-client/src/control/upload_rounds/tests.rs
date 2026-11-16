// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::super::events::{parse_event, HsDescAction, HsDescEvent, TorEvent};
use super::super::framing::ReplyFramer;
use super::super::onion::ServiceId;
use super::super::vanguards::RelayFingerprint;
use super::{DescriptorKey, RoundMark, RoundUpload, UploadEnd, UploadRounds};

/// The throwaway onion of the 2026-10-16 capture (`DiscardPK`; the key is gone).
const CAPTURED_ONION: &str = "url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid";

/// The captured first round of a new service: both `CREATED`s, sixteen
/// `UPLOAD`s (two descriptors, eight HSDirs each), then the twelve
/// `UPLOADED`s that arrived within the capture.
const CAPTURED_ROUND: &str = include_str!("../testdata/hs_desc_round_tor_0_4_9_13.txt");

const FIRST: DescriptorKey = DescriptorKey(0);
const SECOND: DescriptorKey = DescriptorKey(1);
const THIRD: DescriptorKey = DescriptorKey(2);

/// Every descriptor these tests key, all with their open round young: a
/// round is listed only once it has a success. The tests of an older
/// round pass `OLD`.
const YOUNG: &[DescriptorKey] = &[FIRST, SECOND, THIRD, DescriptorKey(3)];

/// No open round young: every open round is listed.
const OLD: &[DescriptorKey] = &[];

fn hs_desc_event(line: &str) -> HsDescEvent {
    let mut framer = ReplyFramer::default();
    framer.push_bytes(format!("650 {line}\r\n").as_bytes());
    let reply = framer
        .next_reply()
        .expect("frames")
        .expect("one complete reply");
    match parse_event(&reply).expect("a 650 event") {
        TorEvent::HsDesc(desc) => desc,
        other => panic!("not HS_DESC: {other:?}"),
    }
}

fn tracker() -> UploadRounds {
    UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("the captured address"))
}

/// An event of `descriptor` at directory `hsdir`; `None` for an end that
/// names no descriptor, as `UPLOADED` does.
fn event(action: HsDescAction, hsdir: u8, descriptor: Option<&str>) -> HsDescEvent {
    HsDescEvent {
        action,
        address: ServiceId::parse(CAPTURED_ONION),
        hsdir: Some(RelayFingerprint::from_bytes([hsdir; 20])),
        descriptor_id: descriptor.map(str::to_owned),
        reason: None,
    }
}

fn upload(hsdir: u8, descriptor: &str) -> HsDescEvent {
    event(HsDescAction::Upload, hsdir, Some(descriptor))
}

fn uploaded(hsdir: u8) -> HsDescEvent {
    event(HsDescAction::Uploaded, hsdir, None)
}

/// A `FAILED` that names no descriptor: an upload's end.
fn failed(hsdir: u8) -> HsDescEvent {
    event(HsDescAction::Failed, hsdir, None)
}

fn created(descriptor: &str) -> HsDescEvent {
    HsDescEvent {
        action: HsDescAction::Created,
        address: ServiceId::parse(CAPTURED_ONION),
        hsdir: None,
        descriptor_id: Some(descriptor.to_owned()),
        reason: None,
    }
}

fn ended(
    descriptor: DescriptorKey,
    uploaded: u32,
    failed: u32,
    refused: u32,
    unfinished: u32,
) -> RoundMark {
    RoundMark::Ended {
        descriptor,
        uploaded,
        failed,
        refused,
        unfinished,
    }
}

fn to(hsdir: u8, descriptor: &str, key: DescriptorKey, ended: UploadEnd) -> RoundUpload {
    RoundUpload {
        hsdir: RelayFingerprint::from_bytes([hsdir; 20]),
        descriptor_id: descriptor.to_owned(),
        descriptor: key,
        ended,
    }
}

/// **The captured first round is two rounds, one per descriptor.** Tor
/// built the current descriptor, then the next, and uploaded each to its
/// eight directories; six of each confirmed within the capture. Each
/// round triggers once and stays open for its two missing ends, and the
/// check's list holds both, the current descriptor's first. Fails if one
/// round holds both descriptors (one `Started`, one trigger), or if the
/// `CREATED` order does not set the keys.
#[test]
fn the_captured_first_round_is_one_round_per_descriptor() {
    let mut rounds = tracker();
    let marks: Vec<RoundMark> = CAPTURED_ROUND
        .lines()
        .filter_map(|line| line.strip_prefix("650 "))
        .map(hs_desc_event)
        .flat_map(|desc| rounds.observe(&desc))
        .collect();
    assert_eq!(
        marks,
        [
            RoundMark::Started { descriptor: FIRST },
            RoundMark::Started { descriptor: SECOND },
            RoundMark::FirstUploaded { descriptor: FIRST },
            RoundMark::FirstUploaded { descriptor: SECOND },
        ]
    );
    assert!(
        rounds.in_round(),
        "two of each descriptor's uploads had not ended"
    );
    let list = rounds.directories(YOUNG);
    assert_eq!(list.len(), 16);
    assert!(list[..8]
        .iter()
        .all(|upload| upload.descriptor == FIRST && upload.descriptor_id.starts_with("GOkbpj")));
    assert!(list[8..].iter().all(|upload| upload.descriptor == SECOND));
    for half in [&list[..8], &list[8..]] {
        assert_eq!(
            half.iter()
                .filter(|upload| upload.ended.confirmed())
                .count(),
            6
        );
    }
}

/// **Split passes keep their own rounds** (the brief's test 1; the floor
/// device's runs of 2026-11-15). The current descriptor's pass begins
/// and one of its uploads ends; the next descriptor's pass begins after
/// that. Its `UPLOAD` neither ends nor joins the current one's round: the
/// current round's late `UPLOADED` closes its own upload, and the list
/// holds both descriptors. Fails if an `UPLOAD` of one descriptor ends
/// the other's round (the late end then closes nothing, and the current
/// descriptor's upload is unfinished).
#[test]
fn split_passes_keep_their_own_rounds() {
    use UploadEnd::{Open, Uploaded as Done};
    let mut rounds = tracker();
    assert_eq!(
        rounds.observe(&upload(1, "cur")),
        [RoundMark::Started { descriptor: FIRST }]
    );
    rounds.observe(&upload(2, "cur"));
    assert_eq!(
        rounds.observe(&uploaded(1)),
        [RoundMark::FirstUploaded { descriptor: FIRST }]
    );
    assert_eq!(
        rounds.observe(&upload(3, "next")),
        [RoundMark::Started { descriptor: SECOND }],
        "the next descriptor's pass starts a round of its own"
    );
    rounds.observe(&upload(4, "next"));
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, Done), to(2, "cur", FIRST, Open)],
        "the next descriptor has no success yet"
    );
    assert_eq!(
        rounds.observe(&uploaded(2)),
        [ended(FIRST, 2, 0, 0, 0)],
        "the late end closes the current descriptor's own upload"
    );
    assert_eq!(
        rounds.observe(&uploaded(3)),
        [RoundMark::FirstUploaded { descriptor: SECOND }]
    );
    assert_eq!(
        rounds.directories(YOUNG),
        [
            to(1, "cur", FIRST, Done),
            to(2, "cur", FIRST, Done),
            to(3, "next", SECOND, Done),
            to(4, "next", SECOND, Open),
        ]
    );
}

/// **A pass is tallied whole, across the other descriptor's upload** (the
/// brief's test 3). One upload of the current descriptor fails, then the
/// next descriptor's pass begins, then the current one's second upload
/// lands: coalesced as one round, the first pass ended at the next
/// descriptor's `UPLOAD` with nothing uploaded, a failed round, and its
/// late success closed nothing. Kept apart, the pass ends with one
/// uploaded and one failed. Likewise a refused majority is counted over
/// the whole pass: three refusals of three, where the cut pass counted
/// one of three, not a majority. Fails if an `UPLOAD` of one descriptor
/// ends the other's round.
#[test]
fn a_pass_is_tallied_whole_across_the_other_descriptors_upload() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&failed(1));
    assert_eq!(
        rounds.observe(&upload(3, "next")),
        [RoundMark::Started { descriptor: SECOND }],
        "the current descriptor's pass is not cut"
    );
    assert_eq!(
        rounds.observe(&uploaded(2)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 1, 0, 0)
        ]
    );

    let refusal = |hsdir: u8| HsDescEvent {
        reason: Some("UPLOAD_REJECTED".to_owned()),
        ..event(HsDescAction::Failed, hsdir, Some("cur"))
    };
    let mut rounds = tracker();
    for hsdir in 1..=3 {
        rounds.observe(&upload(hsdir, "cur"));
    }
    rounds.observe(&refusal(1));
    rounds.observe(&upload(4, "next"));
    rounds.observe(&refusal(2));
    assert_eq!(
        rounds.observe(&refusal(3)),
        [ended(FIRST, 0, 3, 3, 0)],
        "three refused of three: the whole pass"
    );
}

/// A round ends when every upload it began has ended, and the next one
/// starts fresh. Both descriptors went to directory 1; its first end is
/// the upload that began first. Fails if a second success triggers
/// again, or the next round does not.
#[test]
fn a_round_ends_when_every_upload_has_ended_and_the_next_one_starts_fresh() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&upload(1, "next"));
    assert!(rounds.observe(&failed(2)).is_empty());
    assert_eq!(
        rounds.observe(&uploaded(1)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 1, 0, 0)
        ]
    );
    assert_eq!(
        rounds.observe(&uploaded(1)),
        [
            RoundMark::FirstUploaded { descriptor: SECOND },
            ended(SECOND, 1, 0, 0, 0)
        ]
    );
    assert!(!rounds.in_round());
    assert_eq!(
        rounds.observe(&upload(3, "cur")),
        [RoundMark::Started { descriptor: FIRST }]
    );
    assert_eq!(
        rounds.observe(&uploaded(3)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ]
    );
}

#[test]
fn a_round_with_no_success_ends_with_none_uploaded() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    assert_eq!(rounds.observe(&failed(1)), [ended(FIRST, 0, 1, 0, 0)]);
}

/// A fetch of our own descriptor (the probe's `HSFETCH` after a miss)
/// changes no round, even one open on the same HSDir: `REQUESTED` and
/// `RECEIVED` are not upload actions, and a fetch's `FAILED` carries the
/// descriptor id. Lines in the forms tor 0.4.9 writes
/// (`control_events.c`, `event_hs_descriptor_receive_end`). Counting a
/// fetch's `FAILED` as an upload's would end the round with no success
/// and republish for nothing (Rick, 2026-10-29).
#[test]
fn a_fetch_of_our_own_descriptor_changes_no_round() {
    let hsdir = "$9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor";
    let desc = "GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY";
    let mut rounds = tracker();
    // Nothing open: a fetch's events start nothing.
    for line in [
        format!("HS_DESC REQUESTED {CAPTURED_ONION} NO_AUTH {hsdir} {desc}"),
        format!("HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {hsdir} {desc} REASON=NOT_FOUND"),
        format!("HS_DESC RECEIVED {CAPTURED_ONION} NO_AUTH {hsdir} {desc}"),
    ] {
        assert!(rounds.observe(&hs_desc_event(&line)).is_empty(), "{line}");
    }
    assert!(!rounds.in_round());
    // A round open on that very HSDir: the fetch's FAILED closes nothing.
    let upload = format!("HS_DESC UPLOAD {CAPTURED_ONION} UNKNOWN {hsdir} {desc}");
    assert_eq!(
        rounds.observe(&hs_desc_event(&upload)),
        [RoundMark::Started { descriptor: FIRST }]
    );
    for line in [
        format!("HS_DESC REQUESTED {CAPTURED_ONION} NO_AUTH {hsdir} {desc}"),
        format!("HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {hsdir} {desc} REASON=NOT_FOUND"),
        format!("HS_DESC RECEIVED {CAPTURED_ONION} NO_AUTH {hsdir} {desc}"),
    ] {
        assert!(rounds.observe(&hs_desc_event(&line)).is_empty(), "{line}");
    }
    assert!(rounds.in_round(), "the upload is still open");
    let uploaded = format!("HS_DESC UPLOADED {CAPTURED_ONION} UNKNOWN {hsdir}");
    assert_eq!(
        rounds.observe(&hs_desc_event(&uploaded)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ],
        "the round ends on its own upload, with nothing failed"
    );
}

/// An upload whose end never arrives does not wedge the coalescer: the
/// descriptor's next pass ends the incomplete round and can trigger again
/// (Copilot on #1091).
#[test]
fn an_incomplete_round_ends_at_the_next_pass_and_the_next_round_triggers() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&uploaded(1));
    // HSDir 2 never reports. The next pass's first upload ends this one.
    assert_eq!(
        rounds.observe(&upload(3, "cur")),
        [
            ended(FIRST, 1, 0, 0, 1),
            RoundMark::Started { descriptor: FIRST }
        ]
    );
    assert_eq!(
        rounds.observe(&uploaded(3)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ]
    );
}

/// **A second `UPLOAD` of a descriptor to a directory its open round
/// already sent to is its next pass.** One pass never names a directory
/// twice (tor 0.4.9.14 `hs_common.c:1316`), and a new pass first closes
/// the descriptor's pending uploads, unreported (`hs_service.c:3293`).
/// So a pass none of whose uploads ended is still told from the next:
/// the round ends with its uploads unfinished, and the next pass is a
/// round of its own. Fails if `new_pass` looks only at ended uploads
/// (the second pass joins the first, and its success lands in a round
/// that already counts the cancelled uploads).
#[test]
fn a_new_pass_to_the_same_directory_ends_the_round() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    assert_eq!(
        rounds.observe(&upload(1, "cur")),
        [
            ended(FIRST, 0, 0, 0, 2),
            RoundMark::Started { descriptor: FIRST }
        ]
    );
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&uploaded(1));
    assert_eq!(
        rounds.observe(&uploaded(2)),
        [ended(FIRST, 2, 0, 0, 0)],
        "the second pass is a whole round"
    );
}

/// **A round that never ends does not stall the next** (Rick,
/// 2026-10-29). A pass none of whose uploads ended, to directories the
/// next pass does not repeat, cannot be told from its own late uploads by
/// `UPLOAD` alone, so those uploads join it; the supervisor counts it as
/// stuck at five minutes and the driver ends that descriptor's round,
/// after which the next `UPLOAD` starts a round of its own and triggers.
/// Fails if `end_round` ends nothing, or ends the other descriptor's.
#[test]
fn a_round_that_never_ends_does_not_stall_the_next() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&upload(5, "next"));
    assert!(
        rounds.observe(&upload(3, "cur")).is_empty(),
        "indistinguishable from the round's own uploads"
    );
    // The stuck path: the supervisor counts it, the driver ends it.
    assert_eq!(rounds.end_round(FIRST), Some(ended(FIRST, 0, 0, 0, 3)));
    assert_eq!(rounds.end_round(FIRST), None, "nothing left open");
    assert!(rounds.in_round(), "the other descriptor's round stands");
    assert_eq!(
        rounds.observe(&upload(4, "cur")),
        [RoundMark::Started { descriptor: FIRST }],
        "the next round is a round of its own"
    );
    assert_eq!(
        rounds.observe(&uploaded(4)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ]
    );
}

/// After the sink drops events, `resync` ends every open round at once,
/// and the next pass starts a round that triggers.
#[test]
fn resync_ends_every_round_whose_ends_were_lost() {
    let mut rounds = tracker();
    assert!(rounds.resync().is_empty(), "nothing open");
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&upload(3, "next"));
    assert_eq!(
        rounds.resync(),
        [ended(FIRST, 0, 0, 0, 2), ended(SECOND, 0, 0, 0, 1)]
    );
    assert!(!rounds.in_round());
    assert_eq!(
        rounds.observe(&upload(1, "cur")),
        [RoundMark::Started { descriptor: FIRST }]
    );
    assert_eq!(
        rounds.observe(&uploaded(1)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ]
    );
}

/// A fetch's `FAILED` (a descriptor id and no upload's reason), another
/// address's events, and an end for an HSDir with no open upload close
/// nothing.
#[test]
fn only_an_uploads_own_end_closes_it() {
    let mut rounds = tracker();
    assert!(rounds.observe(&uploaded(9)).is_empty());
    rounds.observe(&upload(1, "cur"));
    assert!(rounds
        .observe(&event(HsDescAction::Failed, 1, Some("cur")))
        .is_empty());
    let mut elsewhere = uploaded(1);
    elsewhere.address =
        ServiceId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(rounds.observe(&elsewhere).is_empty());
    assert!(rounds.in_round());
}

/// **An upload's refusal names its descriptor, and ends it** (the clock VM run of
/// 2026-11-01, 19:47Z: eight refusals in a second, and the round stayed open five
/// minutes because a `FAILED` with an id was read as a fetch's). Lines as tor
/// 0.4.9.14 writes them: an upload's `FAILED` goes through
/// `hs_control_desc_event_failed` with the blinded key (`dirclient.c:2815`). A
/// refusal for another descriptor on the same HSDir closes nothing; `UNEXPECTED` is
/// a failure, not a refusal; a fetch's `NOT_FOUND` closes nothing. Fails if `observe`
/// ignores a `FAILED` that carries an id again, or `close` ignores the id.
#[test]
fn an_uploads_refusal_names_its_descriptor_and_ends_it() {
    let one = "$C5F03E7A798CA237E7BDD44091BEFE35F2F59AE1~relay";
    let two = "$1C7BB0BBD04DF9B89FD3A95017355DE946B51279~relay";
    let desc = "6PZZop7jRpfFu0Wf1bew3nmlfJEewJOL4lg5nilPDNM";
    let other = "GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY";
    let mut rounds = tracker();
    for hsdir in [one, two] {
        rounds.observe(&hs_desc_event(&format!(
            "HS_DESC UPLOAD {CAPTURED_ONION} UNKNOWN {hsdir} {desc}"
        )));
    }
    // A refusal is this coalescer's even when no open upload matches.
    // A fetch's NOT_FOUND is not. UNEXPECTED of the open upload is, and
    // UNEXPECTED of another descriptor is not: one line, one owner.
    let rejected_other = hs_desc_event(&format!(
        "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {one} {other} REASON=UPLOAD_REJECTED"
    ));
    let not_found = hs_desc_event(&format!(
        "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {one} {desc} REASON=NOT_FOUND"
    ));
    let unexpected_open = hs_desc_event(&format!(
        "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {two} {desc} REASON=UNEXPECTED"
    ));
    let unexpected_other = hs_desc_event(&format!(
        "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {one} {other} REASON=UNEXPECTED"
    ));
    assert!(rounds.owns_line(&rejected_other));
    assert!(!rounds.owns_line(&not_found));
    assert!(rounds.owns_line(&unexpected_open));
    assert!(!rounds.owns_line(&unexpected_other));
    // None of these closes `one`'s upload. `two`'s unexpected end leaves
    // the round open.
    for event in [&rejected_other, &not_found, &unexpected_open] {
        assert!(rounds.observe(event).is_empty(), "{event:?}");
    }
    assert!(rounds.in_round(), "one upload is still open");
    assert_eq!(
        rounds.observe(&hs_desc_event(&format!(
            "HS_DESC FAILED {CAPTURED_ONION} NO_AUTH {one} {desc} REASON=UPLOAD_REJECTED"
        ))),
        [ended(FIRST, 0, 2, 1, 0)]
    );
}

/// **Every upload is kept with its descriptor and its end**, the failed
/// and the still open among them: the directory check asks every
/// directory a round sent to (SO-D12's run 4). Each descriptor's set is
/// its open round's once that has a success, and its latest such round's
/// after; a later round with no success leaves it. Fails if a failed
/// upload's end is not recorded, if `directories` shows a round with no
/// success, or if one descriptor's round with no success hides the
/// other's.
#[test]
fn every_upload_is_kept_with_its_descriptor_and_its_end() {
    use UploadEnd::{Failed as Fail, Open, Uploaded as Done};
    let mut rounds = tracker();
    assert!(rounds.directories(YOUNG).is_empty());
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&upload(3, "next"));
    rounds.observe(&upload(2, "next"));
    assert!(
        rounds.directories(YOUNG).is_empty(),
        "a round with no success yet says nothing"
    );
    rounds.observe(&uploaded(2));
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, Open), to(2, "cur", FIRST, Done)],
        "the current descriptor's round, once it has a success"
    );
    rounds.observe(&failed(1));
    rounds.observe(&uploaded(3));
    rounds.observe(&uploaded(2));
    let ended = [
        to(1, "cur", FIRST, Fail),
        to(2, "cur", FIRST, Done),
        to(3, "next", SECOND, Done),
        to(2, "next", SECOND, Done),
    ];
    assert_eq!(rounds.directories(YOUNG), ended);
    // A round with no success leaves that descriptor's latest set.
    rounds.observe(&upload(4, "cur"));
    rounds.observe(&failed(4));
    assert_eq!(rounds.directories(YOUNG), ended);
}

/// **An open round older than the wait is listed without a success; a
/// young one is not** (Rick, 2026-11-16). The current descriptor's first
/// pass went to directories 1 and 2 and confirmed; its next pass goes to
/// 3 and 4, and neither upload reports an end. While that round is young
/// the list keeps the last good round. Once it is older than the probe's
/// round wait, the new pass is where the descriptor is now, and its
/// directories are listed though none confirmed. Fails if
/// `Descriptor::directories` lists an open round only once it has a
/// success (the old pass's 1 and 2, which clients may no longer ask).
#[test]
fn an_old_round_is_listed_without_a_success_and_a_young_one_is_not() {
    use UploadEnd::{Open, Uploaded as Done};
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&uploaded(1));
    rounds.observe(&uploaded(2));
    rounds.observe(&upload(3, "cur"));
    rounds.observe(&upload(4, "cur"));
    assert_eq!(
        rounds.directories(&[FIRST]),
        [to(1, "cur", FIRST, Done), to(2, "cur", FIRST, Done)],
        "young: the last good round"
    );
    assert_eq!(
        rounds.directories(OLD),
        [to(3, "cur", FIRST, Open), to(4, "cur", FIRST, Open)],
        "older than the wait: the new pass, to other directories"
    );
}

/// **An end pairs with the earliest upload still open to its directory**,
/// across both descriptors' open rounds. An `UPLOADED` names no
/// descriptor. Directory 2 took the current descriptor, then the next
/// one, each in its own round; its first `UPLOADED` is the current
/// one's, and its second the next one's. Fails if `close` picks the
/// upload by descriptor order or position rather than the order uploads
/// began.
#[test]
fn an_end_pairs_with_the_earliest_open_upload_to_its_directory() {
    use UploadEnd::{Failed as Fail, Open, Uploaded as Done};
    let mut rounds = tracker();
    // The next descriptor was seen first, so its key comes first; the
    // current one's upload to directory 2 still began first.
    rounds.observe(&created("next"));
    rounds.observe(&created("cur"));
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&upload(2, "next"));
    rounds.observe(&upload(7, "next"));
    rounds.observe(&failed(1));
    assert_eq!(
        rounds.observe(&uploaded(2)),
        [
            RoundMark::FirstUploaded { descriptor: SECOND },
            ended(SECOND, 1, 1, 0, 0)
        ],
        "the current descriptor's upload began first"
    );
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", SECOND, Fail), to(2, "cur", SECOND, Done)]
    );
    rounds.observe(&uploaded(2));
    assert_eq!(
        rounds.directories(YOUNG),
        [
            to(2, "next", FIRST, Done),
            to(7, "next", FIRST, Open),
            to(1, "cur", SECOND, Fail),
            to(2, "cur", SECOND, Done),
        ]
    );
}

/// **An upload still open when its round ends is kept as unfinished**,
/// whether the descriptor's next pass ends it or the driver resyncs. Tor
/// sends nothing for an upload whose connection failed, so this is the
/// directory a client may ask and find empty (run 4: four of C's eight
/// current-period uploads). Fails if `end` drops the open records, or
/// keeps them as open.
#[test]
fn an_ended_rounds_open_uploads_are_kept_as_unfinished() {
    use UploadEnd::{Open, Unfinished, Uploaded as Done};
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&uploaded(1));
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, Done), to(2, "cur", FIRST, Open)]
    );
    // The next pass's first UPLOAD ends this one; it has no success yet,
    // so the ended round's set stands, its open upload now unfinished.
    rounds.observe(&upload(3, "cur"));
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, Done), to(2, "cur", FIRST, Unfinished)]
    );
    rounds.observe(&uploaded(3));
    assert_eq!(rounds.directories(YOUNG), [to(3, "cur", FIRST, Done)]);

    // The same through `resync`.
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "cur"));
    rounds.observe(&uploaded(1));
    rounds.resync();
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, Done), to(2, "cur", FIRST, Unfinished)]
    );
}

/// **An `UPLOAD` that names no descriptor is not one of Tor's.** The
/// pinned Tor names the descriptor on every `UPLOAD` and sends none
/// without one (`control_events.c:2070`). Such a line starts no round,
/// holds none open, and is not a directory the check asks. Fails if
/// `observe` keeps it.
#[test]
fn an_upload_that_names_no_descriptor_is_ignored() {
    let mut rounds = tracker();
    assert!(rounds
        .observe(&event(HsDescAction::Upload, 2, None))
        .is_empty());
    assert!(!rounds.in_round());
    rounds.observe(&upload(1, "cur"));
    assert_eq!(
        rounds.observe(&uploaded(1)),
        [
            RoundMark::FirstUploaded { descriptor: FIRST },
            ended(FIRST, 1, 0, 0, 0)
        ]
    );
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", FIRST, UploadEnd::Uploaded)]
    );
}

/// **The order descriptors are kept in is the order this tracker first
/// saw them** (Rick, 2026-11-16). The driver starts the tracker before
/// `ADD_ONION`, so it sees both `CREATED`s, the current descriptor's
/// first (`hs_service.c:2138-2139`), and that order stands even when the
/// next descriptor uploads first, as on the floor device's runs. Without
/// a `CREATED`, the first `UPLOAD` sets it. A repeated `CREATED` moves
/// nothing: at the next rotation the descriptor seen first is still the
/// one dropped. Fails if `see` reorders a descriptor already kept (the
/// next descriptor is dropped), or keys by first upload when a `CREATED`
/// came first.
#[test]
fn descriptors_are_kept_in_the_order_first_seen() {
    let mut rounds = tracker();
    assert!(rounds.observe(&created("cur")).is_empty());
    assert!(rounds.observe(&created("next")).is_empty());
    assert_eq!(
        rounds.observe(&upload(1, "next")),
        [RoundMark::Started { descriptor: SECOND }],
        "the next descriptor keeps the place its CREATED gave it"
    );
    assert!(rounds.observe(&created("cur")).is_empty());
    assert_eq!(
        rounds.observe(&upload(2, "cur")),
        [RoundMark::Started { descriptor: FIRST }]
    );
    assert_eq!(
        rounds.observe(&created("new")),
        [RoundMark::Forgotten { descriptor: FIRST }],
        "the descriptor seen first is still the one dropped"
    );

    let mut rounds = tracker();
    assert_eq!(
        rounds.observe(&upload(1, "next")),
        [RoundMark::Started { descriptor: FIRST }],
        "without CREATED, the first upload is seen first"
    );
    assert_eq!(
        rounds.observe(&upload(2, "cur")),
        [RoundMark::Started { descriptor: SECOND }]
    );
}

/// **At a rotation, a third descriptor drops the one seen first** (Rick,
/// 2026-11-16). Tor frees its current descriptor, promotes the next one,
/// and builds a new next one (`hs_service.c:2860-2876`, `2169`). The
/// freed one had uploaded last, so "the oldest latest upload" would drop
/// the promoted one, which clients ask for until the next time period.
/// The one seen first goes; its open round is forgotten, not ended. The
/// list keeps the promoted descriptor's latest round. Fails if `see`
/// keeps three, drops by upload time, or ends the dropped round.
#[test]
fn a_third_descriptor_drops_the_one_seen_first() {
    let mut rounds = tracker();
    rounds.observe(&created("cur"));
    rounds.observe(&created("next"));
    rounds.observe(&upload(2, "next"));
    rounds.observe(&uploaded(2));
    rounds.observe(&upload(1, "cur"));
    assert_eq!(
        rounds.observe(&created("new")),
        [RoundMark::Forgotten { descriptor: FIRST }],
        "the freed descriptor's open round is forgotten"
    );
    assert_eq!(
        rounds.directories(YOUNG),
        [to(2, "next", SECOND, UploadEnd::Uploaded)],
        "the promoted descriptor's round stands"
    );
    assert!(!rounds.in_round());
    assert!(
        rounds.observe(&uploaded(1)).is_empty(),
        "the freed descriptor's late end closes nothing"
    );
    assert_eq!(
        rounds.observe(&upload(3, "new")),
        [RoundMark::Started { descriptor: THIRD }]
    );
}

/// **A drop made in the wrong order heals on the dropped descriptor's
/// next upload** (Rick, 2026-11-16). Here the tracker saw the next
/// descriptor first (no `CREATED`, and it uploaded first), so at the
/// rotation the promoted one is dropped and the freed one kept. The
/// promoted descriptor's next pass sees it again, the freed one, now
/// seen first, is dropped, and the list holds the promoted descriptor's
/// round with no restart. Fails if a descriptor dropped once cannot be
/// seen again, or if a descriptor whose round has already ended is
/// dropped without [`RoundMark::Forgotten`].
#[test]
fn a_wrong_drop_heals_on_the_dropped_descriptors_next_upload() {
    let mut rounds = tracker();
    rounds.observe(&upload(2, "next"));
    rounds.observe(&uploaded(2));
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&uploaded(1));
    assert_eq!(
        rounds.observe(&created("new")),
        [RoundMark::Forgotten { descriptor: FIRST }],
        "a round that has already ended is forgotten with its descriptor"
    );
    assert_eq!(
        rounds.directories(YOUNG),
        [to(1, "cur", SECOND, UploadEnd::Uploaded)],
        "the wrong descriptor was dropped"
    );
    assert_eq!(
        rounds.observe(&upload(4, "next")),
        [
            RoundMark::Forgotten { descriptor: SECOND },
            RoundMark::Started {
                descriptor: DescriptorKey(3),
            }
        ],
        "seeing the promoted descriptor again drops the one now seen first"
    );
    rounds.observe(&uploaded(4));
    assert_eq!(
        rounds.directories(YOUNG),
        [to(4, "next", DescriptorKey(3), UploadEnd::Uploaded)],
        "the promoted descriptor is back, and the freed one is gone"
    );
}

/// **Keys continue across publications.** The driver starts a tracker
/// at every `ADD_ONION`; the core forgets the rounds open then, and the
/// refusals of those keys. A key is never reused, so a stuck round of
/// the old publication can never end a round of the new one, and a
/// refusal of an old key is not one the new publication can clear.
/// Fails if `next_publication` restarts the keys.
#[test]
fn keys_continue_across_publications() {
    let mut rounds = tracker();
    rounds.observe(&upload(1, "cur"));
    rounds.observe(&upload(2, "next"));
    let mut next =
        rounds.next_publication(ServiceId::parse(CAPTURED_ONION).expect("the captured address"));
    assert!(!next.in_round());
    assert!(next.directories(YOUNG).is_empty());
    assert_eq!(next.end_round(FIRST), None);
    assert_eq!(
        next.observe(&upload(1, "cur")),
        [RoundMark::Started { descriptor: THIRD }]
    );
}
