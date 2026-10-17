// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Descriptor-upload rounds for one onion address (`TOR_SUPERVISOR.md` §4.2, `TSR-Q5`).
//!
//! [`super::events::parse_event`] reads one `HS_DESC` line. This module is the
//! supervisor's policy on those lines: when a round ends early, which `FAILED`
//! is a fetch, and how a consumer resynchronises after the event sink drops
//! events. Nothing in production calls it yet. The later supervisor increments
//! are the caller; the policy is specified and pinned, so it stays.

use super::events::{HsDescAction, HsDescEvent};
use super::onion::ServiceId;
use super::vanguards::RelayFingerprint;

/// The `Ended` counters are `u32`. A round tor runs is a handful of HSDirs. A
/// count that does not fit is reported as this, and the round still closes.
const COUNTER_CEILING: u32 = u32::MAX;

/// The descriptor upload rounds of one onion address, coalesced from its `HS_DESC`
/// events (`TSR-Q5`).
///
/// Tor uploads each of a service's descriptors to several HSDirs: `UPLOAD` when an
/// upload to one HSDir begins, then `UPLOADED` or `FAILED` when it ends. The pinned
/// tor's first round for a new service was sixteen uploads, two descriptors to eight
/// HSDirs each. A round opens at the first `UPLOAD` while none is open, and ends when
/// every upload it opened has ended. The two descriptors can share an HSDir, so the
/// open uploads are a multiset, not a set.
///
/// [`RoundMark::FirstUploaded`] is the probe's one trigger per round. A round in which
/// no upload succeeded ends with `uploaded == 0`, which is §4.4's Service-class
/// evidence.
///
/// **A round whose ends do not all arrive still ends.** Tor starts every upload of a
/// round in one pass of its main loop, before any HSDir can have answered (tor
/// 0.4.9.13, `run_upload_descriptor_event` → `upload_descriptor_to_all`), so an
/// `UPLOAD` that arrives once the open round's uploads have begun to end belongs to the
/// next round: the open one ends there, counting the uploads that never reported in
/// `unfinished`, and the next one starts and can trigger again. An end that is lost
/// (the bounded event sink drops events when its consumer falls behind) leaves the
/// round open until then; a consumer that sees the sink drop events calls
/// [`Self::resync`] to end it at once.
///
/// Only an upload's own end closes it. A `FAILED` that carries a descriptor id is a
/// fetch's (the self-probe fetches our own descriptor), and closes nothing. An
/// `UPLOADED` or `FAILED` naming an HSDir with no open upload, as when the subscription
/// began mid-round, is ignored.
pub struct UploadRounds {
    address: ServiceId,
    open: Vec<RelayFingerprint>,
    uploaded: u32,
    failed: u32,
    triggered: bool,
}

/// A boundary in a round of uploads, reported by [`UploadRounds::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundMark {
    /// The first upload of a round began.
    Started,
    /// The first upload of this round succeeded: the probe's trigger.
    FirstUploaded,
    /// The round ended: every upload it began has ended, the next round began, or the
    /// consumer resynchronised.
    Ended {
        /// Uploads that succeeded.
        uploaded: u32,
        /// Uploads that failed.
        failed: u32,
        /// Uploads that began and reported no end.
        unfinished: u32,
    },
}

impl UploadRounds {
    /// Track the rounds of `address`'s descriptors.
    #[must_use]
    pub fn new(address: ServiceId) -> Self {
        Self {
            address,
            open: Vec::new(),
            uploaded: 0,
            failed: 0,
            triggered: false,
        }
    }

    /// Whether a round is open.
    #[must_use]
    pub fn in_round(&self) -> bool {
        !self.open.is_empty()
    }

    /// Fold one event in. Returns the boundaries it crossed, in order: an `UPLOADED`
    /// that is both the round's first success and its last end returns
    /// [`RoundMark::FirstUploaded`] then [`RoundMark::Ended`].
    pub fn observe(&mut self, event: &HsDescEvent) -> Vec<RoundMark> {
        if event.address.as_ref() != Some(&self.address) {
            return Vec::new();
        }
        let Some(hsdir) = event.hsdir else {
            return Vec::new();
        };
        match event.action {
            HsDescAction::Upload => {
                let mut marks = Vec::new();
                // The open round's uploads have begun to end, so this one is the next
                // round's: tor starts a round's uploads before any of them ends.
                if self.in_round() && (self.uploaded > 0 || self.failed > 0) {
                    marks.push(self.end());
                }
                if !self.in_round() {
                    marks.push(RoundMark::Started);
                }
                self.open.push(hsdir);
                marks
            }
            HsDescAction::Uploaded => self.close(hsdir, true),
            HsDescAction::Failed if event.descriptor_id.is_none() => self.close(hsdir, false),
            _ => Vec::new(),
        }
    }

    fn close(&mut self, hsdir: RelayFingerprint, succeeded: bool) -> Vec<RoundMark> {
        let Some(at) = self.open.iter().position(|open| *open == hsdir) else {
            return Vec::new();
        };
        self.open.swap_remove(at);
        let mut marks = Vec::new();
        if succeeded {
            self.uploaded += 1;
            if !self.triggered {
                self.triggered = true;
                marks.push(RoundMark::FirstUploaded);
            }
        } else {
            self.failed += 1;
        }
        if self.open.is_empty() {
            marks.push(self.end());
        }
        marks
    }

    /// End the open round now, after the event sink dropped events: the ends that were
    /// lost will not arrive, and the next round must be able to trigger. `None` when no
    /// round is open.
    pub fn resync(&mut self) -> Option<RoundMark> {
        self.in_round().then(|| self.end())
    }

    /// Report the open round as ended and start counting the next from nothing.
    fn end(&mut self) -> RoundMark {
        let mark = RoundMark::Ended {
            uploaded: self.uploaded,
            failed: self.failed,
            unfinished: u32::try_from(self.open.len()).unwrap_or(COUNTER_CEILING),
        };
        self.open.clear();
        self.uploaded = 0;
        self.failed = 0;
        self.triggered = false;
        mark
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::{parse_event, HsDescAction, HsDescEvent, TorEvent};
    use super::super::framing::ReplyFramer;
    use super::super::onion::ServiceId;
    use super::super::vanguards::RelayFingerprint;
    use super::{RoundMark, UploadRounds};

    /// The throwaway onion of the 2026-10-16 capture (`DiscardPK`; the key is gone).
    const CAPTURED_ONION: &str = "url5xrvawpg5uv275sjyo6w57vvzopdufb7ffykiqnnqxjwecsxm3lid";

    /// The captured first round of a new service: sixteen `UPLOAD`s (two descriptors,
    /// eight HSDirs each), then the twelve `UPLOADED`s that arrived within the capture.
    const CAPTURED_ROUND: &str = include_str!("testdata/hs_desc_round_tor_0_4_9_13.txt");

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

    fn round_event(action: HsDescAction, hsdir: u8, descriptor: bool) -> HsDescEvent {
        HsDescEvent {
            action,
            address: ServiceId::parse(CAPTURED_ONION),
            hsdir: Some(RelayFingerprint::from_bytes([hsdir; 20])),
            descriptor_id: descriptor.then(|| "d".to_owned()),
            reason: None,
        }
    }

    #[test]
    fn the_captured_round_triggers_once_and_stays_open_for_the_missing_ends() {
        let address = ServiceId::parse(CAPTURED_ONION).expect("the captured address");
        let mut rounds = UploadRounds::new(address);
        let marks: Vec<RoundMark> = CAPTURED_ROUND
            .lines()
            .filter_map(|line| line.strip_prefix("650 "))
            .map(hs_desc_event)
            .flat_map(|desc| rounds.observe(&desc))
            .collect();
        assert_eq!(marks, [RoundMark::Started, RoundMark::FirstUploaded]);
        assert!(
            rounds.in_round(),
            "four of the sixteen uploads had not ended"
        );
    }

    #[test]
    fn a_round_ends_when_every_upload_has_ended_and_the_next_one_starts_fresh() {
        use HsDescAction::{Failed, Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        // Two descriptors share HSDir 1: the multiset needs both ends.
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert!(rounds.observe(&round_event(Upload, 1, true)).is_empty());
        assert!(rounds.observe(&round_event(Upload, 2, true)).is_empty());
        assert!(rounds.observe(&round_event(Failed, 2, false)).is_empty());
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::FirstUploaded]
        );
        // A second success in the round triggers nothing.
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::Ended {
                uploaded: 2,
                failed: 1,
                unfinished: 0
            }]
        );
        assert!(!rounds.in_round());
        // The next round counts from zero and triggers again.
        assert_eq!(
            rounds.observe(&round_event(Upload, 3, true)),
            [RoundMark::Started]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 3, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    #[test]
    fn a_round_with_no_success_ends_with_none_uploaded() {
        use HsDescAction::{Failed, Upload};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        rounds.observe(&round_event(Upload, 1, true));
        assert_eq!(
            rounds.observe(&round_event(Failed, 1, false)),
            [RoundMark::Ended {
                uploaded: 0,
                failed: 1,
                unfinished: 0
            }]
        );
    }

    /// An upload whose end never arrives does not wedge the coalescer: the next batch
    /// of uploads ends the incomplete round and can trigger again (Copilot on #1091).
    #[test]
    fn an_incomplete_round_ends_at_the_next_batch_and_the_next_round_triggers() {
        use HsDescAction::{Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert!(rounds.observe(&round_event(Upload, 2, true)).is_empty());
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [RoundMark::FirstUploaded]
        );
        // HSDir 2 never reports. The next round's first upload ends this one.
        assert_eq!(
            rounds.observe(&round_event(Upload, 3, true)),
            [
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 1
                },
                RoundMark::Started
            ]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 3, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    /// After the sink drops events, `resync` ends the open round at once, and the next
    /// batch starts a round that triggers. Nothing is open after it.
    #[test]
    fn resync_ends_a_round_whose_ends_were_lost() {
        use HsDescAction::{Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert_eq!(rounds.resync(), None, "nothing open");
        rounds.observe(&round_event(Upload, 1, true));
        rounds.observe(&round_event(Upload, 2, true));
        assert_eq!(
            rounds.resync(),
            Some(RoundMark::Ended {
                uploaded: 0,
                failed: 0,
                unfinished: 2
            })
        );
        assert!(!rounds.in_round());
        assert_eq!(
            rounds.observe(&round_event(Upload, 1, true)),
            [RoundMark::Started]
        );
        assert_eq!(
            rounds.observe(&round_event(Uploaded, 1, false)),
            [
                RoundMark::FirstUploaded,
                RoundMark::Ended {
                    uploaded: 1,
                    failed: 0,
                    unfinished: 0
                }
            ]
        );
    }

    /// A fetch's `FAILED` (it carries a descriptor id), another address's events, and
    /// an end for an HSDir with no open upload close nothing.
    #[test]
    fn only_an_uploads_own_end_closes_it() {
        use HsDescAction::{Failed, Upload, Uploaded};
        let mut rounds = UploadRounds::new(ServiceId::parse(CAPTURED_ONION).expect("address"));
        assert!(rounds.observe(&round_event(Uploaded, 9, false)).is_empty());
        rounds.observe(&round_event(Upload, 1, true));
        assert!(rounds.observe(&round_event(Failed, 1, true)).is_empty());
        let mut elsewhere = round_event(Uploaded, 1, false);
        elsewhere.address =
            ServiceId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(rounds.observe(&elsewhere).is_empty());
        assert!(rounds.in_round());
    }
}
