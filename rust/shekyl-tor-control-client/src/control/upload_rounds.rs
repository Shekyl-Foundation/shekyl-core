// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Descriptor-upload rounds for one onion address (`TOR_SUPERVISOR.md` §4.2, `TSR-Q5`).
//!
//! [`super::events::parse_event`] reads one `HS_DESC` line. This module is the
//! supervisor's policy on those lines: which descriptor a round belongs to, when
//! a round ends early, which `FAILED` is an upload's, and how a consumer
//! resynchronises after the event sink drops events. The driver asks
//! [`UploadRounds::owns_line`] before it reads a line as a directory answer,
//! then folds [`UploadRounds::observe`].

use super::events::{HsDescAction, HsDescEvent, HsDescFailure};
use super::onion::ServiceId;
use super::vanguards::RelayFingerprint;

/// How many descriptors a service holds at once: its current one and its
/// next one (tor 0.4.9.14 `hs_service.h`, `desc_current` and `desc_next`).
const KEPT_DESCRIPTORS: usize = 2;

/// The descriptor upload rounds of one onion address, one round at a time per
/// descriptor, coalesced from its `HS_DESC` events (`TSR-Q5`).
///
/// **A round belongs to one descriptor** (Rick, 2026-11-15). A service holds two
/// descriptors, and Tor uploads each on its own clock: each has its own
/// `next_upload_time` and its own introduction circuits, and the upload event
/// walks the current one and then the next, uploading each that is ready
/// (tor 0.4.9.14 `hs_service.c:3446-3490`, `3556-3594`, the walk's order at
/// `89-96`). After an upload Tor draws that descriptor's next upload 60 to 120
/// minutes ahead, alone (`3320-3322`). So the two can go up together or
/// minutes apart (the floor device's runs of 2026-11-15 saw both), and a round
/// that took both together cut the first pass short and could leave the check
/// with only the descriptor clients were not asking for.
///
/// One pass of one descriptor is an `UPLOAD` to each of its directories, all
/// in one turn of Tor's main loop, before any directory can have answered, and
/// never to the same directory twice (`upload_descriptor_to_all`,
/// `hs_service.c:3306-3314`; `hs_common.c:1316`). A round opens at a
/// descriptor's `UPLOAD` while none of that descriptor's is open, and ends when
/// every upload it opened has ended. An `UPLOAD` of that descriptor ends the
/// open round early when the round's uploads have begun to end, or when the
/// round already holds an upload to that directory: either way it is a new
/// pass. A new pass first closes the descriptor's pending uploads, and Tor
/// reports nothing for those (`hs_service.c:792-812`, called at `3293`), so the
/// ended round counts them in `unfinished`. An `UPLOAD` of one descriptor never
/// ends the other's round. Every `UPLOAD` the pinned Tor sends names its
/// descriptor (`control_events.c:2070`); a line that names none is not one of
/// its uploads, and is ignored.
///
/// [`RoundMark::FirstUploaded`] is a round's one trigger for the probe. A round
/// in which no upload succeeded ends with `uploaded == 0`. An end that is lost
/// (the bounded event sink drops events when its consumer falls behind) leaves
/// the round open; a consumer that sees the sink drop events calls
/// [`Self::resync`] to end every open round at once, and one that counts a
/// round stuck calls [`Self::end_round`] for it.
///
/// **Which descriptors are kept.** At most two, in the order this tracker first
/// saw them, a `CREATED` or an `UPLOAD`. Tor builds a new service's current
/// descriptor before its next one (`hs_service.c:2138-2139`) and says `CREATED`
/// for each as it builds it (`2082`); the driver starts the tracker before
/// `ADD_ONION`, so both are seen in that order. At a time-period rotation Tor
/// frees the current descriptor, promotes the next one without uploading it,
/// and builds a new next one (`2860-2876`, `2169`). When a third descriptor is
/// seen, the one seen first is dropped (Rick, 2026-11-16): that is the one Tor
/// freed. Dropping the one whose latest upload is oldest would not do: each
/// descriptor re-uploads on its own clock, so the freed one can have uploaded
/// last, and the promoted one is the descriptor clients ask for until the next
/// time period begins. A drop made in the wrong order heals itself: the
/// dropped descriptor's next `UPLOAD` sees it again, and the one seen first is
/// then dropped instead. A dropped descriptor's open round is
/// [`RoundMark::Forgotten`], not ended: Tor no longer uploads it, and its tally
/// says nothing.
///
/// Only an upload's own end closes it. Tor 0.4.9.14 ends an upload in one place
/// (`dirclient.c:2803-2827`, `handle_response_upload_hsdesc`): `UPLOADED` on 200,
/// with no descriptor id, and `FAILED` with the descriptor id and `REASON=UPLOAD_REJECTED`
/// on 400 or `REASON=UNEXPECTED` on any other status; a connection that fails sends
/// nothing, and leaves the upload unfinished. A fetch's `FAILED` carries the descriptor
/// id too (`NOT_FOUND`, `BAD_DESC`, and `UNEXPECTED`). One line has one consumer.
/// `UPLOAD_REJECTED` is an upload's even when none is open, and then it closes
/// nothing. `UNEXPECTED` closes an upload only while one of that descriptor is open
/// to that directory. A `FAILED` that names no descriptor is an upload's end.
/// `NOT_FOUND`, and any other `FAILED` that names a descriptor, are a fetch's and
/// never end a round. An end that names a directory with no open upload, as when
/// the subscription began mid-round, closes nothing. An end that names no
/// descriptor closes the upload to that directory that began first, across
/// both descriptors' open rounds.
///
/// **Where each descriptor went** ([`Self::directories`]): for each descriptor
/// kept, every directory its latest round with a success sent an upload to,
/// each with the descriptor id (the blinded key) and how that upload ended, for
/// the probe's directory check (`TOR_SUPERVISOR.md` §4.5). The check asks all
/// of them, not only those that confirmed: an upload whose connection failed
/// reports nothing, and its directory is one a client may still ask (SO-D12's
/// run 4, 2026-11-14). Because each descriptor keeps its own latest round, the
/// check always has the descriptor clients ask for once Tor has uploaded it.
pub struct UploadRounds {
    address: ServiceId,
    /// The descriptors kept, in the order this tracker first saw them.
    descriptors: Vec<Descriptor>,
    /// The key the next descriptor seen is given.
    next_key: u64,
    /// The place the next `UPLOAD` takes in the order uploads began.
    next_upload: u64,
}

/// Which of a service's descriptors a round belongs to: the order in which
/// this tracker first saw it. It says nothing about the descriptor itself; the
/// core keys its rounds by it, and the check reads the descriptor id from
/// [`RoundUpload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DescriptorKey(u64);

impl DescriptorKey {
    /// The key with this place in the order. Keys come from
    /// [`UploadRounds::observe`]; this is for the core's tests.
    #[cfg(test)]
    pub(crate) const fn new(place: u64) -> Self {
        Self(place)
    }
}

/// One descriptor, its open round, and its latest round with a success.
struct Descriptor {
    /// Its id: the blinded key, as `HS_DESC` names it.
    id: String,
    key: DescriptorKey,
    /// The open round, in the order its uploads began. An upload stays here
    /// until the round ends. Empty when no round is open.
    open: Vec<OpenUpload>,
    /// The open round's first success has been reported.
    triggered: bool,
    /// The uploads of this descriptor's latest ended round that had a success.
    last: Vec<RoundUpload>,
}

/// One upload of an open round.
struct OpenUpload {
    hsdir: RelayFingerprint,
    /// Its place in the order uploads began, across both descriptors: an end
    /// that names no descriptor closes the one that began first.
    began: u64,
    ended: UploadEnd,
}

/// One upload of a round: the directory, the descriptor its `UPLOAD` named,
/// and how the upload ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundUpload {
    /// The directory.
    pub hsdir: RelayFingerprint,
    /// The descriptor id its `UPLOAD` named: the blinded key.
    pub descriptor_id: String,
    /// Which of the service's descriptors that is, as the rounds' marks name it.
    pub descriptor: DescriptorKey,
    /// How the upload ended, as far as Tor said.
    pub ended: UploadEnd,
}

/// How one upload ended, as Tor reported it (tor 0.4.9.14
/// `dirclient.c:2803-2827`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadEnd {
    /// `UPLOADED`: the directory stored it. The only confirmed end.
    Uploaded,
    /// `FAILED REASON=UNEXPECTED`, or a `FAILED` that names no descriptor.
    Failed,
    /// `FAILED REASON=UPLOAD_REJECTED`: the directory holds a copy whose
    /// revision counter is not below this one's (`hs_cache.c:185`).
    Refused,
    /// No end yet, in the round still open.
    Open,
    /// The round ended without one. A connection that fails sends nothing
    /// (`dirclient.c:713-727`), and a service closes its pending directory
    /// connections, unreported, before it uploads again (`hs_service.c:3293`).
    Unfinished,
}

impl UploadEnd {
    /// Tor said the directory stored the descriptor.
    #[must_use]
    pub const fn confirmed(self) -> bool {
        matches!(self, Self::Uploaded)
    }
}

/// A boundary in a descriptor's rounds, reported by [`UploadRounds::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundMark {
    /// The first upload of a round began.
    Started {
        /// The descriptor the round uploads.
        descriptor: DescriptorKey,
    },
    /// The first upload of this round succeeded: the probe's trigger.
    FirstUploaded {
        /// The descriptor the round uploads.
        descriptor: DescriptorKey,
    },
    /// The round ended: every upload it began has ended, the descriptor's
    /// next pass began, or the consumer ended it.
    Ended {
        /// The descriptor the round uploaded.
        descriptor: DescriptorKey,
        /// Uploads that succeeded.
        uploaded: u32,
        /// Uploads that failed.
        failed: u32,
        /// Of those, the uploads a directory refused (`REASON=UPLOAD_REJECTED`):
        /// it holds a copy whose revision counter is not below this one's
        /// (tor 0.4.9.14 `hs_cache.c:185`).
        refused: u32,
        /// Uploads that began and reported no end.
        unfinished: u32,
    },
    /// The descriptor was dropped while its round was open: Tor freed it at a
    /// rotation, and the round is neither a success nor a failure.
    Forgotten {
        /// The descriptor dropped.
        descriptor: DescriptorKey,
    },
}

impl Descriptor {
    fn new(id: String, key: DescriptorKey) -> Self {
        Self {
            id,
            key,
            open: Vec::new(),
            triggered: false,
            last: Vec::new(),
        }
    }

    /// The uploads to ask about: the open round's once it has a success or
    /// is no longer `young`, else the latest ended round's that had one.
    fn directories(&self, young: bool) -> Vec<RoundUpload> {
        if !self.open.is_empty()
            && (!young || self.open.iter().any(|upload| upload.ended.confirmed()))
        {
            self.project(&self.open)
        } else {
            self.last.clone()
        }
    }

    fn project(&self, round: &[OpenUpload]) -> Vec<RoundUpload> {
        round
            .iter()
            .map(|upload| RoundUpload {
                hsdir: upload.hsdir,
                descriptor_id: self.id.clone(),
                descriptor: self.key,
                ended: upload.ended,
            })
            .collect()
    }

    /// An upload of this descriptor to `hsdir` that has not ended, the one
    /// that began first.
    fn earliest_open(&self, hsdir: RelayFingerprint) -> Option<u64> {
        self.open
            .iter()
            .filter(|upload| upload.ended == UploadEnd::Open && upload.hsdir == hsdir)
            .map(|upload| upload.began)
            .min()
    }

    /// An `UPLOAD` to `hsdir` is this descriptor's next pass, not one of
    /// the open round's: the round's uploads have begun to end, or it
    /// already went to that directory.
    fn new_pass(&self, hsdir: RelayFingerprint) -> bool {
        self.open
            .iter()
            .any(|upload| upload.ended != UploadEnd::Open || upload.hsdir == hsdir)
    }

    /// Report the open round as ended and start the next from nothing. Its
    /// uploads still open are kept as unfinished. A round with a success
    /// becomes the latest round; one without leaves the latest standing.
    fn end(&mut self) -> RoundMark {
        let mut uploaded = 0u32;
        let mut failed = 0u32;
        let mut refused = 0u32;
        let mut unfinished = 0u32;
        for upload in &mut self.open {
            match upload.ended {
                UploadEnd::Uploaded => uploaded = uploaded.saturating_add(1),
                UploadEnd::Refused => {
                    failed = failed.saturating_add(1);
                    refused = refused.saturating_add(1);
                }
                UploadEnd::Failed => failed = failed.saturating_add(1),
                UploadEnd::Open | UploadEnd::Unfinished => {
                    upload.ended = UploadEnd::Unfinished;
                    unfinished = unfinished.saturating_add(1);
                }
            }
        }
        let round = std::mem::take(&mut self.open);
        if uploaded > 0 {
            self.last = self.project(&round);
        }
        self.triggered = false;
        RoundMark::Ended {
            descriptor: self.key,
            uploaded,
            failed,
            refused,
            unfinished,
        }
    }
}

impl UploadRounds {
    /// Track the rounds of `address`'s descriptors.
    #[must_use]
    pub fn new(address: ServiceId) -> Self {
        Self {
            address,
            descriptors: Vec::new(),
            next_key: 0,
            next_upload: 0,
        }
    }

    /// The tracker for the next publication of `address`: no descriptor and
    /// no round, with keys continuing from this one's. The driver starts one
    /// at every `ADD_ONION`, and the core forgets the rounds open then; a key
    /// is never reused, so no mark of one publication is read as another's.
    #[must_use]
    pub fn next_publication(&self, address: ServiceId) -> Self {
        Self {
            address,
            descriptors: Vec::new(),
            next_key: self.next_key,
            next_upload: 0,
        }
    }

    /// For each descriptor kept, in the order first seen, every upload of
    /// the round the check asks about, each with its end (Rick, 2026-11-16):
    /// the open round once it has a success or is no longer young, else the
    /// latest ended round that had a success. `young` names the descriptors
    /// whose open round is younger than the probe's round wait; the core
    /// knows the rounds' ages, and the driver reads them in the same turn as
    /// this list. A young round with no success may yet land, and says
    /// nothing. An older one stands for where the descriptor is now: a new
    /// pass can go to other directories than the last good one, and none of
    /// its uploads confirmed is the case the check must see. Empty before any
    /// round is listed.
    #[must_use]
    pub fn directories(&self, young: &[DescriptorKey]) -> Vec<RoundUpload> {
        self.descriptors
            .iter()
            .flat_map(|held| held.directories(young.contains(&held.key)))
            .collect()
    }

    /// Whether a round is open: an upload has begun and has not ended.
    #[must_use]
    pub fn in_round(&self) -> bool {
        self.descriptors
            .iter()
            .any(|descriptor| !descriptor.open.is_empty())
    }

    /// Whether this line is an upload's, so a directory check does not also
    /// read it. An upload and an `UPLOADED` are. A refusal always is, even
    /// when no open upload matches: it is not a directory's answer. An
    /// `UNEXPECTED` is only while an upload of that descriptor is open to
    /// that directory. A `FAILED` that names no descriptor is an upload's
    /// end. `NOT_FOUND`, and any other `FAILED` that names a descriptor, are
    /// a fetch's.
    #[must_use]
    pub fn owns_line(&self, event: &HsDescEvent) -> bool {
        if event.address.as_ref() != Some(&self.address) || event.hsdir.is_none() {
            return false;
        }
        match event.action {
            HsDescAction::Upload | HsDescAction::Uploaded => true,
            HsDescAction::Failed => self.upload_close(event).is_some(),
            _ => false,
        }
    }

    /// How this `FAILED` closes an upload, when it is an upload's end.
    /// [`Self::owns_line`] and [`Self::observe`] share this, so one line has
    /// one reading.
    fn upload_close(&self, event: &HsDescEvent) -> Option<UploadEnd> {
        let hsdir = event.hsdir?;
        match event.failure() {
            Some(HsDescFailure::UploadRejected) => Some(UploadEnd::Refused),
            Some(HsDescFailure::Unexpected)
                if self
                    .open_upload(hsdir, event.descriptor_id.as_deref())
                    .is_some() =>
            {
                Some(UploadEnd::Failed)
            }
            Some(HsDescFailure::Other) if event.descriptor_id.is_none() => Some(UploadEnd::Failed),
            _ => None,
        }
    }

    /// The descriptor holding the upload to `hsdir` that has not ended and
    /// began first, of `descriptor` when the end names one.
    fn open_upload(&self, hsdir: RelayFingerprint, descriptor: Option<&str>) -> Option<usize> {
        self.descriptors
            .iter()
            .enumerate()
            .filter(|(_, held)| descriptor.is_none_or(|wanted| held.id == wanted))
            .filter_map(|(at, held)| held.earliest_open(hsdir).map(|began| (began, at)))
            .min()
            .map(|(_, at)| at)
    }

    /// Fold one event in. Returns the boundaries it crossed, in order: an
    /// `UPLOADED` that is both its round's first success and its last end
    /// returns [`RoundMark::FirstUploaded`] then [`RoundMark::Ended`].
    pub fn observe(&mut self, event: &HsDescEvent) -> Vec<RoundMark> {
        if event.address.as_ref() != Some(&self.address) {
            return Vec::new();
        }
        match event.action {
            HsDescAction::Created => match &event.descriptor_id {
                Some(id) => self.see(id).1,
                None => Vec::new(),
            },
            HsDescAction::Upload => match (event.hsdir, &event.descriptor_id) {
                (Some(hsdir), Some(id)) => self.upload(hsdir, id),
                _ => Vec::new(),
            },
            HsDescAction::Uploaded => match event.hsdir {
                Some(hsdir) => self.close(hsdir, None, UploadEnd::Uploaded),
                None => Vec::new(),
            },
            HsDescAction::Failed => match (event.hsdir, self.upload_close(event)) {
                (Some(hsdir), Some(ended)) => {
                    self.close(hsdir, event.descriptor_id.as_deref(), ended)
                }
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// The descriptor `id`, kept. A descriptor not yet seen is added, and
    /// when two are kept already, the one seen first is dropped; its open
    /// round, if any, is forgotten.
    fn see(&mut self, id: &str) -> (usize, Vec<RoundMark>) {
        if let Some(at) = self.descriptors.iter().position(|held| held.id == id) {
            return (at, Vec::new());
        }
        let mut marks = Vec::new();
        if self.descriptors.len() >= KEPT_DESCRIPTORS {
            let dropped = self.descriptors.remove(0);
            if !dropped.open.is_empty() {
                marks.push(RoundMark::Forgotten {
                    descriptor: dropped.key,
                });
            }
        }
        let key = DescriptorKey(self.next_key);
        self.next_key = self.next_key.saturating_add(1);
        self.descriptors.push(Descriptor::new(id.to_owned(), key));
        (self.descriptors.len() - 1, marks)
    }

    /// An upload of descriptor `id` to `hsdir` began.
    fn upload(&mut self, hsdir: RelayFingerprint, id: &str) -> Vec<RoundMark> {
        let (at, mut marks) = self.see(id);
        let began = self.next_upload;
        self.next_upload = self.next_upload.saturating_add(1);
        let descriptor = &mut self.descriptors[at];
        if descriptor.new_pass(hsdir) {
            marks.push(descriptor.end());
        }
        if descriptor.open.is_empty() {
            marks.push(RoundMark::Started {
                descriptor: descriptor.key,
            });
        }
        descriptor.open.push(OpenUpload {
            hsdir,
            began,
            ended: UploadEnd::Open,
        });
        marks
    }

    /// End the upload to `hsdir` that has not ended and began first, of
    /// `descriptor` when the end names one. The record that began that
    /// upload is the one that ends.
    fn close(
        &mut self,
        hsdir: RelayFingerprint,
        descriptor: Option<&str>,
        ended: UploadEnd,
    ) -> Vec<RoundMark> {
        let Some(at) = self.open_upload(hsdir, descriptor) else {
            return Vec::new();
        };
        let held = &mut self.descriptors[at];
        let Some(upload) = held
            .open
            .iter_mut()
            .filter(|upload| upload.ended == UploadEnd::Open && upload.hsdir == hsdir)
            .min_by_key(|upload| upload.began)
        else {
            return Vec::new();
        };
        upload.ended = ended;
        let mut marks = Vec::new();
        if ended.confirmed() && !held.triggered {
            held.triggered = true;
            marks.push(RoundMark::FirstUploaded {
                descriptor: held.key,
            });
        }
        if held
            .open
            .iter()
            .all(|upload| upload.ended != UploadEnd::Open)
        {
            marks.push(held.end());
        }
        marks
    }

    /// End every open round now. The driver does this when the sink dropped
    /// events: the ends still missing will not be waited on, and the next
    /// rounds must be able to trigger. An upload that has not ended is
    /// counted unfinished, which is not a failed round.
    pub fn resync(&mut self) -> Vec<RoundMark> {
        self.descriptors
            .iter_mut()
            .filter(|held| !held.open.is_empty())
            .map(Descriptor::end)
            .collect()
    }

    /// End `descriptor`'s open round now: the core counted it stuck. `None`
    /// when that descriptor has no round open, or is no longer kept.
    pub fn end_round(&mut self, descriptor: DescriptorKey) -> Option<RoundMark> {
        self.descriptors
            .iter_mut()
            .find(|held| held.key == descriptor && !held.open.is_empty())
            .map(Descriptor::end)
    }
}

#[cfg(test)]
mod tests {
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
    const CAPTURED_ROUND: &str = include_str!("testdata/hs_desc_round_tor_0_4_9_13.txt");

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
        assert!(
            list[..8]
                .iter()
                .all(|upload| upload.descriptor == FIRST
                    && upload.descriptor_id.starts_with("GOkbpj"))
        );
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
    /// seen again.
    #[test]
    fn a_wrong_drop_heals_on_the_dropped_descriptors_next_upload() {
        let mut rounds = tracker();
        rounds.observe(&upload(2, "next"));
        rounds.observe(&uploaded(2));
        rounds.observe(&upload(1, "cur"));
        rounds.observe(&uploaded(1));
        rounds.observe(&created("new"));
        assert_eq!(
            rounds.directories(YOUNG),
            [to(1, "cur", SECOND, UploadEnd::Uploaded)],
            "the wrong descriptor was dropped"
        );
        rounds.observe(&upload(4, "next"));
        rounds.observe(&uploaded(4));
        assert_eq!(
            rounds.directories(YOUNG),
            [to(4, "next", DescriptorKey(3), UploadEnd::Uploaded)],
            "the promoted descriptor is back, and the freed one is gone"
        );
    }

    /// **Keys continue across publications.** The driver starts a tracker
    /// at every `ADD_ONION`; the core forgets the rounds open then. A key is
    /// never reused, so a stuck round of the old publication can never end a
    /// round of the new one. Fails if `next_publication` restarts the keys.
    #[test]
    fn keys_continue_across_publications() {
        let mut rounds = tracker();
        rounds.observe(&upload(1, "cur"));
        rounds.observe(&upload(2, "next"));
        let mut next = rounds
            .next_publication(ServiceId::parse(CAPTURED_ONION).expect("the captured address"));
        assert!(!next.in_round());
        assert!(next.directories(YOUNG).is_empty());
        assert_eq!(next.end_round(FIRST), None);
        assert_eq!(
            next.observe(&upload(1, "cur")),
            [RoundMark::Started { descriptor: THIRD }]
        );
    }
}
