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
/// then dropped instead. A dropped descriptor is
/// [`RoundMark::Forgotten`], whether or not a round of it is still open. An
/// open round is not ended: Tor no longer uploads it, and its tally says
/// nothing. The mark is what retires that descriptor's refusal in the core.
/// The key is never accepted after the drop, including when the same blinded
/// id is seen again and given a new key.
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
    /// The descriptor left the tracker: Tor freed it at a rotation. An open
    /// round, if it had one, is neither a success nor a failure. The core
    /// retires that descriptor's refusal with the key.
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
    /// at every `ADD_ONION`, and the core forgets the rounds open then and
    /// the refusals of their keys. A key is never reused, so no mark of one
    /// publication is read as another's, and a refusal of an old key is not
    /// one the new publication can clear.
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
    /// when two are kept already, the one seen first is dropped and
    /// forgotten. The mark is the same whether or not its round is still
    /// open: the core retires that key's refusal either way, and a key left
    /// behind is never accepted.
    fn see(&mut self, id: &str) -> (usize, Vec<RoundMark>) {
        if let Some(at) = self.descriptors.iter().position(|held| held.id == id) {
            return (at, Vec::new());
        }
        let mut marks = Vec::new();
        if self.descriptors.len() >= KEPT_DESCRIPTORS {
            let dropped = self.descriptors.remove(0);
            marks.push(RoundMark::Forgotten {
                descriptor: dropped.key,
            });
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
mod tests;
