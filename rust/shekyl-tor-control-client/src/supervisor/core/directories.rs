// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe's directory check (`TOR_SUPERVISOR.md` §4.5).
//!
//! The rendezvous probe never asks a directory: this node's Tor answers it
//! from its own copy of the descriptor, which it keeps until the next time
//! period (tor 0.4.9.14 `hs_cache.c:618`). With each probe this node also
//! asks every directory the latest round sent an upload to, one
//! `HSFETCH … SERVER=` each, whether or not that upload was confirmed: an
//! upload whose connection failed reports nothing, and its directory is one
//! a client may still ask (SO-D12's run 4, 2026-11-14). `HSFETCH` ignores
//! the client cache (`control_cmd.c:1489`). Tor's answers are its own
//! statements: `RECEIVED` only once the descriptor decoded and was stored
//! (`hs_client.c:1667-1690`), `FAILED REASON=NOT_FOUND` when that directory
//! does not have it. A fetch whose circuit or connection fails says nothing
//! at all (`dirclient.c:713-727`), and its answer window decides it.
//!
//! The check is a closed set. A line counts only for a directory this check
//! has already sent a fetch to. `REQUESTED` from one of those names the
//! descriptor Tor's client is asking for; a directory whose upload was a
//! different descriptor is then excluded. An answer that arrives before the
//! send, or from any other directory, is not evidence: the probe and a
//! refetch are answered from caches and from directories this check did not
//! choose.
//!
//! **What an answer counts for depends on the upload** (Rick, 2026-11-15).
//! For an upload Tor confirmed, an answer that says nothing about the copy
//! (a failure other than `NOT_FOUND`, or a counter that cannot be read) is
//! not counted. For one it never confirmed, anything but a matching copy is
//! missing: nothing shows the directory took it. An upload still open
//! arrives already settled, from the reading taken with the list
//! ([`OpenUploads`]): asked once its own round is older than
//! `Policy::round_wait`, and left in flight before that.
//!
//! **Silence counts only when the fetch path is shown working** (Rick,
//! 2026-11-16). A fetch with no answer in its window says nothing about the
//! directory when this node's own circuits are failing: on the floor
//! device's control node (2026-11-15) the probe arrived, Tor reported a
//! guard failing a large share of its circuits, and every counted fetch was
//! silent, three confirmed uploads among them. The directories whose upload
//! Tor confirmed are the control group: each was reachable minutes ago and
//! stored the copy. Silence counts as missing only when more than half of
//! this check's fetches of confirmed uploads of the descriptor clients ask
//! for were answered: a copy, or a failure naming the descriptor. Otherwise
//! every silent fetch is excluded, confirmed or not. With no confirmed upload
//! of that descriptor, silence never counts; only an explicit `NOT_FOUND`
//! does. An answer from a directory of the other descriptor proves nothing
//! about the path to the asked one's. This is decided once, when the check
//! settles, so an answer that comes late still counts for the silent ones.
//!
//! Each fetch's answer window is `probe_within` from the moment Tor accepts
//! that command. It is the supervisor's wait for the `HS_DESC` line, not the
//! connector's dial deadline and not the dialer's outage backoff.

use crate::control::{DescriptorKey, RelayFingerprint, RoundUpload, ServiceDescriptor, UploadEnd};

/// One directory to ask, from the driver: an upload of the latest round,
/// and a CSPRNG draw for this fetch's own delay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryFetch {
    /// Where the upload went, which descriptor it was, and how it ended.
    pub upload: RoundUpload,
    /// Uniform over `u64`; the core maps it onto the probe's delay range.
    pub draw: u64,
}

/// What Tor said about one directory's copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryAnswer {
    /// The copy the directory returned (`HS_DESC_CONTENT`, which Tor sends
    /// only for a descriptor it decoded and stored, `hs_client.c:1686-1689`),
    /// with its revision counter. A copy of the descriptor ours names counts
    /// only at our counter: a directory holding a stale copy is a miss
    /// (Rick, 2026-11-01). A copy of another descriptor counts by being
    /// there: Tor gives no counter for `desc_next`, the descriptor clients
    /// ask for from 12:00 to 00:00 UTC (`hs_service.c:2127-2139`). When Tor
    /// gave no descriptor of ours, the check counts nothing.
    Received {
        /// The copy's `revision-counter`; `None` when it could not be read.
        revision_counter: Option<u64>,
    },
    /// `HS_DESC FAILED REASON=NOT_FOUND`: the directory does not have it.
    NotFound,
    /// `HS_DESC FAILED` for another reason (`QUERY_REJECTED`, `UNEXPECTED`,
    /// `BAD_DESC`): nothing about the descriptor.
    Other,
    /// The driver could not ask: Tor refused the command, or no control
    /// connection.
    Unusable,
}

/// How the check counted one directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counted {
    /// It holds the descriptor Tor's client asks for, at our counter.
    Found,
    /// It does not: `NOT_FOUND`, a stale copy, or, for an upload Tor never
    /// confirmed, any answer but a matching copy; and no answer within the
    /// window, when the fetch path was shown working ([`Exclusion::Silent`]).
    Missing,
    /// Not counted.
    Excluded(Exclusion),
}

/// Why a directory was not counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exclusion {
    /// Its upload was another descriptor than the one Tor's client asks
    /// for: the other time period's.
    OtherDescriptor,
    /// A confirmed upload's directory answered without saying whether it
    /// holds the copy: a failure other than `NOT_FOUND`, or a copy whose
    /// counter could not be read.
    SaidNothing,
    /// This node did not ask: Tor refused the command, there was no control
    /// connection, or the request queue withheld the fetch. Our failure to
    /// ask says nothing about the directory, confirmed or not.
    NotAsked,
    /// The upload was still open and its round younger than
    /// `Policy::round_wait` when the check was drawn: it may yet land.
    UploadInFlight,
    /// No answer within the window, while no more than half of this check's
    /// fetches of confirmed uploads were answered: this node's own fetch
    /// path is the likeliest fault (Rick, 2026-11-16).
    Silent,
}

/// One directory's line in a settled check, said at debug (§4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryReport {
    /// The directory.
    pub hsdir: RelayFingerprint,
    /// How its upload ended.
    pub upload: UploadEnd,
    /// What Tor said about its copy. `None` when nothing came: no answer
    /// within the window, or no fetch sent.
    pub answer: Option<DirectoryAnswer>,
    /// How the check counted it.
    pub counted: Counted,
}

/// How the rounds a directory list was read from treat uploads that have
/// not ended (§4.5). The driver reads it in the same turn as the list and
/// the check keeps that reading: a round may end while the descriptor is
/// being read, and a later reading would be a different round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenUploads {
    /// The descriptors whose open round was younger than
    /// `Policy::round_wait`. An upload of theirs still open may yet land.
    in_flight: Vec<DescriptorKey>,
}

impl OpenUploads {
    /// `in_flight` are the descriptors whose open round is younger than
    /// `Policy::round_wait`.
    #[must_use]
    pub(crate) const fn in_flight(in_flight: Vec<DescriptorKey>) -> Self {
        Self { in_flight }
    }

    /// The descriptors whose open round was younger than
    /// `Policy::round_wait`: the round tracker lists such a round only once
    /// it has a success (`UploadRounds::directories`).
    #[must_use]
    pub fn young(&self) -> &[DescriptorKey] {
        &self.in_flight
    }

    /// An upload of `descriptor` still open is hung, and its directory is
    /// asked: its round was already older than `Policy::round_wait`, or had
    /// ended.
    #[must_use]
    pub fn asks(&self, descriptor: DescriptorKey) -> bool {
        !self.in_flight.contains(&descriptor)
    }
}

/// One directory as the probe hands it to the check. A settled row was
/// decided with the list. The check does not revisit it.
pub(super) enum DirectoryRow {
    /// Ask this directory at `due`.
    Ask {
        /// The upload, and how it ended.
        upload: RoundUpload,
        /// When the fetch comes due.
        due: u64,
    },
    /// Already counted. No fetch, and no answer window.
    Settled {
        /// The upload, and how it ended.
        upload: RoundUpload,
        /// How it was counted.
        counted: Counted,
    },
}

/// The directory half of one probe, from the moment the check is asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DirectoryHalf {
    /// `CheckDirectories` is out. The driver's list has not been folded.
    /// The verdict waits. An empty list is [`Self::Open`] and unmatched,
    /// not this.
    AwaitingDraw,
    /// The list is in.
    Open(DirectoryCheck),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ask {
    hsdir: RelayFingerprint,
    /// The descriptor id the upload named.
    descriptor_id: String,
    /// How the upload ended.
    upload: UploadEnd,
    /// When the fetch comes due. `None` once due or decided.
    due: Option<u64>,
    /// The fetch came due and the driver sent it. Until then it waits in
    /// the request queue: no window runs, and nothing Tor says about the
    /// directory is this check's.
    sent: bool,
    /// When a sent fetch with no answer is silent. `None` until the fetch
    /// is sent, and cleared once the directory is decided.
    answer_by: Option<u64>,
    /// The fetch was sent and its window passed with no answer. How that
    /// counts is decided when the check settles.
    silent: bool,
    /// What Tor said, for the report.
    answer: Option<DirectoryAnswer>,
    /// `None` while undecided.
    counted: Option<Counted>,
}

impl Ask {
    fn start(upload: RoundUpload, due: Option<u64>, counted: Option<Counted>) -> Self {
        Self {
            hsdir: upload.hsdir,
            descriptor_id: upload.descriptor_id,
            upload: upload.ended,
            due,
            sent: false,
            answer_by: None,
            silent: false,
            answer: None,
            counted,
        }
    }

    /// Not decided, and not waiting on the settle as a silent fetch.
    fn is_pending(&self) -> bool {
        self.counted.is_none() && !self.silent
    }

    /// The fetch has been sent and the directory has not been decided.
    fn is_open(&self) -> bool {
        self.is_pending() && self.sent
    }

    /// The fetch came due and waits to be sent.
    fn is_queued(&self) -> bool {
        self.is_pending() && self.due.is_none() && !self.sent
    }

    fn decide(&mut self, counted: Counted) {
        self.counted = Some(counted);
        self.due = None;
        self.answer_by = None;
    }
}

/// The check's verdict over the directories it counted: those holding, or
/// asked for and not holding, the descriptor Tor's client asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DirectoryVerdict {
    /// More than half of the counted directories have it.
    Held,
    /// Half or fewer have it.
    Lost,
    /// None was counted: no directory the round reached holds the
    /// descriptor Tor's client asks for, or none answered about it. The
    /// probe alone decides, and the driver says so once.
    Unmatched,
}

/// The fetches of one probe's check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryCheck {
    /// This service's `desc_current`: a copy of that descriptor counts only
    /// at its counter. `None` when Tor gave none.
    ours: Option<ServiceDescriptor>,
    asks: Vec<Ask>,
    /// The descriptor Tor's client asks for, learned from a `REQUESTED`
    /// of a fetch this check has sent.
    asked_for: Option<String>,
    complete: bool,
}

impl DirectoryCheck {
    /// `rows` are the directories the probe handed over. One already settled
    /// is not asked. A check with nothing to ask is complete: nothing to
    /// count, so the probe decides. So is a missing counter of ours: no
    /// fetch is sent, and the probe is not held for answer windows it
    /// cannot compare (§4.5).
    pub(super) fn new(rows: Vec<DirectoryRow>, ours: Option<ServiceDescriptor>) -> Self {
        let asks = if ours.is_none() {
            Vec::new()
        } else {
            rows.into_iter()
                .map(|row| match row {
                    DirectoryRow::Ask { upload, due } => Ask::start(upload, Some(due), None),
                    DirectoryRow::Settled { upload, counted } => {
                        Ask::start(upload, None, Some(counted))
                    }
                })
                .collect()
        };
        let mut check = Self {
            ours,
            asks,
            asked_for: None,
            complete: false,
        };
        check.settle();
        check
    }

    /// The next time the check needs the core: a fetch to send, or an
    /// answer window ending.
    pub(super) fn due(&self) -> Option<u64> {
        if self.complete {
            return None;
        }
        self.asks
            .iter()
            .filter(|ask| ask.is_pending())
            .filter_map(|ask| ask.due.or(ask.answer_by))
            .min()
    }

    /// The fetches whose time has come, to be sent; and a sent fetch whose
    /// answer window has elapsed is silent. A fetch's window starts
    /// when it is sent ([`Self::dispatched`]): the request queue sends one
    /// request at a time, so a fetch can wait behind others.
    pub(super) fn on_deadline(&mut self, now: u64) -> Vec<RelayFingerprint> {
        self.expire(now);
        let mut fetch = Vec::new();
        for ask in &mut self.asks {
            if ask.is_pending() && ask.due.is_some_and(|due| now >= due) {
                ask.due = None;
                fetch.push(ask.hsdir);
            }
        }
        fetch
    }

    /// A fetch of `hsdir` came due and waits to be sent.
    pub(super) fn queued(&self, hsdir: RelayFingerprint) -> bool {
        self.asks
            .iter()
            .any(|ask| ask.hsdir == hsdir && ask.is_queued())
    }

    /// The driver sent the fetch of `hsdir` at `now`. Its answer window
    /// runs from the send; Tor accepting the command later
    /// ([`Self::accepted`]) starts it over from the acceptance, so a slow
    /// command does not spend the wait.
    pub(super) fn dispatched(&mut self, hsdir: RelayFingerprint, now: u64, within: u64) {
        for ask in &mut self.asks {
            if ask.hsdir == hsdir && ask.is_queued() {
                ask.sent = true;
                ask.answer_by = Some(now.saturating_add(within));
            }
        }
    }

    /// The fetch of `hsdir` was withheld at its turn: it says nothing, and
    /// the check does not wait on it.
    pub(super) fn withheld(&mut self, hsdir: RelayFingerprint) {
        for ask in &mut self.asks {
            if ask.hsdir == hsdir && ask.is_queued() {
                ask.decide(Counted::Excluded(Exclusion::NotAsked));
            }
        }
        self.settle();
    }

    /// Tor accepted the fetch of `hsdir` (`250`). The answer window runs
    /// from `now`.
    pub(super) fn accepted(&mut self, hsdir: RelayFingerprint, now: u64, within: u64) {
        let answer_by = now.saturating_add(within);
        for ask in &mut self.asks {
            if ask.hsdir == hsdir && ask.is_open() {
                ask.answer_by = Some(answer_by);
            }
        }
    }

    /// A fetch this check has sent named `descriptor_id` (`HS_DESC
    /// REQUESTED` for `hsdir`). That id is the descriptor Tor's client
    /// asks for. A `REQUESTED` for a directory this check has not sent is
    /// ignored, and does not choose the descriptor.
    pub(super) fn requested(&mut self, hsdir: RelayFingerprint, descriptor_id: &str) {
        if !self
            .asks
            .iter()
            .any(|ask| ask.hsdir == hsdir && ask.is_open())
        {
            return;
        }
        self.learn(descriptor_id);
        self.settle();
    }

    /// `hsdir` answered a fetch this check has sent. How the answer counts
    /// is [`Self::hold`]'s. An answer for a directory not yet sent, or not
    /// in this check, is ignored.
    pub(super) fn answered(
        &mut self,
        hsdir: RelayFingerprint,
        descriptor_id: Option<&str>,
        answer: DirectoryAnswer,
    ) {
        let Some(at) = self
            .asks
            .iter()
            .position(|ask| ask.hsdir == hsdir && ask.is_open())
        else {
            return;
        };
        let counted = self.hold(&self.asks[at], descriptor_id, answer);
        let ask = &mut self.asks[at];
        ask.answer = Some(answer);
        ask.decide(counted);
        // Tor's answer to a fetch this check sent names the descriptor its
        // client asked for, as the `REQUESTED` before it did. Our own failure
        // to ask names nothing.
        if let (Some(id), false) = (descriptor_id, answer == DirectoryAnswer::Unusable) {
            self.learn(id);
        }
        self.settle();
    }

    /// What this answer does to `ask`'s directory, read in order. An answer
    /// about a descriptor other than the one uploaded there excludes it,
    /// whatever the upload. Our failure to ask excludes it too. Otherwise
    /// the answer counts, and an answer that says nothing about the copy is
    /// excluded only for an upload Tor confirmed: for one it never
    /// confirmed, nothing shows the directory took it (Rick, 2026-11-15).
    fn hold(&self, ask: &Ask, descriptor_id: Option<&str>, answer: DirectoryAnswer) -> Counted {
        if descriptor_id.is_some_and(|id| id != ask.descriptor_id) {
            return Counted::Excluded(Exclusion::OtherDescriptor);
        }
        let counted = match answer {
            DirectoryAnswer::Received { revision_counter } => {
                self.copy_held(&ask.descriptor_id, revision_counter)
            }
            DirectoryAnswer::NotFound => Counted::Missing,
            DirectoryAnswer::Other => Counted::Excluded(Exclusion::SaidNothing),
            DirectoryAnswer::Unusable => return Counted::Excluded(Exclusion::NotAsked),
        };
        match counted {
            Counted::Excluded(Exclusion::SaidNothing) if !ask.upload.confirmed() => {
                Counted::Missing
            }
            counted => counted,
        }
    }

    /// How a stored copy counts (§4.5), asked in order. When Tor gave no
    /// descriptor, the copy says nothing. When ours names a different
    /// descriptor, a stored copy counts by being there (`desc_next`). When
    /// this is the descriptor ours names, the counters decide: equal is
    /// found, any other counter is missing, and an unreadable counter says
    /// nothing.
    fn copy_held(&self, uploaded: &str, revision_counter: Option<u64>) -> Counted {
        let Some(ours) = &self.ours else {
            return Counted::Excluded(Exclusion::SaidNothing);
        };
        if ours.descriptor_id != uploaded {
            return Counted::Found;
        }
        match revision_counter {
            Some(theirs) if theirs == ours.revision_counter => Counted::Found,
            Some(_) => Counted::Missing,
            None => Counted::Excluded(Exclusion::SaidNothing),
        }
    }

    /// The machine slept (§5). A fetch not yet sent waits at least `floor`
    /// from the wake. A fetch already sent gets a fresh answer window.
    pub(super) fn resumed(&mut self, now: u64, floor: u64, within: u64) {
        let earliest = now.saturating_add(floor);
        let answer_by = now.saturating_add(within);
        for ask in &mut self.asks {
            if let Some(due) = &mut ask.due {
                *due = (*due).max(earliest);
            }
            if ask.is_open() {
                ask.answer_by = Some(answer_by);
            }
        }
    }

    /// Every directory answered, was excluded, or its answer window passed,
    /// and the silent ones have been decided.
    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(super) fn verdict(&self) -> DirectoryVerdict {
        let found = self.count(Counted::Found);
        let counted = found + self.count(Counted::Missing);
        if counted == 0 {
            DirectoryVerdict::Unmatched
        } else if found * 2 > counted {
            DirectoryVerdict::Held
        } else {
            DirectoryVerdict::Lost
        }
    }

    /// One line per decided directory, in the round's order.
    pub(super) fn report(&self) -> Vec<DirectoryReport> {
        self.asks
            .iter()
            .filter_map(|ask| {
                ask.counted.map(|counted| DirectoryReport {
                    hsdir: ask.hsdir,
                    upload: ask.upload,
                    answer: ask.answer,
                    counted,
                })
            })
            .collect()
    }

    fn count(&self, counted: Counted) -> usize {
        self.asks
            .iter()
            .filter(|ask| ask.counted == Some(counted))
            .count()
    }

    fn learn(&mut self, descriptor_id: &str) {
        if self.asked_for.is_none() {
            self.asked_for = Some(descriptor_id.to_owned());
        }
        let Some(asked_for) = self.asked_for.clone() else {
            return;
        };
        for ask in &mut self.asks {
            if ask.is_pending() && ask.descriptor_id != asked_for {
                ask.decide(Counted::Excluded(Exclusion::OtherDescriptor));
            }
        }
    }

    fn expire(&mut self, now: u64) {
        for ask in &mut self.asks {
            if ask.is_pending() && ask.answer_by.is_some_and(|at| now >= at) {
                ask.silent = true;
                ask.due = None;
                ask.answer_by = None;
            }
        }
        self.settle();
    }

    /// Once nothing is pending, the silent fetches are decided and the
    /// check is complete.
    fn settle(&mut self) {
        if self.complete || self.asks.iter().any(Ask::is_pending) {
            return;
        }
        let silence = self.silence_counts();
        let asked_for = self.asked_for.clone();
        for ask in &mut self.asks {
            if !ask.silent || ask.counted.is_some() {
                continue;
            }
            let counted = match &asked_for {
                Some(asked_for) if *asked_for != ask.descriptor_id => {
                    Counted::Excluded(Exclusion::OtherDescriptor)
                }
                _ if silence => Counted::Missing,
                _ => Counted::Excluded(Exclusion::Silent),
            };
            ask.counted = Some(counted);
        }
        self.complete = true;
    }

    /// Whether a silent fetch counts as missing: more than half of this
    /// check's fetches of confirmed uploads of the descriptor Tor's client
    /// asks for were answered (Rick, 2026-11-16). Only Tor's own answer is
    /// one: a copy, or a failure naming the descriptor. A fetch this node
    /// failed to send is not in the group. Nothing is, before Tor has named
    /// the descriptor it asks for.
    fn silence_counts(&self) -> bool {
        let Some(asked_for) = &self.asked_for else {
            return false;
        };
        let (answered, fetched) = self
            .asks
            .iter()
            .filter(|ask| {
                ask.upload.confirmed()
                    && ask.sent
                    && ask.descriptor_id == *asked_for
                    && ask.counted != Some(Counted::Excluded(Exclusion::NotAsked))
            })
            .fold((0usize, 0usize), |(answered, fetched), ask| {
                (answered + usize::from(ask.answer.is_some()), fetched + 1)
            });
        answered * 2 > fetched
    }
}
