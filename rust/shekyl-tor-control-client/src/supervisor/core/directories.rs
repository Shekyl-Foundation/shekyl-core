// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe's directory check (`TOR_SUPERVISOR.md` §4.5).
//!
//! The rendezvous probe never asks a directory: this node's Tor answers it
//! from its own copy of the descriptor, which it keeps until the next time
//! period (tor 0.4.9.14 `hs_cache.c:618`). With each probe this node also
//! asks each directory the latest round's uploads reached, one
//! `HSFETCH … SERVER=` each. `HSFETCH` ignores the client cache
//! (`control_cmd.c:1489`). Tor's answers are its own statements: `RECEIVED`
//! only once the descriptor decoded and was stored (`hs_client.c:1667-1690`),
//! `FAILED REASON=NOT_FOUND` when that directory does not have it.
//!
//! The check is a closed set. A line counts only for a directory this check
//! has already sent a fetch to. `REQUESTED` from one of those names the
//! descriptor Tor's client is asking for; a directory whose upload was a
//! different descriptor is then excluded. An answer that arrives before the
//! send, or from any other directory, is not evidence: the probe and a
//! refetch are answered from caches and from directories this check did not
//! choose.
//!
//! Each fetch's answer window is `probe_within` from the moment Tor accepts
//! that command. It is the supervisor's wait for the `HS_DESC` line, not the
//! connector's dial deadline and not the dialer's outage backoff.

use crate::control::RelayFingerprint;

/// One directory to ask, from the driver: where an upload went, which
/// descriptor it was, and a CSPRNG draw for this fetch's own delay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryFetch {
    /// The directory.
    pub hsdir: RelayFingerprint,
    /// The descriptor id its upload named: the blinded key.
    pub descriptor_id: String,
    /// Uniform over `u64`; the core maps it onto the probe's delay range.
    pub draw: u64,
}

/// What Tor said about one directory's copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryAnswer {
    /// `HS_DESC RECEIVED`: the descriptor decoded and was stored.
    Received,
    /// `HS_DESC FAILED REASON=NOT_FOUND`: the directory does not have it.
    NotFound,
    /// `HS_DESC FAILED` for another reason: nothing about the descriptor.
    Other,
    /// The driver could not ask: Tor refused the command, or no control
    /// connection.
    Unusable,
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

/// One directory's place in the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    Pending,
    Found,
    Missing,
    Excluded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ask {
    hsdir: RelayFingerprint,
    /// The descriptor id the upload named.
    descriptor_id: String,
    /// When to send the fetch. `None` once sent, excluded, or answered.
    due: Option<u64>,
    /// When a sent fetch with no answer counts as missing. `None` until
    /// the fetch is sent, and cleared once the directory is decided.
    answer_by: Option<u64>,
    held: Held,
}

impl Ask {
    /// The fetch has been sent and the directory has not been decided.
    fn is_open(&self) -> bool {
        self.held == Held::Pending && self.due.is_none()
    }

    fn exclude(&mut self) {
        self.held = Held::Excluded;
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
    asks: Vec<Ask>,
    /// The descriptor Tor's client asks for, learned from a `REQUESTED`
    /// of a fetch this check has sent.
    asked_for: Option<String>,
    complete: bool,
}

impl DirectoryCheck {
    /// `fetches` are `(directory, uploaded descriptor, when to send)`.
    /// An empty list is complete: nothing to count, so the probe decides.
    pub(super) fn new(fetches: Vec<(RelayFingerprint, String, u64)>) -> Self {
        let complete = fetches.is_empty();
        Self {
            asks: fetches
                .into_iter()
                .map(|(hsdir, descriptor_id, due)| Ask {
                    hsdir,
                    descriptor_id,
                    due: Some(due),
                    answer_by: None,
                    held: Held::Pending,
                })
                .collect(),
            asked_for: None,
            complete,
        }
    }

    /// The next time the check needs the core: a fetch to send, or an
    /// answer window ending.
    pub(super) fn due(&self) -> Option<u64> {
        if self.complete {
            return None;
        }
        self.asks
            .iter()
            .filter(|ask| ask.held == Held::Pending)
            .filter_map(|ask| ask.due.or(ask.answer_by))
            .min()
    }

    /// Send every fetch whose time has come, and count a sent fetch whose
    /// answer window has elapsed as missing. `within` is the answer window
    /// from this send. Tor accepting the command later
    /// ([`Self::accepted`]) starts that fetch's window over from the
    /// acceptance, so a slow command does not spend the wait.
    pub(super) fn on_deadline(&mut self, now: u64, within: u64) -> Vec<RelayFingerprint> {
        self.expire(now);
        let mut fetch = Vec::new();
        for ask in &mut self.asks {
            if ask.held == Held::Pending && ask.due.is_some_and(|due| now >= due) {
                ask.due = None;
                ask.answer_by = Some(now.saturating_add(within));
                fetch.push(ask.hsdir);
            }
        }
        fetch
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

    /// `hsdir` answered a fetch this check has sent. An answer about a
    /// descriptor other than the one uploaded there excludes that
    /// directory. Answers that say nothing about the descriptor exclude
    /// it too. An answer for a directory not yet sent, or not in this
    /// check, is ignored.
    pub(super) fn answered(
        &mut self,
        hsdir: RelayFingerprint,
        descriptor_id: Option<&str>,
        answer: DirectoryAnswer,
    ) {
        let Some(ask) = self
            .asks
            .iter_mut()
            .find(|ask| ask.hsdir == hsdir && ask.is_open())
        else {
            return;
        };
        let uploaded = ask.descriptor_id.clone();
        ask.answer_by = None;
        ask.held = match (descriptor_id, answer) {
            (Some(id), _) if id != uploaded => Held::Excluded,
            (_, DirectoryAnswer::Received) => Held::Found,
            (_, DirectoryAnswer::NotFound) => Held::Missing,
            (_, DirectoryAnswer::Other | DirectoryAnswer::Unusable) => Held::Excluded,
        };
        self.settle();
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

    /// Every directory answered, was excluded, or its answer window passed.
    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(super) fn verdict(&self) -> DirectoryVerdict {
        let found = self.count(Held::Found);
        let counted = found + self.count(Held::Missing);
        if counted == 0 {
            DirectoryVerdict::Unmatched
        } else if found * 2 > counted {
            DirectoryVerdict::Held
        } else {
            DirectoryVerdict::Lost
        }
    }

    fn count(&self, held: Held) -> usize {
        self.asks.iter().filter(|ask| ask.held == held).count()
    }

    fn learn(&mut self, descriptor_id: &str) {
        if self.asked_for.is_none() {
            self.asked_for = Some(descriptor_id.to_owned());
        }
        let Some(asked_for) = self.asked_for.clone() else {
            return;
        };
        for ask in &mut self.asks {
            if ask.held == Held::Pending && ask.descriptor_id != asked_for {
                ask.exclude();
            }
        }
    }

    fn expire(&mut self, now: u64) {
        for ask in &mut self.asks {
            if ask.held == Held::Pending && ask.answer_by.is_some_and(|at| now >= at) {
                ask.held = Held::Missing;
                ask.due = None;
                ask.answer_by = None;
            }
        }
        self.settle();
    }

    fn settle(&mut self) {
        if self.asks.iter().all(|ask| ask.held != Held::Pending) {
            self.complete = true;
        }
    }
}
