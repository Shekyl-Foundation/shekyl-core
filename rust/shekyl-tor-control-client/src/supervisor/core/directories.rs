// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe's directory check (`TOR_SUPERVISOR.md` §4.5; Rick, 2026-10-31).
//!
//! The rendezvous probe never asks a directory: this node's Tor answers it
//! from its own copy of the descriptor, which it keeps until the next time
//! period (tor 0.4.9.14 `hs_cache.c:618`). So the probe cannot see a
//! directory lose the descriptor, even on a correct clock. With each probe
//! this node also asks each directory the latest round's uploads reached,
//! one `HSFETCH … SERVER=` each, which ignores the client cache
//! (`control_cmd.c:1489`). Tor's answers are its own statements: `RECEIVED`
//! only once the descriptor decoded and was stored (`hs_client.c:1667-1690`),
//! `FAILED REASON=NOT_FOUND` when that directory does not have it.
//!
//! A round uploads two descriptors, the current period's and the next's, to
//! different directories, and a fetch asks for the current one. An answer
//! names the descriptor it was about: a directory whose upload was the
//! other descriptor is excluded, not missing. Other `FAILED` reasons, and a
//! directory Tor could not ask, say nothing about the descriptor and are
//! excluded too. A directory with no answer by the check's bound counts as
//! missing: that is what withholding looks like.
//!
//! These fetches run through this node's own Tor, so they share its clock: a
//! descriptor uploaded under a key a correct-clock client would not ask for
//! is found by them as well.

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
    descriptor_id: String,
    /// When to ask; `None` once asked, or once answered without asking.
    due: Option<u64>,
    held: Held,
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

/// The directory half of one probe's check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryCheck {
    asks: Vec<Ask>,
    /// Asks still pending at this time count as missing.
    bound_at: u64,
    /// The descriptor Tor's client asks for, once a fetch named it.
    asked_for: Option<String>,
    complete: bool,
}

impl DirectoryCheck {
    /// Start the check: `fetches` with each one's due time already drawn,
    /// and `within` after the last of them as the bound.
    pub(super) fn new(
        fetches: Vec<(RelayFingerprint, String, u64)>,
        now: u64,
        within: u64,
    ) -> Self {
        let last = fetches.iter().map(|(_, _, due)| *due).max().unwrap_or(now);
        let complete = fetches.is_empty();
        Self {
            asks: fetches
                .into_iter()
                .map(|(hsdir, descriptor_id, due)| Ask {
                    hsdir,
                    descriptor_id,
                    due: Some(due),
                    held: Held::Pending,
                })
                .collect(),
            bound_at: last.saturating_add(within),
            asked_for: None,
            complete,
        }
    }

    /// The next time the check needs the core: a fetch due, or the bound.
    pub(super) fn due(&self) -> Option<u64> {
        if self.complete {
            return None;
        }
        self.asks
            .iter()
            .filter(|ask| ask.held == Held::Pending)
            .filter_map(|ask| ask.due)
            .chain([self.bound_at])
            .min()
    }

    /// The fetches due at `now`, each asked once. At the bound every
    /// directory still pending counts as missing.
    pub(super) fn on_deadline(&mut self, now: u64) -> Vec<RelayFingerprint> {
        let mut fetch = Vec::new();
        for ask in &mut self.asks {
            if ask.held == Held::Pending && ask.due.is_some_and(|due| now >= due) {
                ask.due = None;
                fetch.push(ask.hsdir);
            }
        }
        if !self.complete && now >= self.bound_at {
            for ask in &mut self.asks {
                if ask.held == Held::Pending {
                    ask.held = Held::Missing;
                    ask.due = None;
                }
            }
            self.complete = true;
        }
        fetch
    }

    /// A fetch of this onion named `descriptor_id` (`HS_DESC REQUESTED`):
    /// that is the descriptor Tor's client asks for. A directory whose
    /// upload was another descriptor is excluded, and not asked.
    pub(super) fn asked(&mut self, descriptor_id: &str) {
        self.learn(descriptor_id);
        self.settle();
    }

    /// `hsdir` answered. An answer about a descriptor other than the one it
    /// was sent excludes it; so do answers that say nothing about the
    /// descriptor. An answer for a directory not yet asked (this node's own
    /// probe or refetch can reach it first) counts, and saves the fetch.
    pub(super) fn answered(
        &mut self,
        hsdir: RelayFingerprint,
        descriptor_id: Option<&str>,
        answer: DirectoryAnswer,
    ) {
        if let Some(id) = descriptor_id {
            self.learn(id);
        }
        if let Some(ask) = self
            .asks
            .iter_mut()
            .find(|ask| ask.hsdir == hsdir && ask.held == Held::Pending)
        {
            ask.due = None;
            ask.held = match (descriptor_id, answer) {
                (Some(id), _) if id != ask.descriptor_id => Held::Excluded,
                (_, DirectoryAnswer::Received) => Held::Found,
                (_, DirectoryAnswer::NotFound) => Held::Missing,
                (_, DirectoryAnswer::Other | DirectoryAnswer::Unusable) => Held::Excluded,
            };
        }
        self.settle();
    }

    /// The machine slept (§5): a fetch not yet asked waits at least
    /// `floor` from the wake, and the bound follows the last of them.
    pub(super) fn resumed(&mut self, now: u64, floor: u64, within: u64) {
        let earliest = now.saturating_add(floor);
        let mut last = now;
        for ask in &mut self.asks {
            if let Some(due) = &mut ask.due {
                *due = (*due).max(earliest);
                last = last.max(*due);
            }
        }
        self.bound_at = last.saturating_add(within);
    }

    /// Every directory answered, was excluded, or the bound passed.
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
        let Some(asked_for) = &self.asked_for else {
            return;
        };
        for ask in &mut self.asks {
            if ask.held == Held::Pending && ask.descriptor_id != *asked_for {
                ask.held = Held::Excluded;
                ask.due = None;
            }
        }
    }

    fn settle(&mut self) {
        if self.asks.iter().all(|ask| ask.held != Held::Pending) {
            self.complete = true;
        }
    }
}
