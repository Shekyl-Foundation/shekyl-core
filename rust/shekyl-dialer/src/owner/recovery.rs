// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One recovery episode per connector (dialer brief, "Recovery").
//!
//! A stranded wake — under the target, nothing in flight, nothing
//! drawable — opens the episode, re-admits the configured addresses, and
//! dials nothing. Later wakes that draw those addresses are still the
//! same episode: a dead configured address that is re-admitted, drawn
//! and dropped does not cycle the log.
//!
//! Every wake reports here, including a wake that is stranded again. The
//! report carries the sessions held before this wake's own dial. The
//! episode ends on the first of these:
//!
//! - the connector holds more sessions than when the episode opened;
//! - the connector holds its target.
//!
//! Sessions held, not the `Keep` count: a `Keep` dial in flight holds a
//! target slot but is not a session, and may still fail. A draw is not an
//! end either, whatever list the address came from: an address that thaws,
//! is drawn and fails leaves the connector where it was.
//!
//! A session gained on the previous wake is visible on this one, and
//! this one is often stranded itself: the dial finished, the new session
//! is not a candidate, and nothing else is drawable. Reporting that wake
//! is what closes the episode. [`re_admit`] then opens the next one,
//! because the connector is still stranded.

use std::collections::BTreeSet;

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{ConnectorId, NetworkAddress, Peerlist, Source, Tick};

use super::Shared;

/// Why a recovery episode ended. The leave line names this and no other
/// reason: a risen session count and a met target can both be true on one
/// wake, and the first match is the one said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryEnd {
    /// A session was added after the episode opened.
    KeptRose,
    /// The connector is no longer under its target. The session count may
    /// be the one the episode opened with: the operator lowered the target.
    TargetReached,
}

impl RecoveryEnd {
    const fn phrase(self) -> &'static str {
        match self {
            Self::KeptRose => "a kept session was added",
            Self::TargetReached => "the connector is at its target",
        }
    }
}

/// The open episode: the sessions the connector held when recovery
/// started, and which refusals it has said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Recovery {
    /// The sessions held when the episode opened.
    held_at_entry: usize,
    /// Configured addresses whose refusal this episode has said.
    refused: BTreeSet<NetworkAddress>,
}

impl Recovery {
    fn open(held_at_entry: usize) -> Self {
        Self {
            held_at_entry,
            refused: BTreeSet::new(),
        }
    }

    /// `true` the first time `address` is refused in this episode.
    fn note_refused(&mut self, address: &NetworkAddress) -> bool {
        self.refused.insert(address.clone())
    }

    /// `None` while this episode is still recovery.
    ///
    /// A risen session count wins over the target: it is the progress the
    /// episode exists to notice. A lost session leaves the episode open, so
    /// a later return to the entry count does not look like a gain.
    fn end(&self, held: usize, target: usize) -> Option<RecoveryEnd> {
        if held > self.held_at_entry {
            return Some(RecoveryEnd::KeptRose);
        }
        if held >= target {
            return Some(RecoveryEnd::TargetReached);
        }
        None
    }
}

/// Close `episode` when this wake shows that recovery worked, and say why.
///
/// `held` is the sessions held before this wake's dial. Every wake calls
/// this, so a stranded wake after a gained session is the wake that closes
/// the episode.
pub(in crate::owner) fn report_wake(
    episode: &mut Option<Recovery>,
    connector: ConnectorId,
    held: usize,
    target: usize,
) {
    let Some(end) = episode.as_ref().and_then(|open| open.end(held, target)) else {
        return;
    };
    *episode = None;
    let phrase = end.phrase();
    tracing::info!("{connector:?}: no longer stranded; {phrase}");
}

/// Re-admit the closed network, or the configured seeds and `--add-peer`,
/// as operator-named gray. Already seated is quiet. A refusal is said once
/// per episode. The first call of an episode opens it and says so.
///
/// Called after [`report_wake`] on a stranded wake. A wake that just
/// closed the episode opens the next one here, with the session count the
/// report already saw.
pub(super) fn re_admit<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    connector: ConnectorId,
    now: Tick,
    rng: &mut R,
) {
    let population: Vec<NetworkAddress> = match &shared.exclusive {
        Some(population) => population.iter().cloned().collect(),
        None => shared.configured.clone(),
    };
    let index = connector.index();
    let held = shared.attempts(connector).held();
    let entering = shared.recovery[index].is_none();
    let episode = shared.recovery[index].get_or_insert_with(|| Recovery::open(held));
    let mut admitted = 0usize;
    for address in population
        .iter()
        .filter(|address| Peerlist::connector_of(address) == Some(connector))
    {
        match shared.lists.admit_gray(address, Source::Operator, now, rng) {
            Ok(true) => admitted += 1,
            // Already seated: cooling, outstanding or in a session (the gray
            // lifecycle).
            Ok(false) => {}
            Err(refusal) => {
                if episode.note_refused(address) {
                    tracing::warn!(
                        "{connector:?}: configured address {address:?} was not re-admitted: {refusal:?}"
                    );
                }
            }
        }
    }
    if entering {
        tracing::info!(
            "{connector:?}: under its target with nothing in flight and no drawable candidate; re-admitted {admitted} configured address(es) to gray"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Recovery, RecoveryEnd};

    #[test]
    fn a_risen_session_count_ends_the_episode_ahead_of_the_target() {
        let episode = Recovery::open(1);
        // The target is met too. The risen count is still the reason.
        assert_eq!(episode.end(2, 2), Some(RecoveryEnd::KeptRose));
    }

    #[test]
    fn reaching_the_target_without_a_new_session_is_its_own_reason() {
        let episode = Recovery::open(1);
        assert_eq!(episode.end(1, 1), Some(RecoveryEnd::TargetReached));
    }

    #[test]
    fn a_lost_session_leaves_the_episode_open() {
        let episode = Recovery::open(1);
        let target = 4usize;
        assert_eq!(episode.end(1, target), None);
        // A lost session is not recovery working, and a return to the
        // entry count is not a gain.
        assert_eq!(episode.end(0, target), None);
        assert_eq!(episode.end(1, target), None);
    }
}
