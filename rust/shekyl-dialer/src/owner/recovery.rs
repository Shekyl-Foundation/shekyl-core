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
//! report carries the kept count before this wake's own dial, and the
//! address this wake drew, when it drew one. The episode ends on the
//! first of these:
//!
//! - the kept count is higher than it was when the episode opened;
//! - the connector is no longer under its target;
//! - this wake drew an address the episode did not re-admit.
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
use crate::bans::BanSnapshot;

/// Why a recovery episode ended. The leave line names this and no other
/// reason: a risen kept count, a met target, and a foreign draw can all
/// be true on one wake, and the first match is the one said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryEnd {
    /// A kept session was added after the episode opened.
    KeptRose,
    /// The connector is no longer under its target. The kept count may
    /// be the one the episode opened with: the operator lowered the target.
    TargetReached,
    /// This wake drew an address the episode did not re-admit.
    ForeignCandidate,
}

impl RecoveryEnd {
    const fn phrase(self) -> &'static str {
        match self {
            Self::KeptRose => "a kept session was added",
            Self::TargetReached => "the connector is at its target",
            Self::ForeignCandidate => "a candidate it did not re-admit was drawn",
        }
    }
}

/// The open episode: what the connector had when recovery started, which
/// configured addresses it has put back, and which refusals it has said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Recovery {
    /// The kept count when the episode opened.
    kept_at_entry: usize,
    /// Configured addresses this episode put back on gray.
    re_admitted: BTreeSet<NetworkAddress>,
    /// Configured addresses whose refusal this episode has said.
    refused: BTreeSet<NetworkAddress>,
}

impl Recovery {
    fn open(kept_at_entry: usize) -> Self {
        Self {
            kept_at_entry,
            re_admitted: BTreeSet::new(),
            refused: BTreeSet::new(),
        }
    }

    fn note_re_admitted(&mut self, address: &NetworkAddress) {
        self.re_admitted.insert(address.clone());
    }

    /// `true` the first time `address` is refused in this episode.
    fn note_refused(&mut self, address: &NetworkAddress) -> bool {
        self.refused.insert(address.clone())
    }

    /// `None` while this episode is still recovery.
    ///
    /// A risen kept count wins over the target and over the draw: it is
    /// the progress the episode exists to notice. The target is next, so
    /// a wake that meets it by a lowered target is not described as a
    /// foreign draw. A draw of an address this episode re-admitted, and
    /// a wake that drew nothing, leave the episode open.
    fn end(
        &self,
        kept: usize,
        target: usize,
        drawn: Option<&NetworkAddress>,
    ) -> Option<RecoveryEnd> {
        if kept > self.kept_at_entry {
            return Some(RecoveryEnd::KeptRose);
        }
        if kept >= target {
            return Some(RecoveryEnd::TargetReached);
        }
        if drawn.is_some_and(|address| !self.re_admitted.contains(address)) {
            return Some(RecoveryEnd::ForeignCandidate);
        }
        None
    }
}

/// Close `episode` when this wake shows that recovery worked, and say why.
///
/// `kept` is the count before this wake's dial. `drawn` is the address
/// this wake drew, or `None` when it drew nothing — a recovery wake and
/// an idle wake both pass `None`. Every wake calls this, so a stranded
/// wake after a gained session is the wake that closes the episode.
pub(super) fn report_wake(
    episode: &mut Option<Recovery>,
    connector: ConnectorId,
    kept: usize,
    target: usize,
    drawn: Option<&NetworkAddress>,
) {
    let Some(end) = episode
        .as_ref()
        .and_then(|open| open.end(kept, target, drawn))
    else {
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
/// closed the episode opens the next one here, with the kept count the
/// report already saw.
pub(super) fn re_admit<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    bans: &mut BanSnapshot,
    connector: ConnectorId,
    now: Tick,
    rng: &mut R,
) {
    let population: Vec<NetworkAddress> = match &shared.exclusive {
        Some(population) => population.iter().cloned().collect(),
        None => shared.configured.clone(),
    };
    let index = connector.index();
    let kept = shared.attempts(connector).kept_count();
    let entering = shared.recovery[index].is_none();
    let episode = shared.recovery[index].get_or_insert_with(|| Recovery::open(kept));
    let mut admitted = 0usize;
    for address in population
        .iter()
        .filter(|address| Peerlist::connector_of(address) == Some(connector))
    {
        match shared
            .lists
            .admit_gray(address, Source::Operator, now, bans, rng)
        {
            Ok(true) => {
                admitted += 1;
                episode.note_re_admitted(address);
            }
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
    use std::net::Ipv4Addr;

    use shekyl_peerlist::NetworkAddress;

    use super::{Recovery, RecoveryEnd};

    fn address(n: u8) -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(11, 15, 0, n),
            port: 18080,
        }
    }

    #[test]
    fn a_risen_kept_count_ends_the_episode_ahead_of_the_other_reasons() {
        let mut episode = Recovery::open(1);
        let own = address(1);
        episode.note_re_admitted(&own);
        // The target is met and the draw is an address this episode put
        // back. The risen count is still the reason.
        assert_eq!(episode.end(2, 2, Some(&own)), Some(RecoveryEnd::KeptRose));
    }

    #[test]
    fn reaching_the_target_without_a_new_session_is_its_own_reason() {
        let episode = Recovery::open(1);
        // A foreign draw on the same wake must not hide the met target.
        assert_eq!(
            episode.end(1, 1, Some(&address(2))),
            Some(RecoveryEnd::TargetReached)
        );
    }

    #[test]
    fn a_foreign_draw_ends_the_episode_and_a_re_admitted_draw_does_not() {
        let mut episode = Recovery::open(1);
        let own = address(1);
        episode.note_re_admitted(&own);
        let target = 4usize;
        assert_eq!(
            episode.end(1, target, Some(&address(2))),
            Some(RecoveryEnd::ForeignCandidate)
        );
        assert_eq!(episode.end(1, target, Some(&own)), None);
        assert_eq!(episode.end(1, target, None), None);
        // A lost session is not recovery working. The episode stays open,
        // so a later return to the entry count does not look like a gain.
        assert_eq!(episode.end(0, target, None), None);
    }
}
