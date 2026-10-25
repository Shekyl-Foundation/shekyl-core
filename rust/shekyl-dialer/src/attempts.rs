// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's own count of what it has open and what it is opening
//! (dialer brief, "The fill": the pending attempt and the `Keep` count).
//!
//! The next wake can run while a dial is still in flight. Until the
//! channel is adopted that address is not a session and no row exists,
//! so the board cannot see it. The dialer keeps a pending attempt from
//! the moment the dial starts until its [`DialOutcome`], on every path.
//!
//! The `Keep` count is kept sessions plus pending `Keep` attempts.
//! A confirm dial is not a row and does not count. The board's outbound
//! count knows nothing of a pending attempt.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_peerlist::{DialOutcome, Host, NetworkAddress};

use crate::fill::DialAim;

/// One connector's pending attempts and kept sessions.
#[derive(Debug, Default)]
pub struct Attempts {
    pending: BTreeMap<NetworkAddress, DialAim>,
    kept: BTreeSet<NetworkAddress>,
}

impl Attempts {
    /// Nothing pending, nothing kept.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A dial of `address` starts. `false`, and nothing recorded, when
    /// that address is already pending or already a kept session: the
    /// candidate filter should not have offered it.
    pub fn begin(&mut self, address: &NetworkAddress, aim: DialAim) -> bool {
        if self.pending.contains_key(address) || self.kept.contains(address) {
            return false;
        }
        self.pending.insert(address.clone(), aim);
        true
    }

    /// The attempt ended with `outcome`. The pending entry goes on every
    /// outcome. `SessionAccepted` leaves a kept session; nothing else
    /// does, a `Confirmed` included.
    pub fn finish(&mut self, outcome: &DialOutcome) {
        let address = outcome.address();
        self.pending.remove(address);
        if matches!(outcome, DialOutcome::SessionAccepted(_)) {
            self.kept.insert(address.clone());
        }
    }

    /// A kept session closed.
    pub fn session_closed(&mut self, address: &NetworkAddress) {
        self.kept.remove(address);
    }

    /// A pending attempt to `address` was cancelled (the dialer stopped):
    /// it leaves the pending set with no outcome, and nothing is recorded
    /// on the lists. A kept session is not touched.
    pub fn cancel(&mut self, address: &NetworkAddress) {
        self.pending.remove(address);
    }

    /// The `Keep` count: kept sessions plus pending `Keep` attempts. A
    /// pending `Confirm` does not count.
    #[must_use]
    pub fn kept_count(&self) -> usize {
        self.kept.len()
            + self
                .pending
                .values()
                .filter(|aim| matches!(aim, DialAim::Keep))
                .count()
    }

    /// Dials in flight, of either aim.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Whether `address` is a pending attempt or a kept session.
    #[must_use]
    pub fn holds(&self, address: &NetworkAddress) -> bool {
        self.pending.contains_key(address) || self.kept.contains(address)
    }

    /// Whether a pending attempt or a kept session is to `host`, on any
    /// port. One outbound session per host: a pending attempt's host is
    /// not a candidate either.
    #[must_use]
    pub fn holds_host(&self, host: &Host) -> bool {
        self.pending
            .keys()
            .chain(self.kept.iter())
            .any(|address| address.host() == *host)
    }

    /// The kept sessions to close so that no more than `target` remain,
    /// chosen uniformly. Lowering the cap closes `Keep` rows only: a
    /// pending attempt and a `Confirm` row are never what the cap closes.
    /// The caller closes each and reports it with
    /// [`Self::session_closed`].
    pub fn over_target<R: RelayRng + ?Sized>(
        &self,
        target: usize,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        let excess = self.kept.len().saturating_sub(target);
        let mut pool: Vec<&NetworkAddress> = self.kept.iter().collect();
        let mut out = Vec::with_capacity(excess);
        for _ in 0..excess {
            let Some(last) = pool.len().checked_sub(1) else {
                break;
            };
            let at = usize::try_from(bounded_uniform(rng, last as u64)).unwrap_or(0);
            out.push(pool.swap_remove(at).clone());
        }
        out
    }
}
