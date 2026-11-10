// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The candidate filter (dialer brief, "The candidate filter").
//!
//! Before a draw, an address is a candidate or it is skipped. Every kept
//! row of the brief's table is one variant of [`Skip`]. Three rows are not
//! here because they are not dial-time checks: address validity is the
//! peer lists' rule at the door; a ban bars every seat it covers on the
//! lists when its event arrives, so a barred seat is never drawn
//! ([`shekyl_peerlist::Peerlist::ban`], Rick 2026-10-31); and "one
//! candidate per host" is how the lists draw
//! ([`shekyl_peerlist::Peerlist::draw_gray_where`]).
//!
//! There is no subnet grouping and no last-seen weighting (ruled
//! 2026-10-11). The draw over the candidates is uniform.

use std::collections::BTreeSet;

use shekyl_peerlist::{Host, NetworkAddress};

use crate::attempts::Attempts;

/// Whether `host` is already reached: a live session names it, in either
/// direction, or the dialer has an in-flight test or a kept session to it.
///
/// A waiting test does not count. The outstanding draw already keeps that
/// address from being drawn again, and the wait must not block its own
/// resumption. A session that arrived during the wait is in `sessions`,
/// which is what stops the resumption.
#[must_use]
pub fn host_occupied(
    sessions: &BTreeSet<NetworkAddress>,
    attempts: &Attempts,
    host: &Host,
) -> bool {
    sessions.iter().any(|live| live.host() == *host) || attempts.holds_host(host)
}

/// Why an address is not a dial candidate at this wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// It is this node's own address. A dial to ourselves is not a peer.
    OwnAddress,
    /// A session to this exact address already exists, in either
    /// direction.
    InUse,
    /// This node already has a session to this host, in either direction,
    /// or a pending attempt to it. One session per host: a host that dialed
    /// in is not dialed back. Dialing a node because it connected to us
    /// would hand any node that connects a free outbound slot, the eclipse
    /// attacker's cheapest step (Rick, 2026-11-09). The outbound target is
    /// a best effort at that many distinct nodes.
    HostInSession,
    /// It is a pending attempt or a kept session of the dialer's own.
    Pending,
}

/// What the filter reads, for one connector at one wake.
pub struct CandidateFilter<'a> {
    /// This node's own dialable addresses on the connector.
    pub own: &'a [NetworkAddress],
    /// The address of every live session on the connector, inbound and
    /// outbound. The host check reads this set: a second host set would
    /// be the same addresses projected, and a caller could let the two
    /// disagree.
    pub sessions: &'a BTreeSet<NetworkAddress>,
    /// The dialer's pending attempts and kept sessions.
    pub attempts: &'a Attempts,
}

impl CandidateFilter<'_> {
    /// `Ok` when `address` may be drawn, or the first reason it may not.
    pub fn check(&self, address: &NetworkAddress) -> Result<(), Skip> {
        if self.own.contains(address) {
            return Err(Skip::OwnAddress);
        }
        if self.attempts.holds(address) {
            return Err(Skip::Pending);
        }
        if self.sessions.contains(address) {
            return Err(Skip::InUse);
        }
        if host_occupied(self.sessions, self.attempts, &address.host()) {
            return Err(Skip::HostInSession);
        }
        Ok(())
    }

    /// Whether `address` may be drawn.
    pub fn admits(&self, address: &NetworkAddress) -> bool {
        self.check(address).is_ok()
    }
}
