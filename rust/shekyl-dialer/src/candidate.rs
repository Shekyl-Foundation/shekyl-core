// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The candidate filter (dialer brief, "The candidate filter").
//!
//! Before a draw, an address is a candidate or it is skipped. Every kept
//! row of the brief's table is one variant of [`Skip`]. Two rows are not
//! here because they are not dial-time checks: address validity is the
//! peer lists' rule at the door, and "one candidate per host" is how the
//! lists draw ([`shekyl_peerlist::Peerlist::draw_gray_where`]).
//!
//! There is no subnet grouping and no last-seen weighting (ruled
//! 2026-10-11). The draw over the candidates is uniform.

use std::collections::BTreeSet;

use shekyl_peerlist::{BanQuery, Host, NetworkAddress, Tick};

use crate::attempts::Attempts;
use crate::memory::FailedAddresses;

/// Why an address is not a dial candidate at this wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// It is this node's own address. A dial to ourselves is not a peer.
    OwnAddress,
    /// A session to this exact address already exists, in either
    /// direction.
    InUse,
    /// This node already has an outbound session, or a pending attempt,
    /// to this host on another port. One outbound session per host.
    HostHasOutbound,
    /// It is a pending attempt or a kept session of the dialer's own.
    Pending,
    /// The host is under an active ban.
    Banned,
    /// A recent dial failure suppresses it. On clearnet nothing writes
    /// that memory (R2), so this never skips a clearnet address.
    RecentlyFailed,
}

/// What the filter reads, for one connector at one wake.
pub struct CandidateFilter<'a> {
    /// This node's own dialable addresses on the connector.
    pub own: &'a [NetworkAddress],
    /// The address of every live session on the connector, inbound and
    /// outbound.
    pub sessions: &'a BTreeSet<NetworkAddress>,
    /// The host of every outbound session on the connector.
    pub outbound_hosts: &'a BTreeSet<Host>,
    /// The dialer's pending attempts and kept sessions.
    pub attempts: &'a Attempts,
    /// The failed-address memory.
    pub failed: &'a FailedAddresses,
    /// The transport layer's bans.
    pub bans: &'a mut dyn BanQuery,
    /// The wake's time.
    pub now: Tick,
}

impl CandidateFilter<'_> {
    /// `Ok` when `address` may be drawn, or the first reason it may not.
    pub fn check(&mut self, address: &NetworkAddress) -> Result<(), Skip> {
        if self.own.contains(address) {
            return Err(Skip::OwnAddress);
        }
        if self.attempts.holds(address) {
            return Err(Skip::Pending);
        }
        if self.sessions.contains(address) {
            return Err(Skip::InUse);
        }
        let host = address.host();
        if self.outbound_hosts.contains(&host) || self.attempts.holds_host(&host) {
            return Err(Skip::HostHasOutbound);
        }
        if address
            .ip()
            .is_some_and(|ip| self.bans.is_banned(ip, self.now))
        {
            return Err(Skip::Banned);
        }
        if self.failed.is_recently_failed(address, self.now) {
            return Err(Skip::RecentlyFailed);
        }
        Ok(())
    }

    /// Whether `address` may be drawn.
    pub fn admits(&mut self, address: &NetworkAddress) -> bool {
        self.check(address).is_ok()
    }
}
