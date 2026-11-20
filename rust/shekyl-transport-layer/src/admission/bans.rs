// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The socket table's bans.
//!
//! [`Sockets::commit_ban`] stores a ban, closes the live sockets it covers,
//! and rings subscribers after the table lock has dropped. A lift, an
//! expiry and a subscription share that ring-after-drop half. A ban that
//! does not change the list closes nothing and rings nothing.

use std::net::IpAddr;
use std::sync::Arc;

use shekyl_timing_engine::Tick;

use super::{release, BanExpiry, CloseResult, Inner, ObservedEndpoint, SocketId, Sockets};
use crate::ban::{BanFeed, BanLeft, BanList, Ipv4Subnet, ListedBan};
use crate::{CloseCause, CloseKind};

impl Sockets {
    /// Whether a ban in force covers `host`. A lookup changes nothing: a
    /// timed ban ends when the ban list's timing owner expires it.
    pub fn is_banned(&self, host: IpAddr) -> bool {
        self.lock().bans.is_banned(host)
    }

    /// Ban `host` until `until` and close live sockets to that host.
    /// A deadline that has already passed bans nothing and closes nothing.
    /// A deadline that is not later than the one stored does not shorten it.
    /// Each closed socket is [`CloseKind::LocalClose`], once.
    pub fn ban_host(&self, host: IpAddr, until: Tick, now: Tick) -> Vec<SocketId> {
        self.commit_ban(
            |bans| bans.ban_host(host, until, now),
            BanSubject::Host(host),
            Some(until),
        )
    }

    /// Ban an IPv4 subnet and close live IPv4 sockets inside it.
    /// The deadline rule is the same as [`Self::ban_host`].
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> Vec<SocketId> {
        self.commit_ban(
            |bans| bans.ban_subnet(subnet, until, now),
            BanSubject::Subnet(subnet),
            Some(until),
        )
    }

    /// Ban `host` until it is lifted, and close live sockets to it.
    /// A ban that is already permanent closes nothing new.
    pub fn ban_host_permanent(&self, host: IpAddr) -> Vec<SocketId> {
        self.commit_ban(
            |bans| bans.ban_host_permanent(host),
            BanSubject::Host(host),
            None,
        )
    }

    /// Ban `subnet` until it is lifted, and close live sockets inside it.
    pub fn ban_subnet_permanent(&self, subnet: Ipv4Subnet) -> Vec<SocketId> {
        self.commit_ban(
            |bans| bans.ban_subnet_permanent(subnet),
            BanSubject::Subnet(subnet),
            None,
        )
    }

    /// Store a ban, close what it covers, then ring once the table lock
    /// has dropped.
    ///
    /// `store` records the ban and reports whether the list changed. A ban
    /// that changes nothing closes nothing and rings nothing. `arm_until`
    /// is the deadline to tell the timing owner when this ban made it the
    /// earliest; a permanent ban has none, so it arms nothing.
    fn commit_ban(
        &self,
        store: impl FnOnce(&mut BanList) -> bool,
        subject: BanSubject,
        arm_until: Option<Tick>,
    ) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !store(&mut inner.bans) {
            return Vec::new();
        }
        let closed = close_matching(&mut inner, subject);
        let expiry = arm_until.and_then(|until| inner.expiry_for(until));
        let rings = inner.bans.take_rings();
        drop(inner);
        if let (Some(until), Some(BanExpiry(arm))) = (arm_until, expiry) {
            arm(until);
        }
        rings.ring();
        closed
    }

    /// Remove a host ban. Sockets that are already open stay open.
    pub fn lift_host(&self, host: IpAddr) -> bool {
        self.with_bans(|bans| bans.lift_host(host))
    }

    /// Remove a subnet ban. Sockets that are already open stay open.
    pub fn lift_subnet(&self, subnet: Ipv4Subnet) -> bool {
        self.with_bans(|bans| bans.lift_subnet(subnet))
    }

    /// Drop every ban. Open sockets stay open. The daemon lifts one entry
    /// at a time; a test process uses this because the list outlives the
    /// `node_server` that used to own it.
    pub fn clear_bans(&self) {
        self.with_bans(BanList::clear);
    }

    /// Install the ban list's timing owner. `arm` is told the earliest
    /// deadline now, and afterwards each deadline a new ban makes the
    /// earliest; when it fires, the owner calls [`Self::expire_bans`] and
    /// arms what that returns. A later install replaces this one.
    pub fn set_ban_expiry(&self, arm: Arc<dyn Fn(Tick) + Send + Sync>) {
        let expiry = BanExpiry(arm);
        let earliest = {
            let mut inner = self.lock();
            inner.ban_expiry = Some(expiry.clone());
            inner.bans.earliest()
        };
        if let Some(deadline) = earliest {
            (expiry.0)(deadline);
        }
    }

    /// End every timed ban whose deadline is at or before `now`, posting
    /// each lift to the subscribers. The ban list's timing owner calls
    /// this when its deadline fires; returns the next deadline to arm.
    pub fn expire_bans(&self, now: Tick) -> Option<Tick> {
        self.with_bans(|bans| bans.expire(now))
    }

    /// Subscribe to the bans: a queue that starts with a ban event for
    /// every entry in force and then receives each ban and lift in order,
    /// ringing `ring` after each, once the table's lock has dropped. The
    /// seed and the subscription are taken under one hold of the lock.
    pub fn subscribe_bans(&self, ring: Arc<dyn Fn() + Send + Sync>) -> BanFeed {
        self.with_bans(|bans| bans.subscribe(ring))
    }

    /// Change the ban list under the table's lock, then ring the
    /// subscribers it posted to once the lock has dropped: a ring never
    /// runs under the table's lock.
    fn with_bans<T>(&self, change: impl FnOnce(&mut BanList) -> T) -> T {
        let mut inner = self.lock();
        let out = change(&mut inner.bans);
        let rings = inner.bans.take_rings();
        drop(inner);
        rings.ring();
        out
    }

    /// Time left on the longest ban that covers `host`.
    pub fn remaining(&self, host: IpAddr, now: Tick) -> Option<BanLeft> {
        self.lock().bans.remaining(host, now)
    }

    /// Bans still in force, with nanoseconds left from `now`.
    pub fn listed(&self, now: Tick) -> Vec<ListedBan> {
        self.lock().bans.listed(now)
    }

    /// Take the ban timer for `generation`, or `None` when a task already
    /// holds the claim for that generation. A different generation takes
    /// the claim immediately. The guard releases it on drop only when the
    /// table still records this generation, so an older task cannot clear
    /// a newer claim.
    pub fn take_ban_timer(&self, generation: u64) -> Option<BanTimer> {
        let mut inner = self.lock();
        if inner.timer_generation == Some(generation) {
            return None;
        }
        inner.timer_generation = Some(generation);
        Some(BanTimer {
            sockets: self.clone(),
            generation,
        })
    }
}

/// The task that ends timed bans. Dropped when that task ends, which
/// releases the table for a later generation.
pub struct BanTimer {
    sockets: Sockets,
    generation: u64,
}

impl Drop for BanTimer {
    fn drop(&mut self) {
        let mut inner = self.sockets.lock();
        if inner.timer_generation == Some(self.generation) {
            inner.timer_generation = None;
        }
    }
}

#[derive(Clone, Copy)]
enum BanSubject {
    Host(IpAddr),
    Subnet(Ipv4Subnet),
}

fn endpoint_is_subject(subject: BanSubject, endpoint: ObservedEndpoint) -> bool {
    match (subject, endpoint) {
        (BanSubject::Host(host), ObservedEndpoint::Host(observed)) => observed == host,
        (BanSubject::Subnet(subnet), ObservedEndpoint::Host(IpAddr::V4(observed))) => {
            subnet.contains(observed)
        }
        (BanSubject::Host(_) | BanSubject::Subnet(_), ObservedEndpoint::Zone)
        | (BanSubject::Subnet(_), ObservedEndpoint::Host(IpAddr::V6(_))) => false,
    }
}

fn close_matching(inner: &mut Inner, subject: BanSubject) -> Vec<SocketId> {
    let ids: Vec<SocketId> = inner
        .live
        .iter()
        .filter(|(_, live)| endpoint_is_subject(subject, live.endpoint))
        .map(|(id, _)| *id)
        .collect();
    for id in &ids {
        let result = release(inner, *id, CloseCause::new(CloseKind::LocalClose));
        debug_assert!(matches!(result, CloseResult::Recorded(_)));
    }
    debug_assert!(inner.holds());
    ids
}
