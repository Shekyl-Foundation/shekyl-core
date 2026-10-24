// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One wake's copy of what the peer lists ask about the outside: the
//! transport bans, and the addresses this node holds a live session to.
//!
//! The peer lists take a [`BanQuery`]. The bans and the board live in the
//! seam hub. The dialer holds both and never asks the hub while its own
//! lock is held, so it copies them out first. The copy is the wake's view:
//! ban expiry has already been applied, and the copy does not expire
//! again; a session that ends after the copy is reported by its close.

use std::collections::BTreeSet;
use std::net::IpAddr;

use shekyl_peerlist::{BanQuery, NetworkAddress, Tick};
use shekyl_seam::{Hub, Ipv4Subnet, ListedBan};

use crate::owner::address_of;

/// Hosts and subnets banned, and the addresses of the live sessions, at
/// the tick the snapshot was taken.
pub struct BanSnapshot {
    hosts: BTreeSet<IpAddr>,
    subnets: Vec<Ipv4Subnet>,
    live: BTreeSet<NetworkAddress>,
}

impl BanSnapshot {
    /// The hub's bans and its board's session addresses, copied out. The
    /// hub lock is not held afterwards.
    #[must_use]
    pub fn take(hub: &Hub) -> Self {
        let mut snapshot = Self::from_listed(hub.listed_bans());
        snapshot.live = hub
            .board()
            .rows()
            .iter()
            .filter_map(|row| address_of(&row.endpoint()))
            .collect();
        snapshot
    }

    fn from_listed(listed: Vec<ListedBan>) -> Self {
        let mut hosts = BTreeSet::new();
        let mut subnets = Vec::new();
        for ban in listed {
            match ban {
                ListedBan::Host { host, left: _ } => {
                    hosts.insert(host);
                }
                ListedBan::Subnet { subnet, left: _ } => subnets.push(subnet),
            }
        }
        Self {
            hosts,
            subnets,
            live: BTreeSet::new(),
        }
    }

    /// Whether `host` was banned when this snapshot was taken, including
    /// by a subnet that contains it.
    #[must_use]
    pub fn covers(&self, host: IpAddr) -> bool {
        if self.hosts.contains(&host) {
            return true;
        }
        match host {
            IpAddr::V4(ip) => self.subnets.iter().any(|subnet| subnet.contains(ip)),
            IpAddr::V6(_) => false,
        }
    }
}

impl BanQuery for BanSnapshot {
    fn is_banned(&mut self, host: IpAddr, _now: Tick) -> bool {
        self.covers(host)
    }

    fn has_live_session(&mut self, address: &NetworkAddress) -> bool {
        self.live.contains(address)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_seam::BanLeft;

    use super::*;

    #[test]
    fn a_snapshot_covers_a_host_and_a_subnet_that_contains_the_address() {
        let host = IpAddr::V4(Ipv4Addr::new(11, 12, 0, 9));
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 3), 8).expect("prefix");
        let snapshot = BanSnapshot::from_listed(vec![
            ListedBan::Host {
                host,
                left: BanLeft::Permanent,
            },
            ListedBan::Subnet {
                subnet,
                left: BanLeft::Permanent,
            },
        ]);
        assert!(snapshot.covers(host));
        assert!(snapshot.covers(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))));
        assert!(!snapshot.covers(IpAddr::V4(Ipv4Addr::new(11, 12, 0, 8))));
    }
}
