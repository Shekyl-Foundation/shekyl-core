// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One wake's copy of the transport bans.
//!
//! The peer lists take a [`BanQuery`]. The bans live in the seam hub.
//! The dialer holds both and never asks the hub while its own lock is
//! held, so it copies the bans out first. The copy is the wake's view:
//! expiry has already been applied, and the copy does not expire again.

use std::collections::BTreeSet;
use std::net::IpAddr;

use shekyl_peerlist::{BanQuery, Tick};
use shekyl_seam::{Hub, Ipv4Subnet, ListedBan};

/// Hosts and subnets banned at the tick the snapshot was taken.
pub struct BanSnapshot {
    hosts: BTreeSet<IpAddr>,
    subnets: Vec<Ipv4Subnet>,
}

impl BanSnapshot {
    /// The hub's bans, copied out. The hub lock is not held afterwards.
    #[must_use]
    pub fn take(hub: &Hub) -> Self {
        Self::from_listed(hub.listed_bans())
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
        Self { hosts, subnets }
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
