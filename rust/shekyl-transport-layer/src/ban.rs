// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban list. IPv4 subnets and host addresses. Expiry is checked when
//! an entry is looked up, not on a timer.
//!
//! The RPC path does not call this yet. That call is the seam, when Rust
//! owns the sockets. One list lives in the socket table; this type is that
//! list.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_timing_engine::Tick;

/// An IPv4 prefix. `prefix_len` is the number of leading bits in network
/// order, so `/24` is the first three octets. Bits outside the prefix are
/// cleared when the subnet is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Subnet {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Subnet {
    /// `None` when `prefix_len` is greater than 32.
    #[must_use]
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        Some(Self {
            network: mask(addr, prefix_len),
            prefix_len,
        })
    }

    /// The masked network address.
    #[must_use]
    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Whether `addr` is inside this prefix.
    #[must_use]
    pub fn contains(self, addr: Ipv4Addr) -> bool {
        mask(addr, self.prefix_len) == self.network
    }
}

fn mask(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let shift = 32 - u32::from(prefix_len);
    Ipv4Addr::from(u32::from(addr) & (u32::MAX << shift))
}

#[derive(Clone, Debug, Default)]
pub struct BanList {
    hosts: HashMap<IpAddr, Tick>,
    subnets: Vec<(Ipv4Subnet, Tick)>,
}

impl BanList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a host ban that lasts until `until`. A deadline that has
    /// already passed is not a ban: the list is unchanged and this returns
    /// false. A later deadline replaces an earlier one.
    pub fn ban_host(&mut self, host: IpAddr, until: Tick, now: Tick) -> bool {
        if now >= until {
            return false;
        }
        self.hosts.insert(host, until);
        true
    }

    /// Record an IPv4 subnet ban. Same deadline rule as [`Self::ban_host`].
    /// The same subnet is replaced, not stacked.
    pub fn ban_subnet(&mut self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> bool {
        if now >= until {
            return false;
        }
        if let Some(entry) = self.subnets.iter_mut().find(|(have, _)| *have == subnet) {
            entry.1 = until;
        } else {
            self.subnets.push((subnet, until));
        }
        true
    }

    /// Remove a host ban. Expired entries are removed too.
    pub fn lift_host(&mut self, host: IpAddr) -> bool {
        self.hosts.remove(&host).is_some()
    }

    /// Remove a subnet ban.
    pub fn lift_subnet(&mut self, subnet: Ipv4Subnet) -> bool {
        let before = self.subnets.len();
        self.subnets.retain(|(have, _)| *have != subnet);
        self.subnets.len() != before
    }

    /// Whether `host` is banned at `now`. An entry whose deadline has
    /// arrived is removed by this lookup and is not banned.
    pub fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool {
        let host_hit = match self.hosts.get(&host).copied() {
            Some(until) if now < until => true,
            Some(_) => {
                self.hosts.remove(&host);
                false
            }
            None => false,
        };
        let subnet_hit = match host {
            IpAddr::V4(ip) => self.expire_subnets(now, Some(ip)),
            IpAddr::V6(_) => {
                self.expire_subnets(now, None);
                false
            }
        };
        host_hit || subnet_hit
    }

    /// Host bans still in force at `now`. Expired ones are dropped.
    pub fn hosts(&mut self, now: Tick) -> Vec<(IpAddr, Tick)> {
        self.hosts.retain(|_, until| now < *until);
        let mut out: Vec<_> = self
            .hosts
            .iter()
            .map(|(host, until)| (*host, *until))
            .collect();
        out.sort_by_key(|(host, _)| *host);
        out
    }

    /// Subnet bans still in force at `now`. Expired ones are dropped.
    pub fn subnets(&mut self, now: Tick) -> Vec<(Ipv4Subnet, Tick)> {
        self.expire_subnets(now, None);
        let mut out = self.subnets.clone();
        out.sort_by_key(|(subnet, _)| *subnet);
        out
    }

    /// Drop expired subnets. When `probe` is set, report whether any
    /// remaining subnet contains it.
    fn expire_subnets(&mut self, now: Tick, probe: Option<Ipv4Addr>) -> bool {
        let mut hit = false;
        self.subnets.retain(|(subnet, until)| {
            if now < *until {
                if probe.is_some_and(|ip| subnet.contains(ip)) {
                    hit = true;
                }
                true
            } else {
                false
            }
        });
        hit
    }
}

#[cfg(test)]
mod tests {
    use super::{BanList, Ipv4Subnet};
    use shekyl_timing_engine::Tick;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    #[test]
    fn a_prefix_is_the_leading_octets() {
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24).expect("prefix");
        assert_eq!(subnet.network(), Ipv4Addr::new(10, 1, 2, 0));
        assert!(subnet.contains(Ipv4Addr::new(10, 1, 2, 255)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 1, 3, 1)));
        assert_eq!(
            Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24),
            Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 1), 24)
        );
        assert!(Ipv4Subnet::new(Ipv4Addr::LOCALHOST, 33).is_none());
        let everything = Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 0).expect("prefix 0");
        assert!(everything.contains(Ipv4Addr::new(192, 168, 0, 1)));
    }

    #[test]
    fn a_ban_expires_when_it_is_looked_up() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(50)));
        assert!(bans.is_banned(host, Tick::new(99)));
        assert!(!bans.is_banned(host, Tick::new(100)));
        assert!(!bans.is_banned(host, Tick::new(101)));
        assert!(bans.hosts(Tick::new(101)).is_empty());
    }

    #[test]
    fn a_subnet_ban_expires_when_it_is_looked_up() {
        let mut bans = BanList::new();
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24).expect("prefix");
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        let inside = v4([10, 1, 2, 5]);
        let outside = v4([10, 1, 3, 5]);
        assert!(bans.is_banned(inside, Tick::new(99)));
        assert!(!bans.is_banned(outside, Tick::new(99)));
        assert!(!bans.is_banned(inside, Tick::new(100)));
        assert!(bans.subnets(Tick::new(100)).is_empty());
    }

    #[test]
    fn a_deadline_that_has_passed_does_not_replace_a_live_ban() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(1)));
        assert!(!bans.ban_host(host, Tick::new(10), Tick::new(50)));
        assert!(bans.is_banned(host, Tick::new(50)));
    }

    #[test]
    fn lift_removes_a_host_and_a_subnet() {
        let mut bans = BanList::new();
        let host = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(1)));
        assert!(bans.lift_host(host));
        assert!(!bans.is_banned(host, Tick::new(2)));
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("prefix");
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        assert!(bans.lift_subnet(subnet));
        assert!(!bans.is_banned(v4([10, 1, 1, 1]), Tick::new(2)));
    }

    #[test]
    fn an_ipv6_host_is_not_inside_an_ipv4_subnet() {
        let mut bans = BanList::new();
        let subnet = Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0).expect("prefix 0");
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        assert!(!bans.is_banned(IpAddr::V6(Ipv6Addr::LOCALHOST), Tick::new(2)));
        assert!(bans.is_banned(v4([8, 8, 8, 8]), Tick::new(2)));
    }
}
