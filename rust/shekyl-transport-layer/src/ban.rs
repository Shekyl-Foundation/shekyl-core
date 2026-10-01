// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban list. IPv4 subnets and host addresses. Expiry is checked when
//! an entry is looked up, not on a timer.
//!
//! RPC and misbehaviour scoring both write this list, through a duration
//! added to the monotonic clock. A duration that does not fit a [`Tick`]
//! is not stored. A ban from the operator's ban file has no deadline:
//! it stays until it is lifted. One list lives in the socket table; this
//! type is that list.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_timing_engine::Tick;

/// How long a ban still has, read at one tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanLeft {
    /// Nanoseconds until the deadline.
    Remaining { nanos: u64 },
    /// No deadline. The ban stays until it is lifted.
    Permanent,
}

/// One row of the list, with time left from the tick it was read at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListedBan {
    /// A single host.
    Host {
        /// The banned address.
        host: IpAddr,
        /// Time left, or none.
        left: BanLeft,
    },
    /// An IPv4 prefix.
    Subnet {
        /// The prefix.
        subnet: Ipv4Subnet,
        /// Time left, or none.
        left: BanLeft,
    },
}

/// A stored ban. Permanent has no deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Term {
    Until(Tick),
    Permanent,
}

/// `now + duration_ns`, or `None` when the sum does not fit a [`Tick`].
/// Zero is not a duration.
#[must_use]
pub fn deadline_after(now: Tick, duration_ns: u64) -> Option<Tick> {
    if duration_ns == 0 {
        return None;
    }
    now.get().checked_add(duration_ns).map(Tick::new)
}

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

fn term_live(term: Term, now: Tick) -> bool {
    match term {
        Term::Permanent => true,
        Term::Until(until) => now < until,
    }
}

/// A permanent ban is not shortened by a deadline. A deadline replaces
/// another only when it is later. Permanent replaces a deadline.
fn term_replaces(current: Option<Term>, next: Term) -> bool {
    match (current, next) {
        (Some(Term::Permanent), _) => false,
        (_, Term::Permanent) | (None, Term::Until(_)) => true,
        (Some(Term::Until(have)), Term::Until(until)) => until > have,
    }
}

fn term_left(term: Term, now: Tick) -> Option<BanLeft> {
    match term {
        Term::Permanent => Some(BanLeft::Permanent),
        Term::Until(until) if now < until => Some(BanLeft::Remaining {
            nanos: until.get() - now.get(),
        }),
        Term::Until(_) => None,
    }
}

fn longer(left: BanLeft, right: BanLeft) -> BanLeft {
    match (left, right) {
        (BanLeft::Permanent, _) | (_, BanLeft::Permanent) => BanLeft::Permanent,
        (BanLeft::Remaining { nanos: a }, BanLeft::Remaining { nanos: b }) => {
            BanLeft::Remaining { nanos: a.max(b) }
        }
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
    hosts: HashMap<IpAddr, Term>,
    subnets: Vec<(Ipv4Subnet, Term)>,
}

impl BanList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a host ban that lasts until `until`. A deadline that has
    /// already passed is not a ban. A deadline that is not later than the
    /// one already stored does not shorten it: [`Self::lift_host`] is how a
    /// ban ends early. Returns whether this call stored `until`.
    pub fn ban_host(&mut self, host: IpAddr, until: Tick, now: Tick) -> bool {
        if now >= until {
            return false;
        }
        self.store_host(host, Term::Until(until))
    }

    /// Ban `host` until it is lifted. A deadline already stored is replaced.
    /// A ban that is already permanent is left as it is.
    pub fn ban_host_permanent(&mut self, host: IpAddr) -> bool {
        self.store_host(host, Term::Permanent)
    }

    fn store_host(&mut self, host: IpAddr, next: Term) -> bool {
        if !term_replaces(self.hosts.get(&host).copied(), next) {
            return false;
        }
        self.hosts.insert(host, next);
        true
    }

    /// Record an IPv4 subnet ban. Same deadline rule as [`Self::ban_host`].
    /// One subnet is one entry.
    pub fn ban_subnet(&mut self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> bool {
        if now >= until {
            return false;
        }
        self.store_subnet(subnet, Term::Until(until))
    }

    /// Ban `subnet` until it is lifted. Same replacement rule as
    /// [`Self::ban_host_permanent`].
    pub fn ban_subnet_permanent(&mut self, subnet: Ipv4Subnet) -> bool {
        self.store_subnet(subnet, Term::Permanent)
    }

    fn store_subnet(&mut self, subnet: Ipv4Subnet, next: Term) -> bool {
        if let Some(entry) = self.subnets.iter_mut().find(|(have, _)| *have == subnet) {
            if !term_replaces(Some(entry.1), next) {
                return false;
            }
            entry.1 = next;
        } else if term_replaces(None, next) {
            self.subnets.push((subnet, next));
        } else {
            return false;
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

    /// Drop every host and subnet ban.
    ///
    /// The process list outlives one `node_server`. A test process resets
    /// it between servers; the daemon lifts entries one at a time.
    pub fn clear(&mut self) {
        self.hosts.clear();
        self.subnets.clear();
    }

    /// Whether `host` is banned at `now`. An entry whose deadline has
    /// arrived is removed by this lookup and is not banned.
    pub fn is_banned(&mut self, host: IpAddr, now: Tick) -> bool {
        let host_hit = match self.hosts.get(&host).copied() {
            Some(term) if term_live(term, now) => true,
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
    fn hosts(&mut self, now: Tick) -> Vec<(IpAddr, Term)> {
        self.hosts.retain(|_, term| term_live(*term, now));
        let mut out: Vec<_> = self
            .hosts
            .iter()
            .map(|(host, term)| (*host, *term))
            .collect();
        out.sort_by_key(|(host, _)| *host);
        out
    }

    /// Subnet bans still in force at `now`. Expired ones are dropped.
    fn subnets(&mut self, now: Tick) -> Vec<(Ipv4Subnet, Term)> {
        self.expire_subnets(now, None);
        let mut out = self.subnets.clone();
        out.sort_by_key(|(subnet, _)| *subnet);
        out
    }

    /// Time left on the longest ban that covers `host`.
    /// `None` when nothing covers it. Expired entries are removed.
    /// A permanent ban is [`BanLeft::Permanent`], not a number of seconds.
    pub fn remaining(&mut self, host: IpAddr, now: Tick) -> Option<BanLeft> {
        let host_left = match self.hosts.get(&host).copied() {
            Some(term) => match term_left(term, now) {
                Some(left) => Some(left),
                None => {
                    self.hosts.remove(&host);
                    None
                }
            },
            None => None,
        };
        let subnet_left = match host {
            IpAddr::V4(ip) => {
                let mut best = None;
                self.subnets.retain(|(subnet, term)| {
                    if !term_live(*term, now) {
                        return false;
                    }
                    if subnet.contains(ip) {
                        if let Some(left) = term_left(*term, now) {
                            best = Some(match best {
                                Some(have) => longer(have, left),
                                None => left,
                            });
                        }
                    }
                    true
                });
                best
            }
            IpAddr::V6(_) => {
                self.expire_subnets(now, None);
                None
            }
        };
        match (host_left, subnet_left) {
            (Some(host_ban), Some(subnet_ban)) => Some(longer(host_ban, subnet_ban)),
            (Some(host_ban), None) => Some(host_ban),
            (None, Some(subnet_ban)) => Some(subnet_ban),
            (None, None) => None,
        }
    }

    /// Every ban still in force, with time left from `now`.
    pub fn listed(&mut self, now: Tick) -> Vec<ListedBan> {
        let hosts = self.hosts(now);
        let subnets = self.subnets(now);
        let mut out = Vec::with_capacity(hosts.len() + subnets.len());
        for (host, term) in hosts {
            if let Some(left) = term_left(term, now) {
                out.push(ListedBan::Host { host, left });
            }
        }
        for (subnet, term) in subnets {
            if let Some(left) = term_left(term, now) {
                out.push(ListedBan::Subnet { subnet, left });
            }
        }
        out
    }

    /// Drop expired subnets. When `probe` is set, report whether any
    /// remaining subnet contains it.
    fn expire_subnets(&mut self, now: Tick, probe: Option<Ipv4Addr>) -> bool {
        let mut hit = false;
        self.subnets.retain(|(subnet, term)| {
            if term_live(*term, now) {
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
    use super::{deadline_after, BanLeft, BanList, Ipv4Subnet};
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
    fn clear_drops_hosts_and_subnets() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24).expect("prefix");
        assert!(bans.ban_host_permanent(host));
        assert!(bans.ban_subnet_permanent(subnet));
        bans.clear();
        assert!(!bans.is_banned(host, Tick::new(1)));
        assert!(!bans.is_banned(v4([10, 1, 2, 5]), Tick::new(1)));
        assert!(bans.hosts(Tick::new(1)).is_empty());
        assert!(bans.subnets(Tick::new(1)).is_empty());
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
    fn a_shorter_future_ban_does_not_shorten_and_a_later_one_extends() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        assert!(bans.ban_host(host, Tick::new(500), Tick::new(1)));
        assert!(!bans.ban_host(host, Tick::new(200), Tick::new(50)));
        assert!(bans.is_banned(host, Tick::new(400)));
        assert!(bans.ban_host(host, Tick::new(800), Tick::new(50)));
        assert!(bans.is_banned(host, Tick::new(700)));

        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 0, 0), 24).expect("prefix");
        let inside = v4([10, 1, 0, 9]);
        assert!(bans.ban_subnet(subnet, Tick::new(500), Tick::new(1)));
        assert!(!bans.ban_subnet(subnet, Tick::new(200), Tick::new(50)));
        assert!(bans.is_banned(inside, Tick::new(400)));
        assert!(bans.ban_subnet(subnet, Tick::new(800), Tick::new(50)));
        assert!(bans.is_banned(inside, Tick::new(700)));
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

    #[test]
    fn remaining_time_is_the_deadline_minus_now() {
        let mut bans = BanList::new();
        let host = v4([1, 2, 3, 4]);
        let now = Tick::new(1_000);
        assert!(bans.ban_host(host, Tick::new(1_000 + 5_000_000_000), now));
        assert_eq!(
            bans.remaining(host, now),
            Some(BanLeft::Remaining {
                nanos: 5_000_000_000
            })
        );
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(9, 9, 9, 1), 24).expect("prefix");
        assert!(bans.ban_subnet(subnet, Tick::new(1_000 + 2_000), now));
        assert_eq!(
            bans.remaining(v4([9, 9, 9, 8]), now),
            Some(BanLeft::Remaining { nanos: 2_000 })
        );
    }

    #[test]
    fn a_permanent_ban_has_no_deadline_and_is_not_shortened() {
        let mut bans = BanList::new();
        let host = v4([1, 2, 3, 4]);
        assert!(bans.ban_host_permanent(host));
        assert!(bans.is_banned(host, Tick::new(u64::MAX - 1)));
        assert!(!bans.ban_host(host, Tick::new(50), Tick::new(1)));
        assert_eq!(bans.remaining(host, Tick::new(1)), Some(BanLeft::Permanent));
        let later = v4([8, 8, 8, 8]);
        assert!(bans.ban_host(later, Tick::new(20), Tick::new(1)));
        assert!(bans.ban_host_permanent(later));
        assert_eq!(
            bans.remaining(later, Tick::new(100)),
            Some(BanLeft::Permanent)
        );
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 8).expect("prefix");
        assert!(bans.ban_subnet_permanent(subnet));
        assert!(bans.is_banned(v4([10, 1, 1, 1]), Tick::new(u64::MAX - 1)));
        assert!(!bans.ban_subnet(subnet, Tick::new(40), Tick::new(1)));
    }

    #[test]
    fn a_duration_that_does_not_fit_is_not_a_deadline() {
        assert!(deadline_after(Tick::new(u64::MAX - 10), 11).is_none());
        assert!(deadline_after(Tick::new(1), 0).is_none());
        assert_eq!(deadline_after(Tick::new(1), 5).expect("fits").get(), 6);
    }
}
