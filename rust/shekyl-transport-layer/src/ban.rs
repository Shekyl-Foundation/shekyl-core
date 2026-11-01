// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban list. IPv4 subnets and host addresses. A timed ban ends when
//! the list's timing owner reaches its deadline ([`BanList::expire`]), or
//! when it is lifted; a lookup never changes the list (Rick, 2026-10-31).
//!
//! RPC and misbehaviour scoring both write this list, through a duration
//! added to the monotonic clock. A duration that does not fit a [`Tick`]
//! is not stored. A ban from the operator's ban file has no deadline:
//! it stays until it is lifted. One list lives in the socket table; this
//! type is that list.
//!
//! Each ban and each lift is posted, in order, to every subscriber's
//! queue ([`BanFeed`]). The list only collects which subscribers to ring
//! ([`BanList::take_rings`]); its owner rings them once its lock has
//! dropped, so a ring never runs under the table's lock. A subscription
//! starts with a ban event for every entry in force, taken in the same
//! lock section, so no lift between the seed and the subscription is lost.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, Weak};

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
    /// `0.0.0.0/0`: the least subnet in the order, where a range over the
    /// subnet entries starts.
    const EVERYTHING: Self = Self {
        network: Ipv4Addr::UNSPECIFIED,
        prefix_len: 0,
    };

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

/// One active ban, as the ban list posts it to the peer list: a host, or
/// an IPv4 subnet. The expiry stays with the ban list; an entry the peer
/// list holds is in force until the ban list posts its lift.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BanEntry {
    /// One host.
    Host(IpAddr),
    /// Every IPv4 host inside the prefix.
    Subnet(Ipv4Subnet),
}

impl BanEntry {
    /// Whether this entry covers `host`, as [`BanList::is_banned`] matches
    /// it: a subnet covers IPv4 hosts only, so an IPv6 host is covered by a
    /// host entry alone.
    #[must_use]
    pub fn covers(self, host: IpAddr) -> bool {
        match (self, host) {
            (Self::Host(banned), _) => banned == host,
            (Self::Subnet(subnet), IpAddr::V4(ip)) => subnet.contains(ip),
            (Self::Subnet(_), IpAddr::V6(_)) => false,
        }
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

/// Time left at `now`. An entry stays in force until its timing owner
/// expires it, so a deadline that has passed and not yet been reached by
/// the owner has no time left, and is still a ban.
fn term_left(term: Term, now: Tick) -> BanLeft {
    match term {
        Term::Permanent => BanLeft::Permanent,
        Term::Until(until) => BanLeft::Remaining {
            nanos: until.get().saturating_sub(now.get()),
        },
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

/// Ban entries keyed for lookup, each with a value: the ban list keeps an
/// entry's term, the peer list nothing. A host is an exact match on its
/// key; its subnets are a range over the subnet keys, which sort after
/// every host. The one shape both sides look a host up in.
#[derive(Clone, Debug)]
pub struct BanSet<T = ()> {
    entries: BTreeMap<BanEntry, T>,
}

impl<T> Default for BanSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> BanSet<T> {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Hold `entry` with `value`. Returns the value it held, if any.
    pub fn insert(&mut self, entry: BanEntry, value: T) -> Option<T> {
        self.entries.insert(entry, value)
    }

    /// The value `entry` is held with.
    #[must_use]
    pub fn get(&self, entry: &BanEntry) -> Option<&T> {
        self.entries.get(entry)
    }

    /// Drop `entry`. Returns the value it was held with.
    pub fn remove(&mut self, entry: &BanEntry) -> Option<T> {
        self.entries.remove(entry)
    }

    /// Every entry, hosts then subnets, each in order, with its value.
    pub fn iter(&self) -> impl Iterator<Item = (BanEntry, &T)> {
        self.entries.iter().map(|(entry, value)| (*entry, value))
    }

    /// The values of the entries that cover `host`: its host entry, then
    /// every subnet that contains it.
    pub fn covering(&self, host: IpAddr) -> impl Iterator<Item = &T> {
        let own = self.entries.get(&BanEntry::Host(host));
        let subnets = self
            .entries
            .range(BanEntry::Subnet(Ipv4Subnet::EVERYTHING)..)
            .filter(move |(entry, _)| entry.covers(host))
            .map(|(_, value)| value);
        own.into_iter().chain(subnets)
    }

    /// Whether an entry covers `host`.
    #[must_use]
    pub fn covers(&self, host: IpAddr) -> bool {
        self.covering(host).next().is_some()
    }
}

/// One change to the list, as a subscriber receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanEvent {
    /// The entry is in force from now. Extending a ban posts nothing.
    Banned(BanEntry),
    /// The entry is no longer in force: lifted, cleared, or expired.
    Lifted(BanEntry),
}

/// A subscriber's queue: what the list posts, and the subscriber's bell.
struct FeedQueue {
    events: Mutex<VecDeque<BanEvent>>,
    ring: Arc<dyn Fn() + Send + Sync>,
}

impl FeedQueue {
    fn post(&self, event: BanEvent) {
        self.events
            .lock()
            .expect("ban feed lock poisoned")
            .push_back(event);
    }
}

/// The subscribers a change posted to, to ring once the lock that guards
/// the list has dropped.
#[must_use = "a subscriber is woken only when its ring runs"]
pub struct BanRings(Vec<Weak<FeedQueue>>);

impl BanRings {
    /// Ring each subscriber once; one dropped since is not rung.
    pub fn ring(self) {
        for queue in self.0.iter().filter_map(Weak::upgrade) {
            (queue.ring)();
        }
    }
}

/// One subscription to the list: its events in the order the list made
/// them, starting with a ban event for each entry in force when it was
/// taken. Dropping it ends the subscription.
pub struct BanFeed {
    queue: Arc<FeedQueue>,
}

impl BanFeed {
    /// Every event posted since the last call, oldest first.
    #[must_use]
    pub fn take(&self) -> Vec<BanEvent> {
        std::mem::take(&mut *self.queue.events.lock().expect("ban feed lock poisoned")).into()
    }
}

impl std::fmt::Debug for BanFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BanFeed").finish_non_exhaustive()
    }
}

/// The entries in force, each timed one in the deadline index, and the
/// subscribers' queues.
#[derive(Default)]
pub struct BanList {
    entries: BanSet<Term>,
    /// Every timed entry, ordered by `(deadline, entry)`: the first is
    /// the deadline the list's timing owner holds. A permanent entry is
    /// not here; an extension moves its entry.
    deadlines: BTreeSet<(Tick, BanEntry)>,
    feeds: Vec<Weak<FeedQueue>>,
    /// The subscribers posted to since the last [`Self::take_rings`],
    /// held weakly so a pending ring keeps no subscription alive.
    rings: Vec<Weak<FeedQueue>>,
}

impl std::fmt::Debug for BanList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BanList")
            .field("entries", &self.entries)
            .field("feeds", &self.feeds.len())
            .field("rings", &self.rings.len())
            .finish_non_exhaustive()
    }
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
        now < until && self.store(BanEntry::Host(host), Term::Until(until))
    }

    /// Ban `host` until it is lifted. A deadline already stored is replaced.
    /// A ban that is already permanent is left as it is.
    pub fn ban_host_permanent(&mut self, host: IpAddr) -> bool {
        self.store(BanEntry::Host(host), Term::Permanent)
    }

    /// Record an IPv4 subnet ban. Same deadline rule as [`Self::ban_host`].
    /// One subnet is one entry.
    pub fn ban_subnet(&mut self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> bool {
        now < until && self.store(BanEntry::Subnet(subnet), Term::Until(until))
    }

    /// Ban `subnet` until it is lifted. Same replacement rule as
    /// [`Self::ban_host_permanent`].
    pub fn ban_subnet_permanent(&mut self, subnet: Ipv4Subnet) -> bool {
        self.store(BanEntry::Subnet(subnet), Term::Permanent)
    }

    fn store(&mut self, entry: BanEntry, next: Term) -> bool {
        let current = self.entries.get(&entry).copied();
        if !term_replaces(current, next) {
            return false;
        }
        if let Some(Term::Until(was)) = current {
            self.deadlines.remove(&(was, entry));
        }
        if let Term::Until(until) = next {
            self.deadlines.insert((until, entry));
        }
        self.entries.insert(entry, next);
        if current.is_none() {
            self.post(BanEvent::Banned(entry));
        }
        true
    }

    /// Remove a host ban.
    pub fn lift_host(&mut self, host: IpAddr) -> bool {
        self.lift(BanEntry::Host(host))
    }

    /// Remove a subnet ban.
    pub fn lift_subnet(&mut self, subnet: Ipv4Subnet) -> bool {
        self.lift(BanEntry::Subnet(subnet))
    }

    fn lift(&mut self, entry: BanEntry) -> bool {
        let Some(term) = self.entries.remove(&entry) else {
            return false;
        };
        if let Term::Until(until) = term {
            self.deadlines.remove(&(until, entry));
        }
        self.post(BanEvent::Lifted(entry));
        true
    }

    /// Drop every host and subnet ban.
    ///
    /// The process list outlives one `node_server`. A test process resets
    /// it between servers; the daemon lifts entries one at a time.
    pub fn clear(&mut self) {
        let entries = std::mem::take(&mut self.entries);
        self.deadlines.clear();
        for (entry, _) in entries.iter() {
            self.post(BanEvent::Lifted(entry));
        }
    }

    /// End every timed ban whose deadline is at or before `now`, posting
    /// each lift. The list's timing owner calls this when its deadline
    /// fires; nothing else ends a timed ban but a lift. Returns the next
    /// deadline the owner holds, if any.
    pub fn expire(&mut self, now: Tick) -> Option<Tick> {
        while let Some(&(until, entry)) = self.deadlines.first() {
            if until > now {
                break;
            }
            self.deadlines.pop_first();
            self.entries.remove(&entry);
            self.post(BanEvent::Lifted(entry));
        }
        self.earliest()
    }

    /// The deadline the list's timing owner holds: the earliest timed ban.
    #[must_use]
    pub fn earliest(&self) -> Option<Tick> {
        self.deadlines.first().map(|&(until, _)| until)
    }

    /// Whether an entry in force covers `host`.
    #[must_use]
    pub fn is_banned(&self, host: IpAddr) -> bool {
        self.entries.covers(host)
    }

    /// Time left on the longest ban that covers `host`, from `now`.
    /// `None` when nothing covers it. A permanent ban is
    /// [`BanLeft::Permanent`], not a number of seconds.
    #[must_use]
    pub fn remaining(&self, host: IpAddr, now: Tick) -> Option<BanLeft> {
        self.entries
            .covering(host)
            .map(|term| term_left(*term, now))
            .reduce(longer)
    }

    /// Every ban in force, hosts then subnets, with time left from `now`.
    #[must_use]
    pub fn listed(&self, now: Tick) -> Vec<ListedBan> {
        self.entries
            .iter()
            .map(|(entry, term)| {
                let left = term_left(*term, now);
                match entry {
                    BanEntry::Host(host) => ListedBan::Host { host, left },
                    BanEntry::Subnet(subnet) => ListedBan::Subnet { subnet, left },
                }
            })
            .collect()
    }

    /// Subscribe: a queue that starts with a ban event for every entry in
    /// force and then receives every change; `ring` is rung after each
    /// change, by whoever takes the rings. The seed and the registration
    /// are one call under the caller's lock, so nothing between them is
    /// lost; a non-empty seed is rung like a change.
    pub fn subscribe(&mut self, ring: Arc<dyn Fn() + Send + Sync>) -> BanFeed {
        let seed: VecDeque<BanEvent> = self
            .entries
            .iter()
            .map(|(entry, _)| BanEvent::Banned(entry))
            .collect();
        let seeded = !seed.is_empty();
        let queue = Arc::new(FeedQueue {
            events: Mutex::new(seed),
            ring,
        });
        self.feeds.push(Arc::downgrade(&queue));
        if seeded {
            self.rings.push(Arc::downgrade(&queue));
        }
        BanFeed { queue }
    }

    /// The subscribers posted to since the last call, to ring after the
    /// caller's lock drops.
    pub fn take_rings(&mut self) -> BanRings {
        BanRings(std::mem::take(&mut self.rings))
    }

    fn post(&mut self, event: BanEvent) {
        let rings = &mut self.rings;
        self.feeds.retain(|feed| match feed.upgrade() {
            Some(queue) => {
                queue.post(event);
                if !rings.iter().any(|rung| Weak::ptr_eq(rung, feed)) {
                    rings.push(Weak::clone(feed));
                }
                true
            }
            None => false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        deadline_after, BanEntry, BanEvent, BanFeed, BanLeft, BanList, Ipv4Subnet, ListedBan,
    };
    use shekyl_timing_engine::Tick;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn subscribed(bans: &mut BanList) -> (BanFeed, Arc<AtomicUsize>) {
        let rings = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&rings);
        let feed = bans.subscribe(Arc::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
        }));
        (feed, rings)
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
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        bans.clear();
        assert!(!bans.is_banned(host));
        assert!(!bans.is_banned(v4([10, 1, 2, 5])));
        assert!(bans.listed(Tick::new(1)).is_empty());
        assert_eq!(bans.earliest(), None, "a cleared deadline is not held");
    }

    /// The timer is the only expiry (Rick, 2026-10-31): a lookup after the
    /// deadline leaves the entry, and only [`BanList::expire`] ends it.
    /// `is_banned` takes `&self`, so it cannot remove one. Red edit: answer
    /// a passed deadline as no ban in `remaining`.
    #[test]
    fn a_lookup_after_the_deadline_leaves_the_entry_until_expire() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24).expect("prefix");
        let inside = v4([10, 1, 2, 5]);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(50)));
        assert!(bans.ban_subnet(subnet, Tick::new(120), Tick::new(50)));
        assert_eq!(bans.earliest(), Some(Tick::new(100)));
        let late = Tick::new(200);
        assert!(bans.is_banned(host));
        assert!(bans.is_banned(inside));
        assert_eq!(
            bans.remaining(host, late),
            Some(BanLeft::Remaining { nanos: 0 }),
            "in force, with no time left"
        );
        assert_eq!(bans.listed(late).len(), 2);
        assert!(bans.is_banned(host), "the lookups removed nothing");
        assert_eq!(bans.expire(Tick::new(99)), Some(Tick::new(100)));
        assert!(bans.is_banned(host), "before its deadline");
        assert_eq!(bans.expire(Tick::new(100)), Some(Tick::new(120)));
        assert!(!bans.is_banned(host));
        assert!(bans.is_banned(inside));
        assert_eq!(bans.expire(late), None);
        assert!(!bans.is_banned(inside));
        assert!(bans.listed(late).is_empty());
    }

    /// An extension moves the entry in the deadline index: the old
    /// deadline ends nothing and the owner's next deadline is the new one.
    /// Red edit: leave the old `(deadline, entry)` in the index on an
    /// extension.
    #[test]
    fn an_extension_re_arms_the_entry_at_its_new_deadline() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        assert!(bans.ban_host(host, Tick::new(500), Tick::new(1)));
        assert!(
            !bans.ban_host(host, Tick::new(200), Tick::new(50)),
            "not shorter"
        );
        assert!(bans.ban_host(host, Tick::new(800), Tick::new(50)));
        assert_eq!(bans.earliest(), Some(Tick::new(800)));
        assert_eq!(bans.expire(Tick::new(500)), Some(Tick::new(800)));
        assert!(bans.is_banned(host), "the old deadline ended nothing");
        assert_eq!(bans.expire(Tick::new(800)), None);
        assert!(!bans.is_banned(host));

        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 0, 0), 24).expect("prefix");
        let inside = v4([10, 1, 0, 9]);
        assert!(bans.ban_subnet(subnet, Tick::new(500), Tick::new(1)));
        assert!(!bans.ban_subnet(subnet, Tick::new(200), Tick::new(50)));
        assert!(bans.ban_subnet(subnet, Tick::new(800), Tick::new(50)));
        assert_eq!(bans.expire(Tick::new(500)), Some(Tick::new(800)));
        assert!(bans.is_banned(inside));
    }

    /// A permanent ban holds no deadline, so the owner never ends it, even
    /// when it replaced a timed ban. Red edit: leave the replaced deadline
    /// in the index when a ban becomes permanent.
    #[test]
    fn a_permanent_ban_is_never_expired() {
        let mut bans = BanList::new();
        let host = v4([1, 2, 3, 4]);
        assert!(bans.ban_host(host, Tick::new(20), Tick::new(1)));
        assert!(bans.ban_host_permanent(host));
        assert!(
            !bans.ban_host(host, Tick::new(50), Tick::new(1)),
            "not shortened"
        );
        assert_eq!(bans.earliest(), None);
        assert_eq!(bans.expire(Tick::new(u64::MAX)), None);
        assert!(bans.is_banned(host));
        assert_eq!(bans.remaining(host, Tick::new(1)), Some(BanLeft::Permanent));
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 8).expect("prefix");
        assert!(bans.ban_subnet(subnet, Tick::new(40), Tick::new(1)));
        assert!(bans.ban_subnet_permanent(subnet));
        assert_eq!(bans.expire(Tick::new(u64::MAX)), None);
        assert!(bans.is_banned(v4([10, 1, 1, 1])));
    }

    /// A subscription starts with the entries in force and then gets every
    /// change in order; a lift made after the seed is delivered after it.
    /// Red edit: do not register the queue in `subscribe` (the seed alone
    /// is delivered, and the later lift is lost).
    #[test]
    fn a_lift_after_the_seed_is_delivered_after_it() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 9), 24).expect("prefix");
        assert!(bans.ban_host_permanent(host));
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        let (feed, rings) = subscribed(&mut bans);
        assert!(bans.lift_host(host));
        assert_eq!(bans.expire(Tick::new(100)), None);
        assert_eq!(
            feed.take(),
            vec![
                BanEvent::Banned(BanEntry::Host(host)),
                BanEvent::Banned(BanEntry::Subnet(subnet)),
                BanEvent::Lifted(BanEntry::Host(host)),
                BanEvent::Lifted(BanEntry::Subnet(subnet)),
            ]
        );
        assert_eq!(
            rings.load(Ordering::Relaxed),
            0,
            "nothing rings under the list"
        );
        bans.take_rings().ring();
        assert_eq!(
            rings.load(Ordering::Relaxed),
            1,
            "one ring for what was posted"
        );
        assert!(feed.take().is_empty(), "taken once");
    }

    /// Only a change of what is in force is posted: an extension, a
    /// refused shorter deadline and a lift of nothing post nothing, and a
    /// dropped subscription is no longer posted to.
    #[test]
    fn an_extension_posts_nothing_and_a_dropped_feed_is_forgotten() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        let (feed, _) = subscribed(&mut bans);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(1)));
        assert!(bans.ban_host(host, Tick::new(200), Tick::new(1)));
        assert!(!bans.ban_host(host, Tick::new(150), Tick::new(1)));
        assert!(bans.ban_host_permanent(host));
        assert!(!bans.lift_host(v4([10, 0, 0, 2])));
        assert_eq!(feed.take(), vec![BanEvent::Banned(BanEntry::Host(host))]);
        drop(feed);
        assert!(bans.lift_host(host));
        assert!(bans.feeds.is_empty(), "the dropped feed was pruned");
    }

    #[test]
    fn a_deadline_that_has_passed_does_not_replace_a_live_ban() {
        let mut bans = BanList::new();
        let host = v4([10, 0, 0, 1]);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(1)));
        assert!(!bans.ban_host(host, Tick::new(10), Tick::new(50)));
        assert!(bans.is_banned(host));
        assert!(!bans.ban_host(v4([10, 0, 0, 2]), Tick::new(50), Tick::new(50)));
    }

    #[test]
    fn lift_removes_a_host_and_a_subnet() {
        let mut bans = BanList::new();
        let host = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(bans.ban_host(host, Tick::new(100), Tick::new(1)));
        assert!(bans.lift_host(host));
        assert!(!bans.is_banned(host));
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("prefix");
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        assert!(bans.lift_subnet(subnet));
        assert!(!bans.is_banned(v4([10, 1, 1, 1])));
        assert_eq!(bans.earliest(), None, "a lifted deadline is not held");
    }

    #[test]
    fn an_ipv6_host_is_not_inside_an_ipv4_subnet() {
        let mut bans = BanList::new();
        let subnet = Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0).expect("prefix 0");
        assert!(bans.ban_subnet(subnet, Tick::new(100), Tick::new(1)));
        assert!(!bans.is_banned(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(bans.is_banned(v4([8, 8, 8, 8])));
    }

    #[test]
    fn remaining_time_is_the_longest_cover_minus_now() {
        let mut bans = BanList::new();
        let host = v4([9, 9, 9, 8]);
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
            bans.remaining(v4([9, 9, 9, 7]), now),
            Some(BanLeft::Remaining { nanos: 2_000 })
        );
        assert_eq!(
            bans.remaining(host, now),
            Some(BanLeft::Remaining {
                nanos: 5_000_000_000
            }),
            "the longer of the host and its subnet"
        );
        assert_eq!(bans.remaining(v4([9, 9, 8, 1]), now), None);
    }

    #[test]
    fn the_listing_is_hosts_then_subnets_in_order() {
        let mut bans = BanList::new();
        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 1, 2, 0), 24).expect("prefix");
        assert!(bans.ban_subnet_permanent(subnet));
        assert!(bans.ban_host(v4([10, 0, 0, 9]), Tick::new(30), Tick::new(10)));
        assert!(bans.ban_host_permanent(v4([10, 0, 0, 2])));
        assert_eq!(
            bans.listed(Tick::new(10)),
            vec![
                ListedBan::Host {
                    host: v4([10, 0, 0, 2]),
                    left: BanLeft::Permanent
                },
                ListedBan::Host {
                    host: v4([10, 0, 0, 9]),
                    left: BanLeft::Remaining { nanos: 20 }
                },
                ListedBan::Subnet {
                    subnet,
                    left: BanLeft::Permanent
                },
            ]
        );
    }

    #[test]
    fn a_duration_that_does_not_fit_is_not_a_deadline() {
        assert!(deadline_after(Tick::new(u64::MAX - 10), 11).is_none());
        assert!(deadline_after(Tick::new(1), 0).is_none());
        assert_eq!(deadline_after(Tick::new(1), 5).expect("fits").get(), 6);
    }
}
