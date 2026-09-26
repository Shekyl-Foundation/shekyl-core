// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Socket admission without sockets. The count is the live set.
//!
//! Accept compares the inbound count with [`InboundCeiling`](shekyl_peer_policy::InboundCeiling)
//! and increments it in the same lock. Close removes the socket once.
//! A second close does not decrement again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;

use crate::address::PeerAddress;
use crate::ban::{BanList, Ipv4Subnet};
use crate::declaration::ConnectorId;
use crate::dial::check_tor_dial;
use crate::{CloseCause, CloseKind};

/// Which way the socket was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Accepted.
    Inbound,
    /// Dialed.
    Outbound,
}

/// One live socket. There is no public constructor: the table mints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketId(u64);

impl SocketId {
    /// The id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a socket was not reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// A D12 cause. Nothing was reserved.
    Refused(CloseCause),
    /// The id counter cannot mint another id.
    Exhausted,
}

/// The first close records its cause. A later close does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseResult {
    /// This call removed the socket and recorded `cause`.
    Recorded(CloseCause),
    /// The socket was already gone. The count did not change.
    AlreadyClosed,
}

#[derive(Debug)]
struct Live {
    connector: ConnectorId,
    direction: Direction,
    ip: Option<IpAddr>,
}

#[derive(Debug)]
struct Inner {
    next_id: u64,
    /// Clearnet inbound, clearnet outbound, Tor inbound, Tor outbound.
    counts: [u64; 4],
    live: HashMap<SocketId, Live>,
    bans: BanList,
}

impl Inner {
    fn new() -> Self {
        Self {
            next_id: 1,
            counts: [0; 4],
            live: HashMap::new(),
            bans: BanList::new(),
        }
    }

    fn holds(&self) -> bool {
        let mut expect = [0u64; 4];
        for live in self.live.values() {
            let Some(count) = expect[slot(live.connector, live.direction)].checked_add(1) else {
                return false;
            };
            expect[slot(live.connector, live.direction)] = count;
        }
        expect == self.counts
    }

    fn inbound_total(&self) -> Option<u64> {
        self.counts[slot(ConnectorId::Clearnet, Direction::Inbound)]
            .checked_add(self.counts[slot(ConnectorId::Tor, Direction::Inbound)])
    }
}

const fn slot(connector: ConnectorId, direction: Direction) -> usize {
    let base = match connector {
        ConnectorId::Clearnet => 0,
        ConnectorId::Tor => 2,
    };
    base + match direction {
        Direction::Inbound => 0,
        Direction::Outbound => 1,
    }
}

/// The socket table. Clones share it. A poisoned lock aborts the process:
/// a panic while the table was held has already broken the count.
#[derive(Clone, Debug)]
pub struct Sockets {
    inner: Arc<Mutex<Inner>>,
}

impl Sockets {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("socket table lock poisoned")
    }

    /// Inbound clearnet. A banned address is [`CloseKind::AdmissionRefused`]
    /// and reserves nothing.
    pub fn accept_clearnet(
        &self,
        ip: IpAddr,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<OpenSocket, OpenError> {
        self.reserve(
            ConnectorId::Clearnet,
            Direction::Inbound,
            Some(ip),
            Some(ceiling),
            now,
        )
    }

    /// Outbound clearnet. The inbound ceiling does not apply. A banned
    /// address is still refused.
    pub fn open_clearnet(&self, ip: IpAddr, now: Tick) -> Result<OpenSocket, OpenError> {
        self.reserve(
            ConnectorId::Clearnet,
            Direction::Outbound,
            Some(ip),
            None,
            now,
        )
    }

    /// Inbound Tor. There is no address to ban.
    pub fn accept_tor(&self, ceiling: InboundCeiling, now: Tick) -> Result<OpenSocket, OpenError> {
        self.reserve(
            ConnectorId::Tor,
            Direction::Inbound,
            None,
            Some(ceiling),
            now,
        )
    }

    /// Outbound Tor. Anything other than an onion v3 hostname is
    /// [`CloseKind::DialFailed`] and reserves nothing.
    pub fn open_tor(&self, address: &PeerAddress) -> Result<OpenSocket, OpenError> {
        check_tor_dial(address).map_err(OpenError::Refused)?;
        self.reserve(
            ConnectorId::Tor,
            Direction::Outbound,
            None,
            None,
            Tick::new(0),
        )
    }

    /// Close `id` with `cause`. The first call removes it. A later call
    /// leaves the count where the first call put it.
    pub fn close(&self, id: SocketId, cause: CloseCause) -> CloseResult {
        let mut inner = self.lock();
        release(&mut inner, id, cause)
    }

    /// Whether `host` is banned at `now`. The lookup drops an expired entry.
    pub fn is_banned(&self, host: IpAddr, now: Tick) -> bool {
        self.lock().bans.is_banned(host, now)
    }

    /// Ban `host` until `until` and close live sockets to that host.
    /// A deadline that has already passed bans nothing and closes nothing.
    /// Each closed socket is [`CloseKind::LocalClose`], once.
    pub fn ban_host(&self, host: IpAddr, until: Tick, now: Tick) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_host(host, until, now) {
            return Vec::new();
        }
        close_matching(&mut inner, Match::Host(host))
    }

    /// Ban an IPv4 subnet and close live IPv4 sockets inside it.
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_subnet(subnet, until, now) {
            return Vec::new();
        }
        close_matching(&mut inner, Match::Subnet(subnet))
    }

    /// Remove a host ban. Sockets that are already open stay open.
    pub fn lift_host(&self, host: IpAddr) -> bool {
        self.lock().bans.lift_host(host)
    }

    /// How many live sockets this connector has in this direction.
    #[must_use]
    pub fn socket_count(&self, connector: ConnectorId, direction: Direction) -> u64 {
        self.lock().counts[slot(connector, direction)]
    }

    /// How many sockets are live, in every connector and direction.
    #[must_use]
    pub fn live(&self) -> u64 {
        u64::try_from(self.lock().live.len()).expect("live socket count fits")
    }

    /// Whether `id` is still in the live set.
    #[must_use]
    pub fn is_live(&self, id: SocketId) -> bool {
        self.lock().live.contains_key(&id)
    }

    fn reserve(
        &self,
        connector: ConnectorId,
        direction: Direction,
        ip: Option<IpAddr>,
        ceiling: Option<InboundCeiling>,
        now: Tick,
    ) -> Result<OpenSocket, OpenError> {
        let mut inner = self.lock();
        if let Some(ip) = ip {
            if inner.bans.is_banned(ip, now) {
                return Err(OpenError::Refused(CloseCause::new(
                    CloseKind::AdmissionRefused,
                )));
            }
        }
        if let Some(ceiling) = ceiling {
            let total = inner.inbound_total().ok_or(OpenError::Exhausted)?;
            if let InboundCeiling::Bounded(limit) = ceiling {
                if total >= u64::from(limit) {
                    return Err(OpenError::Refused(CloseCause::new(
                        CloseKind::AdmissionRefused,
                    )));
                }
            }
        }
        let next = inner.next_id.checked_add(1).ok_or(OpenError::Exhausted)?;
        let index = slot(connector, direction);
        let count = inner.counts[index]
            .checked_add(1)
            .ok_or(OpenError::Exhausted)?;
        let id = SocketId(inner.next_id);
        inner.next_id = next;
        inner.counts[index] = count;
        inner.live.insert(
            id,
            Live {
                connector,
                direction,
                ip,
            },
        );
        debug_assert!(inner.holds());
        drop(inner);
        Ok(OpenSocket {
            sockets: self.clone(),
            id,
            open: true,
        })
    }
}

impl Default for Sockets {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
enum Match {
    Host(IpAddr),
    Subnet(Ipv4Subnet),
}

fn is_match(banned: Match, ip: Option<IpAddr>) -> bool {
    match (banned, ip) {
        (Match::Host(host), Some(observed)) => observed == host,
        (Match::Subnet(subnet), Some(IpAddr::V4(observed))) => subnet.contains(observed),
        (Match::Host(_) | Match::Subnet(_), None) | (Match::Subnet(_), Some(IpAddr::V6(_))) => {
            false
        }
    }
}

fn close_matching(inner: &mut Inner, banned: Match) -> Vec<SocketId> {
    let ids: Vec<SocketId> = inner
        .live
        .iter()
        .filter(|(_, live)| is_match(banned, live.ip))
        .map(|(id, _)| *id)
        .collect();
    for id in &ids {
        let result = release(inner, *id, CloseCause::new(CloseKind::LocalClose));
        debug_assert!(matches!(result, CloseResult::Recorded(_)));
    }
    debug_assert!(inner.holds());
    ids
}

fn release(inner: &mut Inner, id: SocketId, cause: CloseCause) -> CloseResult {
    let Some(live) = inner.live.remove(&id) else {
        return CloseResult::AlreadyClosed;
    };
    let index = slot(live.connector, live.direction);
    inner.counts[index] = inner.counts[index]
        .checked_sub(1)
        .expect("socket count underflow");
    debug_assert!(inner.holds());
    CloseResult::Recorded(cause)
}

/// A reserved socket. Dropping it closes with [`CloseKind::LocalClose`]
/// if nothing has closed it yet, so a failure before the channel exists
/// does not leave the count up.
#[derive(Debug)]
pub struct OpenSocket {
    sockets: Sockets,
    id: SocketId,
    open: bool,
}

impl OpenSocket {
    /// The id.
    #[must_use]
    pub const fn id(&self) -> SocketId {
        self.id
    }

    /// Close with `cause`. Drop will not close again.
    pub fn close(mut self, cause: CloseCause) -> CloseResult {
        self.open = false;
        self.sockets.close(self.id, cause)
    }
}

impl Drop for OpenSocket {
    fn drop(&mut self) {
        if self.open {
            match self
                .sockets
                .close(self.id, CloseCause::new(CloseKind::LocalClose))
            {
                CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseResult, OpenError};
    pub(super) use super::{Direction, Sockets};
    use crate::address::PeerAddress;
    use crate::ban::Ipv4Subnet;
    pub(super) use crate::declaration::ConnectorId;
    use crate::{CloseCause, CloseKind};
    use shekyl_onion_v3::v3_onion_hostname;
    use shekyl_peer_policy::InboundCeiling;
    use shekyl_timing_engine::Tick;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn now() -> Tick {
        Tick::new(1_000)
    }

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn refused(error: OpenError) -> CloseKind {
        match error {
            OpenError::Refused(cause) => cause.kind(),
            OpenError::Exhausted => panic!("exhausted"),
        }
    }

    #[test]
    fn a_ceiling_of_zero_admits_nothing_and_an_unbounded_ceiling_does() {
        let sockets = Sockets::new();
        let error = sockets
            .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(0), now())
            .expect_err("none");
        assert_eq!(refused(error), CloseKind::AdmissionRefused);
        assert_eq!(sockets.live(), 0);
        let _open = sockets
            .accept_tor(
                InboundCeiling::Unbounded(shekyl_peer_policy::UnboundedReason::Unlimited),
                now(),
            )
            .expect("admitted");
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
            1
        );
    }

    #[test]
    fn a_banned_accept_does_not_take_a_slot() {
        let sockets = Sockets::new();
        let host = ip([10, 0, 0, 1]);
        assert_eq!(sockets.ban_host(host, Tick::new(2_000), now()).len(), 0);
        let error = sockets
            .accept_clearnet(host, InboundCeiling::Bounded(4), now())
            .expect_err("banned");
        assert_eq!(refused(error), CloseKind::AdmissionRefused);
        assert_eq!(sockets.live(), 0);
        assert!(!sockets.is_banned(host, Tick::new(2_000)));
        let _open = sockets
            .accept_clearnet(host, InboundCeiling::Bounded(4), Tick::new(2_000))
            .expect("expired");
        assert_eq!(sockets.live(), 1);
    }

    #[test]
    fn close_releases_once_and_drop_does_not_release_again() {
        let sockets = Sockets::new();
        let open = sockets
            .accept_tor(InboundCeiling::Bounded(2), now())
            .expect("open");
        let id = open.id();
        assert_eq!(
            open.close(CloseCause::new(CloseKind::TransportHandshakeFailed)),
            CloseResult::Recorded(CloseCause::new(CloseKind::TransportHandshakeFailed))
        );
        assert_eq!(
            sockets.close(id, CloseCause::new(CloseKind::PeerClosed)),
            CloseResult::AlreadyClosed
        );
        assert_eq!(sockets.live(), 0);
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
            0
        );
    }

    #[test]
    fn drop_releases_a_socket_that_failed_before_the_channel_existed() {
        let sockets = Sockets::new();
        let open = sockets
            .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(2), now())
            .expect("open");
        drop(open);
        assert_eq!(sockets.live(), 0);
    }

    #[test]
    fn outbound_does_not_consume_the_inbound_ceiling() {
        let sockets = Sockets::new();
        let ceiling = InboundCeiling::Bounded(1);
        let _inbound = sockets
            .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
            .expect("one inbound");
        let error = sockets
            .accept_clearnet(ip([10, 0, 0, 2]), ceiling, now())
            .expect_err("full");
        assert_eq!(refused(error), CloseKind::AdmissionRefused);
        let _outbound = sockets
            .open_clearnet(ip([10, 0, 0, 3]), now())
            .expect("outbound");
        assert_eq!(
            sockets.socket_count(ConnectorId::Clearnet, Direction::Outbound),
            1
        );
        assert_eq!(
            sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
            1
        );
    }

    #[test]
    fn a_tor_dial_that_is_not_an_onion_reserves_nothing() {
        let sockets = Sockets::new();
        let error = sockets
            .open_tor(&PeerAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 18080,
            })
            .expect_err("not an onion");
        assert_eq!(refused(error), CloseKind::DialFailed);
        assert_eq!(sockets.live(), 0);
        let host = v3_onion_hostname(&[0x22; 32]);
        let _open = sockets
            .open_tor(&PeerAddress::Tor { host, port: 18080 })
            .expect("onion");
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Outbound),
            1
        );
    }

    #[test]
    fn a_new_ban_closes_matching_sockets_once() {
        let sockets = Sockets::new();
        let banned = ip([10, 1, 2, 5]);
        let other = ip([10, 9, 0, 1]);
        let inside = sockets
            .accept_clearnet(banned, InboundCeiling::Bounded(8), now())
            .expect("in");
        let outbound = sockets.open_clearnet(banned, now()).expect("out");
        let kept = sockets
            .accept_clearnet(other, InboundCeiling::Bounded(8), now())
            .expect("other");
        let tor = sockets
            .accept_tor(InboundCeiling::Bounded(8), now())
            .expect("tor");
        let v6 = sockets
            .accept_clearnet(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                InboundCeiling::Bounded(8),
                now(),
            )
            .expect("v6");
        let closed = sockets.ban_host(banned, Tick::new(5_000), now());
        assert_eq!(closed.len(), 2);
        assert!(!sockets.is_live(inside.id()));
        assert!(!sockets.is_live(outbound.id()));
        assert!(sockets.is_live(kept.id()));
        assert!(sockets.is_live(tor.id()));
        assert!(sockets.is_live(v6.id()));
        assert_eq!(
            sockets.close(inside.id(), CloseCause::new(CloseKind::LocalClose)),
            CloseResult::AlreadyClosed
        );
        assert_eq!(sockets.live(), 3);
        drop(inside);
        drop(outbound);
        assert_eq!(sockets.live(), 3);

        let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 9, 0, 9), 24).expect("prefix");
        let closed = sockets.ban_subnet(subnet, Tick::new(5_000), now());
        assert_eq!(closed, vec![kept.id()]);
        assert!(sockets.is_live(v6.id()));
        assert_eq!(sockets.live(), 2);
        drop(kept);
        drop(tor);
        drop(v6);
        assert_eq!(sockets.live(), 0);
    }

    #[test]
    fn lift_does_not_close_and_a_later_accept_is_admitted() {
        let sockets = Sockets::new();
        let host = ip([10, 0, 0, 8]);
        sockets.ban_host(host, Tick::new(5_000), now());
        assert!(sockets.lift_host(host));
        let _open = sockets
            .accept_clearnet(host, InboundCeiling::Bounded(2), now())
            .expect("lifted");
    }

    #[test]
    fn racing_accepts_do_not_pass_the_ceiling() {
        let sockets = Sockets::new();
        let held = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            for _ in 0..8 {
                let sockets = sockets.clone();
                let held = Arc::clone(&held);
                scope.spawn(move || {
                    for _ in 0..20 {
                        if let Ok(open) = sockets.accept_tor(InboundCeiling::Bounded(5), now()) {
                            held.lock().expect("held").push(open);
                        }
                    }
                });
            }
        });
        let guard = held.lock().expect("held");
        assert_eq!(guard.len(), 5);
        assert_eq!(sockets.live(), 5);
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
            5
        );
        drop(guard);
        drop(held);
        assert_eq!(sockets.live(), 0);
    }

    #[test]
    fn simultaneous_closes_release_the_slot_once() {
        let sockets = Sockets::new();
        let open = sockets
            .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(2), now())
            .expect("open");
        let id = open.id();
        let results = thread::scope(|scope| {
            let first = scope.spawn(|| sockets.close(id, CloseCause::new(CloseKind::PeerClosed)));
            let second = scope.spawn(|| sockets.close(id, CloseCause::new(CloseKind::LocalClose)));
            (first.join().expect("join"), second.join().expect("join"))
        });
        let recorded = [results.0, results.1]
            .into_iter()
            .filter(|result| matches!(result, CloseResult::Recorded(_)))
            .count();
        assert_eq!(recorded, 1);
        assert_eq!(sockets.live(), 0);
        drop(open);
        assert_eq!(sockets.live(), 0);
    }

    #[test]
    fn churn_of_accepts_and_closes_returns_to_zero() {
        let sockets = Sockets::new();
        thread::scope(|scope| {
            for n in 0..8u8 {
                let sockets = sockets.clone();
                scope.spawn(move || {
                    let host = ip([10, 0, 0, n]);
                    for i in 0..40 {
                        if let Ok(open) =
                            sockets.accept_clearnet(host, InboundCeiling::Bounded(64), now())
                        {
                            assert_eq!(
                                open.close(CloseCause::new(CloseKind::LocalClose)),
                                CloseResult::Recorded(CloseCause::new(CloseKind::LocalClose))
                            );
                        }
                        if i % 2 == 0 {
                            if let Ok(open) = sockets.accept_tor(InboundCeiling::Bounded(64), now())
                            {
                                drop(open);
                            }
                        }
                    }
                });
            }
        });
        assert_eq!(sockets.live(), 0);
        assert_eq!(
            sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
            0
        );
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
            0
        );
    }

    fn cases_from_env() -> u32 {
        match std::env::var("PROPTEST_CASES") {
            Ok(raw) => raw
                .parse()
                .unwrap_or_else(|_| panic!("PROPTEST_CASES must be a u32, got {raw}")),
            Err(std::env::VarError::NotPresent) => 64,
            Err(std::env::VarError::NotUnicode(_)) => panic!("PROPTEST_CASES is not Unicode"),
        }
    }

    pub(super) fn proptest_config() -> proptest::test_runner::Config {
        proptest::test_runner::Config {
            cases: cases_from_env(),
            ..proptest::test_runner::Config::default()
        }
    }

    pub(super) fn apply(sockets: &Sockets, open: &mut Vec<super::OpenSocket>, byte: u8) {
        let hosts = [
            ip([10, 0, 0, 1]),
            ip([10, 0, 0, 2]),
            ip([10, 1, 0, 1]),
            ip([192, 168, 0, 1]),
        ];
        let ceiling = InboundCeiling::Bounded(4);
        match byte % 6 {
            0 => {
                if let Ok(sock) =
                    sockets.accept_clearnet(hosts[usize::from(byte) % hosts.len()], ceiling, now())
                {
                    open.push(sock);
                }
            }
            1 => {
                if let Ok(sock) = sockets.accept_tor(ceiling, now()) {
                    open.push(sock);
                }
            }
            2 => {
                if let Ok(sock) =
                    sockets.open_clearnet(hosts[usize::from(byte) % hosts.len()], now())
                {
                    open.push(sock);
                }
            }
            3 => {
                let host = v3_onion_hostname(&[0x33; 32]);
                if let Ok(sock) = sockets.open_tor(&PeerAddress::Tor { host, port: 18080 }) {
                    open.push(sock);
                }
            }
            4 => {
                if !open.is_empty() {
                    let index = usize::from(byte) % open.len();
                    let sock = open.swap_remove(index);
                    let id = sock.id();
                    assert!(matches!(
                        sockets.close(id, CloseCause::new(CloseKind::PeerClosed)),
                        CloseResult::Recorded(_)
                    ));
                    assert_eq!(
                        sockets.close(id, CloseCause::new(CloseKind::IoError)),
                        CloseResult::AlreadyClosed
                    );
                    drop(sock);
                }
            }
            _ => {
                if let Ok(sock) = sockets.accept_clearnet(hosts[0], ceiling, now()) {
                    assert_eq!(
                        sock.close(CloseCause::new(CloseKind::TransportHandshakeFailed)),
                        CloseResult::Recorded(CloseCause::new(CloseKind::TransportHandshakeFailed))
                    );
                }
            }
        }
    }
}

#[cfg(test)]
proptest::proptest! {
    #![proptest_config(tests::proptest_config())]
    #[test]
    fn socket_count_matches_live_sockets_under_churn(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..48)
    ) {
        let sockets = tests::Sockets::new();
        let mut open = Vec::new();
        for byte in bytes {
            tests::apply(&sockets, &mut open, byte);
            assert_eq!(sockets.live(), u64::try_from(open.len()).expect("len"));
            let inbound = sockets
                .socket_count(tests::ConnectorId::Clearnet, tests::Direction::Inbound)
                .checked_add(
                    sockets.socket_count(tests::ConnectorId::Tor, tests::Direction::Inbound),
                )
                .expect("inbound");
            assert!(inbound <= 4);
        }
        open.clear();
        assert_eq!(sockets.live(), 0);
    }
}
