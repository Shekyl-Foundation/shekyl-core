// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Socket admission without sockets. The occupancy table is the live set.
//!
//! Accept compares the process-wide inbound occupancy — every connector's
//! inbound row, summed — with [`InboundCeiling`](shekyl_peer_policy::InboundCeiling)
//! and increments that row in the same lock. Close removes the socket once.
//! A second close does not decrement again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;

use crate::ban::{BanLeft, BanList, Ipv4Subnet, ListedBan};
use crate::declaration::{declaration, Assessment, BannableInbound, ConnectorId, InboundIdentity};
use crate::dial::check_dial;
use crate::{CloseCause, CloseKind};

/// Which way the socket was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// Accepted.
    Inbound = 0,
    /// Dialed.
    Outbound = 1,
}

impl Direction {
    /// Columns in one connector's occupancy row.
    pub const COUNT: usize = 2;

    /// Column of this direction. [`Self::Inbound`] is 0 and [`Self::Outbound`] is 1.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Inbound => 0,
            Self::Outbound => 1,
        }
    }
}

const _: () = {
    assert!(Direction::Inbound.index() == 0);
    assert!(Direction::Outbound.index() == 1);
    assert!(Direction::Inbound.index() != Direction::Outbound.index());
    assert!(Direction::COUNT == 2);
};

/// What the connector saw. The session records this. It is not the
/// loopback socket a local overlay router accepted on, and the port is
/// not part of it: a ban names the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservedEndpoint {
    /// A clearnet host.
    Host(IpAddr),
    /// Overlay peer. This zone, no address.
    Zone,
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

    /// The id that crossed the FFI, rebuilt as a key.
    ///
    /// Zero is not an id. This does not reserve a socket: a lookup that
    /// misses is an unknown id.
    #[must_use]
    pub const fn from_ffi(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }
}

/// Why a socket was not reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// A D12 cause. Nothing was reserved.
    Refused(CloseCause),
    /// The id counter or the occupancy counter cannot move.
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

/// Clearnet inbound is a host a ban can name. Tor inbound is the zone.
const _: () = {
    assert!(matches!(
        declaration(ConnectorId::Clearnet.column()).bannable_inbound(),
        Assessment::Assessed(BannableInbound::Yes)
    ));
    assert!(matches!(
        declaration(ConnectorId::Clearnet.column()).inbound_identity(),
        Assessment::Assessed(InboundIdentity::SocketAddress)
    ));
    assert!(matches!(
        declaration(ConnectorId::Tor.column()).bannable_inbound(),
        Assessment::Assessed(BannableInbound::NoAddress)
    ));
    assert!(matches!(
        declaration(ConnectorId::Tor.column()).inbound_identity(),
        Assessment::Assessed(InboundIdentity::ZoneNoAddress)
    ));
};

fn inbound_observation_matches(connector: ConnectorId, endpoint: ObservedEndpoint) -> bool {
    let column = declaration(connector.column());
    matches!(
        (
            column.bannable_inbound(),
            column.inbound_identity(),
            endpoint
        ),
        (
            Assessment::Assessed(BannableInbound::Yes),
            Assessment::Assessed(InboundIdentity::SocketAddress),
            ObservedEndpoint::Host(_),
        ) | (
            Assessment::Assessed(BannableInbound::NoAddress),
            Assessment::Assessed(InboundIdentity::ZoneNoAddress),
            ObservedEndpoint::Zone,
        )
    )
}

fn admission_refused() -> OpenError {
    OpenError::Refused(CloseCause::new(CloseKind::AdmissionRefused))
}

/// Per-connector, per-direction reservation counts.
///
/// Indexed by [`ConnectorId::index`] and [`Direction::index`], both dense
/// from zero over [`ConnectorId::ALL`]. The process ceiling sums the
/// inbound column of every row in that list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Occupancy {
    rows: [[u64; Direction::COUNT]; ConnectorId::COUNT],
}

impl Occupancy {
    const fn new() -> Self {
        Self {
            rows: [[0; Direction::COUNT]; ConnectorId::COUNT],
        }
    }

    fn get(&self, connector: ConnectorId, direction: Direction) -> u64 {
        self.rows[connector.index()][direction.index()]
    }

    fn try_increment(&mut self, connector: ConnectorId, direction: Direction) -> Option<()> {
        let cell = &mut self.rows[connector.index()][direction.index()];
        let next = cell.checked_add(1)?;
        *cell = next;
        Some(())
    }

    fn decrement(&mut self, connector: ConnectorId, direction: Direction) {
        let cell = &mut self.rows[connector.index()][direction.index()];
        *cell = cell.checked_sub(1).expect("socket count underflow");
    }

    /// Inbound reservations on every built connector.
    fn process_inbound(&self) -> Option<u64> {
        let mut sum = 0u64;
        for id in ConnectorId::ALL {
            sum = sum.checked_add(self.get(*id, Direction::Inbound))?;
        }
        Some(sum)
    }
}

#[derive(Debug)]
struct Live {
    connector: ConnectorId,
    direction: Direction,
    endpoint: ObservedEndpoint,
}

#[derive(Debug)]
struct Inner {
    next_id: u64,
    occupancy: Occupancy,
    live: HashMap<SocketId, Live>,
    bans: BanList,
    /// An operator cap for one connector. `None` means that connector has
    /// no cap of its own. The process ceiling applies either way.
    zone_caps: [Option<u32>; ConnectorId::COUNT],
}

impl Inner {
    fn new() -> Self {
        Self {
            next_id: 1,
            occupancy: Occupancy::new(),
            live: HashMap::new(),
            bans: BanList::new(),
            zone_caps: [None; ConnectorId::COUNT],
        }
    }

    fn holds(&self) -> bool {
        let mut expect = Occupancy::new();
        for live in self.live.values() {
            if expect
                .try_increment(live.connector, live.direction)
                .is_none()
            {
                return false;
            }
        }
        expect == self.occupancy
    }
}

fn refuse_over_process_ceiling(inner: &Inner, ceiling: InboundCeiling) -> Result<(), OpenError> {
    let total = inner
        .occupancy
        .process_inbound()
        .ok_or(OpenError::Exhausted)?;
    if let InboundCeiling::Bounded(limit) = ceiling {
        if total >= u64::from(limit) {
            return Err(admission_refused());
        }
    }
    Ok(())
}

/// Refuse when this connector's cap is full, and when the process
/// ceiling is full. The cap does not replace the ceiling: each connector
/// can be under its own number while the sum still exhausts the descriptors.
fn refuse_inbound(
    inner: &Inner,
    connector: ConnectorId,
    ceiling: InboundCeiling,
) -> Result<(), OpenError> {
    if let Some(cap) = inner.zone_caps[connector.index()] {
        let held = inner.occupancy.get(connector, Direction::Inbound);
        if held >= u64::from(cap) {
            return Err(admission_refused());
        }
    }
    refuse_over_process_ceiling(inner, ceiling)
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

    /// The operator's inbound cap for one connector. `None` clears it.
    /// The process ceiling still bounds the sum.
    pub fn set_zone_cap(&self, connector: ConnectorId, cap: Option<u32>) {
        self.lock().zone_caps[connector.index()] = cap;
    }

    /// Inbound clearnet.
    ///
    /// `ceiling` is the process-wide inbound ceiling: this row and every
    /// other connector's inbound row are one sum. A banned address is
    /// [`CloseKind::AdmissionRefused`] and reserves nothing.
    pub fn accept_clearnet(
        &self,
        ip: IpAddr,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<OpenSocket, OpenError> {
        let endpoint = ObservedEndpoint::Host(ip);
        assert!(
            inbound_observation_matches(ConnectorId::Clearnet, endpoint),
            "clearnet inbound observation does not match its declaration"
        );
        let mut inner = self.lock();
        if inner.bans.is_banned(ip, now) {
            return Err(admission_refused());
        }
        refuse_inbound(&inner, ConnectorId::Clearnet, ceiling)?;
        self.mint(
            &mut inner,
            ConnectorId::Clearnet,
            Direction::Inbound,
            endpoint,
        )
    }

    /// Outbound clearnet. The inbound ceiling does not apply. A banned
    /// address is still refused.
    pub fn open_clearnet(&self, ip: IpAddr, now: Tick) -> Result<OpenSocket, OpenError> {
        let mut inner = self.lock();
        if inner.bans.is_banned(ip, now) {
            return Err(admission_refused());
        }
        self.mint(
            &mut inner,
            ConnectorId::Clearnet,
            Direction::Outbound,
            ObservedEndpoint::Host(ip),
        )
    }

    /// Inbound Tor. There is no address to ban.
    ///
    /// `ceiling` is the same process-wide sum as [`Self::accept_clearnet`].
    pub fn accept_tor(&self, ceiling: InboundCeiling) -> Result<OpenSocket, OpenError> {
        let endpoint = ObservedEndpoint::Zone;
        assert!(
            inbound_observation_matches(ConnectorId::Tor, endpoint),
            "tor inbound observation does not match its declaration"
        );
        let mut inner = self.lock();
        refuse_inbound(&inner, ConnectorId::Tor, ceiling)?;
        self.mint(&mut inner, ConnectorId::Tor, Direction::Inbound, endpoint)
    }

    /// Outbound Tor. The addressing cell says what may be dialed. Anything
    /// else is [`CloseKind::DialFailed`] and reserves nothing.
    pub fn open_tor(&self, address: &NetworkAddress) -> Result<OpenSocket, OpenError> {
        check_dial(ConnectorId::Tor, address).map_err(OpenError::Refused)?;
        let mut inner = self.lock();
        self.mint(
            &mut inner,
            ConnectorId::Tor,
            Direction::Outbound,
            ObservedEndpoint::Zone,
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
    /// A deadline that is not later than the one stored does not shorten it.
    /// Each closed socket is [`CloseKind::LocalClose`], once.
    pub fn ban_host(&self, host: IpAddr, until: Tick, now: Tick) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_host(host, until, now) {
            return Vec::new();
        }
        close_matching(&mut inner, BanSubject::Host(host))
    }

    /// Ban an IPv4 subnet and close live IPv4 sockets inside it.
    /// The deadline rule is the same as [`Self::ban_host`].
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_subnet(subnet, until, now) {
            return Vec::new();
        }
        close_matching(&mut inner, BanSubject::Subnet(subnet))
    }

    /// Ban `host` until it is lifted, and close live sockets to it.
    /// A ban that is already permanent closes nothing new.
    pub fn ban_host_permanent(&self, host: IpAddr) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_host_permanent(host) {
            return Vec::new();
        }
        close_matching(&mut inner, BanSubject::Host(host))
    }

    /// Ban `subnet` until it is lifted, and close live sockets inside it.
    pub fn ban_subnet_permanent(&self, subnet: Ipv4Subnet) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_subnet_permanent(subnet) {
            return Vec::new();
        }
        close_matching(&mut inner, BanSubject::Subnet(subnet))
    }

    /// Remove a host ban. Sockets that are already open stay open.
    pub fn lift_host(&self, host: IpAddr) -> bool {
        self.lock().bans.lift_host(host)
    }

    /// Remove a subnet ban. Sockets that are already open stay open.
    pub fn lift_subnet(&self, subnet: Ipv4Subnet) -> bool {
        self.lock().bans.lift_subnet(subnet)
    }

    /// Drop every ban. Open sockets stay open. The daemon lifts one entry
    /// at a time; a test process uses this because the list outlives the
    /// `node_server` that used to own it.
    pub fn clear_bans(&self) {
        self.lock().bans.clear();
    }

    /// Time left on the longest ban that covers `host`.
    pub fn remaining(&self, host: IpAddr, now: Tick) -> Option<BanLeft> {
        self.lock().bans.remaining(host, now)
    }

    /// Bans still in force, with nanoseconds left from `now`.
    pub fn listed(&self, now: Tick) -> Vec<ListedBan> {
        self.lock().bans.listed(now)
    }

    /// How many live sockets this connector has in this direction.
    ///
    /// This is a snapshot for reporting. Accept does not read it.
    /// [`Self::accept_clearnet`] and [`Self::accept_tor`] hold the table
    /// lock across the ceiling check and the mint.
    #[must_use]
    pub fn socket_count(&self, connector: ConnectorId, direction: Direction) -> u64 {
        self.lock().occupancy.get(connector, direction)
    }

    /// Inbound sockets on every connector.
    ///
    /// This is the `inbound_held` input of the descriptor ceiling: fds
    /// already inside the process count, so a later derive does not charge
    /// them twice. Outbound sockets stay in that process count. Their cap
    /// is reserved separately. Accept does not read this sum.
    #[must_use]
    pub fn inbound_held(&self) -> u64 {
        self.lock()
            .occupancy
            .process_inbound()
            .expect("inbound socket count fits in u64")
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

    /// The endpoint recorded for `id`, when the socket is still live.
    #[must_use]
    pub fn endpoint(&self, id: SocketId) -> Option<ObservedEndpoint> {
        self.lock().live.get(&id).map(|live| live.endpoint)
    }

    fn mint(
        &self,
        inner: &mut Inner,
        connector: ConnectorId,
        direction: Direction,
        endpoint: ObservedEndpoint,
    ) -> Result<OpenSocket, OpenError> {
        let next = inner.next_id.checked_add(1).ok_or(OpenError::Exhausted)?;
        inner
            .occupancy
            .try_increment(connector, direction)
            .ok_or(OpenError::Exhausted)?;
        let id = SocketId(inner.next_id);
        inner.next_id = next;
        inner.live.insert(
            id,
            Live {
                connector,
                direction,
                endpoint,
            },
        );
        debug_assert!(inner.holds());
        Ok(OpenSocket {
            inner: Arc::new(Reservation {
                sockets: self.clone(),
                id,
                open: AtomicBool::new(true),
            }),
        })
    }
}

impl Default for Sockets {
    fn default() -> Self {
        Self::new()
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

fn release(inner: &mut Inner, id: SocketId, cause: CloseCause) -> CloseResult {
    let Some(live) = inner.live.remove(&id) else {
        return CloseResult::AlreadyClosed;
    };
    inner.occupancy.decrement(live.connector, live.direction);
    debug_assert!(inner.holds());
    CloseResult::Recorded(cause)
}

/// The reservation behind every clone of one [`OpenSocket`].
///
/// The first [`OpenSocket::close`] releases the row. Dropping the last
/// clone does the same with [`CloseKind::LocalClose`] when nobody closed
/// it, so a failure before the channel is published cannot leave the
/// count up. Dropping an earlier clone does not: the connection task and
/// the seam each hold one, and either of them may close first.
struct Reservation {
    sockets: Sockets,
    id: SocketId,
    open: AtomicBool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.open.swap(false, Ordering::AcqRel) {
            match self
                .sockets
                .close(self.id, CloseCause::new(CloseKind::LocalClose))
            {
                CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
            }
        }
    }
}

/// A reserved socket. Clones name the same row.
///
/// The connection task keeps one clone and closes it when the socket
/// ends. The seam keeps another and can close it earlier. The first
/// close releases the row. A later close is [`CloseResult::AlreadyClosed`].
#[derive(Clone, Debug)]
#[must_use = "dropping the last OpenSocket releases the reservation"]
pub struct OpenSocket {
    inner: Arc<Reservation>,
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("id", &self.id)
            .field("open", &self.open.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl OpenSocket {
    /// The id.
    #[must_use]
    pub fn id(&self) -> SocketId {
        self.inner.id
    }

    /// Close with `cause`. A clone that is still held does not close again.
    pub fn close(self, cause: CloseCause) -> CloseResult {
        if self.inner.open.swap(false, Ordering::AcqRel) {
            self.inner.sockets.close(self.inner.id, cause)
        } else {
            CloseResult::AlreadyClosed
        }
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

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
