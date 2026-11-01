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

use crate::accept_rate::{accept_bound, AcceptGate, RateRefusal};
use crate::ban::{BanFeed, BanLeft, BanList, Ipv4Subnet, ListedBan};
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
///
/// The table starts at 1 and increments, and it never reuses an id.
/// Admission order is that sequence. This type does not order itself:
/// a reader that needs the sequence sorts the copy it publishes.
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

const fn admission_refused() -> OpenError {
    OpenError::Refused(CloseCause::new(CloseKind::AdmissionRefused))
}

const fn accept_rate_exceeded() -> OpenError {
    OpenError::Refused(CloseCause::new(CloseKind::AcceptRateExceeded))
}

const fn inbound_not_accepted() -> OpenError {
    OpenError::Refused(CloseCause::new(CloseKind::InboundNotAccepted))
}

/// Accepts the socket table refused since the counts were last taken.
///
/// The rate buckets are the flood signal: a warning names them. A ban, a
/// ceiling of zero, and a full ceiling are ordinary refusals and are
/// reported without that warning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptRefusals {
    /// The host's bucket could not pay.
    pub over_host_rate: u64,
    /// The connector's bucket could not pay.
    pub over_connector_rate: u64,
    /// A ceiling or a connector cap of zero.
    pub inbound_closed: u64,
    /// A ban, a full ceiling or cap, or an id or occupancy that cannot move.
    pub full_or_banned: u64,
}

impl AcceptRefusals {
    /// The rate refusals together: the count a warning names.
    #[must_use]
    pub const fn over_rate(self) -> u64 {
        self.over_host_rate.saturating_add(self.over_connector_rate)
    }

    /// Whether any accept was refused.
    #[must_use]
    pub const fn any(self) -> bool {
        self.over_rate() > 0 || self.inbound_closed > 0 || self.full_or_banned > 0
    }
}

/// One accept the table refused, named by the decision that refused it.
///
/// Recorded on the accept path only. An outbound ban is the same close
/// cause and is not an accept, so it is not one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptRefusal {
    /// A ceiling or a connector cap of zero.
    InboundClosed,
    /// A ban, a full ceiling or cap, or an id or occupancy that cannot move.
    FullOrBanned,
    /// The host's bucket could not pay.
    OverHostRate,
    /// The connector's bucket could not pay.
    OverConnectorRate,
}

impl AcceptRefusal {
    const fn open_error(self) -> OpenError {
        match self {
            Self::InboundClosed => inbound_not_accepted(),
            Self::FullOrBanned => admission_refused(),
            Self::OverHostRate | Self::OverConnectorRate => accept_rate_exceeded(),
        }
    }

    /// Count this refusal and return the close the accept already returned.
    fn record(self, inner: &mut Inner) -> OpenError {
        let cell = match self {
            Self::InboundClosed => &mut inner.refusals.inbound_closed,
            Self::FullOrBanned => &mut inner.refusals.full_or_banned,
            Self::OverHostRate => &mut inner.refusals.over_host_rate,
            Self::OverConnectorRate => &mut inner.refusals.over_connector_rate,
        };
        *cell = cell.saturating_add(1);
        self.open_error()
    }
}

impl From<RateRefusal> for AcceptRefusal {
    fn from(bucket: RateRefusal) -> Self {
        match bucket {
            RateRefusal::Host => Self::OverHostRate,
            RateRefusal::Connector => Self::OverConnectorRate,
        }
    }
}

/// How an inbound limit stands against the sockets already held under it.
///
/// [`Self::Closed`] is a limit of zero: holding fewer sockets cannot open
/// it, so the refusal is [`CloseKind::InboundNotAccepted`]. [`Self::Full`]
/// is a positive limit the held count has reached: a later close can open
/// a slot, so the refusal is [`CloseKind::AdmissionRefused`]. [`Self::Open`]
/// is no limit, or a positive limit not yet reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LimitStance {
    Open,
    Closed,
    Full,
}

impl LimitStance {
    /// `None` is no limit. Zero is closed at every `held`. A positive limit
    /// is full when `held` has reached it.
    fn classify(limit: Option<u32>, held: u64) -> Self {
        match limit {
            Some(0) => Self::Closed,
            Some(limit) if held >= u64::from(limit) => Self::Full,
            None | Some(_) => Self::Open,
        }
    }

    /// Closed outranks full. A connector cap and the process ceiling are
    /// the same kind of limit, so either one being closed refuses the accept.
    const fn prefer(self, other: Self) -> Self {
        match (self, other) {
            (Self::Closed, _) | (_, Self::Closed) => Self::Closed,
            (Self::Full, _) | (_, Self::Full) => Self::Full,
            (Self::Open, Self::Open) => Self::Open,
        }
    }

    const fn refusal(self) -> Result<(), AcceptRefusal> {
        match self {
            Self::Closed => Err(AcceptRefusal::InboundClosed),
            Self::Full => Err(AcceptRefusal::FullOrBanned),
            Self::Open => Ok(()),
        }
    }
}

fn process_limit(ceiling: InboundCeiling) -> Option<u32> {
    match ceiling {
        InboundCeiling::Bounded(limit) => Some(limit),
        InboundCeiling::Unbounded(_) => None,
    }
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

/// The ban list's timing owner, as the table tells it of a deadline that
/// has become the earliest. Called outside the table's lock.
#[derive(Clone)]
struct BanExpiry(Arc<dyn Fn(Tick) + Send + Sync>);

impl std::fmt::Debug for BanExpiry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BanExpiry")
    }
}

#[derive(Debug)]
struct Inner {
    next_id: u64,
    occupancy: Occupancy,
    live: HashMap<SocketId, Live>,
    bans: BanList,
    /// The ban list's timing owner, once one is installed
    /// ([`Sockets::set_ban_expiry`]).
    ban_expiry: Option<BanExpiry>,
    /// An operator cap for one connector. `None` means that connector has
    /// no cap of its own. The process ceiling applies either way.
    zone_caps: [Option<u32>; ConnectorId::COUNT],
    /// Clearnet's accept-rate bound (D10.3), or `None` when its row has no
    /// limiter.
    clearnet_rate: Option<AcceptGate>,
    /// Accepts refused since the counts were last taken. Outbound opens
    /// do not write it.
    refusals: AcceptRefusals,
}

impl Inner {
    fn new(clearnet_rate: Option<AcceptGate>) -> Self {
        Self {
            next_id: 1,
            occupancy: Occupancy::new(),
            live: HashMap::new(),
            bans: BanList::new(),
            ban_expiry: None,
            zone_caps: [None; ConnectorId::COUNT],
            clearnet_rate,
            refusals: AcceptRefusals::default(),
        }
    }

    /// The timing owner to tell of `until`, when a ban just stored made it
    /// the earliest deadline.
    fn expiry_for(&self, until: Tick) -> Option<BanExpiry> {
        (self.bans.earliest() == Some(until))
            .then(|| self.ban_expiry.clone())
            .flatten()
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

/// Refuse when this connector's cap is full, and when the process
/// ceiling is full. The cap does not replace the ceiling: each connector
/// can be under its own number while the sum still exhausts the descriptors.
///
/// Both bounds are a [`LimitStance`]. A limit of zero is closed
/// ([`CloseKind::InboundNotAccepted`]). A positive limit that occupancy
/// has reached is full ([`CloseKind::AdmissionRefused`]). Closed outranks
/// full. A ban is [`CloseKind::AdmissionRefused`], and it is decided before
/// this function.
///
/// A closed bound returns before the process sum. A zero ceiling is then
/// not reported as an overflow of the occupancy counter. The caller
/// records the refusal: this function only decides.
fn refuse_inbound(
    inner: &Inner,
    connector: ConnectorId,
    ceiling: InboundCeiling,
) -> Result<(), AcceptRefusal> {
    let cap = inner.zone_caps[connector.index()];
    let held = inner.occupancy.get(connector, Direction::Inbound);
    let zone = LimitStance::classify(cap, held);
    let limit = process_limit(ceiling);
    // Held 0 asks only whether the ceiling is zero. A positive ceiling is
    // open at held 0; fullness uses the real process sum below.
    let decided = LimitStance::prefer(zone, LimitStance::classify(limit, 0));
    if decided != LimitStance::Open {
        return decided.refusal();
    }
    let Some(total) = inner.occupancy.process_inbound() else {
        return Err(AcceptRefusal::FullOrBanned);
    };
    LimitStance::classify(limit, total).refusal()
}

/// Which inbound clearnet row this call is reserving.
///
/// A network accept spends the accept-rate gate. A reservation does not:
/// the harnesses that call it have no handshake for the gate to price,
/// and the listener's accept is the only call that does.
#[derive(Clone, Copy)]
enum ClearnetInbound {
    /// [`Sockets::accept_clearnet`]: ban, ceiling, rate, then the row.
    Network,
    /// [`Sockets::reserve_clearnet_inbound`]: ban, ceiling, then the row.
    Reserved,
}

/// The socket table. Clones share it. A poisoned lock aborts the process:
/// a panic while the table was held has already broken the count.
#[derive(Clone, Debug)]
pub struct Sockets {
    inner: Arc<Mutex<Inner>>,
}

impl Sockets {
    /// An empty table. Clearnet accepts pass the gate its row in
    /// [`accept_bound`] describes.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clearnet_gate(AcceptGate::for_bound(accept_bound(ConnectorId::Clearnet)))
    }

    /// An empty table whose clearnet accepts pass `gate`, or no gate, in
    /// place of the connector's row: for harnesses and tests that exercise
    /// the mechanism with rates the table does not hold. The daemon's table
    /// is [`Self::new`].
    #[must_use]
    pub fn with_clearnet_gate(gate: Option<AcceptGate>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new(gate))),
        }
    }

    /// Accepts refused since the last call, and start counting again.
    ///
    /// The rate buckets, a ban, a ceiling and a cap that cannot move are
    /// one ledger: the minute report reads it, and nothing else counts an
    /// accept by matching a close cause after the fact.
    pub fn take_accept_refusals(&self) -> AcceptRefusals {
        std::mem::take(&mut self.lock().refusals)
    }

    /// How many refused clearnet accepts may linger half-closed at once
    /// for `span` (D10.2): what the accept-rate gate's connector bucket
    /// admits in that time ([`AcceptGate::linger_cap`]). Zero with no gate.
    #[must_use]
    pub fn clearnet_linger_cap(&self, span: Tick) -> usize {
        self.lock()
            .clearnet_rate
            .as_ref()
            .map_or(0, |gate| gate.linger_cap(span))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("socket table lock poisoned")
    }

    /// The operator's inbound cap for one connector. `None` clears it.
    /// The process ceiling still bounds the sum.
    pub fn set_zone_cap(&self, connector: ConnectorId, cap: Option<u32>) {
        self.lock().zone_caps[connector.index()] = cap;
    }

    /// Drop every connector cap. The socket table outlives the zone that
    /// set them, and a later admit would keep a cap that zone no longer has.
    /// The process ceiling still bounds the sum.
    pub fn clear_zone_caps(&self) {
        for connector in ConnectorId::ALL {
            self.set_zone_cap(*connector, None);
        }
    }

    /// Inbound clearnet.
    ///
    /// `ceiling` is the process-wide inbound ceiling: this row and every
    /// other connector's inbound row are one sum. A banned address, and a
    /// positive ceiling or connector cap that is full, are
    /// [`CloseKind::AdmissionRefused`]. A ceiling or connector cap of zero
    /// is [`CloseKind::InboundNotAccepted`]. An accept the connector's or
    /// the host's rate bucket cannot pay for is
    /// [`CloseKind::AcceptRateExceeded`] (D10.3); it is decided after the
    /// ban and the ceilings, so a connection those refuse spends no token.
    /// Every refusal reserves nothing. This is the listener's accept.
    /// A harness reserves through [`Self::reserve_clearnet_inbound`] and
    /// spends no token.
    pub fn accept_clearnet(
        &self,
        ip: IpAddr,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<OpenSocket, OpenError> {
        self.clearnet_inbound(ip, ceiling, now, ClearnetInbound::Network)
    }

    /// Reserve an inbound clearnet row that is not a network accept.
    ///
    /// The listener's accept is [`Self::accept_clearnet`], and that is
    /// the call that spends an accept-rate token. This one is the row a
    /// harness reserves: the in-memory loopback dialer, and the tests
    /// that admit through it. A harness has no handshake, so the gate
    /// has nothing to price, and the socket table is process-global, so
    /// charging the harness would spend the tokens the listener's
    /// accepts are counted against.
    ///
    /// A ban, a full ceiling and a ceiling of zero still refuse, and
    /// still count on the refusal ledger. The rate is not consulted, so
    /// the refusal is never [`CloseKind::AcceptRateExceeded`].
    pub fn reserve_clearnet_inbound(
        &self,
        ip: IpAddr,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<OpenSocket, OpenError> {
        self.clearnet_inbound(ip, ceiling, now, ClearnetInbound::Reserved)
    }

    /// Ban, then the ceilings, then the rate when `inbound` is a network
    /// accept, then the row. One order, so the two callers cannot drift.
    fn clearnet_inbound(
        &self,
        ip: IpAddr,
        ceiling: InboundCeiling,
        now: Tick,
        inbound: ClearnetInbound,
    ) -> Result<OpenSocket, OpenError> {
        let endpoint = ObservedEndpoint::Host(ip);
        assert!(
            inbound_observation_matches(ConnectorId::Clearnet, endpoint),
            "clearnet inbound observation does not match its declaration"
        );
        let mut inner = self.lock();
        if inner.bans.is_banned(ip) {
            return Err(AcceptRefusal::FullOrBanned.record(&mut inner));
        }
        if let Err(refusal) = refuse_inbound(&inner, ConnectorId::Clearnet, ceiling) {
            return Err(refusal.record(&mut inner));
        }
        match inbound {
            ClearnetInbound::Network => {
                // The gate borrow ends before the refusal is recorded.
                let rate_refusal = inner
                    .clearnet_rate
                    .as_mut()
                    .and_then(|gate| gate.admit(ip, now).err());
                if let Some(bucket) = rate_refusal {
                    return Err(AcceptRefusal::from(bucket).record(&mut inner));
                }
            }
            // A harness has no handshake. The gate prices the listener's accept.
            ClearnetInbound::Reserved => {}
        }
        admitted(self, &mut inner, ConnectorId::Clearnet, endpoint)
    }

    /// Outbound clearnet. The inbound ceiling does not apply. A banned
    /// address is still refused.
    pub fn open_clearnet(&self, ip: IpAddr) -> Result<OpenSocket, OpenError> {
        let mut inner = self.lock();
        if inner.bans.is_banned(ip) {
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
    /// A zero ceiling, or a zero cap on this connector, is
    /// [`CloseKind::InboundNotAccepted`].
    pub fn accept_tor(&self, ceiling: InboundCeiling) -> Result<OpenSocket, OpenError> {
        let endpoint = ObservedEndpoint::Zone;
        assert!(
            inbound_observation_matches(ConnectorId::Tor, endpoint),
            "tor inbound observation does not match its declaration"
        );
        let mut inner = self.lock();
        if let Err(refusal) = refuse_inbound(&inner, ConnectorId::Tor, ceiling) {
            return Err(refusal.record(&mut inner));
        }
        admitted(self, &mut inner, ConnectorId::Tor, endpoint)
    }

    /// Outbound Tor. The addressing cell says what may be dialed. Anything
    /// else is [`CloseKind::LocalClose`] and reserves nothing.
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
        let mut inner = self.lock();
        if !inner.bans.ban_host(host, until, now) {
            return Vec::new();
        }
        let closed = close_matching(&mut inner, BanSubject::Host(host));
        let expiry = inner.expiry_for(until);
        let rings = inner.bans.take_rings();
        drop(inner);
        if let Some(BanExpiry(arm)) = expiry {
            arm(until);
        }
        rings.ring();
        closed
    }

    /// Ban an IPv4 subnet and close live IPv4 sockets inside it.
    /// The deadline rule is the same as [`Self::ban_host`].
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick, now: Tick) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_subnet(subnet, until, now) {
            return Vec::new();
        }
        let closed = close_matching(&mut inner, BanSubject::Subnet(subnet));
        let expiry = inner.expiry_for(until);
        let rings = inner.bans.take_rings();
        drop(inner);
        if let Some(BanExpiry(arm)) = expiry {
            arm(until);
        }
        rings.ring();
        closed
    }

    /// Ban `host` until it is lifted, and close live sockets to it.
    /// A ban that is already permanent closes nothing new.
    pub fn ban_host_permanent(&self, host: IpAddr) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_host_permanent(host) {
            return Vec::new();
        }
        let closed = close_matching(&mut inner, BanSubject::Host(host));
        let rings = inner.bans.take_rings();
        drop(inner);
        rings.ring();
        closed
    }

    /// Ban `subnet` until it is lifted, and close live sockets inside it.
    pub fn ban_subnet_permanent(&self, subnet: Ipv4Subnet) -> Vec<SocketId> {
        let mut inner = self.lock();
        if !inner.bans.ban_subnet_permanent(subnet) {
            return Vec::new();
        }
        let closed = close_matching(&mut inner, BanSubject::Subnet(subnet));
        let rings = inner.bans.take_rings();
        drop(inner);
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

/// Mint an inbound socket, and count an id or occupancy that cannot move
/// as a full table. An outbound mint does not: it is not an accept.
fn admitted(
    sockets: &Sockets,
    inner: &mut Inner,
    connector: ConnectorId,
    endpoint: ObservedEndpoint,
) -> Result<OpenSocket, OpenError> {
    match sockets.mint(inner, connector, Direction::Inbound, endpoint) {
        Ok(open) => Ok(open),
        Err(OpenError::Exhausted) => Err(AcceptRefusal::FullOrBanned.record(inner)),
        Err(error @ OpenError::Refused(_)) => Err(error),
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
