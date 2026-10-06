// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One process-wide seam.
//!
//! The hub does not dial and does not build a session. A [`Dial`] produces
//! a channel the connector admitted. [`Hub::adopt`] posts `established`
//! under the table lock. [`Hub::deliver`] posts one frame and waits until
//! the strand returns. The first [`CloseCause`] wins. [`Hub::reap`] drops
//! the row when the executor drops the link.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};

use tokio::sync::oneshot;

use shekyl_capped_stream::{SendHalf, Session};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{Clock, MonotonicClock, Tick};
use shekyl_transport_layer::{
    CloseCause, CloseKind, CloseResult, ConnectorId, Direction, Ipv4Subnet, OpenSocket, SocketId,
    Sockets,
};

use crate::connection::Connection;
use crate::dial::Dial;
use crate::endpoint::Endpoint;
use crate::loopback::Loopback;
use crate::registry::{Board, Row};

/// What the strand is asked to run. The post returns before the strand does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Post {
    /// Create the handler. The channel already exists.
    Established {
        /// The admission id.
        id: SocketId,
        /// The endpoint the adapter writes before arming the handler.
        endpoint: Endpoint,
    },
    /// One delivery. The handler parses these bytes.
    Deliver {
        /// The admission id.
        id: SocketId,
        /// The connector this id was established on. The adapter keeps one
        /// binding per connector and routes by this; a post without it went
        /// to the clearnet binding, which dropped every Tor delivery.
        connector: ConnectorId,
        /// One whole message.
        bytes: Vec<u8>,
    },
    /// The socket is gone. Destroy the handler when its call count is zero.
    Closed {
        /// The admission id.
        id: SocketId,
        /// The connector this id was established on, as on `Deliver`.
        connector: ConnectorId,
        /// The cause that won.
        cause: CloseCause,
    },
}

impl Post {
    /// The admission id this post names.
    #[must_use]
    pub const fn id(&self) -> SocketId {
        match self {
            Self::Established { id, .. } | Self::Deliver { id, .. } | Self::Closed { id, .. } => {
                *id
            }
        }
    }
}

/// A channel the hub has posted `established` for.
pub struct Attached {
    /// The admission id.
    pub id: SocketId,
    /// The pump's end of the session.
    pub session: Session,
}

/// Where the handler is. The variants are the only states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// `established` is posted. The pump must not deliver.
    Arming,
    /// The handler is armed.
    Open,
    /// A frame is on the strand.
    Delivering,
    /// `closed` is posted. The row stays until [`Hub::reap`].
    Closed,
}

struct Conn {
    open: Option<OpenSocket>,
    send: Option<SendHalf>,
    cause: Option<CloseCause>,
    phase: Phase,
    /// The identity observed at adopt. The address is not rewritten.
    /// Claims recorded later do not replace it.
    connection: Connection,
    /// The Levin handshake has finished. Distinct from [`Phase`]: a row can
    /// be open to frames before the handshake, and closed after it.
    established: bool,
    /// Wakes this row's inbound drive, and only it. A hub-wide wake would
    /// wake every waiting driver on every strand answer, O(N) per delivery
    /// on the zone whose N is adversarial. `notify_one` stores a permit when
    /// no driver is waiting, so a change between the driver dropping the
    /// table lock and awaiting is not lost.
    notify: Arc<tokio::sync::Notify>,
    /// How many `Deliver` posts have been queued. The injector waits on this.
    posted_deliveries: u64,
    /// The strand has entered `closed`. A late refusal records nothing.
    strand_closed: bool,
    /// Fires when the Levin handshake completes. Dropped when the row
    /// closes, which is what ends the connector's gap wait. The sender
    /// lives here, on the row, so a connection that never finishes the
    /// handshake does not leave one behind in a side table.
    gap: Option<oneshot::Sender<()>>,
}

struct Inner {
    sockets: Sockets,
    conns: HashMap<SocketId, Conn>,
    ceiling: InboundCeiling,
    /// The last board published. Readers clone this. They do not lock the table.
    board: Board,
}

/// What one locked look at a row told [`Hub::deliver_async`].
enum DeliverStep {
    Done(bool),
    Wait,
}

/// One seam. Clones share the table.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Mutex<Inner>>,
    /// Wakes the thread waiters: the harness pump and the open path. Task
    /// waiters have one [`tokio::sync::Notify`] per row.
    ready: Arc<Condvar>,
    post: Arc<dyn Fn(Post) + Send + Sync>,
    clock: Arc<dyn Clock + Send + Sync>,
    dial: Arc<RwLock<Option<Arc<dyn Dial>>>>,
}

/// What one `send` did. `found` is whether the registry held the id.
pub struct SendReport {
    pub accepted: bool,
    pub found: bool,
    pub cause: Option<CloseKind>,
}

impl Hub {
    /// `sockets` is the process-wide admission table. Connectors receive
    /// the same table from the caller; this hub does not mint one.
    /// `post` enqueues onto that connection's strand and returns. It must
    /// not call back into the hub: posts run while the table lock is held,
    /// so `established` cannot land after `closed`.
    /// `ceiling` is the descriptor-derived inbound bound the caller resolved.
    #[must_use]
    pub fn new(
        sockets: Sockets,
        ceiling: InboundCeiling,
        post: Arc<dyn Fn(Post) + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                sockets,
                conns: HashMap::new(),
                ceiling,
                board: Board::empty(),
            })),
            ready: Arc::new(Condvar::new()),
            post,
            clock,
            dial: Arc::new(RwLock::new(None)),
        }
    }

    /// Wake every thread waiter.
    fn wake(&self) {
        self.ready.notify_all();
    }

    /// Wake one row's inbound drive.
    fn wake_row(conn: &Conn) {
        conn.notify.notify_one();
    }

    /// [`Self::new`] with the monotonic clock.
    #[must_use]
    pub fn with_clock(
        sockets: Sockets,
        ceiling: InboundCeiling,
        post: Arc<dyn Fn(Post) + Send + Sync>,
    ) -> Self {
        Self::new(sockets, ceiling, post, Arc::new(MonotonicClock::new()))
    }

    /// Replace the inbound bound. The next admit reads it.
    pub fn set_ceiling(&self, ceiling: InboundCeiling) {
        self.lock().ceiling = ceiling;
    }

    /// Install the dialer zone bind will use. The previous dialer is dropped
    /// after the write lock is released: its drop joins the harness pump,
    /// and that pump calls [`Self::finish`], which takes the same lock.
    pub fn install_dial(&self, dial: Arc<dyn Dial>) {
        let previous = {
            let mut slot = self.dial.write().expect("seam dial");
            slot.replace(dial)
        };
        drop(previous);
    }

    /// Install the in-memory harness dialer. Zone bind installs a connector
    /// dialer instead, on the same [`Sockets`] this hub already holds.
    pub fn install_loopback(&self, send_cap: usize) {
        let sockets = self.lock().sockets.clone();
        self.install_dial(Arc::new(Loopback::new(sockets, send_cap)));
    }

    /// Close every row and join the dialer's threads.
    ///
    /// The hub stays published while this runs, so a strand callback still
    /// reaches this binding. Rows are removed after the threads have joined.
    /// A later [`Self::reap`] for one of those ids finds nothing.
    pub fn shutdown(&self) {
        let ids: Vec<SocketId> = self.lock().conns.keys().copied().collect();
        for id in ids {
            self.finish(id, CloseCause::new(CloseKind::LocalClose));
        }
        let previous = {
            let mut slot = self.dial.write().expect("seam dial");
            slot.take()
        };
        drop(previous);
        self.lock().conns.clear();
        self.wake();
    }

    fn now(&self) -> Tick {
        self.clock.now()
    }

    fn current_dial(&self) -> Option<Arc<dyn Dial>> {
        self.dial.read().expect("seam dial").clone()
    }

    /// Ask the installed dialer for a channel and post `established`.
    ///
    /// No dialer is [`CloseKind::DialFailed`]. The caller drives
    /// [`crate::drive_inbound`] on the returned session.
    pub fn connect(&self, endpoint: &Endpoint) -> Result<Attached, CloseCause> {
        let dial = self
            .current_dial()
            .ok_or_else(|| CloseCause::new(CloseKind::DialFailed))?;
        let ceiling = self.lock().ceiling;
        let now = self.now();
        let channel = dial.connect(endpoint, ceiling, now)?;
        self.adopt(channel.open, channel.session, channel.endpoint, channel.gap)
    }

    /// Register a channel the connector already admitted.
    ///
    /// Posts `established` under the table lock. The session stays with the
    /// caller, who runs the inbound pump.
    pub fn adopt(
        &self,
        open: OpenSocket,
        session: Session,
        endpoint: Endpoint,
        gap: Option<oneshot::Sender<()>>,
    ) -> Result<Attached, CloseCause> {
        let id = open.id();
        let started = self.now();
        let send = session.send_half();
        let poster = Arc::clone(&self.post);
        let mut inner = self.lock();
        if inner.conns.contains_key(&id) {
            drop(inner);
            drop(open);
            return Err(CloseCause::new(CloseKind::DialFailed));
        }
        inner.conns.insert(
            id,
            Conn {
                open: Some(open),
                send: Some(send),
                cause: None,
                phase: Phase::Arming,
                connection: Connection::open(id, endpoint, started),
                established: false,
                notify: Arc::new(tokio::sync::Notify::new()),
                posted_deliveries: 0,
                strand_closed: false,
                gap,
            },
        );
        Self::republish(&mut inner);
        poster(Post::Established { id, endpoint });
        Ok(Attached { id, session })
    }

    /// The sessions as of the last publish. The returned board does not
    /// change when a later session arrives or closes.
    #[must_use]
    pub fn board(&self) -> Board {
        self.lock().board.clone()
    }

    /// Rebuild the published board from rows that are still connected.
    ///
    /// The live table is a hash map, keyed for lookup by admission id.
    /// Publish sorts the copy. This is O(N) per accept. Under an accept
    /// flood that is O(N²) across the flood. D5's thread-budget flood leg
    /// measures that cost; it is not a reason to hand a reader the live
    /// row. A closed row stays in the table until [`Self::reap`] and is
    /// not on the board.
    fn republish(inner: &mut Inner) {
        let rows = inner
            .conns
            .iter()
            .filter(|(_, conn)| !matches!(conn.phase, Phase::Closed))
            .map(|(&id, conn)| Row::new(id, *conn.connection.endpoint().get(), conn.established))
            .collect();
        inner.board = Board::from_rows(rows);
    }

    /// Block until the handler is armed, or until the id has closed.
    #[must_use]
    pub fn await_armed(&self, id: SocketId) -> bool {
        let mut inner = self.lock();
        loop {
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            match conn.phase {
                Phase::Open | Phase::Delivering => return true,
                Phase::Closed => return false,
                Phase::Arming => inner = self.wait(inner),
            }
        }
    }

    /// The strand finished `established`. `armed` false records
    /// [`CloseKind::LocalClose`] and wakes the waiter.
    pub fn handler_armed(&self, id: SocketId, armed: bool) {
        if !armed {
            self.finish(id, CloseCause::new(CloseKind::LocalClose));
            return;
        }
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            if conn.cause.is_none() && matches!(conn.phase, Phase::Arming) {
                conn.phase = Phase::Open;
            }
            Self::wake_row(conn);
        }
        self.wake();
    }

    /// How many `Deliver` posts have been queued for `id`.
    #[must_use]
    pub fn posted_deliveries(&self, id: SocketId) -> Option<u64> {
        self.lock()
            .conns
            .get(&id)
            .map(|conn| conn.posted_deliveries)
    }

    /// Block until a `Deliver` newer than `before` is queued, or the id closes.
    #[must_use]
    pub fn wait_delivery_posted(&self, id: SocketId, before: u64) -> bool {
        let mut inner = self.lock();
        loop {
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            if conn.posted_deliveries > before {
                return true;
            }
            if matches!(conn.phase, Phase::Closed) {
                return false;
            }
            inner = self.wait(inner);
        }
    }

    /// Push one frame at the harness dialer. A connector dialer has no injector.
    #[must_use]
    pub fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        self.current_dial()
            .is_some_and(|dial| dial.inject(id, frame))
    }

    /// Remember the harness pump so [`Self::reap`] can join it.
    pub fn track_pump(&self, id: SocketId, pump: std::thread::JoinHandle<()>) {
        if let Some(dial) = self.current_dial() {
            dial.track_pump(id, pump);
        }
    }

    /// Post one frame and wait until the strand accepts it or the id closes.
    ///
    /// The caller is the inbound pump. It does not take the next frame
    /// until this returns. The wait is the hub condvar. [`Self::deliver_async`]
    /// is the same step on the row's [`tokio::sync::Notify`].
    #[must_use]
    pub fn deliver(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        let mut bytes = Some(bytes);
        let mut inner = self.lock();
        loop {
            match self.deliver_step(&mut inner, id, &mut bytes) {
                DeliverStep::Done(result) => return result,
                DeliverStep::Wait => inner = self.wait(inner),
            }
        }
    }

    /// [`Self::deliver`] for a task. The wait is the row's own
    /// [`tokio::sync::Notify`], so the task holds no thread while the strand
    /// parses and a strand answer wakes one driver, not every driver. A zone
    /// with one blocking lane drove one connection at a time when this was a
    /// blocking call; every later connection sat deaf in the pool's queue
    /// until the first one closed.
    pub async fn deliver_async(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        let mut bytes = Some(bytes);
        let Some(notify) = self
            .lock()
            .conns
            .get(&id)
            .map(|conn| Arc::clone(&conn.notify))
        else {
            return false;
        };
        loop {
            let step = {
                let mut inner = self.lock();
                self.deliver_step(&mut inner, id, &mut bytes)
            };
            match step {
                DeliverStep::Done(result) => return result,
                // A wake between the lock drop and this await is a stored
                // permit, so it is not lost; a stale permit costs one more
                // look under the lock.
                DeliverStep::Wait => notify.notified().await,
            }
        }
    }

    /// One look at the row under the lock. Posts the frame when the row is
    /// open and the frame is still in hand; reports the outcome once the
    /// frame is out and the row is open again.
    fn deliver_step(
        &self,
        inner: &mut Inner,
        id: SocketId,
        bytes: &mut Option<Vec<u8>>,
    ) -> DeliverStep {
        let Some(conn) = inner.conns.get_mut(&id) else {
            return DeliverStep::Done(false);
        };
        match (conn.phase, bytes.is_some()) {
            (Phase::Closed, _) => DeliverStep::Done(false),
            (Phase::Open, false) => DeliverStep::Done(true),
            (Phase::Open, true) => {
                if conn.cause.is_some() {
                    return DeliverStep::Done(false);
                }
                conn.phase = Phase::Delivering;
                conn.posted_deliveries = conn.posted_deliveries.saturating_add(1);
                let connector = conn.connection.endpoint().get().connector();
                let frame = bytes.take().expect("checked above");
                (self.post)(Post::Deliver {
                    id,
                    connector,
                    bytes: frame,
                });
                self.wake();
                DeliverStep::Wait
            }
            (Phase::Arming | Phase::Delivering, _) => DeliverStep::Wait,
        }
    }

    /// The strand finished `handle_recv`.
    ///
    /// A refusal records [`CloseKind::SessionRefused`] only when no cause
    /// is recorded yet and the strand has not entered `closed`.
    pub fn delivery_finished(&self, id: SocketId, accepted: bool) {
        if !accepted {
            let record_refusal = {
                let inner = self.lock();
                inner
                    .conns
                    .get(&id)
                    .is_some_and(|conn| conn.cause.is_none() && !conn.strand_closed)
            };
            if record_refusal {
                self.finish(id, CloseCause::new(CloseKind::SessionRefused));
            } else {
                self.wake();
            }
            return;
        }
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            if conn.cause.is_none() && matches!(conn.phase, Phase::Delivering) {
                conn.phase = Phase::Open;
            }
            Self::wake_row(conn);
        }
        self.wake();
    }

    /// One whole message. A buffer that does not fit is not stored.
    ///
    /// [`CloseKind::SendQueueFull`] is recorded before this returns.
    #[must_use]
    pub fn send(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        self.send_report(id, bytes).accepted
    }

    /// The same send, with whether the registry held `id` and any cause.
    pub fn send_report(&self, id: SocketId, bytes: Vec<u8>) -> SendReport {
        let outcome = {
            let inner = self.lock();
            let Some(conn) = inner.conns.get(&id) else {
                return SendReport {
                    accepted: false,
                    found: false,
                    cause: None,
                };
            };
            if let Some(cause) = conn.cause {
                return SendReport {
                    accepted: false,
                    found: true,
                    cause: Some(cause.kind()),
                };
            }
            let Some(send) = conn.send.as_ref() else {
                return SendReport {
                    accepted: false,
                    found: true,
                    cause: None,
                };
            };
            send.try_send(bytes)
        };
        match outcome {
            Ok(()) => SendReport {
                accepted: true,
                found: true,
                cause: None,
            },
            Err(CloseKind::SendQueueFull) => {
                self.finish(id, CloseCause::new(CloseKind::SendQueueFull));
                SendReport {
                    accepted: false,
                    found: true,
                    cause: Some(CloseKind::SendQueueFull),
                }
            }
            Err(kind) => SendReport {
                accepted: false,
                found: true,
                cause: Some(kind),
            },
        }
    }

    /// Record [`CloseKind::LocalClose`] when no cause is recorded yet.
    pub fn close(&self, id: SocketId) {
        self.finish(id, CloseCause::new(CloseKind::LocalClose));
    }

    /// Record `cause` when no cause is recorded yet, and post `closed`.
    ///
    /// The connector calls this when its read or write side finishes.
    /// A transport failure does not ban the host.
    pub fn finish(&self, id: SocketId, cause: CloseCause) -> CloseResult {
        self.record(id, cause)
    }

    /// The Levin handshake finished. Fires this row's gap sender, if it
    /// still has one.
    ///
    /// A missing row, and a row already in [`Phase::Closed`], are left
    /// alone. A close is not a handshake, and the closed row stays until
    /// [`Self::reap`].
    pub fn session_established(&self, id: SocketId) {
        let sender = {
            let mut inner = self.lock();
            let mut sender = None;
            let mut publish = false;
            if let Some(conn) = inner.conns.get_mut(&id) {
                if !matches!(conn.phase, Phase::Closed) {
                    conn.established = true;
                    sender = conn.gap.take();
                    publish = true;
                }
            }
            if publish {
                Self::republish(&mut inner);
            }
            sender
        };
        if let Some(sender) = sender {
            match sender.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
    }

    /// The inbound ceiling the next accept reads. One value: the zone host
    /// does not keep a second copy.
    #[must_use]
    pub fn ceiling(&self) -> InboundCeiling {
        self.lock().ceiling
    }

    /// The strand has started `closed`. A later refusal records nothing.
    pub fn handler_gone(&self, id: SocketId) {
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            conn.strand_closed = true;
        }
    }

    /// The executor dropped the link. The row is gone after this returns.
    pub fn reap(&self, id: SocketId) {
        let dial = self.current_dial();
        {
            let mut inner = self.lock();
            if let Some(conn) = inner.conns.remove(&id) {
                Self::wake_row(&conn);
            }
            Self::republish(&mut inner);
            self.wake();
        }
        if let Some(dial) = dial {
            dial.retired(id);
        }
    }

    /// The cause that won, if the row is still here.
    #[must_use]
    pub fn cause(&self, id: SocketId) -> Option<CloseCause> {
        self.lock().conns.get(&id).and_then(|conn| conn.cause)
    }

    /// Ban `host` until `until` and post `closed` for each live socket the
    /// ban drops. A deadline that has already passed bans nothing.
    pub fn ban_host(&self, host: IpAddr, until: Tick) -> Vec<SocketId> {
        let now = self.now();
        let ids = self.lock().sockets.ban_host(host, until, now);
        for id in &ids {
            self.finish(*id, CloseCause::new(CloseKind::LocalClose));
        }
        ids
    }

    /// Ban an IPv4 subnet the same way as [`Self::ban_host`].
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick) -> Vec<SocketId> {
        let now = self.now();
        let ids = self.lock().sockets.ban_subnet(subnet, until, now);
        for id in &ids {
            self.finish(*id, CloseCause::new(CloseKind::LocalClose));
        }
        ids
    }

    /// Ban `host` until it is lifted, and post `closed` for each live socket
    /// the ban drops. A ban that is already permanent drops nothing new.
    pub fn ban_host_permanent(&self, host: IpAddr) -> Vec<SocketId> {
        let ids = self.lock().sockets.ban_host_permanent(host);
        for id in &ids {
            self.finish(*id, CloseCause::new(CloseKind::LocalClose));
        }
        ids
    }

    /// Ban an IPv4 subnet until it is lifted, the same way as
    /// [`Self::ban_host_permanent`].
    pub fn ban_subnet_permanent(&self, subnet: Ipv4Subnet) -> Vec<SocketId> {
        let ids = self.lock().sockets.ban_subnet_permanent(subnet);
        for id in &ids {
            self.finish(*id, CloseCause::new(CloseKind::LocalClose));
        }
        ids
    }

    /// Per-connector socket count. Accept does not read this.
    #[must_use]
    pub fn socket_count(&self, connector: ConnectorId, direction: Direction) -> u64 {
        self.lock().sockets.socket_count(connector, direction)
    }

    /// Inbound sockets on every connector.
    #[must_use]
    pub fn inbound_held(&self) -> u64 {
        self.lock().sockets.inbound_held()
    }

    /// Whether `host` is banned at the hub's current tick.
    #[must_use]
    pub fn is_banned(&self, host: IpAddr) -> bool {
        let now = self.now();
        self.lock().sockets.is_banned(host, now)
    }

    fn record(&self, id: SocketId, cause: CloseCause) -> CloseResult {
        let poster = Arc::clone(&self.post);
        let dial = self.current_dial();
        let (open, send, gap) = {
            let mut inner = self.lock();
            let Some(conn) = inner.conns.get_mut(&id) else {
                return CloseResult::AlreadyClosed;
            };
            if conn.cause.is_some() {
                return CloseResult::AlreadyClosed;
            }
            conn.cause = Some(cause);
            conn.phase = Phase::Closed;
            let open = conn.open.take();
            let send = conn.send.take();
            let gap = conn.gap.take();
            let connector = conn.connection.endpoint().get().connector();
            poster(Post::Closed {
                id,
                connector,
                cause,
            });
            Self::wake_row(conn);
            self.wake();
            Self::republish(&mut inner);
            (open, send, gap)
        };
        // The sender is dropped off the table lock: the connector task it
        // wakes may call back into the hub.
        drop(gap);
        if let Some(open) = open {
            let _ = open.close(cause);
        }
        // The cause is recorded whichever side it came from; the socket
        // has to follow. Discarding the send queue ends the connector's
        // writer (its next `pop` is the close reason), which ends its connection
        // task, which drops the socket. Measured before this (clearnet, LAN,
        // 2026-09-30): after a local close the socket stayed open until the
        // peer's next frame arrived, 54 s later on the timed-sync cadence.
        // Nothing else here reaches the wire: `open.close` releases the
        // admission slot, and the session whose drop closes the queue is
        // parked in the inbound drive. The tail is dropped, not flushed —
        // every cause this path records (ban, refusal, del_in_connections,
        // peer-gone) has nothing queued it needs delivered.
        if let Some(send) = send {
            send.discard();
        }
        if let Some(dial) = dial {
            dial.reader_stopped(id);
        }
        CloseResult::Recorded(cause)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("seam table")
    }

    fn wait<'a>(&'a self, inner: MutexGuard<'a, Inner>) -> MutexGuard<'a, Inner> {
        self.ready
            .wait(inner)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "hub_tests.rs"]
mod tests;
