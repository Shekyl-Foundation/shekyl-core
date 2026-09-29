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

use shekyl_capped_stream::{SendHalf, Session};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{Clock, MonotonicClock, Tick};
use shekyl_transport_layer::{
    CloseCause, CloseKind, CloseResult, ConnectorId, Direction, Ipv4Subnet, OpenSocket, SocketId,
    Sockets,
};

use crate::dial::Dial;
use crate::endpoint::Endpoint;
use crate::loopback::Loopback;

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
        /// One whole message.
        bytes: Vec<u8>,
    },
    /// The socket is gone. Destroy the handler when its call count is zero.
    Closed {
        /// The admission id.
        id: SocketId,
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
    /// How many `Deliver` posts have been queued. The injector waits on this.
    posted_deliveries: u64,
    /// The strand has entered `closed`. A late refusal records nothing.
    strand_closed: bool,
}

struct Inner {
    sockets: Sockets,
    conns: HashMap<SocketId, Conn>,
    ceiling: InboundCeiling,
}

/// One seam. Clones share the table.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Mutex<Inner>>,
    ready: Arc<Condvar>,
    post: Arc<dyn Fn(Post) + Send + Sync>,
    clock: Arc<dyn Clock + Send + Sync>,
    dial: Arc<RwLock<Option<Arc<dyn Dial>>>>,
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
            })),
            ready: Arc::new(Condvar::new()),
            post,
            clock,
            dial: Arc::new(RwLock::new(None)),
        }
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
        self.ready.notify_all();
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
        self.adopt(channel.open, channel.session, channel.endpoint)
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
    ) -> Result<Attached, CloseCause> {
        let id = open.id();
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
                posted_deliveries: 0,
                strand_closed: false,
            },
        );
        poster(Post::Established { id, endpoint });
        Ok(Attached { id, session })
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
        }
        self.ready.notify_all();
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
    /// until this returns.
    #[must_use]
    pub fn deliver(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        let poster = Arc::clone(&self.post);
        let mut inner = self.lock();
        loop {
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            match conn.phase {
                Phase::Closed => return false,
                Phase::Open => break,
                Phase::Arming | Phase::Delivering => inner = self.wait(inner),
            }
        }
        let Some(conn) = inner.conns.get_mut(&id) else {
            return false;
        };
        if conn.cause.is_some() || !matches!(conn.phase, Phase::Open) {
            return false;
        }
        conn.phase = Phase::Delivering;
        conn.posted_deliveries = conn.posted_deliveries.saturating_add(1);
        poster(Post::Deliver { id, bytes });
        self.ready.notify_all();
        loop {
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            match conn.phase {
                Phase::Open => return true,
                Phase::Closed => return false,
                Phase::Delivering | Phase::Arming => inner = self.wait(inner),
            }
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
                self.ready.notify_all();
            }
            return;
        }
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            if conn.cause.is_none() && matches!(conn.phase, Phase::Delivering) {
                conn.phase = Phase::Open;
            }
        }
        self.ready.notify_all();
    }

    /// One whole message. A buffer that does not fit is not stored.
    ///
    /// [`CloseKind::SendQueueFull`] is recorded before this returns.
    #[must_use]
    pub fn send(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        let outcome = {
            let inner = self.lock();
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            if conn.cause.is_some() {
                return false;
            }
            let Some(send) = conn.send.as_ref() else {
                return false;
            };
            send.try_send(bytes)
        };
        match outcome {
            Ok(()) => true,
            Err(CloseKind::SendQueueFull) => {
                self.finish(id, CloseCause::new(CloseKind::SendQueueFull));
                false
            }
            Err(_) => false,
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
            inner.conns.remove(&id);
            self.ready.notify_all();
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
        let open = {
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
            poster(Post::Closed { id, cause });
            self.ready.notify_all();
            open
        };
        if let Some(open) = open {
            let _ = open.close(cause);
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
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use shekyl_capped_stream::{FrameSender, StreamEnds};
    use shekyl_peer_policy::InboundCeiling;
    use shekyl_timing_engine::{Clock, ManualClock, Tick};
    use shekyl_transport_layer::{
        CloseCause, CloseKind, CloseResult, ConnectorId, Direction, Sockets,
    };

    use super::{Hub, Phase, Post};
    use crate::drive_inbound;
    use crate::endpoint::{admit, Endpoint};

    fn endpoint(ip: Ipv4Addr, direction: Direction) -> Endpoint {
        Endpoint::Clearnet {
            ip: IpAddr::V4(ip),
            port: 18080,
            direction,
        }
    }

    struct Rig {
        hub: Hub,
        posts: Arc<Mutex<VecDeque<Post>>>,
        clock: ManualClock,
    }

    fn rig() -> Rig {
        let posts = Arc::new(Mutex::new(VecDeque::new()));
        let clock = ManualClock::new(Tick::new(1));
        let hub = Hub::new(
            Sockets::new(),
            InboundCeiling::Bounded(8),
            queue_poster(&posts),
            Arc::new(clock.clone()),
        );
        Rig { hub, posts, clock }
    }

    fn queue_poster(queue: &Arc<Mutex<VecDeque<Post>>>) -> Arc<dyn Fn(Post) + Send + Sync> {
        let queue = Arc::clone(queue);
        Arc::new(move |post| {
            queue.lock().expect("posts").push_back(post);
        })
    }

    fn doc_ip() -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, 10)
    }

    struct Opened {
        id: shekyl_transport_layer::SocketId,
        inbound: FrameSender,
        writer: shekyl_capped_stream::ByteQueue,
        _hold: shekyl_capped_stream::QueueHold,
        session: Option<shekyl_capped_stream::Session>,
    }

    fn adopt(rig: &Rig, direction: Direction, cap: usize) -> Opened {
        let ends = StreamEnds::open(cap);
        let inbound = ends.inbound.clone();
        let writer = ends.writer_queue.clone();
        let hold = ends.hold;
        let endpoint = endpoint(doc_ip(), direction);
        let now = rig.clock.now();
        let ceiling = rig.hub.lock().ceiling;
        let sockets = rig.hub.lock().sockets.clone();
        let open = admit(&sockets, &endpoint, now, ceiling).expect("admit");
        let attached = rig.hub.adopt(open, ends.session, endpoint).expect("adopt");
        Opened {
            id: attached.id,
            inbound,
            writer,
            _hold: hold,
            session: Some(attached.session),
        }
    }

    fn service(rig: &Rig, accepted: bool) {
        let next = rig.posts.lock().expect("posts").pop_front();
        let Some(post) = next else {
            return;
        };
        match post {
            Post::Established { id, .. } => rig.hub.handler_armed(id, true),
            Post::Deliver { id, .. } => rig.hub.delivery_finished(id, accepted),
            Post::Closed { id, .. } => {
                rig.hub.handler_gone(id);
                rig.hub.reap(id);
            }
        }
    }

    #[test]
    fn a_delivery_posted_before_closed_is_parsed() {
        let rig = rig();
        let mut opened = adopt(&rig, Direction::Outbound, 32);
        service(&rig, true);
        let session = opened.session.take().expect("session");
        let hub = rig.hub.clone();
        let id = opened.id;
        let pump = thread::spawn(move || drive_inbound(&hub, id, session));
        opened
            .inbound
            .blocking_send(b"hello".to_vec())
            .expect("inject");
        let before = 0;
        assert!(rig.hub.wait_delivery_posted(id, before));
        rig.hub.close(id);
        let kinds: Vec<_> = rig
            .posts
            .lock()
            .expect("posts")
            .iter()
            .map(|post| match post {
                Post::Deliver { .. } => Phase::Delivering,
                Post::Closed { .. } => Phase::Closed,
                Post::Established { .. } => Phase::Arming,
            })
            .collect();
        assert_eq!(kinds, vec![Phase::Delivering, Phase::Closed]);
        service(&rig, true);
        service(&rig, true);
        pump.join().expect("pump");
        assert!(rig.hub.cause(id).is_none());
    }

    #[test]
    fn send_after_close_keeps_the_first_cause() {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 32);
        rig.hub.close(opened.id);
        assert!(!rig.hub.send(opened.id, b"more".to_vec()));
        rig.hub.close(opened.id);
        assert_eq!(
            rig.hub.cause(opened.id).map(CloseCause::kind),
            Some(CloseKind::LocalClose)
        );
    }

    #[test]
    fn a_message_that_does_not_fit_is_send_queue_full() {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 4);
        assert!(rig.hub.send(opened.id, b"ab".to_vec()));
        assert!(!rig.hub.send(opened.id, b"cdef".to_vec()));
        assert_eq!(
            rig.hub.cause(opened.id).map(CloseCause::kind),
            Some(CloseKind::SendQueueFull)
        );
        rig.hub.delivery_finished(opened.id, false);
        assert_eq!(
            rig.hub.cause(opened.id).map(CloseCause::kind),
            Some(CloseKind::SendQueueFull)
        );
    }

    #[test]
    fn a_refused_delivery_is_session_refused() {
        let rig = rig();
        let mut opened = adopt(&rig, Direction::Inbound, 32);
        service(&rig, true);
        let session = opened.session.take().expect("session");
        let hub = rig.hub.clone();
        let id = opened.id;
        let pump = thread::spawn(move || drive_inbound(&hub, id, session));
        opened
            .inbound
            .blocking_send(b"no".to_vec())
            .expect("inject");
        assert!(rig.hub.wait_delivery_posted(id, 0));
        service(&rig, false);
        pump.join().expect("pump");
        assert_eq!(
            rig.hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::SessionRefused)
        );
    }

    #[test]
    fn socket_count_is_outbound_and_inbound_held_leaves_it_out() {
        let rig = rig();
        let _opened = adopt(&rig, Direction::Outbound, 32);
        assert_eq!(
            rig.hub
                .socket_count(ConnectorId::Clearnet, Direction::Outbound),
            1
        );
        assert_eq!(rig.hub.inbound_held(), 0);
    }

    #[test]
    fn a_zero_ceiling_refuses_inbound() {
        let rig = rig();
        rig.hub.set_ceiling(InboundCeiling::Bounded(0));
        let ends = StreamEnds::open(32);
        let endpoint = endpoint(doc_ip(), Direction::Inbound);
        let now = rig.clock.now();
        let err = admit(
            &rig.hub.lock().sockets,
            &endpoint,
            now,
            InboundCeiling::Bounded(0),
        )
        .expect_err("ceiling");
        assert_eq!(err.kind(), CloseKind::AdmissionRefused);
        drop(ends);
    }

    #[test]
    fn replacing_the_dialer_joins_the_pump_and_the_next_hub_keeps_the_id() {
        let sockets = Sockets::new();
        let posts = Arc::new(Mutex::new(VecDeque::new()));
        let clock = ManualClock::new(Tick::new(1));
        let first = Hub::new(
            sockets.clone(),
            InboundCeiling::Bounded(8),
            queue_poster(&posts),
            Arc::new(clock.clone()),
        );
        first.install_loopback(32);
        let endpoint = endpoint(doc_ip(), Direction::Outbound);
        let attached = first.connect(&endpoint).expect("open");
        let id = attached.id;
        let hub = first.clone();
        let pump = thread::spawn(move || drive_inbound(&hub, id, attached.session));
        first.track_pump(id, pump);
        first.install_loopback(32);
        first.shutdown();
        assert!(first.cause(id).is_none());
        let second = Hub::new(
            sockets,
            InboundCeiling::Bounded(8),
            queue_poster(&posts),
            Arc::new(clock),
        );
        second.install_loopback(32);
        let again = second.connect(&endpoint).expect("next id");
        assert_ne!(again.id, id);
        drop(again);
        second.shutdown();
    }

    #[test]
    fn a_banned_clearnet_host_is_admission_refused_until_the_deadline() {
        let rig = rig();
        rig.hub.install_loopback(32);
        let endpoint = endpoint(doc_ip(), Direction::Outbound);
        let first = rig.hub.connect(&endpoint).expect("open");
        let closed = rig.hub.ban_host(IpAddr::V4(doc_ip()), Tick::new(50));
        assert_eq!(closed, vec![first.id]);
        drop(first);
        let Err(banned) = rig.hub.connect(&endpoint) else {
            panic!("a banned host was admitted");
        };
        assert_eq!(banned.kind(), CloseKind::AdmissionRefused);
        rig.clock.set(Tick::new(50));
        let again = rig.hub.connect(&endpoint).expect("expired");
        drop(again);
    }

    #[test]
    fn a_transport_close_does_not_ban_the_host() {
        let host = doc_ip();
        for kind in CloseKind::ALL {
            let rig = rig();
            let opened = adopt(&rig, Direction::Outbound, 32);
            let cause = if *kind == CloseKind::ProxyRefused {
                CloseCause::proxy_refused(1)
            } else {
                CloseCause::new(*kind)
            };
            assert!(matches!(
                rig.hub.finish(opened.id, cause),
                CloseResult::Recorded(_)
            ));
            assert!(
                !rig.hub.is_banned(IpAddr::V4(host)),
                "{kind:?} banned the host"
            );
        }
    }

    #[test]
    fn established_carries_the_endpoint() {
        let rig = rig();
        let _opened = adopt(&rig, Direction::Outbound, 32);
        let post = rig.posts.lock().expect("posts").pop_front().expect("post");
        let Post::Established {
            endpoint: observed, ..
        } = post
        else {
            panic!("established is the first post");
        };
        assert_eq!(observed, endpoint(doc_ip(), Direction::Outbound));
    }

    #[test]
    fn send_is_readable_by_the_connector_writer() {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 32);
        assert!(rig.hub.send(opened.id, b"hello".to_vec()));
        let bytes = opened.writer.try_pop().expect("queued");
        opened.writer.release(bytes.len());
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn a_failed_arm_unblocks_the_waiter() {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 32);
        let hub = rig.hub.clone();
        let id = opened.id;
        let waiter = thread::spawn(move || hub.await_armed(id));
        let post = rig.posts.lock().expect("posts").pop_front().expect("post");
        let Post::Established { id, .. } = post else {
            panic!("established");
        };
        rig.hub.handler_armed(id, false);
        assert!(!waiter.join().expect("waiter"));
        assert_eq!(
            rig.hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::LocalClose)
        );
    }

    #[test]
    fn reap_forgets_the_row() {
        let rig = rig();
        let opened = adopt(&rig, Direction::Outbound, 32);
        rig.hub.close(opened.id);
        rig.hub.reap(opened.id);
        assert!(rig.hub.cause(opened.id).is_none());
        assert!(!rig.hub.send(opened.id, b"late".to_vec()));
    }

    #[test]
    fn connect_without_a_dialer_is_dial_failed() {
        let rig = rig();
        let Err(err) = rig.hub.connect(&endpoint(doc_ip(), Direction::Outbound)) else {
            panic!("connect without a dialer admitted a channel");
        };
        assert_eq!(err.kind(), CloseKind::DialFailed);
    }
}
