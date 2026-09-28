// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seam between a connector and the Levin handler.
//!
//! The admission [`SocketId`] is the only id that crosses. Rust holds the
//! socket and the byte cap. C++ holds the handler. This crate records the
//! cause and asks the caller to post `established`, `deliver`, and
//! `closed` onto that connection's strand. It does not run the strand.
//!
//! A `send` is one whole Levin message. A message that does not fit the
//! cap is not stored, and the cause is [`CloseKind::SendQueueFull`].
//! A later refusal from `handle_recv` does not replace that cause.

#![deny(unsafe_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;

use shekyl_capped_stream::StreamEnds;
use shekyl_peer_policy::InboundCeiling;
use shekyl_thread_ledger::{BlockingLanes, ExecutorBudget, ExecutorBudgetError};
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{
    CloseCause, CloseKind, CloseResult, ConnectorId, Direction, NetworkAddress, SocketId, Sockets,
};

/// `epee::net_utils::address_type`. The peer-exchange union uses these tags.
pub const ADDR_IPV4: u8 = 1;
pub const ADDR_IPV6: u8 = 2;
pub const ADDR_I2P: u8 = 3;
pub const ADDR_TOR: u8 = 4;

/// Host bytes, not counting a trailing NUL. Tor's buffer holds 62.
pub const HOST_MAX: usize = 62;

/// What `established` tells the adapter to write into the connection context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// Clearnet or Tor.
    pub connector: ConnectorId,
    /// Inbound or outbound.
    pub direction: Direction,
    /// [`ADDR_IPV4`], [`ADDR_IPV6`], [`ADDR_I2P`], or [`ADDR_TOR`].
    pub address_type: u8,
    /// Tor or I2P inbound with no peer address. The adapter writes `unknown()`.
    pub zone_only: bool,
    /// The port the union carries. Unused when `zone_only` is set.
    pub port: u16,
    /// Address octets or host bytes. Empty when `zone_only` is set.
    pub bytes: Vec<u8>,
}

/// What the strand is asked to run. The bytes and the cause are copies.
/// The post returns before the strand runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    /// The admission id.
    pub id: SocketId,
    /// Which handler call.
    pub kind: PostKind,
    /// `Deliver` carries the message. The other kinds carry nothing.
    pub bytes: Vec<u8>,
    /// `Closed` carries the cause that won. The other kinds carry none.
    pub cause: Option<CloseCause>,
    /// `Established` carries the endpoint the adapter writes before `arm`.
    pub observed: Option<Observed>,
}

/// The three posts onto one connection's strand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PostKind {
    /// Create the handler. The channel already exists.
    Established = 1,
    /// One delivery. The handler parses these bytes.
    Deliver = 2,
    /// The socket is gone. Destroy the handler when its call count is zero.
    Closed = 3,
}

/// One seam. Clones share the table.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Mutex<Inner>>,
    ready: Arc<Condvar>,
    post: Arc<dyn Fn(Post) + Send + Sync>,
    send_cap: usize,
}

struct Inner {
    sockets: Sockets,
    conns: std::collections::HashMap<SocketId, Conn>,
}

struct Conn {
    open: Option<shekyl_transport_layer::OpenSocket>,
    ends: Option<StreamEnds>,
    cause: Option<CloseCause>,
    /// A deliver is on the strand and has not returned.
    delivering: bool,
    /// The strand has run `established`.
    handler_ready: bool,
    /// `closed` has started on the strand. A later deliver is the guard.
    handler_gone: bool,
    /// Bytes `deliver_result` accepted, in order. The test reads this.
    parsed: Vec<u8>,
    /// Filled into the context when the strand runs `established`.
    observed: Observed,
}

impl Hub {
    /// `send_cap` is the outbound byte cap for each connection.
    /// `post` enqueues onto that connection's strand and returns.
    #[must_use]
    pub fn new(send_cap: usize, post: Arc<dyn Fn(Post) + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                sockets: Sockets::new(),
                conns: std::collections::HashMap::new(),
            })),
            ready: Arc::new(Condvar::new()),
            post,
            send_cap,
        }
    }

    /// The socket table. Ban-list and count reads use this.
    #[must_use]
    pub fn sockets(&self) -> Sockets {
        self.lock().sockets.clone()
    }

    /// Reserve a socket for `peer` and remember the endpoint `established` posts.
    ///
    /// Refusal is a D12 cause. Nothing is reserved in that case.
    pub fn open(&self, peer: &Peer) -> Result<SocketId, CloseCause> {
        let observed = peer.observed()?;
        let mut inner = self.lock();
        let open = admit(&inner.sockets, peer)?;
        let id = open.id();
        inner.conns.insert(
            id,
            Conn {
                open: Some(open),
                ends: Some(StreamEnds::open(self.send_cap)),
                cause: None,
                delivering: false,
                handler_ready: false,
                handler_gone: false,
                parsed: Vec::new(),
                observed,
            },
        );
        Ok(id)
    }

    /// Post `established` and wait until the strand has built the handler.
    ///
    /// The waiter holds no lock the strand needs. An executor thread may
    /// call this only when another executor thread is free to run the post.
    pub fn await_handler(&self, id: SocketId) -> bool {
        let post = {
            let inner = self.lock();
            if !inner.conns.contains_key(&id) {
                return false;
            }
            Post {
                id,
                kind: PostKind::Established,
                bytes: Vec::new(),
                cause: None,
                observed: Some(inner.conns[&id].observed.clone()),
            }
        };
        (self.post)(post);
        let mut inner = self.lock();
        loop {
            let Some(conn) = inner.conns.get(&id) else {
                return false;
            };
            if conn.handler_ready {
                return true;
            }
            if conn.cause.is_some() {
                return false;
            }
            inner = self
                .ready
                .wait(inner)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// The strand finished `established`.
    pub fn handler_ready(&self, id: SocketId) {
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            conn.handler_ready = true;
        }
        self.ready.notify_all();
    }

    /// Post one delivery when none is in flight.
    ///
    /// `false` means the id is gone, the handler is already gone, or a
    /// delivery is still on the strand. The bytes are not posted.
    pub fn deliver(&self, id: SocketId, bytes: &[u8]) -> bool {
        let post = {
            let mut inner = self.lock();
            let Some(conn) = inner.conns.get_mut(&id) else {
                return false;
            };
            if conn.handler_gone || conn.cause.is_some() || conn.delivering {
                return false;
            }
            conn.delivering = true;
            Post {
                id,
                kind: PostKind::Deliver,
                bytes: bytes.to_vec(),
                cause: None,
                observed: None,
            }
        };
        (self.post)(post);
        true
    }

    /// The strand finished `handle_recv`.
    ///
    /// A handler that is already gone refuses the bytes and records
    /// nothing: that is the guard for a post that escaped the strand.
    /// A false return records [`CloseKind::SessionRefused`] only when
    /// no cause is recorded yet.
    pub fn deliver_result(&self, id: SocketId, bytes: &[u8], accepted: bool) -> bool {
        let mut inner = self.lock();
        let Some(conn) = inner.conns.get_mut(&id) else {
            return false;
        };
        conn.delivering = false;
        if conn.handler_gone {
            return false;
        }
        if !accepted {
            drop(inner);
            let _ = self.record(id, CloseCause::new(CloseKind::SessionRefused));
            return true;
        }
        conn.parsed.extend_from_slice(bytes);
        true
    }

    /// Bytes the handler accepted, in order.
    #[must_use]
    pub fn parsed(&self, id: SocketId) -> Option<Vec<u8>> {
        self.lock().conns.get(&id).map(|conn| conn.parsed.clone())
    }

    /// One whole message. A buffer that does not fit is not stored.
    ///
    /// [`CloseKind::SendQueueFull`] is recorded before this returns, so a
    /// following `handle_recv` false return finds the id already closed.
    pub fn send(&self, id: SocketId, bytes: Vec<u8>) -> bool {
        {
            let mut inner = self.lock();
            let Some(conn) = inner.conns.get_mut(&id) else {
                return false;
            };
            if conn.cause.is_some() {
                return false;
            }
            let Some(ends) = conn.ends.as_ref() else {
                return false;
            };
            match ends.session.try_send(bytes) {
                Ok(()) => return true,
                Err(CloseKind::SendQueueFull) => {}
                Err(_) => return false,
            }
        }
        let _ = self.record(id, CloseCause::new(CloseKind::SendQueueFull));
        false
    }

    /// Record [`CloseKind::LocalClose`] when no cause is recorded yet,
    /// drop the socket, and post `closed`.
    pub fn close(&self, id: SocketId) {
        let _ = self.record(id, CloseCause::new(CloseKind::LocalClose));
    }

    /// The strand has started `closed`. Further delivers are the guard.
    pub fn handler_gone(&self, id: SocketId) {
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&id) {
            conn.handler_gone = true;
        }
    }

    /// The cause that won, if the connection has closed.
    #[must_use]
    pub fn cause(&self, id: SocketId) -> Option<CloseCause> {
        self.lock().conns.get(&id).and_then(|conn| conn.cause)
    }

    /// The id the table minted, looked up from the raw value that crossed
    /// the FFI. Zero is not an id. An unknown value is `None`.
    #[must_use]
    pub fn id_of(&self, raw: u64) -> Option<SocketId> {
        if raw == 0 {
            return None;
        }
        self.lock().conns.keys().copied().find(|id| id.get() == raw)
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

    fn record(&self, id: SocketId, cause: CloseCause) -> CloseResult {
        let result = {
            let mut inner = self.lock();
            let Some(conn) = inner.conns.get_mut(&id) else {
                return CloseResult::AlreadyClosed;
            };
            if conn.cause.is_some() {
                return CloseResult::AlreadyClosed;
            }
            conn.cause = Some(cause);
            conn.ends.take();
            match conn.open.take() {
                Some(open) => open.close(cause),
                None => CloseResult::AlreadyClosed,
            }
        };
        if matches!(result, CloseResult::Recorded(_)) {
            (self.post)(Post {
                id,
                kind: PostKind::Closed,
                bytes: Vec::new(),
                cause: Some(cause),
                observed: None,
            });
            self.ready.notify_all();
        }
        result
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("seam table lock poisoned")
    }
}

/// A peer the seam may reserve a socket for.
///
/// `address_type` is the peer-exchange tag. `bytes` are the octets or the
/// host. `zone_only` is Tor or I2P inbound with no peer address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Clearnet or Tor.
    pub connector: ConnectorId,
    /// Accepted, rather than dialed.
    pub inbound: bool,
    /// [`ADDR_IPV4`], [`ADDR_IPV6`], [`ADDR_I2P`], or [`ADDR_TOR`].
    pub address_type: u8,
    /// No peer address. The adapter writes `unknown()`.
    pub zone_only: bool,
    /// Port. Unused when `zone_only` is set.
    pub port: u16,
    /// Address octets or host bytes.
    pub bytes: Vec<u8>,
}

impl Peer {
    fn observed(&self) -> Result<Observed, CloseCause> {
        if self.bytes.len() > HOST_MAX {
            return Err(CloseCause::new(CloseKind::DialFailed));
        }
        Ok(Observed {
            connector: self.connector,
            direction: if self.inbound {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
            address_type: self.address_type,
            zone_only: self.zone_only,
            port: self.port,
            bytes: self.bytes.clone(),
        })
    }
}

fn admit(sockets: &Sockets, peer: &Peer) -> Result<shekyl_transport_layer::OpenSocket, CloseCause> {
    let now = Tick::new(1);
    let ceiling = InboundCeiling::Bounded(1024);
    let opened = match (
        peer.connector,
        peer.address_type,
        peer.inbound,
        peer.zone_only,
    ) {
        (ConnectorId::Clearnet, ADDR_IPV4, false, false) => {
            let ip = ipv4(peer)?;
            sockets.open_clearnet(IpAddr::V4(ip), now)
        }
        (ConnectorId::Clearnet, ADDR_IPV4, true, false) => {
            let ip = ipv4(peer)?;
            sockets.accept_clearnet(IpAddr::V4(ip), ceiling, now)
        }
        (ConnectorId::Clearnet, ADDR_IPV6, false, false) => {
            let ip = ipv6(peer)?;
            sockets.open_clearnet(IpAddr::V6(ip), now)
        }
        (ConnectorId::Clearnet, ADDR_IPV6, true, false) => {
            let ip = ipv6(peer)?;
            sockets.accept_clearnet(IpAddr::V6(ip), ceiling, now)
        }
        (ConnectorId::Tor, ADDR_TOR, true, true) => sockets.accept_tor(ceiling),
        (ConnectorId::Tor, ADDR_TOR, false, false) => {
            let host = host(peer)?;
            sockets.open_tor(&NetworkAddress::Tor {
                host,
                port: peer.port,
            })
        }
        _ => return Err(CloseCause::new(CloseKind::DialFailed)),
    };
    match opened {
        Ok(open) => Ok(open),
        Err(shekyl_transport_layer::OpenError::Refused(cause)) => Err(cause),
        Err(shekyl_transport_layer::OpenError::Exhausted) => {
            Err(CloseCause::new(CloseKind::AdmissionRefused))
        }
    }
}

fn ipv4(peer: &Peer) -> Result<Ipv4Addr, CloseCause> {
    let bytes: [u8; 4] = peer
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| CloseCause::new(CloseKind::DialFailed))?;
    Ok(Ipv4Addr::from(bytes))
}

fn ipv6(peer: &Peer) -> Result<Ipv6Addr, CloseCause> {
    let bytes: [u8; 16] = peer
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| CloseCause::new(CloseKind::DialFailed))?;
    Ok(Ipv6Addr::from(bytes))
}

fn host(peer: &Peer) -> Result<String, CloseCause> {
    if peer.bytes.is_empty() {
        return Err(CloseCause::new(CloseKind::DialFailed));
    }
    String::from_utf8(peer.bytes.clone()).map_err(|_| CloseCause::new(CloseKind::DialFailed))
}

/// The floor the seam's executor uses while `idle_worker` blocks on it.
///
/// One lane, so the pool needs two workers. A count below that does not
/// start. This is the same check [`ExecutorBudget::above_floor`] owns.
pub fn executor_floor(
    lanes: BlockingLanes,
    workers: usize,
) -> Result<ExecutorBudget, ExecutorBudgetError> {
    ExecutorBudget::above_floor(lanes, workers)
}

/// Run queued posts in the order they were posted. This is what one
/// strand guarantees. The test uses it so a delivery posted before
/// `closed` is parsed, and so running `closed` first takes the guard.
pub fn run_in_post_order(hub: &Hub, posts: &Mutex<VecDeque<Post>>) {
    loop {
        let next = posts.lock().expect("post queue").pop_front();
        let Some(post) = next else {
            return;
        };
        match post.kind {
            PostKind::Established => hub.handler_ready(post.id),
            PostKind::Deliver => {
                let accepted = hub.deliver_result(post.id, &post.bytes, true);
                assert!(accepted, "a delivery posted before closed is parsed");
            }
            PostKind::Closed => hub.handler_gone(post.id),
        }
    }
}

/// A poster that queues. The test drains it with [`run_in_post_order`].
#[must_use]
pub fn queue_poster(queue: &Arc<Mutex<VecDeque<Post>>>) -> Arc<dyn Fn(Post) + Send + Sync> {
    let queue = Arc::clone(queue);
    Arc::new(move |post| {
        queue.lock().expect("post queue").push_back(post);
    })
}

/// Spawn a thread that waits for the handler, and a thread that runs the
/// posts. Both finish. This is the floor of two: the waiter is not the
/// thread that runs the strand.
pub fn await_handler_on_two_threads(
    hub: &Hub,
    id: SocketId,
    posts: &Arc<Mutex<VecDeque<Post>>>,
) -> bool {
    let runner = {
        let hub = hub.clone();
        let posts = Arc::clone(posts);
        thread::spawn(move || {
            // The waiter posts established before it blocks. Spin until
            // that post is visible, then run the queue.
            while posts.lock().expect("post queue").is_empty() {
                thread::yield_now();
            }
            run_in_post_order(&hub, &posts);
        })
    };
    let waited = hub.await_handler(id);
    runner.join().expect("strand thread");
    waited
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clearnet(ip: Ipv4Addr) -> Peer {
        Peer {
            connector: ConnectorId::Clearnet,
            inbound: false,
            address_type: ADDR_IPV4,
            zone_only: false,
            port: 18080,
            bytes: ip.octets().to_vec(),
        }
    }

    fn hub(cap: usize) -> (Hub, Arc<Mutex<VecDeque<Post>>>) {
        let posts = Arc::new(Mutex::new(VecDeque::new()));
        let hub = Hub::new(cap, queue_poster(&posts));
        (hub, posts)
    }

    #[test]
    fn a_delivery_posted_before_closed_is_parsed() {
        let (hub, posts) = hub(32);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        assert!(hub.deliver(id, b"hello"));
        hub.close(id);
        run_in_post_order(&hub, &posts);
        assert_eq!(hub.parsed(id).as_deref(), Some(b"hello".as_slice()));
        assert_eq!(
            hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::LocalClose)
        );
    }

    #[test]
    fn a_delivery_after_the_handler_is_gone_is_the_guard() {
        let (hub, _posts) = hub(32);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        hub.handler_gone(id);
        assert!(!hub.deliver_result(id, b"late", true));
        assert_eq!(hub.parsed(id).as_deref(), Some(b"".as_slice()));
    }

    #[test]
    fn send_after_close_returns_false_and_keeps_the_cause() {
        let (hub, posts) = hub(32);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        hub.close(id);
        assert!(!hub.send(id, b"more".to_vec()));
        assert_eq!(
            hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::LocalClose)
        );
        let _ = posts;
    }

    #[test]
    fn a_message_that_does_not_fit_is_send_queue_full_and_the_false_recv_leaves_it() {
        let (hub, _posts) = hub(4);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        assert!(hub.send(id, b"ab".to_vec()));
        assert!(!hub.send(id, b"cdef".to_vec()));
        assert_eq!(
            hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::SendQueueFull)
        );
        assert!(hub.deliver_result(id, b"", false));
        assert_eq!(
            hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::SendQueueFull)
        );
    }

    #[test]
    fn two_closes_keep_the_first_cause() {
        let (hub, _posts) = hub(32);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        hub.close(id);
        hub.close(id);
        assert_eq!(
            hub.cause(id).map(CloseCause::kind),
            Some(CloseKind::LocalClose)
        );
    }

    #[test]
    fn the_executor_accepts_the_floor_and_refuses_one_below_it() {
        let lanes = BlockingLanes::new(1);
        assert!(matches!(
            executor_floor(lanes, 1),
            Err(ExecutorBudgetError::BelowFloor { floor: 2, .. })
        ));
        assert_eq!(executor_floor(lanes, 2).expect("floor").workers().get(), 2);
    }

    #[test]
    fn await_handler_finishes_when_another_thread_runs_the_post() {
        let (hub, posts) = hub(32);
        let id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        assert!(await_handler_on_two_threads(&hub, id, &posts));
    }

    #[test]
    fn socket_count_is_the_open_outbound_and_inbound_held_leaves_it_out() {
        let (hub, _posts) = hub(32);
        let _id = hub
            .open(&clearnet(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("open");
        assert_eq!(
            hub.socket_count(ConnectorId::Clearnet, Direction::Outbound),
            1
        );
        assert_eq!(hub.inbound_held(), 0);
    }

    #[test]
    fn a_clearnet_open_refuses_a_tor_address_with_dial_failed() {
        let (hub, _posts) = hub(32);
        let err = hub
            .open(&Peer {
                connector: ConnectorId::Clearnet,
                inbound: false,
                address_type: ADDR_TOR,
                zone_only: false,
                port: 18080,
                bytes: b"example.onion".to_vec(),
            })
            .expect_err("not a clearnet address");
        assert_eq!(err.kind(), CloseKind::DialFailed);
    }

    #[test]
    fn a_banned_clearnet_host_is_admission_refused() {
        let (hub, _posts) = hub(32);
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let _closed = hub
            .sockets()
            .ban_host(IpAddr::V4(ip), Tick::new(50), Tick::new(1));
        let err = hub.open(&clearnet(ip)).expect_err("banned");
        assert_eq!(err.kind(), CloseKind::AdmissionRefused);
    }

    #[test]
    fn established_carries_the_observed_endpoint() {
        let (hub, posts) = hub(32);
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let id = hub.open(&clearnet(ip)).expect("open");
        assert!(await_handler_on_two_threads(&hub, id, &posts));
        let observed = hub
            .lock()
            .conns
            .get(&id)
            .map(|conn| conn.observed.clone())
            .expect("connection");
        assert_eq!(observed.connector, ConnectorId::Clearnet);
        assert_eq!(observed.direction, Direction::Outbound);
        assert_eq!(observed.address_type, ADDR_IPV4);
        assert_eq!(observed.bytes, ip.octets());
        assert!(!observed.zone_only);
    }
}
