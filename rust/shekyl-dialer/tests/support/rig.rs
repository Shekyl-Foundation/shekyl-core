// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's test rig: the session layer over the harness's in-memory
//! peer, on a manual clock, with the dialer attached as its peers owner
//! and a recorder standing in for the sync and relay owners.
//!
//! The tests are threads, as the daemon's owner loops are. The session
//! layer's tasks run on a runtime the rig holds; the test plays the far
//! side through the [`Wire`] each dial or accept hands it.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    GetTxpoolComplement, HandshakeRequest, NewTransactions, PeerlistEntry, PortableMap, Received,
};
use shekyl_p2p_session::harness::{self, Loopback, Wire};
use shekyl_p2p_session::{
    Channel, ClaimCarrier, Command, ConnectFuture, CoreSyncData, Dial, Endpoint, Established,
    Intervals, Owners, Parts, PerConnector, ProbeArrival, ProbeSink, RelayOwner, SessionConfig,
    SessionFacts, SessionLayer, SyncInbound, SyncOwner, Taken,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, NetworkAddress, RefusedSet, Tick};
use shekyl_timing_engine::{Clock, EngineService, Handle, ManualClock};
use shekyl_transport_layer::{
    DialEnd, DialFailure, Links, Route, RoutePublish, SocketId, Sockets, StreamEnd,
};
use tokio::sync::{mpsc, watch};

pub const NETWORK: [u8; 16] = [7; 16];
pub const OTHER_NETWORK: [u8; 16] = [9; 16];
pub const SEND_CAP: usize = 64 * 1024;
pub const CEILING: InboundCeiling = InboundCeiling::Bounded(64);
/// How long a test waits for anything before it fails.
pub const WAIT: Duration = Duration::from_secs(5);

/// This node's tip, as the rig publishes it.
pub fn our_tip() -> CoreSyncData {
    CoreSyncData {
        current_height: 10,
        cumulative_difficulty: 100,
        cumulative_difficulty_top64: 0,
        top_id: [1; 32],
    }
}

/// A peer's tip at `height`.
pub fn peer_tip(height: u64) -> CoreSyncData {
    CoreSyncData {
        current_height: height,
        cumulative_difficulty: 200,
        cumulative_difficulty_top64: 0,
        top_id: [2; 32],
    }
}

/// A peer's handshake response on `network_id` disclosing `peers`, at
/// height 20.
pub fn reply(network_id: [u8; 16], peers: Vec<NetworkAddress>) -> Vec<u8> {
    reply_at(network_id, peers, 20)
}

/// [`reply`] at `height`.
pub fn reply_at(network_id: [u8; 16], peers: Vec<NetworkAddress>, height: u64) -> Vec<u8> {
    harness::handshake_response(
        network_id,
        peers.into_iter().map(|adr| PeerlistEntry { adr }).collect(),
        peer_tip(height),
    )
}

/// A peer's handshake request carrying `nonce`.
pub fn request(network_id: [u8; 16], nonce: [u8; 32]) -> Vec<u8> {
    harness::handshake_request(network_id, nonce, peer_tip(20))
}

/// A clearnet peer in the test range.
pub fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 12, 0, n),
        port: 18080,
    }
}

/// Poll `condition` until it holds, or fail after [`WAIT`].
pub fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < WAIT, "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// What the sync and relay owners were told, in order.
#[derive(Debug)]
pub enum Told {
    Established(SocketId),
    Closed(SocketId, DialEnd),
    Claim(SocketId, u64, ClaimCarrier),
    Sync(SocketId, Command),
    Relay(SocketId, usize),
    Complement(SocketId, usize),
    Probe(ProbeArrival),
}

/// Stands in for the sync and relay owners and the probe sink.
#[derive(Default)]
pub struct Recorder {
    told: Mutex<Vec<Told>>,
}

impl Recorder {
    fn note(&self, told: Told) {
        self.told.lock().expect("recorder").push(told);
    }

    /// Everything told so far, taken.
    pub fn take(&self) -> Vec<Told> {
        std::mem::take(&mut *self.told.lock().expect("recorder"))
    }

    /// Whether the sync owner was told `id` closed. The peers owner is
    /// told first, so this is also the dialer having seen the close.
    pub fn was_told_closed(&self, id: SocketId) -> bool {
        self.told
            .lock()
            .expect("recorder")
            .iter()
            .any(|told| matches!(told, Told::Closed(told_id, _) if *told_id == id))
    }

    /// Whether the sync owner was told `id` is established.
    pub fn was_told_established(&self, id: SocketId) -> bool {
        self.told
            .lock()
            .expect("recorder")
            .iter()
            .any(|told| matches!(told, Told::Established(told_id) if *told_id == id))
    }

    /// The height the sync owner was handed for `id`'s handshake, if any.
    pub fn handshake_height(&self, id: SocketId) -> Option<u64> {
        self.told
            .lock()
            .expect("recorder")
            .iter()
            .find_map(|told| match told {
                Told::Claim(told_id, height, ClaimCarrier::Handshake) if *told_id == id => {
                    Some(*height)
                }
                _ => None,
            })
    }
}

impl SyncOwner for Recorder {
    fn claim(
        &self,
        session: &Established,
        sync: CoreSyncData,
        carrier: ClaimCarrier,
        _taken: Taken,
    ) {
        self.note(Told::Claim(session.id(), sync.current_height, carrier));
    }

    fn message(&self, session: &Established, message: SyncInbound, _taken: Taken) {
        self.note(Told::Sync(session.id(), message.command()));
    }

    fn on_established(&self, session: &Established) {
        self.note(Told::Established(session.id()));
    }

    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.note(Told::Closed(facts.id, end));
    }
}

impl RelayOwner for Recorder {
    fn new_transactions(&self, session: &Established, batch: NewTransactions, _taken: Taken) {
        self.note(Told::Relay(session.id(), batch.txs.len()));
    }

    fn txpool_complement(
        &self,
        session: &Established,
        request: GetTxpoolComplement,
        _taken: Taken,
    ) {
        self.note(Told::Complement(session.id(), request.hashes.len()));
    }
}

impl ProbeSink for Recorder {
    fn probe_arrived(&self, arrival: ProbeArrival) {
        self.note(Told::Probe(arrival));
    }
}

/// How the peer answers the next dial.
#[derive(Clone)]
pub enum Answer {
    /// Admit and build a channel; the wire goes to the test.
    Connect,
    /// Connect, and the far side closes as soon as the channel is open.
    PeerCloses,
    /// Connect, and the far side has this frame waiting in the channel
    /// before the dial returns: a handshake answered without the test
    /// playing the peer.
    Answered(Vec<u8>),
    /// Refuse with this end before any I/O, after `took` on the clock.
    Refuse(DialEnd, Duration),
    /// A connect that never resolves, counted while it is alive.
    Stall,
}

/// A connect that never resolves, counted while it is alive.
struct Stalled {
    alive: Arc<AtomicUsize>,
}

impl Future for Stalled {
    type Output = Result<Channel, DialEnd>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        self.alive.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The far side: the harness's loopback, answering as the test queued.
pub struct Peer {
    loopback: Arc<Loopback>,
    dialed: Mutex<mpsc::UnboundedReceiver<Wire>>,
    wires: mpsc::UnboundedSender<Wire>,
    answers: Mutex<VecDeque<Answer>>,
    /// With nothing queued: this answer, or connect.
    fallback: Mutex<Option<Answer>>,
    clock: ManualClock,
    /// Every connect, refused or not.
    pub connects: AtomicUsize,
    /// Stalled connects still alive.
    pub stalled_alive: Arc<AtomicUsize>,
}

impl Peer {
    /// Queue how the next dial is answered. With nothing queued, it
    /// connects.
    pub fn answer_next(&self, answer: Answer) {
        self.answers.lock().expect("answers").push_back(answer);
    }

    /// Queue `count` answers.
    pub fn answer_each(&self, count: usize, mut answer: impl FnMut() -> Answer) {
        for _ in 0..count {
            self.answer_next(answer());
        }
    }

    /// The next connect fails with `cause` after `took` on the clock.
    pub fn refuse_after(&self, cause: DialEnd, took: Duration) {
        self.answer_next(Answer::Refuse(cause, took));
    }

    /// From now on a dial with no queued answer is answered with `answer`.
    pub fn answer_unqueued(&self, answer: Answer) {
        *self.fallback.lock().expect("fallback") = Some(answer);
    }

    /// From now on a dial with no queued answer is refused with `end`
    /// before any I/O: no connector is installed.
    pub fn refuse_unqueued(&self, end: DialEnd) {
        self.answer_unqueued(Answer::Refuse(end, Duration::ZERO));
    }

    /// From now on the peer closes each channel as soon as it opens: a
    /// stream that opened, then the peer's end.
    pub fn close_on_open(&self) {
        self.answer_unqueued(Answer::PeerCloses);
    }

    /// Connects made so far.
    pub fn connects(&self) -> usize {
        self.connects.load(Ordering::Acquire)
    }

    /// Start the connect count over.
    pub fn reset_connects(&self) {
        self.connects.store(0, Ordering::Release);
    }
}

impl Dial for Peer {
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture {
        self.connects.fetch_add(1, Ordering::AcqRel);
        let answer = self
            .answers
            .lock()
            .expect("answers")
            .pop_front()
            .unwrap_or_else(|| {
                self.fallback
                    .lock()
                    .expect("fallback")
                    .clone()
                    .unwrap_or(Answer::Connect)
            });
        match answer {
            Answer::Refuse(end, took) => {
                let took = u64::try_from(took.as_nanos()).expect("a short wait");
                self.clock
                    .set(Tick::new(self.clock.now().get().saturating_add(took)));
                Box::pin(std::future::ready(Err(end)))
            }
            Answer::Stall => {
                self.stalled_alive.fetch_add(1, Ordering::AcqRel);
                Box::pin(Stalled {
                    alive: Arc::clone(&self.stalled_alive),
                })
            }
            Answer::Connect | Answer::PeerCloses | Answer::Answered(_) => {
                // The loopback admits and hands the wire over before its
                // future is returned; the future is already resolved.
                let future = self.loopback.connect_async(endpoint);
                let wire = self.dialed.lock().expect("dialed").try_recv().ok();
                let wires = self.wires.clone();
                Box::pin(async move {
                    if let Some(mut wire) = wire {
                        match answer {
                            Answer::PeerCloses => wire.peer_closes(),
                            Answer::Answered(frame) => wire.inject(frame).await,
                            _ => {}
                        }
                        if let Err(_test_gone) = wires.send(wire) {}
                    }
                    future.await
                })
            }
        }
    }

    fn stamp_stream_end(&self, connector: ConnectorId, end: StreamEnd) -> DialFailure {
        super::tables::tables(connector, end)
    }
}

/// What a rig is built with.
pub struct Build {
    pub clock: ManualClock,
    /// The connectors whose link the rig publishes as usable.
    pub routes: Vec<ConnectorId>,
    pub ceiling: InboundCeiling,
    pub send_cap: usize,
    pub handshake_within: Duration,
    pub intervals: Intervals,
    /// Whether the layer is attached to the dialer at build.
    pub attach: bool,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            clock: ManualClock::new(Tick::new(1)),
            routes: vec![ConnectorId::Clearnet, ConnectorId::Tor],
            ceiling: CEILING,
            send_cap: SEND_CAP,
            // The dialer's tests move the clock by cooldowns and dial
            // windows, never by a timed-sync interval: the layer's own
            // timers sit far past anything these tests jump over. A test
            // of those timers sets them.
            handshake_within: Duration::from_secs(24 * 3600),
            intervals: Intervals {
                invoke_timeout: Duration::from_secs(365 * 24 * 3600),
                timed_sync_min: Duration::from_secs(365 * 24 * 3600),
                timed_sync_jitter: Duration::from_secs(1),
            },
            attach: true,
        }
    }
}

impl Build {
    pub fn on(clock: &ManualClock) -> Self {
        Self {
            clock: clock.clone(),
            ..Self::default()
        }
    }

    pub fn routes(mut self, routes: &[ConnectorId]) -> Self {
        self.routes = routes.to_vec();
        self
    }

    pub fn unattached(mut self) -> Self {
        self.attach = false;
        self
    }

    pub fn finish(self) -> Rig {
        Rig::build(self)
    }
}

/// Everything one test holds.
pub struct Rig {
    pub clock: ManualClock,
    pub sockets: Sockets,
    pub links: Arc<Links>,
    pub peer: Arc<Peer>,
    pub layer: SessionLayer<ManualClock>,
    pub dialer: Arc<Dialer<ManualClock>>,
    pub recorder: Arc<Recorder>,
    pub tip: watch::Sender<CoreSyncData>,
    pub timing: Handle<ManualClock>,
    wires: Mutex<mpsc::UnboundedReceiver<Wire>>,
    /// Dialed channels taken from `wires` by [`Self::opened`].
    held: Mutex<Vec<Wire>>,
    engine: EngineService<ManualClock>,
    /// Dropped last: the layer's tasks run on it.
    runtime: tokio::runtime::Runtime,
}

impl Default for Rig {
    fn default() -> Self {
        Self::new()
    }
}

impl Rig {
    /// Both links usable, the layer attached, the clock at tick 1.
    pub fn new() -> Self {
        Self::build(Build::default())
    }

    /// [`Self::new`] on `clock`.
    pub fn on(clock: &ManualClock) -> Self {
        Self::build(Build::on(clock))
    }

    pub fn build(build: Build) -> Self {
        Self::build_with(build, |_sockets| {})
    }

    /// [`Self::build`] after `prepare` has had the admission table: what it
    /// bans is in force when the dialer subscribes.
    pub fn build_with(build: Build, prepare: impl FnOnce(&Sockets)) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the rig's runtime");
        // No accept-rate gate: the loopback admits at a fixed tick.
        let sockets = Sockets::with_clearnet_gate(None);
        prepare(&sockets);
        let links = Arc::new(Links::new());
        for connector in &build.routes {
            // The loopback dials any endpoint itself: every route is direct.
            assert!(
                matches!(
                    links.publish_usable(*connector, Route::Direct, Tick::new(1)),
                    RoutePublish::Installed { .. }
                ),
                "the test route was not already usable"
            );
        }
        let (loopback, dialed) = Loopback::new(sockets.clone(), build.ceiling, build.send_cap);
        let (wires_tx, wires) = mpsc::unbounded_channel();
        let peer = Arc::new(Peer {
            loopback,
            dialed: Mutex::new(dialed),
            wires: wires_tx,
            answers: Mutex::new(VecDeque::new()),
            fallback: Mutex::new(None),
            clock: build.clock.clone(),
            connects: AtomicUsize::new(0),
            stalled_alive: Arc::new(AtomicUsize::new(0)),
        });
        let engine = EngineService::start(build.clock.clone());
        let timing = engine.handle();
        let dialer = Arc::new(Dialer::new(
            timing.clone(),
            Arc::clone(&links),
            &sockets,
            RefusedSet::NON_GLOBAL,
            Box::new(SplitMix64::new(0x5eed)),
        ));
        let recorder = Arc::new(Recorder::default());
        let (tip, tip_rx) = watch::channel(our_tip());
        let layer = SessionLayer::new(Parts {
            sockets: sockets.clone(),
            config: SessionConfig {
                network_id: NETWORK,
                handshake_within: PerConnector::both(build.handshake_within),
                intervals: build.intervals,
            },
            owners: Owners {
                peers: dialer.clone(),
                sync: recorder.clone(),
                relay: recorder.clone(),
                probes: recorder.clone(),
            },
            connectors: peer.clone(),
            timing: timing.clone(),
            tip: tip_rx,
            runtime: runtime.handle().clone(),
            rng: Box::new(SplitMix64::new(0x5eed + 1)),
        });
        if build.attach {
            dialer.attach(layer.clone());
        }
        Self {
            clock: build.clock,
            sockets,
            links,
            peer,
            layer,
            dialer,
            recorder,
            tip,
            timing,
            wires: Mutex::new(wires),
            held: Mutex::new(Vec::new()),
            engine,
            runtime,
        }
    }

    /// Close the timing engine: every owner's wait ends.
    pub fn close_engine(&self) {
        self.engine.close();
    }

    /// The far side of the next dialed channel, waiting up to [`WAIT`].
    ///
    /// # Panics
    /// No dial opened a channel within [`WAIT`].
    pub fn dialed(&self) -> Wire {
        let start = Instant::now();
        loop {
            if let Ok(wire) = self.wires.lock().expect("wires").try_recv() {
                return wire;
            }
            assert!(start.elapsed() < WAIT, "the channel never opened");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// The far side of the next dialed channel, if one has opened.
    pub fn try_dialed(&self) -> Option<Wire> {
        self.wires.lock().expect("wires").try_recv().ok()
    }

    /// Every channel a dial has opened so far, held by the rig and
    /// addressed by id ([`Self::request`], [`Self::answer`],
    /// [`Self::close_as_peer`]), in id order. A held wire stays held after
    /// its session closes: this is what opened, not what is open.
    pub fn opened(&self) -> Vec<SocketId> {
        let mut held = self.held.lock().expect("held");
        while let Ok(wire) = self.wires.lock().expect("wires").try_recv() {
            held.push(wire);
        }
        held.sort_by_key(|wire| wire.id.get());
        held.iter().map(|wire| wire.id).collect()
    }

    fn with_held<T>(&self, id: SocketId, f: impl FnOnce(&mut Wire) -> T) -> T {
        self.opened();
        let mut held = self.held.lock().expect("held");
        let wire = held
            .iter_mut()
            .find(|wire| wire.id == id)
            .unwrap_or_else(|| panic!("{id:?} is not a held channel"));
        f(wire)
    }

    /// The handshake request the dialer wrote on held channel `id`.
    pub fn request(&self, id: SocketId) -> HandshakeRequest {
        self.with_held(id, |wire| match wire.read_blocking() {
            Received::Request { command, payload } if command == Command::Handshake.wire_id() => {
                HandshakeRequest::load(&payload).expect("a handshake request")
            }
            other => panic!("not a handshake request: {other:?}"),
        })
    }

    /// Inject `frame` on held channel `id`: the peer's answer.
    pub fn answer(&self, id: SocketId, frame: Vec<u8>) {
        self.with_held(id, |wire| wire.inject_blocking(frame));
    }

    /// The peer closes held channel `id`. Returns once the owners were told,
    /// so the dialer has recorded the close.
    pub fn close_as_peer(&self, id: SocketId) {
        self.with_held(id, Wire::peer_closes);
        wait_until("the owners were told of the close", || {
            self.recorder.was_told_closed(id)
        });
    }

    /// Admit an inbound connection from `endpoint` and adopt it; the far
    /// side is returned.
    pub fn accept(&self, endpoint: Endpoint) -> Wire {
        let (wire, channel) = self.peer.loopback.accept(endpoint, SEND_CAP, true);
        self.layer.adopt(channel);
        wire
    }

    /// Run the inbound handshake on `wire` from the far side and wait
    /// until the row is established.
    pub fn establish_inbound(&self, wire: &mut Wire) {
        wire.inject_blocking(request(NETWORK, [9; 32]));
        let received = wire.read_blocking();
        let Received::Response { command, .. } = received else {
            panic!("expected the handshake response, got {received:?}");
        };
        assert_eq!(command, Command::Handshake.wire_id());
        let id = wire.id;
        wait_until("the inbound row is established", || {
            self.layer
                .board()
                .get(id)
                .is_some_and(|row| row.established())
        });
    }

    /// Wait until `id` has no row on the board.
    pub fn wait_closed(&self, id: SocketId) {
        wait_until("the row left the board", || {
            self.layer.board().get(id).is_none()
        });
    }

    /// Run one dial on an owner thread while the far side reads the request
    /// and injects `frames`. Returns the kept session's id and the far
    /// side, which the test holds while the session is to stay open:
    /// dropping it is the peer closing.
    pub fn dial_with(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        frames: Vec<Vec<u8>>,
    ) -> (Option<SocketId>, Wire) {
        let dialer = Arc::clone(&self.dialer);
        let target = address.clone();
        let owner =
            thread::spawn(move || dialer.dial(connector, &target, aim, &mut SplitMix64::new(1)));
        let mut wire = self.dialed();
        let received = wire.read_blocking();
        assert!(
            matches!(received, Received::Request { command, .. } if command == Command::Handshake.wire_id()),
            "the dialer wrote its handshake request first, not {received:?}"
        );
        for frame in frames {
            wire.inject_blocking(frame);
        }
        (owner.join().expect("owner thread"), wire)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.layer.shutdown();
    }
}
