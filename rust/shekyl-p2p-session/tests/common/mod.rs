// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The in-memory harness the session tests drive: a `Dial` whose channels
//! are two capped-stream ends with the test on the far side, owners that
//! record what they are handed, and a real timing engine on the
//! monotonic clock with the intervals narrowed.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{GetTxpoolComplement, NewTransactions, PeerlistEntry, Received};
use shekyl_net_address::NetworkAddress;
use shekyl_p2p_session::harness;
use shekyl_p2p_session::{
    ClaimCarrier, CloseKind, Command, ConnectorId, CoreSyncData, DialEnd, Direction, Endpoint,
    Established, Intervals, Owners, Parts, PeerOwner, PerConnector, ProbeArrival, ProbeSink,
    RelayOwner, SessionConfig, SessionFacts, SessionLayer, SocketId, SyncInbound, SyncOwner, Taken,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{EngineService, MonotonicClock};
use shekyl_transport_layer::Sockets;
use tokio::sync::{mpsc, oneshot, watch};

pub const NETWORK: [u8; 16] = *b"shekyl-test-net!";
pub const OTHER_NETWORK: [u8; 16] = *b"another-network!";
pub const PEER_HEIGHT: u64 = 41;
pub const OUR_HEIGHT: u64 = 7;
pub const SEND_CAP: usize = 1 << 20;

pub use harness::{within, Answer, Loopback, Wire, SETTLE};

/// Our tip as the tests publish it.
pub fn our_tip() -> CoreSyncData {
    CoreSyncData {
        current_height: OUR_HEIGHT,
        cumulative_difficulty: 70,
        cumulative_difficulty_top64: 0,
        top_id: [7; 32],
    }
}

/// The far side's tip.
pub fn peer_tip() -> CoreSyncData {
    CoreSyncData {
        current_height: PEER_HEIGHT,
        cumulative_difficulty: 410,
        cumulative_difficulty_top64: 0,
        top_id: [41; 32],
    }
}

pub fn entry(last: u8) -> PeerlistEntry {
    PeerlistEntry {
        adr: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(203, 0, 113, last),
            port: 12_000,
        },
    }
}

pub fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
}

pub fn inbound_clearnet(last: u8) -> Endpoint {
    Endpoint::Clearnet {
        ip: ip(last),
        port: 40_000 + u16::from(last),
        direction: Direction::Inbound,
    }
}

pub fn outbound_clearnet(last: u8) -> Endpoint {
    Endpoint::Clearnet {
        ip: ip(last),
        port: 12_000,
        direction: Direction::Outbound,
    }
}

pub const CEILING: InboundCeiling = InboundCeiling::Bounded(64);

/// What the owners were handed, in order.
#[derive(Debug)]
pub enum Event {
    Established(Established),
    Closed(SessionFacts, DialEnd),
    Claim(SocketId, u64, ClaimCarrier),
    ListReceived(SocketId, usize),
    Sync(SocketId, Command, Taken),
    Relay(SocketId, usize, Taken),
    Complement(SocketId, usize, Taken),
    Probe(ProbeArrival),
}

/// One recorder stands in for all three owners and the probe sink. The
/// established and closed events are recorded from the peers owner's
/// hooks; the other two owners' hooks count, so a test can show all
/// three were told.
pub struct Recorder {
    events: mpsc::UnboundedSender<Event>,
    pub disclosure: Vec<PeerlistEntry>,
    pub established_told: AtomicUsize,
    pub closed_told: AtomicUsize,
    /// When set, a claim's permit is kept in `held_claims` instead of
    /// dropped as the claim is recorded: the owner has not taken it yet.
    pub hold_claims: AtomicBool,
    pub held_claims: Mutex<Vec<Taken>>,
}

impl PeerOwner for Recorder {
    fn disclosure(&self, _connector: ConnectorId) -> Vec<PeerlistEntry> {
        self.disclosure.clone()
    }

    fn list_received(&self, session: &Established, list: Vec<PeerlistEntry>) {
        self.send(Event::ListReceived(session.id(), list.len()));
    }

    fn on_established(&self, session: &Established) {
        self.established_told.fetch_add(1, Ordering::SeqCst);
        self.send(Event::Established(session.clone()));
    }

    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.closed_told.fetch_add(1, Ordering::SeqCst);
        self.send(Event::Closed(*facts, end));
    }
}

impl SyncOwner for Recorder {
    fn claim(
        &self,
        session: &Established,
        sync: CoreSyncData,
        carrier: ClaimCarrier,
        taken: Taken,
    ) {
        if self.hold_claims.load(Ordering::SeqCst) {
            self.held_claims.lock().expect("held claims").push(taken);
        }
        self.send(Event::Claim(session.id(), sync.current_height, carrier));
    }

    fn message(&self, session: &Established, message: SyncInbound, taken: Taken) {
        self.send(Event::Sync(session.id(), message.command(), taken));
    }

    fn on_established(&self, _session: &Established) {
        self.established_told.fetch_add(1, Ordering::SeqCst);
    }

    fn on_closed(&self, _facts: &SessionFacts, _end: DialEnd) {
        self.closed_told.fetch_add(1, Ordering::SeqCst);
    }
}

impl RelayOwner for Recorder {
    fn new_transactions(&self, session: &Established, batch: NewTransactions, taken: Taken) {
        self.send(Event::Relay(session.id(), batch.txs.len(), taken));
    }

    fn txpool_complement(&self, session: &Established, request: GetTxpoolComplement, taken: Taken) {
        self.send(Event::Complement(session.id(), request.hashes.len(), taken));
    }

    fn on_established(&self, _session: &Established) {
        self.established_told.fetch_add(1, Ordering::SeqCst);
    }

    fn on_closed(&self, _facts: &SessionFacts, _end: DialEnd) {
        self.closed_told.fetch_add(1, Ordering::SeqCst);
    }
}

impl ProbeSink for Recorder {
    fn probe_arrived(&self, arrival: ProbeArrival) {
        self.send(Event::Probe(arrival));
    }
}

impl Recorder {
    fn send(&self, event: Event) {
        if let Err(_test_gone) = self.events.send(event) {}
    }
}

/// Everything one test holds.
pub struct Rig {
    pub layer: SessionLayer<MonotonicClock>,
    pub sockets: Sockets,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub dialed: mpsc::UnboundedReceiver<Wire>,
    pub recorder: Arc<Recorder>,
    pub loopback: Arc<Loopback>,
    pub tip: watch::Sender<CoreSyncData>,
    pub timing: shekyl_timing_engine::Handle<MonotonicClock>,
    _engine: EngineService<MonotonicClock>,
}

/// The settings a test narrows.
pub struct Settings {
    pub handshake_within: Duration,
    pub intervals: Intervals,
    pub send_cap: usize,
    pub disclosure: Vec<PeerlistEntry>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            handshake_within: Duration::from_secs(30),
            intervals: Intervals {
                invoke_timeout: Duration::from_secs(30),
                timed_sync_min: Duration::from_secs(30),
                timed_sync_jitter: Duration::from_secs(1),
            },
            send_cap: SEND_CAP,
            disclosure: vec![entry(1), entry(2)],
        }
    }
}

impl Rig {
    pub fn new(settings: Settings) -> Self {
        // No accept-rate gate: the loopback admits at a fixed tick.
        let sockets = Sockets::with_clearnet_gate(None);
        let (events_tx, events) = mpsc::unbounded_channel();
        let recorder = Arc::new(Recorder {
            events: events_tx,
            disclosure: settings.disclosure,
            established_told: AtomicUsize::new(0),
            closed_told: AtomicUsize::new(0),
            hold_claims: AtomicBool::new(false),
            held_claims: Mutex::new(Vec::new()),
        });
        let (loopback, dialed) = Loopback::new(sockets.clone(), CEILING, settings.send_cap);
        let engine = EngineService::start(MonotonicClock::new());
        let timing = engine.handle();
        let (tip, tip_rx) = watch::channel(our_tip());
        let owners = Owners {
            peers: recorder.clone(),
            sync: recorder.clone(),
            relay: recorder.clone(),
            probes: recorder.clone(),
        };
        let layer = SessionLayer::new(Parts {
            sockets: sockets.clone(),
            config: SessionConfig {
                network_id: NETWORK,
                handshake_within: PerConnector::both(settings.handshake_within),
                intervals: settings.intervals,
            },
            owners,
            connectors: loopback.clone(),
            timing: timing.clone(),
            tip: tip_rx,
            runtime: tokio::runtime::Handle::current(),
            rng: Box::new(SplitMix64::new(0x5eed)),
        });
        Self {
            layer,
            sockets,
            events,
            dialed,
            recorder,
            loopback,
            tip,
            timing,
            _engine: engine,
        }
    }

    /// Queue how the loopback answers the next dial.
    pub fn next_dial(&self, answer: Answer) {
        self.loopback.answer_next(answer);
    }

    /// Admit an inbound connection from `endpoint` and adopt it. Returns
    /// the far side and the gap's receiver.
    pub fn accept(&self, endpoint: Endpoint) -> (Wire, oneshot::Receiver<()>) {
        self.accept_with_cap(endpoint, SEND_CAP, true)
    }

    /// [`Self::accept`] with the session's send cap and whether the
    /// writer drains it.
    pub fn accept_with_cap(
        &self,
        endpoint: Endpoint,
        send_cap: usize,
        drain: bool,
    ) -> (Wire, oneshot::Receiver<()>) {
        let (wire, mut channel) = self.loopback.accept(endpoint, send_cap, drain);
        let (gap, gap_rx) = oneshot::channel();
        channel.gap = Some(gap);
        self.layer.adopt(channel);
        (wire, gap_rx)
    }

    /// The next event an owner recorded.
    pub async fn event(&mut self) -> Event {
        within("an owner event", self.events.recv())
            .await
            .expect("the recorder is alive")
    }

    /// Whether no event arrives within [`SETTLE`].
    pub async fn no_event(&mut self) -> bool {
        tokio::time::timeout(SETTLE, self.events.recv())
            .await
            .is_err()
    }

    /// Wait for the close of `id` and return its facts and end. Events
    /// before it are dropped.
    pub async fn closed(&mut self, id: SocketId) -> (SessionFacts, DialEnd) {
        loop {
            match self.event().await {
                Event::Closed(facts, end) if facts.id == id => return (facts, end),
                _ => {}
            }
        }
    }

    /// Run the inbound handshake on `wire` and return once the session is
    /// established: the response read, the events consumed.
    pub async fn establish_inbound(&mut self, wire: &mut Wire) -> Established {
        wire.inject(handshake_request(NETWORK, [9; 32])).await;
        let received = wire.read().await;
        let Received::Response { command, .. } = received else {
            panic!("expected the handshake response, got {received:?}");
        };
        assert_eq!(command, Command::Handshake.wire_id());
        let mut established = None;
        loop {
            match self.event().await {
                Event::Established(session) => {
                    assert_eq!(session.id(), wire.id);
                    established = Some(session);
                }
                Event::Claim(id, height, ClaimCarrier::Handshake) => {
                    assert_eq!(id, wire.id);
                    assert_eq!(height, PEER_HEIGHT);
                    break;
                }
                other => panic!("unexpected event during the handshake: {other:?}"),
            }
        }
        let row = self.layer.board();
        let row = row.get(wire.id).expect("the row is on the board");
        assert!(row.established());
        established.expect("the owners were told before the claim")
    }

    /// Dial with [`shekyl_p2p_session::DialAim::Keep`] and run the far
    /// side's half of the handshake.
    pub async fn dial_kept(&mut self, endpoint: Endpoint) -> (Established, Wire) {
        let layer = self.layer.clone();
        let dial = tokio::spawn(async move {
            layer
                .dial(endpoint, shekyl_p2p_session::DialAim::Keep)
                .await
        });
        let mut wire = within("the dialed wire", self.dialed.recv())
            .await
            .expect("the loopback is alive");
        let received = wire.read().await;
        let Received::Request { command, .. } = received else {
            panic!("expected the handshake request, got {received:?}");
        };
        assert_eq!(command, Command::Handshake.wire_id());
        wire.inject(handshake_response(NETWORK, vec![entry(5)]))
            .await;
        let outcome = within("the dial outcome", dial)
            .await
            .expect("the dial task")
            .expect("the dial succeeded");
        let shekyl_p2p_session::DialOutcome::Kept { session, .. } = outcome else {
            panic!("expected Kept, got {outcome:?}");
        };
        loop {
            match self.event().await {
                Event::Established(session) => assert_eq!(session.id(), wire.id),
                Event::Claim(id, _, ClaimCarrier::Handshake) => {
                    assert_eq!(id, wire.id);
                    break;
                }
                other => panic!("unexpected event during the dial: {other:?}"),
            }
        }
        (session, wire)
    }
}

pub fn handshake_request(network_id: [u8; 16], nonce: [u8; 32]) -> Vec<u8> {
    harness::handshake_request(network_id, nonce, peer_tip())
}

pub fn handshake_response(network_id: [u8; 16], list: Vec<PeerlistEntry>) -> Vec<u8> {
    harness::handshake_response(network_id, list, peer_tip())
}

pub fn timed_sync_request() -> Vec<u8> {
    harness::timed_sync_request(peer_tip())
}

pub fn timed_sync_response(list: Vec<PeerlistEntry>) -> Vec<u8> {
    harness::timed_sync_response(list, peer_tip())
}

pub use harness::{new_transactions, request_headers, txpool_complement};

pub fn kind(end: DialEnd) -> CloseKind {
    end.cause().kind()
}
