// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The in-memory harness the session tests drive: a `Dial` whose channels
//! are two capped-stream ends with the test on the far side, owners that
//! record what they are handed, and a real timing engine on the
//! monotonic clock with the intervals narrowed.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use shekyl_capped_stream::{ByteQueue, InboundEnd, QueueHold, Session, StreamEnds};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    invoke, notify, response, BasicNodeData, BucketReader, GetTxpoolComplement, HandshakeRequest,
    HandshakeResponse, NewTransactions, PeerlistEntry, PortableMap, Received, TimedSyncRequest,
    TimedSyncResponse, DEFAULT_MAX_PACKET_SIZE,
};
use shekyl_net_address::NetworkAddress;
use shekyl_p2p_session::{
    admit, Channel, ClaimCarrier, CloseKind, Command, ConnectFuture, ConnectorId, CoreSyncData,
    Dial, DialEnd, Direction, Endpoint, Established, Intervals, Owners, Parts, PeerOwner,
    PerConnector, ProbeArrival, ProbeSink, RelayOwner, SessionConfig, SessionFacts, SessionLayer,
    SocketId, SyncInbound, SyncOwner, Taken,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{DialFailure, Reached, Retry, Sockets, StreamEnd};
use tokio::sync::{mpsc, oneshot, watch};

pub const NETWORK: [u8; 16] = *b"shekyl-test-net!";
pub const OTHER_NETWORK: [u8; 16] = *b"another-network!";
pub const PEER_HEIGHT: u64 = 41;
pub const OUR_HEIGHT: u64 = 7;
pub const SEND_CAP: usize = 1 << 20;
pub const WAIT: Duration = Duration::from_secs(5);
pub const SETTLE: Duration = Duration::from_millis(300);

/// Block until `fut` resolves, or fail the test after [`WAIT`].
pub async fn within<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(WAIT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing within {WAIT:?}"))
}

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
    fn claim(&self, session: &Established, sync: CoreSyncData, carrier: ClaimCarrier) {
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

/// The far side of one channel: inject bytes toward the session, read
/// what the session wrote.
pub struct Wire {
    pub id: SocketId,
    inject: Option<InboundEnd>,
    out: mpsc::UnboundedReceiver<Vec<u8>>,
    hold: Option<QueueHold>,
    writer: Option<JoinHandle<()>>,
    reader: BucketReader,
}

impl Wire {
    /// Build both ends. The writer thread drains the session's queue to
    /// `out`, one push per bucket.
    fn open(id: SocketId, send_cap: usize, drain: bool) -> (Self, Session) {
        let ends = StreamEnds::open(send_cap);
        let (tx, out) = mpsc::unbounded_channel();
        let writer = drain.then(|| {
            let queue: ByteQueue = ends.writer_queue.clone();
            thread::spawn(move || {
                while let Ok(bytes) = queue.pop_blocking() {
                    queue.release(bytes.len());
                    if let Err(_test_gone) = tx.send(bytes) {}
                }
            })
        });
        let mut reader = BucketReader::new();
        reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
        (
            Self {
                id,
                inject: Some(ends.inbound),
                out,
                hold: Some(ends.hold),
                writer,
                reader,
            },
            ends.session,
        )
    }

    /// Push raw bytes toward the session, as a connector's reader would.
    pub async fn inject(&self, bytes: Vec<u8>) {
        let end = self.inject.as_ref().expect("the inbound end is still open");
        end.send(bytes).await.expect("the session still reads");
    }

    /// Close the inbound end without storing an end: the peer closed.
    pub fn peer_closes(&mut self) {
        drop(self.inject.take());
    }

    /// Close the inbound end with `end` stored: the connector saw it.
    pub fn connector_ends(&mut self, end: DialEnd) {
        if let Some(inbound) = self.inject.take() {
            inbound.close(end);
            drop(inbound);
        }
    }

    /// The next bucket the session wrote.
    pub async fn read(&mut self) -> Received {
        loop {
            match self.reader.next_message() {
                Ok(Some(received)) => return received,
                Ok(None) => {}
                Err(error) => panic!("the session wrote a malformed bucket: {error:?}"),
            }
            let bytes = within("a bucket from the session", self.out.recv())
                .await
                .expect("the session's queue closed before the bucket");
            self.reader.feed(&bytes).expect("the session's bytes frame");
        }
    }

    /// `true` once the session's queue closed with nothing more to read.
    pub async fn drained(&mut self) -> bool {
        within("the session's queue to close", self.out.recv())
            .await
            .is_none()
    }

    /// Whether anything is waiting to be read, after [`SETTLE`].
    pub async fn is_quiet(&mut self) -> bool {
        tokio::time::sleep(SETTLE).await;
        self.out.try_recv().is_err()
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        drop(self.inject.take());
        drop(self.hold.take());
        if let Some(writer) = self.writer.take() {
            writer.join().expect("harness writer");
        }
    }
}

/// How the loopback answers the next dial.
pub enum Answer {
    /// Admit and build a channel; the wire goes to the test.
    Connect,
    /// Refuse with this end before any I/O.
    Refuse(DialEnd),
}

/// The connectors: admission through the shared table, channels built
/// in memory.
pub struct Loopback {
    sockets: Sockets,
    answers: Mutex<VecDeque<Answer>>,
    dialed: mpsc::UnboundedSender<Wire>,
    send_cap: usize,
}

impl Dial for Loopback {
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture {
        let endpoint = *endpoint;
        let answer = self
            .answers
            .lock()
            .expect("answers")
            .pop_front()
            .unwrap_or(Answer::Connect);
        let result = match answer {
            Answer::Refuse(end) => Err(end),
            Answer::Connect => {
                let now = Tick::new(0);
                match admit(&self.sockets, &endpoint, now, CEILING) {
                    Err(cause) => Err(DialEnd::new(
                        DialFailure::local(Retry::Again, Reached::NoStream),
                        cause,
                    )),
                    Ok(open) => {
                        let (wire, session) = Wire::open(open.id(), self.send_cap, true);
                        if let Err(_test_gone) = self.dialed.send(wire) {}
                        Ok(Channel {
                            open,
                            session,
                            endpoint,
                            gap: None,
                        })
                    }
                }
            }
        };
        Box::pin(async move { result })
    }

    fn stamp_stream_end(&self, _connector: ConnectorId, end: StreamEnd) -> DialFailure {
        match end {
            StreamEnd::PeerClosed => DialFailure::uncertain(Retry::Again, Reached::StreamOpened),
            StreamEnd::IoError | StreamEnd::SendQueueFull => {
                DialFailure::local(Retry::Again, Reached::StreamOpened)
            }
        }
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
        let sockets = Sockets::new();
        let (events_tx, events) = mpsc::unbounded_channel();
        let recorder = Arc::new(Recorder {
            events: events_tx,
            disclosure: settings.disclosure,
            established_told: AtomicUsize::new(0),
            closed_told: AtomicUsize::new(0),
        });
        let (dialed_tx, dialed) = mpsc::unbounded_channel();
        let loopback = Arc::new(Loopback {
            sockets: sockets.clone(),
            answers: Mutex::new(VecDeque::new()),
            dialed: dialed_tx,
            send_cap: settings.send_cap,
        });
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
        self.loopback
            .answers
            .lock()
            .expect("answers")
            .push_back(answer);
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
        let open = admit(&self.sockets, &endpoint, Tick::new(0), CEILING).expect("admitted");
        let (wire, session) = Wire::open(open.id(), send_cap, drain);
        let (gap, gap_rx) = oneshot::channel();
        self.layer.adopt(Channel {
            open,
            session,
            endpoint,
            gap: Some(gap),
        });
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
    let payload = HandshakeRequest {
        node_data: BasicNodeData { network_id },
        payload_data: peer_tip(),
        nonce,
    }
    .store()
    .expect("request stores");
    invoke(Command::Handshake.wire_id(), &payload)
}

pub fn handshake_response(network_id: [u8; 16], list: Vec<PeerlistEntry>) -> Vec<u8> {
    let payload = HandshakeResponse {
        node_data: BasicNodeData { network_id },
        payload_data: peer_tip(),
        local_peerlist_new: list,
    }
    .store()
    .expect("response stores");
    response(Command::Handshake.wire_id(), &payload)
}

pub fn timed_sync_request() -> Vec<u8> {
    let payload = TimedSyncRequest {
        payload_data: peer_tip(),
    }
    .store()
    .expect("request stores");
    invoke(Command::TimedSync.wire_id(), &payload)
}

pub fn timed_sync_response(list: Vec<PeerlistEntry>) -> Vec<u8> {
    let payload = TimedSyncResponse {
        payload_data: peer_tip(),
        local_peerlist_new: list,
    }
    .store()
    .expect("response stores");
    response(Command::TimedSync.wire_id(), &payload)
}

pub fn new_transactions(count: u8) -> Vec<u8> {
    let payload = NewTransactions {
        txs: (0..count).map(|i| vec![i; 8]).collect(),
        padding: Vec::new(),
        dandelionpp_fluff: true,
    }
    .store()
    .expect("batch stores");
    notify(Command::NewTransactions.wire_id(), &payload)
}

pub fn txpool_complement(count: u8) -> Vec<u8> {
    let payload = GetTxpoolComplement {
        hashes: (0..count).map(|i| [i; 32]).collect(),
    }
    .store()
    .expect("request stores");
    notify(Command::GetTxpoolComplement.wire_id(), &payload)
}

pub fn request_headers() -> Vec<u8> {
    let payload = shekyl_levin::RequestHeaders {
        block_ids: vec![[3; 32]],
    }
    .store()
    .expect("request stores");
    notify(Command::RequestHeaders.wire_id(), &payload)
}

pub fn kind(end: DialEnd) -> CloseKind {
    end.cause().kind()
}
