// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay owner on live sessions: a session layer over the harness's
//! in-memory peer, the real [`Port`] in its relay seat, a fake pool, and
//! a manual clock behind the timing engine. Tests sit on the far side of
//! the wire, as a peer does.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{
    notify, GetTxpoolComplement, NewTransactions, PeerlistEntry, PortableMap, Received,
    NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_p2p_session::harness::{self, Loopback, Wire};
use shekyl_p2p_session::{
    ClaimCarrier, Command, CoreSyncData, DialAim, DialEnd, DialOutcome, Direction, Endpoint,
    Established, Intervals, Owners, Parts, PeerOwner, PerConnector, ProbeArrival, ProbeSink,
    SessionConfig, SessionFacts, SessionLayer, SocketId, SyncInbound, SyncOwner, Taken,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_relay::owner::{
    start, Admit, PoolDoor, Port, RelayConfig, RelayHandle, RelayParts, Started,
};
use shekyl_relay::{ConnectorId, NodeSync, TxId};
use shekyl_timing_engine::{
    Clock, EngineService, Handle, ManualClock, OwnerClass, OwnerHandle, Tick,
};
use shekyl_transport_layer::Sockets;
use tokio::sync::watch;

pub const NETWORK: [u8; 16] = [7; 16];
pub const SEND_CAP: usize = 64 * 1024;
pub const CEILING: InboundCeiling = InboundCeiling::Bounded(64);
pub const WAIT: Duration = Duration::from_secs(5);
/// Long enough for anything queued to have been written.
pub const SETTLE: Duration = Duration::from_millis(150);

pub fn tip() -> CoreSyncData {
    CoreSyncData {
        current_height: 10,
        cumulative_difficulty: 100,
        cumulative_difficulty_top64: 0,
        top_id: [1; 32],
    }
}

pub fn inbound_clearnet(last: u8) -> Endpoint {
    Endpoint::Clearnet {
        ip: IpAddr::V4(Ipv4Addr::new(10, 1, 0, last)),
        port: 40_000 + u16::from(last),
        direction: Direction::Inbound,
    }
}

pub fn outbound_clearnet(last: u8) -> Endpoint {
    Endpoint::Clearnet {
        ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, last)),
        port: 12_000,
        direction: Direction::Outbound,
    }
}

/// A 2002 carrying `blobs` with the given flag.
pub fn new_transactions(blobs: Vec<Vec<u8>>, fluff: bool) -> Vec<u8> {
    let payload = NewTransactions {
        txs: blobs,
        padding: Vec::new(),
        dandelionpp_fluff: fluff,
    }
    .store()
    .expect("a batch stores");
    notify(NOTIFY_NEW_TRANSACTIONS, &payload)
}

/// A 2010 naming `known`.
pub fn txpool_complement(known: Vec<[u8; 32]>) -> Vec<u8> {
    let payload = GetTxpoolComplement { hashes: known }
        .store()
        .expect("a complement request stores");
    notify(Command::GetTxpoolComplement.wire_id(), &payload)
}

/// The id a blob gets in the fake pool: its first byte repeated.
pub fn id_of(blob: &[u8]) -> TxId {
    TxId::from_bytes([blob[0]; 32])
}

pub fn blob(tag: u8) -> Vec<u8> {
    vec![tag; 16]
}

/// Poll `condition` until it holds, or fail after [`WAIT`].
pub fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < WAIT, "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// What the fake pool was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    Admit(Vec<u8>),
    Shown(TxId),
    Complement(Vec<TxId>),
}

/// The pool as the owner sees it, scripted per blob.
#[derive(Default)]
pub struct FakePool {
    verdicts: Mutex<HashMap<Vec<u8>, Admit>>,
    held: Mutex<Vec<TxId>>,
    complement: Mutex<Vec<Vec<u8>>>,
    asked: Mutex<Vec<Asked>>,
    /// While closed, `admit` blocks: the backpressure test's gate.
    gate: (Mutex<bool>, Condvar),
}

impl FakePool {
    pub fn new() -> Arc<Self> {
        let pool = Self::default();
        *pool.gate.0.lock().expect("gate") = true;
        Arc::new(pool)
    }

    /// What `admit` answers for `blob`. Unscripted blobs are admitted
    /// under [`id_of`].
    pub fn script(&self, blob: &[u8], verdict: Admit) {
        self.verdicts
            .lock()
            .expect("verdicts")
            .insert(blob.to_vec(), verdict);
    }

    pub fn set_complement(&self, txs: Vec<Vec<u8>>) {
        *self.complement.lock().expect("complement") = txs;
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().expect("asked").clone()
    }

    pub fn admits(&self) -> Vec<Vec<u8>> {
        self.asked()
            .into_iter()
            .filter_map(|asked| match asked {
                Asked::Admit(blob) => Some(blob),
                _ => None,
            })
            .collect()
    }

    pub fn shown(&self) -> Vec<TxId> {
        self.asked()
            .into_iter()
            .filter_map(|asked| match asked {
                Asked::Shown(tx) => Some(tx),
                _ => None,
            })
            .collect()
    }

    /// Close the gate: `admit` blocks until [`Self::open`].
    pub fn close_gate(&self) {
        *self.gate.0.lock().expect("gate") = false;
    }

    pub fn open_gate(&self) {
        *self.gate.0.lock().expect("gate") = true;
        self.gate.1.notify_all();
    }

    fn record(&self, asked: Asked) {
        self.asked.lock().expect("asked").push(asked);
    }
}

impl PoolDoor for FakePool {
    fn admit(&self, blob: &[u8]) -> Admit {
        self.record(Asked::Admit(blob.to_vec()));
        {
            let mut open = self.gate.0.lock().expect("gate");
            while !*open {
                open = self.gate.1.wait(open).expect("gate");
            }
        }
        let verdict = self
            .verdicts
            .lock()
            .expect("verdicts")
            .get(blob)
            .copied()
            .unwrap_or(Admit::Admitted(id_of(blob)));
        if let Admit::Admitted(tx) | Admit::Held(tx) = verdict {
            self.held.lock().expect("held").push(tx);
        }
        verdict
    }

    fn holds(&self, tx: &TxId) -> bool {
        self.held.lock().expect("held").contains(tx)
    }

    fn shown(&self, tx: &TxId) {
        self.record(Asked::Shown(*tx));
    }

    fn complement(&self, known: &[TxId]) -> Vec<Vec<u8>> {
        self.record(Asked::Complement(known.to_vec()));
        self.complement.lock().expect("complement").clone()
    }
}

/// The other owners: a peers owner with nothing to say, and recorders.
#[derive(Default)]
pub struct Others {
    pub told: Mutex<Vec<Told>>,
}

#[derive(Debug)]
pub enum Told {
    Established(SocketId),
    Closed(SocketId, DialEnd),
    Sync(SocketId, Command),
}

impl PeerOwner for Others {
    fn disclosure(&self, _connector: ConnectorId) -> Vec<PeerlistEntry> {
        Vec::new()
    }
    fn list_received(&self, _session: &Established, _list: Vec<PeerlistEntry>) {}
}

impl SyncOwner for Others {
    fn claim(&self, _session: &Established, _sync: CoreSyncData, _carrier: ClaimCarrier) {}
    fn message(&self, session: &Established, message: SyncInbound, taken: Taken) {
        self.told
            .lock()
            .expect("told")
            .push(Told::Sync(session.id(), message.command()));
        drop(taken);
    }
    fn on_established(&self, session: &Established) {
        self.told
            .lock()
            .expect("told")
            .push(Told::Established(session.id()));
    }
    fn on_closed(&self, facts: &SessionFacts, end: DialEnd) {
        self.told
            .lock()
            .expect("told")
            .push(Told::Closed(facts.id, end));
    }
}

impl ProbeSink for Others {
    fn probe_arrived(&self, _arrival: ProbeArrival) {}
}

#[derive(Clone, Copy)]
pub struct Build {
    pub noise: bool,
    pub node_sync: NodeSync,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            noise: false,
            node_sync: NodeSync::Synchronised,
        }
    }
}

pub struct Rig {
    pub clock: ManualClock,
    pub sockets: Sockets,
    pub layer: SessionLayer<ManualClock>,
    pub pool: Arc<FakePool>,
    pub relay: RelayHandle,
    pub port: Arc<Port>,
    pub node_sync: watch::Sender<NodeSync>,
    pub timing: Handle<ManualClock>,
    pub others: Arc<Others>,
    /// Outlives the layer, which reads it.
    tip: watch::Sender<CoreSyncData>,
    /// A manual clock does not wake the engine by moving: a command does.
    /// This owner's `clear` is that command.
    nudge: OwnerHandle<ManualClock>,
    loopback: Arc<Loopback>,
    dialed: Mutex<tokio::sync::mpsc::UnboundedReceiver<Wire>>,
    engine: EngineService<ManualClock>,
    runtime: tokio::runtime::Runtime,
}

impl Rig {
    pub fn build(build: Build) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the rig's runtime");
        let clock = ManualClock::new(Tick::new(1_000_000));
        let sockets = Sockets::new();
        let (loopback, dialed) = Loopback::new(sockets.clone(), CEILING, SEND_CAP);
        let engine = EngineService::start(clock.clone());
        let timing = engine.handle();
        let nudge = timing
            .register(OwnerClass::Housekeeping)
            .expect("the nudge registers");
        let pool = FakePool::new();
        let (node_sync, node_sync_rx) = watch::channel(build.node_sync);
        let Started { port, handle } = start(RelayParts {
            config: RelayConfig::inherited(vec![ConnectorId::Clearnet], build.noise),
            pool: pool.clone(),
            node_sync: node_sync_rx,
            timing: timing.clone(),
            runtime: runtime.handle().clone(),
            rng: Box::new(SplitMix64::new(0x5eed)),
        })
        .expect("the relay owner starts");
        let others = Arc::new(Others::default());
        let (tip_tx, tip_rx) = watch::channel(tip());
        let layer = SessionLayer::new(Parts {
            sockets: sockets.clone(),
            config: SessionConfig {
                network_id: NETWORK,
                handshake_within: PerConnector::both(Duration::from_secs(24 * 3600)),
                intervals: Intervals {
                    invoke_timeout: Duration::from_secs(365 * 24 * 3600),
                    timed_sync_min: Duration::from_secs(365 * 24 * 3600),
                    timed_sync_jitter: Duration::from_secs(1),
                },
            },
            owners: Owners {
                peers: others.clone(),
                sync: others.clone(),
                relay: port.clone(),
                probes: others.clone(),
            },
            connectors: loopback.clone(),
            timing: timing.clone(),
            tip: tip_rx,
            runtime: runtime.handle().clone(),
            rng: Box::new(SplitMix64::new(0x5eed + 1)),
        });
        Self {
            clock,
            sockets,
            layer,
            pool,
            relay: handle,
            port,
            node_sync,
            timing,
            others,
            tip: tip_tx,
            nudge,
            loopback,
            dialed: Mutex::new(dialed),
            engine,
            runtime,
        }
    }

    /// Advance the manual clock by `by` and let the engine fire what is
    /// due.
    pub fn advance(&self, by: Duration) {
        let now = self.clock.now();
        let ns = u64::try_from(by.as_nanos()).expect("fits");
        self.clock.set(Tick::new(now.get() + ns));
        self.nudge.clear().expect("the engine is open");
    }

    /// An inbound channel from `endpoint`, adopted by the layer; the far
    /// side is returned.
    pub fn accept(&self, endpoint: Endpoint) -> Wire {
        let (wire, channel) = self.loopback.accept(endpoint, SEND_CAP, true);
        self.layer.adopt(channel);
        wire
    }

    /// Run the inbound handshake on `wire` from the far side and wait
    /// until the relay owner holds the session.
    pub fn establish_inbound(&self, wire: &mut Wire) {
        wire.inject_blocking(harness::handshake_request(NETWORK, [9; 32], tip()));
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

    /// An inbound peer, established.
    pub fn inbound(&self, last: u8) -> Wire {
        let mut wire = self.accept(inbound_clearnet(last));
        self.establish_inbound(&mut wire);
        wire
    }

    /// An outbound session kept by the layer, with the far side answering
    /// the handshake. Returns the far side.
    pub fn outbound(&self, last: u8) -> Wire {
        let layer = self.layer.clone();
        let endpoint = outbound_clearnet(last);
        let dial = self
            .runtime
            .spawn(async move { layer.dial(endpoint, DialAim::Keep).await });
        let mut wire = self.dialed();
        let received = wire.read_blocking();
        assert!(
            matches!(received, Received::Request { command, .. } if command == Command::Handshake.wire_id()),
            "the layer wrote its handshake request first, not {received:?}"
        );
        wire.inject_blocking(harness::handshake_response(NETWORK, Vec::new(), tip()));
        let outcome = self
            .runtime
            .block_on(dial)
            .expect("dial task")
            .expect("the dial is kept");
        assert!(matches!(outcome, DialOutcome::Kept { .. }));
        wait_until("the outbound row is established", || {
            self.layer
                .board()
                .get(wire.id)
                .is_some_and(|row| row.established())
        });
        wire
    }

    fn dialed(&self) -> Wire {
        let start = Instant::now();
        loop {
            if let Ok(wire) = self.dialed.lock().expect("dialed").try_recv() {
                return wire;
            }
            assert!(start.elapsed() < WAIT, "the channel never opened");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// Wait until the row left the board.
    pub fn wait_closed(&self, id: SocketId) {
        wait_until("the row left the board", || {
            self.layer.board().get(id).is_none()
        });
    }

    /// The next frame `wire` reads within `within`, if any.
    pub fn read_within(&self, wire: &mut Wire, within: Duration) -> Option<Received> {
        self.runtime
            .block_on(async { tokio::time::timeout(within, wire.read()).await })
            .ok()
    }

    /// Whether `wire` reads nothing within [`SETTLE`].
    pub fn quiet(&self, wire: &mut Wire) -> bool {
        self.read_within(wire, SETTLE).is_none()
    }

    /// The next 2002 `wire` reads within [`SETTLE`].
    pub fn read_batch(&self, wire: &mut Wire) -> NewTransactions {
        let received = self
            .read_within(wire, SETTLE)
            .expect("a batch within the settle window");
        batch_of(received)
    }

    /// Advance the clock a minute at a time until `wire` reads a 2002,
    /// up to `steps` minutes.
    pub fn read_batch_within(&self, wire: &mut Wire, steps: u32) -> NewTransactions {
        let mut stepped = 0;
        loop {
            if let Some(received) = self.read_within(wire, SETTLE) {
                return batch_of(received);
            }
            assert!(stepped < steps, "no batch within {steps} minutes");
            self.advance(Duration::from_secs(60));
            stepped += 1;
        }
    }
}

/// `received` as the 2002 it must be.
pub fn batch_of(received: Received) -> NewTransactions {
    let Received::Notification { command, payload } = received else {
        panic!("expected a notification, got {received:?}");
    };
    assert_eq!(command, NOTIFY_NEW_TRANSACTIONS);
    NewTransactions::load(&payload).expect("a batch")
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.relay.stop();
        self.layer.shutdown();
        self.engine.close();
    }
}
