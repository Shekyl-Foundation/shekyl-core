// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay task: the zone, its driver, the floor watch and the session
//! map, owned by one task and reached by [`Cmd`]. The carrier's schedule
//! and queue live in their own task; this one holds a [`CarrierLink`] when
//! cover is on. This is `levin_notify.cpp`'s strand with the callbacks made
//! direct calls (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, "Relay dispatch").
//!
//! Three things wake it: a command from a port or a handle, the timing
//! engine at the zone's `next_wake`, and the node's sync watch turning
//! (a held origin becomes due the moment the node is synchronised, RX-2).
//! After any of them the wake is re-armed at the zone's new `next_wake`
//! and the published snapshot replaced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use shekyl_draw_rng::RelayRng;
use shekyl_levin::noise_notify;
use shekyl_p2p_session::{Direction, Established, SocketId, Taken};
use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::params::{DandelionParams, MIN_PROVISIONED_OUT_PEERS};
use shekyl_relay_privacy::schedule::{Millis, PeerDirection};
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::{Clock, EngineError, Handle, OwnerClass, OwnerHandle, Tick};
use tokio::sync::{mpsc, watch};

use super::carrier::{CarrierLink, CarrierTask};
use super::pool::PoolDoor;
use super::port::Port;
use super::snapshot::RelaySnapshot;
use crate::carrier::Carrier;
use crate::driver::{Driver, Effect};
use crate::floor_diag::{AchievedOutConnections, FloorTransition, FloorWatch};
use crate::graph::{
    ConnectorId, NodeSync, OriginPublication, OriginVerdict, Relay, RelayNewError, TxBlob,
};
use crate::noise_queue::{CarrierOutcome, NoiseQueues};
use crate::stem_watch::TxId;

mod dispatch;

/// The zone a node runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    /// Outgoing stem connections per epoch.
    pub stems: usize,
    /// The epoch floor, seconds.
    pub min_epoch_secs: u32,
    /// Added to the floor at each draw, up to this many seconds.
    pub epoch_jitter_secs: u32,
    /// Whether the zone runs the cover carrier (`relay-cover`, `CVR-R1`):
    /// on unless the operator opted out. Off, this node relays no stems —
    /// a stem it receives is broadcast — and its own transactions stem
    /// without cover.
    pub noise: bool,
    /// The connectors this node built. The zone's embargo timers and its
    /// hidden slot are derived from their declarations.
    pub connectors: Vec<ConnectorId>,
    /// The built connectors whose sessions this node wraps in an encryption
    /// layer the transport adds (Noise on clearnet, when this node chose
    /// it). Cover reads it with each connector's native encryption.
    pub added_encryption: Vec<ConnectorId>,
}

impl RelayConfig {
    /// The inherited zone: two stems, a ten-minute epoch with up to thirty
    /// seconds of jitter (`DandelionParams::inherited`), the carrier as
    /// `noise` says.
    #[must_use]
    pub fn inherited(
        connectors: Vec<ConnectorId>,
        added_encryption: Vec<ConnectorId>,
        noise: bool,
    ) -> Self {
        Self {
            stems: 2,
            min_epoch_secs: 600,
            epoch_jitter_secs: 30,
            noise,
            connectors,
            added_encryption,
        }
    }
}

/// What the owner is built with.
pub struct RelayParts<C: Clock + Clone + Send + Sync + 'static> {
    /// The zone.
    pub config: RelayConfig,
    /// The node's pool.
    pub pool: Arc<dyn PoolDoor>,
    /// The node's sync state, as the chain publishes it.
    pub node_sync: watch::Receiver<NodeSync>,
    /// The timing engine the wake registers with.
    pub timing: Handle<C>,
    /// Where the task runs.
    pub runtime: tokio::runtime::Handle,
    /// The zone's draws. `SecureRelayRng` in production.
    pub rng: Box<dyn RelayRng + Send>,
    /// The carrier task's draws, its cadence's: a stream of its own, so the
    /// carrier draws without the zone's turn (`CVR-R6`). `SecureRelayRng`
    /// in production.
    pub carrier_rng: Box<dyn RelayRng + Send>,
    /// Who hears the hop-0 verdict for a local origin: the managed Tor
    /// supervisor (`GS-Q3`). `None` when none runs.
    pub verdict: Option<VerdictSink>,
}

/// Where the relay reports its hop-0 verdict for a local origin: the value
/// at start, then each change. Called from the relay's task: it must not
/// block.
pub type VerdictSink = Arc<dyn Fn(OriginVerdict) + Send + Sync>;

/// Why the owner did not start.
#[derive(Debug)]
pub enum RelayStartError {
    /// `min_epoch_secs` was zero: no epoch can be drawn.
    ZeroEpoch,
    /// The zone refused its configuration.
    Zone(RelayNewError),
    /// The timing engine refused the registration: it is closing.
    Timing(EngineError),
    /// The carrier's dummy window could not be framed.
    Carrier(shekyl_levin::Error),
    /// The carrier's queue refused its shape: an empty window or a zero
    /// budget.
    CarrierQueue,
}

impl std::fmt::Display for RelayStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroEpoch => f.write_str("the relay epoch floor is zero"),
            Self::Zone(err) => write!(f, "the relay zone refused its configuration: {err:?}"),
            Self::Timing(err) => write!(f, "the timing engine refused the relay owner: {err:?}"),
            Self::Carrier(err) => write!(f, "the carrier's dummy window did not frame: {err:?}"),
            Self::CarrierQueue => f.write_str("the carrier's queue refused its window or budget"),
        }
    }
}

impl std::error::Error for RelayStartError {}

/// The owner, started: its seat for the session layer and its handle for
/// the node.
pub struct Started {
    /// Goes to `Owners::relay`.
    pub port: Arc<Port>,
    /// Stays with the node.
    pub handle: RelayHandle,
}

/// The relay task's clock, cloned onto the handle so a publication read
/// is judged when it is asked. The closure is the clock; `Debug` names
/// the clock rather than printing it.
struct RelayNow {
    now: Arc<dyn Fn() -> Millis + Send + Sync>,
}

impl RelayNow {
    fn new(now: impl Fn() -> Millis + Send + Sync + 'static) -> Self {
        Self { now: Arc::new(now) }
    }

    fn get(&self) -> Millis {
        (self.now)()
    }
}

impl Clone for RelayNow {
    fn clone(&self) -> Self {
        Self {
            now: Arc::clone(&self.now),
        }
    }
}

impl std::fmt::Debug for RelayNow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayNow")
    }
}

/// The node's end of the owner.
#[derive(Clone, Debug)]
pub struct RelayHandle {
    inbox: mpsc::UnboundedSender<Cmd>,
    snapshot: Arc<Mutex<Arc<RelaySnapshot>>>,
    /// This node's origin arm times. Not a field of [`RelaySnapshot`]:
    /// that snapshot is what health projects, and a transaction id does
    /// not belong on it. A read judges the arm with [`RelayNow`].
    origins: Arc<Mutex<Arc<HashMap<TxId, Millis>>>>,
    now: RelayNow,
}

impl RelayHandle {
    /// A transaction this node originated: it stems from here. `true` when
    /// the relay took it; `false` when the owner has stopped, which is the
    /// one case the pool shows the transaction itself (RX-2).
    pub fn relay_local(&self, tx: TxId, blob: Vec<u8>) -> bool {
        self.inbox
            .send(Cmd::Local {
                tx,
                blob: blob.into(),
            })
            .is_ok()
    }

    /// Transactions that left the pool: their relay state is released.
    pub fn departed(&self, txs: Vec<TxId>) {
        let _gone = self.inbox.send(Cmd::Departed(txs));
    }

    /// The zone's published reads.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RelaySnapshot> {
        Arc::clone(&self.snapshot.lock().expect("relay snapshot"))
    }

    /// This node's judgment of `tx`, if it still holds the origin
    /// unpublished. Absent once the transaction has fluffed, and absent
    /// for a relay position.
    ///
    /// The arm time is the last snapshot. The clock is this read's. A
    /// timer that has not yet woken still reports
    /// [`OriginPublication::HeldOverdue`] once the budget has elapsed.
    #[must_use]
    pub fn origin_publication(&self, tx: TxId) -> Option<OriginPublication> {
        let armed_at = self
            .origins
            .lock()
            .expect("origin arms")
            .get(&tx)
            .copied()?;
        Some(OriginPublication::judge(armed_at, self.now.get()))
    }

    /// End the task. Sessions established after this are not relayed to.
    pub fn stop(&self) {
        let _gone = self.inbox.send(Cmd::Stop);
    }
}

/// What reaches the task.
pub(super) enum Cmd {
    /// A session completed its handshake.
    Established(Established),
    /// A session is gone.
    Closed(SocketId),
    /// A 2002 batch, admitted. `parsed` is every id the pool could read;
    /// `stem` and `fluff` are the admitted ones, split by the batch's flag.
    Arrived {
        source: ConnectionId,
        parsed: Vec<TxId>,
        stem: Vec<(TxId, TxBlob)>,
        fluff: Vec<(TxId, TxBlob)>,
        /// The session's permit for the batch, dropped once the arrival
        /// is in the zone: the session reads its next frame then.
        taken: Taken,
    },
    /// A transaction this node originated.
    Local { tx: TxId, blob: TxBlob },
    /// Transactions that left the pool.
    Departed(Vec<TxId>),
    /// What the carrier task did with messages it was handed: sent to a
    /// peer, or discarded (a refusal at its door included).
    Carrier(Vec<CarrierOutcome>),
    /// End the task.
    Stop,
}

/// The zone's name for a session: the socket id, little-endian, in the
/// first eight bytes. The nil id stays "this node" (`Relay`'s local
/// origin), which no socket id maps to: zero is not a socket id.
#[must_use]
pub fn connection_id(id: SocketId) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&id.get().to_le_bytes());
    ConnectionId::from_bytes(bytes)
}

/// What the owner's `stem_out` did with a stem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StemOut {
    /// Written on the ordinary connection and recorded.
    Written,
    /// Queued on a carrier channel; the verdict records it. Any refused part
    /// already took its no-window path.
    Carried,
    /// No window could take it: an origin is held, a relayed stem ended.
    Ended,
    /// The ordinary write failed; nothing was recorded.
    WriteFailed,
}

/// Why a relayed stem ended its stem phase here and was broadcast. None is
/// a fault. A node with no outbound session takes it
/// for every stem it holds, so it is a debug line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StemFallback {
    /// No outbound session is a stem successor, after the refresh.
    NoSuccessor,
    /// The refresh turned the epoch to fluff.
    EpochFluffs,
    /// The successor's session was gone when it was written, twice.
    WriteFailed,
    /// The successor's session carries cover and no window could take the
    /// stem: its channel's queue refused it, or it holds no slot
    /// (`CVR-R6`). On a covered session a stem leaves only inside a window.
    NoWindow,
}

impl StemFallback {
    const fn reason(self) -> &'static str {
        match self {
            Self::NoSuccessor => "no outbound session to stem to",
            Self::EpochFluffs => "the epoch turned to fluff",
            Self::WriteFailed => "the stem successor's session was closing",
            Self::NoWindow => "no carrier window could take the stem",
        }
    }
}

/// Start the owner on `parts.runtime`.
///
/// # Errors
/// [`RelayStartError`]: the zone refused the configuration, the timing
/// engine is closing, or the carrier's dummy did not frame.
pub fn start<C: Clock + Clone + Send + Sync + 'static>(
    parts: RelayParts<C>,
) -> Result<Started, RelayStartError> {
    let RelayParts {
        config,
        pool,
        node_sync,
        timing,
        runtime,
        verdict,
        mut rng,
        mut carrier_rng,
    } = parts;
    if config.min_epoch_secs == 0 {
        return Err(RelayStartError::ZeroEpoch);
    }
    let owner = timing
        .register(OwnerClass::Relay)
        .map_err(RelayStartError::Timing)?;
    let clock = owner.clock().clone();
    let now = millis(clock.now());
    // The epoch scheduler reads only this pair; embargo timers are built per
    // connector inside `Relay::new`, from the declarations.
    let params = DandelionParams {
        min_epoch_secs: config.min_epoch_secs,
        epoch_jitter_secs: config.epoch_jitter_secs,
        ..DandelionParams::inherited()
    };
    let zone = Relay::new(
        params,
        config.stems,
        config.noise,
        &config.connectors,
        &config.added_encryption,
        now,
        &mut *rng,
    )
    .map_err(RelayStartError::Zone)?;
    // The carrier exists exactly when the zone carries. The dummy goes on
    // the wire, so it is a Levin frame (`noise_notify`), never a zeroed
    // buffer; a channel holds at most one full-size message pending.
    let (inbox_tx, inbox) = mpsc::unbounded_channel();
    let carrier = if config.noise {
        let dummy = noise_notify(carrier::WINDOW_BYTES).map_err(RelayStartError::Carrier)?;
        let window = dummy.len();
        let budget = carrier::BACKLOG_CAP_WINDOWS;
        let queues = NoiseQueues::new(
            config.stems,
            dummy,
            usize::try_from(budget).unwrap_or(usize::MAX),
        )
        .ok_or(RelayStartError::CarrierQueue)?;
        let carrier_owner = timing
            .register(OwnerClass::Carrier)
            .map_err(RelayStartError::Timing)?;
        let schedule = Carrier::new(config.stems, now, &mut *carrier_rng);
        let (carrier_tx, carrier_inbox) = mpsc::unbounded_channel();
        runtime.spawn(
            CarrierTask {
                carrier: schedule,
                queues,
                sessions: HashMap::new(),
                rng: carrier_rng,
                owner: carrier_owner,
                inbox: carrier_inbox,
                to_owner: inbox_tx.clone(),
            }
            .run(),
        );
        Some(CarrierLink::new(carrier_tx, window))
    } else {
        None
    };
    let floors = config
        .connectors
        .iter()
        .map(|connector| (*connector, FloorWatch::new(MIN_PROVISIONED_OUT_PEERS)))
        .collect();
    let last_verdict = zone.origin_verdict();
    if let Some(sink) = &verdict {
        sink(last_verdict);
    }
    let snapshot = Arc::new(Mutex::new(Arc::new(RelaySnapshot::default())));
    let origins = Arc::new(Mutex::new(Arc::new(HashMap::new())));
    let port = Arc::new(Port::new(
        inbox_tx.clone(),
        Arc::clone(&pool),
        node_sync.clone(),
    ));
    let handle = RelayHandle {
        inbox: inbox_tx,
        snapshot: Arc::clone(&snapshot),
        origins: Arc::clone(&origins),
        now: RelayNow::new(move || millis(clock.now())),
    };
    let actor = Actor {
        driver: Driver::new(zone),
        carrier,
        rng,
        sessions: HashMap::new(),
        floors,
        pool,
        node_sync,
        owner,
        inbox,
        verdict,
        last_verdict,
        snapshot,
        origins,
    };
    runtime.spawn(actor.run());
    Ok(Started { port, handle })
}

/// Nanoseconds in a millisecond: the engine's ticks are nanoseconds, the
/// zone's clock milliseconds.
const NANOS_PER_MILLI: u64 = 1_000_000;

pub(super) fn millis(tick: Tick) -> Millis {
    tick.get() / NANOS_PER_MILLI
}

pub(super) fn tick_of(ms: Millis) -> Tick {
    Tick::new(ms.saturating_mul(NANOS_PER_MILLI))
}

struct Actor<C: Clock + Clone + Send + Sync + 'static> {
    driver: Driver,
    /// The owner's side of the carrier task. `None` when cover is off.
    carrier: Option<CarrierLink>,
    rng: Box<dyn RelayRng + Send>,
    /// The registry: every established session, by the zone's name for it.
    sessions: HashMap<ConnectionId, Established>,
    floors: Vec<(ConnectorId, FloorWatch)>,
    pool: Arc<dyn PoolDoor>,
    node_sync: watch::Receiver<NodeSync>,
    owner: OwnerHandle<C>,
    inbox: mpsc::UnboundedReceiver<Cmd>,
    /// Who hears the hop-0 verdict, and the value it last heard.
    verdict: Option<VerdictSink>,
    last_verdict: OriginVerdict,
    snapshot: Arc<Mutex<Arc<RelaySnapshot>>>,
    origins: Arc<Mutex<Arc<HashMap<TxId, Millis>>>>,
}

impl<C: Clock + Clone + Send + Sync + 'static> Actor<C> {
    async fn run(mut self) {
        // The zone's own sync state starts from the watch as it reads now:
        // a node already synchronised has no change to wait for, and the
        // zone's planner of held origins reads only its own copy.
        let sync = *self.node_sync.borrow_and_update();
        let now = self.now();
        self.driver.zone_mut().set_node_sync(sync, now);
        // The zone drew its first epoch at construction; arm its deadline.
        self.arm();
        self.publish();
        loop {
            tokio::select! {
                biased;
                cmd = self.inbox.recv() => match cmd {
                    None | Some(Cmd::Stop) => break,
                    Some(cmd) => self.on_cmd(cmd),
                },
                wake = self.owner.wait_wake_async() => {
                    if wake.is_err() {
                        break;
                    }
                    self.on_wake();
                }
                changed = self.node_sync.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    self.on_sync_changed();
                }
            }
        }
        if let Some(carrier) = &self.carrier {
            carrier.stop();
        }
        if let Err(_engine_closing) = self.owner.deregister() {}
    }

    fn now(&self) -> Millis {
        millis(self.owner.clock().now())
    }

    fn arm(&self) {
        if let Err(_engine_closing) = self.owner.clear() {}
        if let Err(_engine_closing) = self.owner.arm(tick_of(self.driver.next_wake())) {}
    }

    fn publish(&mut self) {
        let zone = self.driver.zone();
        let snapshot = RelaySnapshot {
            noise: zone.noise_enabled(),
            live_stems: zone.live_stems(),
            stem_in_flight: zone.stem_observations_in_flight(),
            tallies: zone.stem_snapshot(),
            floors: self
                .floors
                .iter()
                .filter_map(|(connector, watch)| watch.snapshot().map(|snap| (*connector, snap)))
                .collect(),
        };
        if let Ok(mut slot) = self.snapshot.lock() {
            *slot = Arc::new(snapshot);
        }
        if let Ok(mut slot) = self.origins.lock() {
            *slot = Arc::new(zone.origin_armed());
        }
        let verdict = zone.origin_verdict();
        if verdict != self.last_verdict {
            self.last_verdict = verdict;
            if let Some(sink) = &self.verdict {
                sink(verdict);
            }
        }
    }

    fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Established(session) => {
                let id = connection_id(session.id());
                let direction = match session.direction() {
                    Direction::Inbound => PeerDirection::Inbound,
                    Direction::Outbound => PeerDirection::Outbound,
                };
                let connector = session.connector();
                if let Some(carrier) = &self.carrier {
                    carrier.set_session(id, Some(session.clone()));
                }
                self.sessions.insert(id, session);
                self.driver.zone_mut().on_session_established(
                    id,
                    direction,
                    connector,
                    &mut *self.rng,
                );
            }
            Cmd::Closed(socket) => {
                let id = connection_id(socket);
                self.sessions.remove(&id);
                if let Some(carrier) = &self.carrier {
                    carrier.set_session(id, None);
                }
                self.driver.zone_mut().on_connection_close(&id);
            }
            Cmd::Carrier(outcomes) => {
                for outcome in outcomes {
                    self.apply_verdict(outcome);
                }
            }
            Cmd::Arrived {
                source,
                parsed,
                stem,
                fluff,
                taken,
            } => {
                // Seen circulating: the stem watch resolves what it was
                // waiting on, and the pool shows those (Q9).
                let propagated = self.driver.zone_mut().record_arrival(&parsed, Some(source));
                for tx in &propagated {
                    self.pool.shown(tx);
                }
                if !stem.is_empty() {
                    self.dispatch(&stem, Some(source), false);
                }
                if !fluff.is_empty() {
                    self.fluff_and_record(&fluff, Some(source));
                }
                drop(taken);
            }
            Cmd::Local { tx, blob } => self.dispatch(&[(tx, blob)], None, true),
            Cmd::Departed(txs) => {
                for tx in &txs {
                    self.driver.zone_mut().release(tx);
                }
            }
            Cmd::Stop => {}
        }
        self.tell_carrier();
        self.arm();
        self.publish();
    }

    fn on_sync_changed(&mut self) {
        let sync = *self.node_sync.borrow_and_update();
        let now = self.now();
        self.driver.zone_mut().set_node_sync(sync, now);
        // A turn to synchronised makes held origins due now: poll rather
        // than wait for the grid.
        self.on_wake();
    }

    /// The timing engine's wake: the floor watch, then the zone's poll and
    /// its effects, then the carrier's verdicts.
    fn on_wake(&mut self) {
        self.note_floors();
        let now = self.now();
        let effects = self.driver.poll(now, &mut *self.rng);
        for effect in effects {
            self.apply(effect);
        }
        self.tell_carrier();
        self.arm();
        self.publish();
    }

    /// Hand the carrier task the zone's view of its slots and covered
    /// sessions when it changed, and say when an epoch began since.
    fn tell_carrier(&mut self) {
        let zone = self.driver.zone();
        if let Some(carrier) = self.carrier.as_mut() {
            carrier.tell(zone);
        }
    }

    /// Per configured connector, the achieved outbound count against the
    /// provisioning floor; a crossing is logged once each way (§16.6).
    fn note_floors(&mut self) {
        for (connector, watch) in &mut self.floors {
            let achieved = self
                .sessions
                .values()
                .filter(|session: &&Established| {
                    session.direction() == Direction::Outbound && session.connector() == *connector
                })
                .count();
            let achieved = u32::try_from(achieved).unwrap_or(u32::MAX);
            match watch.note(AchievedOutConnections::new(achieved)) {
                FloorTransition::Steady => {}
                FloorTransition::WentBelow => tracing::warn!(
                    ?connector,
                    achieved,
                    floor = MIN_PROVISIONED_OUT_PEERS,
                    "outbound connections fell below the relay provisioning floor"
                ),
                FloorTransition::Recovered => tracing::warn!(
                    ?connector,
                    achieved,
                    floor = MIN_PROVISIONED_OUT_PEERS,
                    "outbound connections recovered the relay provisioning floor"
                ),
            }
        }
    }

    fn apply(&mut self, effect: Effect) {
        match effect {
            Effect::Fluff { peer, blobs } => {
                if self.send_batch(peer, &blobs, true) {
                    tracing::debug!(
                        ?peer,
                        count = blobs.len(),
                        bytes = blobs.iter().map(|blob| blob.len()).sum::<usize>(),
                        "a fluff batch was written"
                    );
                } else {
                    tracing::debug!(?peer, "a fluff batch was not written; the session is gone");
                }
            }
            // The log never names a stem's successor or its transactions
            // (`RPC_CHANNEL.md` §6.4, RT-O9.3): it sits on disk, at any
            // level a runtime option may raise.
            Effect::Stem {
                peer,
                tx,
                blob,
                source,
                carrier,
            } => {
                let one = [(tx, blob)];
                let now = self.now();
                match self.stem_out(&one, peer, carrier, source, source.is_none(), now) {
                    StemOut::Written => {
                        tracing::debug!("a zone stem was written");
                    }
                    StemOut::WriteFailed => {
                        tracing::debug!("a zone stem was not written");
                        self.missed_ordinary_write(&one, peer, source, now);
                    }
                    StemOut::Carried | StemOut::Ended => {}
                }
            }
            Effect::Published { txs } => {
                for tx in &txs {
                    self.pool.shown(tx);
                }
            }
        }
    }

    /// A carrier verdict: the last window of a held message went out, or
    /// the carrier dropped it. The pool is told only now, when the send is
    /// known to have been made and the successor is known (§3.1d).
    fn apply_verdict(&mut self, outcome: CarrierOutcome) {
        let Some(carrier) = self.carrier.as_mut() else {
            return;
        };
        let Some(pending) = carrier.take(outcome.token()) else {
            tracing::debug!("a carrier verdict named a token nothing holds");
            return;
        };
        // Taken by a block meanwhile: nothing to relay or observe.
        if !self.pool.holds(&pending.tx) {
            return;
        }
        let one = [(pending.tx, pending.blob)];
        if let CarrierOutcome::Discarded { started, .. } = outcome {
            // The carrier dropped it (`CVR-R6`).
            tracing::debug!("the carrier discarded a stem");
            let now = self.now();
            self.no_window(&one, pending.source, pending.local, started, now);
            return;
        }
        let Some(successor) = outcome.peer() else {
            return;
        };
        let now = self.now();
        self.driver
            .zone_mut()
            .record_stem(&one, successor, pending.source, now, &mut *self.rng);
    }
}

/// The transactions' short ids for a debug line, in a measurement build
/// only ([`TxId::measured_list`]).
fn measured_ids(txs: &[(TxId, TxBlob)]) -> Option<String> {
    let ids: Vec<TxId> = txs.iter().map(|(tx, _)| *tx).collect();
    TxId::measured_list(&ids)
}
