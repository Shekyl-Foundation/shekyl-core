// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay task: the zone, its driver, the carrier queues, the floor
//! watch and the session map, owned by one task and reached by
//! [`Cmd`]. This is `levin_notify.cpp`'s strand with the callbacks made
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
use shekyl_levin::{
    fragmented_notify, noise_notify, NewTransactions, PortableMap, NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_p2p_session::{Direction, Established, Message, SocketId, Taken};
use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::params::{DandelionParams, MIN_PROVISIONED_OUT_PEERS};
use shekyl_relay_privacy::schedule::{Millis, PeerDirection};
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::{Clock, EngineError, Handle, OwnerClass, OwnerHandle, Tick};
use tokio::sync::{mpsc, watch};

use super::pool::PoolDoor;
use super::port::Port;
use super::snapshot::RelaySnapshot;
use crate::driver::{Driver, Effect};
use crate::floor_diag::{AchievedOutConnections, FloorTransition, FloorWatch};
use crate::graph::{
    ConnectorId, NodeSync, OriginVerdict, Relay, RelayCarrier, RelayDispatch, RelayNewError,
    RelayPlan, TxBlob,
};
use crate::noise_queue::{CarrierOutcome, CarrierToken, NoiseQueues};
use crate::stem_watch::TxId;

/// The zone a node runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    /// Outgoing stem connections per epoch.
    pub stems: usize,
    /// The epoch floor, seconds.
    pub min_epoch_secs: u32,
    /// Added to the floor at each draw, up to this many seconds.
    pub epoch_jitter_secs: u32,
    /// Whether the zone runs the covert carrier. Development only
    /// (`dev-relay-cover`); a shipped node never sets it.
    pub noise: bool,
    /// The connectors this node built. The zone's embargo timers and its
    /// hidden slot are derived from their declarations.
    pub connectors: Vec<ConnectorId>,
}

impl RelayConfig {
    /// The inherited zone: two stems, a ten-minute epoch with up to thirty
    /// seconds of jitter (`CRYPTONOTE_DANDELIONPP_STEMS`, `_MIN_EPOCH`,
    /// `_EPOCH_RANGE`), the carrier off unless asked.
    #[must_use]
    pub fn inherited(connectors: Vec<ConnectorId>, noise: bool) -> Self {
        Self {
            stems: 2,
            min_epoch_secs: 600,
            epoch_jitter_secs: 30,
            noise,
            connectors,
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
}

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
}

impl std::fmt::Display for RelayStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroEpoch => f.write_str("the relay epoch floor is zero"),
            Self::Zone(err) => write!(f, "the relay zone refused its configuration: {err:?}"),
            Self::Timing(err) => write!(f, "the timing engine refused the relay owner: {err:?}"),
            Self::Carrier(err) => write!(f, "the carrier's dummy window did not frame: {err:?}"),
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

/// The node's end of the owner.
#[derive(Clone, Debug)]
pub struct RelayHandle {
    inbox: mpsc::UnboundedSender<Cmd>,
    verdict: watch::Receiver<OriginVerdict>,
    snapshot: Arc<Mutex<Arc<RelaySnapshot>>>,
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

    /// Whether a local origin leaves on a session that hides this node's
    /// address, as the zone last judged it. The managed Tor supervisor and
    /// the node's health read this.
    #[must_use]
    pub fn origin_verdict(&self) -> watch::Receiver<OriginVerdict> {
        self.verdict.clone()
    }

    /// The zone's published reads.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RelaySnapshot> {
        Arc::clone(&self.snapshot.lock().expect("relay snapshot"))
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

/// A transaction the carrier holds, by its token, until the carrier says
/// whether its last window went out.
struct Pending {
    tx: TxId,
    blob: TxBlob,
    source: Option<ConnectionId>,
    /// Originated here: not sent means held, never fluffed (§92.5c).
    local: bool,
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
        mut rng,
    } = parts;
    if config.min_epoch_secs == 0 {
        return Err(RelayStartError::ZeroEpoch);
    }
    let owner = timing
        .register(OwnerClass::Relay)
        .map_err(RelayStartError::Timing)?;
    let now = millis(owner.clock().now());
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
        now,
        &mut *rng,
    )
    .map_err(RelayStartError::Zone)?;
    // The carrier's buffers exist exactly when the zone carries. The dummy
    // goes on the wire, so it is a Levin frame (`noise_notify`), never a
    // zeroed buffer; the budget is what one epoch can deliver on a channel.
    let noise = if config.noise {
        let dummy = noise_notify(carrier::WINDOW_BYTES).map_err(RelayStartError::Carrier)?;
        let budget = carrier::noise_windows_in_epoch(config.min_epoch_secs);
        NoiseQueues::new(
            config.stems,
            dummy,
            usize::try_from(budget).unwrap_or(usize::MAX),
        )
    } else {
        None
    };
    let floors = config
        .connectors
        .iter()
        .map(|connector| (*connector, FloorWatch::new(MIN_PROVISIONED_OUT_PEERS)))
        .collect();
    let (inbox_tx, inbox) = mpsc::unbounded_channel();
    let (verdict_tx, verdict) = watch::channel(zone.origin_verdict());
    let snapshot = Arc::new(Mutex::new(Arc::new(RelaySnapshot::default())));
    let port = Arc::new(Port::new(
        inbox_tx.clone(),
        Arc::clone(&pool),
        node_sync.clone(),
    ));
    let handle = RelayHandle {
        inbox: inbox_tx,
        verdict,
        snapshot: Arc::clone(&snapshot),
    };
    let actor = Actor {
        driver: Driver::new(zone),
        noise,
        rng,
        sessions: HashMap::new(),
        carrier_pending: HashMap::new(),
        next_token: 0,
        floors,
        pool,
        node_sync,
        owner,
        inbox,
        verdict: verdict_tx,
        snapshot,
    };
    runtime.spawn(actor.run());
    Ok(Started { port, handle })
}

fn millis(tick: Tick) -> Millis {
    tick.get() / 1_000_000
}

fn tick_of(ms: Millis) -> Tick {
    Tick::new(ms.saturating_mul(1_000_000))
}

struct Actor<C: Clock + Clone + Send + Sync + 'static> {
    driver: Driver,
    noise: Option<NoiseQueues>,
    rng: Box<dyn RelayRng + Send>,
    /// The registry: every established session, by the zone's name for it.
    sessions: HashMap<ConnectionId, Established>,
    carrier_pending: HashMap<u64, Pending>,
    next_token: u64,
    floors: Vec<(ConnectorId, FloorWatch)>,
    pool: Arc<dyn PoolDoor>,
    node_sync: watch::Receiver<NodeSync>,
    owner: OwnerHandle<C>,
    inbox: mpsc::UnboundedReceiver<Cmd>,
    verdict: watch::Sender<OriginVerdict>,
    snapshot: Arc<Mutex<Arc<RelaySnapshot>>>,
}

impl<C: Clock + Clone + Send + Sync + 'static> Actor<C> {
    async fn run(mut self) {
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
        if let Err(_engine_closing) = self.owner.deregister() {}
    }

    fn now(&self) -> Millis {
        millis(self.owner.clock().now())
    }

    fn arm(&self) {
        if let Err(_engine_closing) = self.owner.clear() {}
        if let Err(_engine_closing) = self.owner.arm(tick_of(self.driver.next_wake())) {}
    }

    fn publish(&self) {
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
        let verdict = zone.origin_verdict();
        self.verdict.send_if_modified(|current| {
            if *current == verdict {
                false
            } else {
                *current = verdict;
                true
            }
        });
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
                self.driver.zone_mut().on_connection_close(&id);
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
        let outcomes = self
            .noise
            .as_mut()
            .map(NoiseQueues::take_resolved)
            .unwrap_or_default();
        for outcome in outcomes {
            self.apply_verdict(outcome);
        }
        self.arm();
        self.publish();
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
                if !self.send_batch(peer, &blobs, true) {
                    tracing::debug!(?peer, "a fluff batch was not written; the session is gone");
                }
            }
            Effect::Stem { peer, blobs } => {
                if !self.send_batch(peer, &blobs, false) {
                    tracing::debug!(
                        ?peer,
                        "a reshape stem was not written; the next fire fluffs"
                    );
                }
            }
            Effect::Published { txs } => {
                for tx in &txs {
                    self.pool.shown(tx);
                }
            }
            Effect::NoiseSend { channel, peer } => {
                // `take_for_send` hands back the same window until a
                // resolution: `sent` advances one fragment, `failed` restarts
                // the channel so a partly sent message is never finished to
                // a different successor.
                let Some(queue) = self.noise.as_mut() else {
                    debug_assert!(false, "NoiseSend on a zone with no carrier");
                    return;
                };
                let Some(send) = queue.take_for_send(channel, peer) else {
                    return;
                };
                let written = self
                    .sessions
                    .get(&peer)
                    .is_some_and(|session: &Established| session.send_window(send.bytes()).is_ok());
                if written {
                    send.sent(queue);
                } else {
                    send.failed(queue);
                }
            }
            Effect::NoiseUnbind { channel } => {
                let Some(queue) = self.noise.as_mut() else {
                    debug_assert!(false, "NoiseUnbind on a zone with no carrier");
                    return;
                };
                queue.unbind(channel);
            }
        }
    }

    /// A carrier verdict: the last window of a held message went out, or
    /// the carrier dropped it. The pool is told only now, when the send is
    /// known to have been made and the successor is known (§3.1d).
    fn apply_verdict(&mut self, outcome: CarrierOutcome) {
        let CarrierToken(token) = outcome.token();
        let Some(pending) = self.carrier_pending.remove(&token) else {
            tracing::debug!(token, "a carrier verdict named a token nothing holds");
            return;
        };
        // Taken by a block meanwhile: nothing to relay or observe.
        if !self.pool.holds(&pending.tx) {
            return;
        }
        let one = [(pending.tx, pending.blob)];
        if !outcome.was_sent() {
            if pending.local {
                // An origin the carrier dropped is held, neither shown nor
                // fluffed (§92.5c).
                let now = self.now();
                self.driver.zone_mut().hold_origin(&one, now);
                return;
            }
            // A forwarded stem the carrier dropped takes the failed-stem
            // fallback: it fluffs, which is what moves it along.
            tracing::debug!(tx = ?pending.tx, "the carrier discarded a forwarded stem; fluffing");
            self.fluff_and_record(&one, pending.source);
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

    /// `dandelionpp_notify`: plan, then send on the carrier the plan names,
    /// retry once over refreshed stems, and fluff what could not stem.
    fn dispatch(&mut self, txs: &[(TxId, TxBlob)], source: Option<ConnectionId>, local: bool) {
        let node_sync = *self.node_sync.borrow();
        let now = self.now();
        let RelayDispatch { plan, carrier } = self.driver.zone_mut().plan_dispatch_with_refresh(
            source,
            local,
            node_sync,
            &mut *self.rng,
        );
        match plan {
            RelayPlan::AwaitSync => {
                tracing::debug!("unsynchronised node originates no stem; the zone holds it");
                self.driver.zone_mut().hold_origin(txs, now);
                return;
            }
            RelayPlan::NoOwnEdge => {
                tracing::debug!("no outbound edge hides this node's address; the origin is held");
                self.driver.zone_mut().hold_origin(txs, now);
                return;
            }
            RelayPlan::OwnEdge(destination) => {
                if self.send_stem(destination, txs) {
                    self.driver.zone_mut().record_stem(
                        txs,
                        destination,
                        source,
                        now,
                        &mut *self.rng,
                    );
                    return;
                }
                tracing::debug!("the own-edge write failed; the origin is held");
                self.driver.zone_mut().hold_origin(txs, now);
                return;
            }
            RelayPlan::Stem(_) | RelayPlan::NoRoute | RelayPlan::FluffEpoch => {}
        }
        let mut to_send: Vec<(TxId, TxBlob)> = txs.to_vec();
        if let (RelayPlan::Stem(_), RelayCarrier::Noise { channel }) = (plan, carrier) {
            // One transaction per carrier message: two in one would share
            // a window, a slot and a successor. What the carrier refuses
            // takes the ordinary stem below; the batch splits rather than
            // failing whole, so one oversize transaction does not put its
            // neighbours on the clear wire.
            let mut refused = Vec::new();
            for (tx, blob) in to_send {
                if self
                    .carrier_pending
                    .values()
                    .any(|pending| pending.tx == tx)
                {
                    // The carrier owns it; its verdict resolves it.
                    continue;
                }
                let Some(framed) = self.frame_for_carrier(&blob) else {
                    refused.push((tx, blob));
                    continue;
                };
                let token = self.next_token;
                self.next_token = self.next_token.wrapping_add(1);
                // Recorded before enqueued: both sides own the token or
                // neither does.
                self.carrier_pending.insert(
                    token,
                    Pending {
                        tx,
                        blob: TxBlob::clone(&blob),
                        source,
                        local,
                    },
                );
                let enqueued = self
                    .noise
                    .as_mut()
                    .is_some_and(|queue| queue.enqueue(channel.get(), framed, CarrierToken(token)));
                if !enqueued {
                    self.carrier_pending.remove(&token);
                    refused.push((tx, blob));
                }
            }
            to_send = refused;
            if to_send.is_empty() {
                return;
            }
        }
        if plan != RelayPlan::FluffEpoch {
            if let RelayPlan::Stem(destination) = plan {
                if self.send_stem(destination, &to_send) {
                    self.driver.zone_mut().record_stem(
                        &to_send,
                        destination,
                        source,
                        now,
                        &mut *self.rng,
                    );
                    return;
                }
            }
            self.driver.zone_mut().update_stems(&mut *self.rng);
            let retry = self
                .driver
                .zone_mut()
                .plan_relay(source, local, node_sync, &mut *self.rng);
            match retry {
                RelayPlan::AwaitSync => return,
                RelayPlan::Stem(destination) | RelayPlan::OwnEdge(destination) => {
                    if self.send_stem(destination, &to_send) {
                        self.driver.zone_mut().record_stem(
                            &to_send,
                            destination,
                            source,
                            now,
                            &mut *self.rng,
                        );
                        return;
                    }
                }
                RelayPlan::NoRoute | RelayPlan::FluffEpoch | RelayPlan::NoOwnEdge => {}
            }
            tracing::error!("unable to send transaction(s) via Dandelion++ stem");
        }
        self.fluff_and_record(&to_send, source);
    }

    /// The pool is told the transactions are shown, then the zone queues
    /// them for the next fluff release. One argument for both, so what is
    /// recorded is what is sent.
    fn fluff_and_record(&mut self, txs: &[(TxId, TxBlob)], source: Option<ConnectionId>) {
        for (tx, _) in txs {
            self.pool.shown(tx);
        }
        let blobs: Vec<TxBlob> = txs.iter().map(|(_, blob)| TxBlob::clone(blob)).collect();
        let now = self.now();
        let accepted = self
            .driver
            .zone_mut()
            .queue_fluff(&blobs, source, now, &mut *self.rng);
        if accepted == 0 {
            tracing::warn!("unable to send transaction(s), no available connections");
        }
    }

    fn send_stem(&self, destination: ConnectionId, txs: &[(TxId, TxBlob)]) -> bool {
        let blobs: Vec<TxBlob> = txs.iter().map(|(_, blob)| TxBlob::clone(blob)).collect();
        self.send_batch(destination, &blobs, false)
    }

    /// One 2002 to `peer`, `fluff` as the batch's flag. `false` when the
    /// session is not held or the write was refused.
    fn send_batch(&self, peer: ConnectionId, blobs: &[TxBlob], fluff: bool) -> bool {
        let Some(session): Option<&Established> = self.sessions.get(&peer) else {
            return false;
        };
        let message = Message::NewTransactions(NewTransactions {
            txs: blobs.iter().map(|blob| blob.to_vec()).collect(),
            padding: Vec::new(),
            dandelionpp_fluff: fluff,
        });
        match session.send(&message) {
            Ok(()) => true,
            Err(refused) => {
                tracing::debug!(?peer, %refused, "a transaction batch was not sent");
                false
            }
        }
    }

    /// A stem as the carrier carries it: one 2002 with the one blob, cut
    /// into the carrier's windows.
    fn frame_for_carrier(&self, blob: &TxBlob) -> Option<Vec<u8>> {
        let window = self.noise.as_ref()?.window();
        let payload = NewTransactions {
            txs: vec![blob.to_vec()],
            padding: Vec::new(),
            dandelionpp_fluff: false,
        }
        .store()
        .ok()?;
        fragmented_notify(window, NOTIFY_NEW_TRANSACTIONS, &payload).ok()
    }
}
