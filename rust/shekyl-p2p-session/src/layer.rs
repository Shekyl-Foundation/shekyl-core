// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The session table and the layer's verbs (brief §7.1, §7.8).
//!
//! The table has one row per admitted connection from adoption to the end
//! of its task. The row's state is written by the session's own task and
//! by [`SessionLayer::close`], which records the first end; everything
//! else reads a published [`Board`]. The admission reservation and the
//! send half sit in the row so that a close from any thread reaches the
//! socket at once; the receive half sits in the task alone.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shekyl_capped_stream::SendHalf;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{BasicNodeData, CoreSyncData, PeerlistEntry};
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{
    monotonic_ms, CloseCause, CloseKind, ConnectorId, DialEnd, DialFailure, Ipv4Subnet, OpenSocket,
    Reached, Retry, SocketId, Sockets, StreamEnd,
};
use tokio::sync::{oneshot, watch, Notify};

use crate::board::{Board, Row};
use crate::dial::{Channel, Dial};
use crate::endpoint::Endpoint;
use crate::handle::{Control, Established, SendRefused, SessionHandle};
use crate::handshake;
use crate::nonce::{HandshakeNonceSet, InFlightNonce};
use crate::owners::{Owners, SessionFacts};
use crate::session::{self, Role};
use crate::timing::Intervals;

/// Messages a session hands to owners before it reads the next frame
/// (brief §7.7): one. The owner's [`crate::Taken`] is the permit; a
/// second slot would hide the stall from the peer.
pub const SESSION_QUEUE_DEPTH: usize = 1;

/// One value per connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerConnector<T> {
    /// Clearnet's.
    pub clearnet: T,
    /// Tor's.
    pub tor: T,
}

impl<T: Copy> PerConnector<T> {
    /// The same value on both connectors.
    pub const fn both(value: T) -> Self {
        Self {
            clearnet: value,
            tor: value,
        }
    }

    /// `connector`'s value.
    pub const fn get(&self, connector: ConnectorId) -> T {
        match connector {
            ConnectorId::Clearnet => self.clearnet,
            ConnectorId::Tor => self.tor,
        }
    }
}

/// What the layer is told once, at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// This node's network. A handshake naming another is dropped.
    pub network_id: [u8; 16],
    /// How long an inbound session may sit in `Handshaking`, per
    /// connector: the connector profile's `handshake_within`.
    pub handshake_within: PerConnector<Duration>,
    /// The invoke deadline and the timed-sync draw.
    pub intervals: Intervals,
}

/// Why the dialer dials (brief §7.4): to keep the session, or to confirm
/// the address answers and close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialAim {
    /// Keep the session: it becomes [`Established`].
    Keep,
    /// Confirm the address and close after the handshake response.
    Confirm,
}

/// What an outbound dial returns when the handshake response passed the
/// checks. A failure is the [`DialEnd`] the row kept.
#[derive(Debug)]
pub enum DialOutcome {
    /// [`DialAim::Keep`]: the session is established and the owners have
    /// been told. The response's list is the dialer's to admit, once.
    Kept {
        session: Established,
        node_data: BasicNodeData,
        list: Vec<PeerlistEntry>,
        sync: CoreSyncData,
    },
    /// [`DialAim::Confirm`]: the response passed and the session is
    /// closed as this node's own close after the channel. `id` is the
    /// admission the response came on, so the list can be admitted under
    /// the session that carried it.
    Confirmed {
        id: SocketId,
        node_data: BasicNodeData,
        list: Vec<PeerlistEntry>,
        sync: CoreSyncData,
    },
}

/// The managed Tor's probe of this node's own onion (`TOR_SUPERVISOR.md`
/// §4.5), ready to write ([`SessionLayer::mint_probe`]).
///
/// Holding it keeps the nonce in the set: dropping it erases the nonce, so
/// a probe the supervisor gave up on cannot arrive as evidence afterwards.
/// The supervisor holds it, not the dial task. The dial can end before the
/// inbound handshake takes the nonce, and aborting the task drops whatever
/// it owns later, on that task.
#[derive(Debug)]
pub struct ProbeHandshake {
    /// The probe nonce. Keep it until the probe ends.
    pub nonce: InFlightNonce,
    /// The 1001 request frame carrying the nonce.
    pub request: Vec<u8>,
    /// When the nonce was minted; the arrival names the probe by it.
    pub minted_at: Tick,
}

/// A channel the layer opened for an outbound dial, before its handshake
/// ([`SessionLayer::connect`]). The caller dates the stream's open here,
/// then runs [`Self::handshake`]. Dropped unhandshaken, the channel is
/// closed as this node's own close and no row is ever placed.
pub struct Dialed<C: Clock + Clone + Send + Sync + 'static> {
    shared: Arc<Shared<C>>,
    channel: Option<Channel>,
    nonce: Option<InFlightNonce>,
    request: Vec<u8>,
}

impl<C: Clock + Clone + Send + Sync + 'static> Dialed<C> {
    /// The admission id the handshake will run under.
    #[must_use]
    pub fn id(&self) -> SocketId {
        self.channel
            .as_ref()
            .expect("a dialed channel is held until its handshake")
            .open
            .id()
    }

    /// Run the outbound handshake and return what it said. [`DialAim::Keep`]
    /// leaves the session established; the owners have been told before
    /// this returns. A failure is the row's end. A caller that stops
    /// waiting (drops this future after the row is placed) ends the
    /// session as this node's own close after the channel: a session
    /// nobody is waiting to keep is not kept.
    ///
    /// # Errors
    /// The handshake's end.
    pub async fn handshake(mut self, aim: DialAim) -> Result<DialOutcome, DialEnd> {
        let channel = self
            .channel
            .take()
            .expect("a dialed channel is held until its handshake");
        let nonce = self
            .nonce
            .take()
            .expect("a dialed channel holds its nonce until its handshake");
        let request = std::mem::take(&mut self.request);
        let id = channel.open.id();
        let (reply, outcome) = oneshot::channel();
        self.shared.place(
            channel,
            Role::Outbound {
                request,
                nonce,
                aim,
                reply,
            },
        );
        tracing::debug!(?id, ?aim, "session adopted (outbound)");
        let mut abandon = Abandon {
            shared: Arc::clone(&self.shared),
            id,
            armed: true,
        };
        let result = outcome
            .await
            .unwrap_or_else(|_| Err(DialEnd::local_close_after_channel()));
        abandon.armed = false;
        result
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> Drop for Dialed<C> {
    fn drop(&mut self) {
        let Some(Channel {
            open, session, gap, ..
        }) = self.channel.take()
        else {
            return;
        };
        drop(session);
        drop(gap);
        let _ = open.close(CloseCause::new(CloseKind::LocalClose));
    }
}

/// Ends a placed outbound session when the dial's caller stops waiting
/// for it. Disarmed once the outcome has been read.
struct Abandon<C: Clock + Clone + Send + Sync + 'static> {
    shared: Arc<Shared<C>>,
    id: SocketId,
    armed: bool,
}

impl<C: Clock + Clone + Send + Sync + 'static> Drop for Abandon<C> {
    fn drop(&mut self) {
        if self.armed {
            self.shared
                .close(self.id, DialEnd::local_close_after_channel());
        }
    }
}

/// What the composition hands the layer.
pub struct Parts<C: Clock + Clone> {
    /// The admission table, shared with the connectors.
    pub sockets: Sockets,
    pub config: SessionConfig,
    pub owners: Owners,
    /// The connectors, for outbound dials.
    pub connectors: Arc<dyn Dial>,
    /// The daemon's one timing engine.
    pub timing: Handle<C>,
    /// This node's tip, published by the chain. Read at each handshake
    /// and each timed sync.
    pub tip: watch::Receiver<CoreSyncData>,
    /// Where session tasks run: the transport runtime.
    pub runtime: tokio::runtime::Handle,
    /// The nonce bytes and the timed-sync jitter.
    pub rng: Box<dyn RelayRng + Send>,
}

pub(crate) struct Slot {
    pub(crate) endpoint: Endpoint,
    pub(crate) established: bool,
    pub(crate) end: Option<DialEnd>,
    open: Option<OpenSocket>,
    send: SendHalf,
    started_unix: u64,
    started_mono: u64,
    stop: Arc<Notify>,
}

struct Table {
    slots: HashMap<SocketId, Slot>,
    board: Board,
}

impl Table {
    fn republish(&mut self) {
        let rows = self
            .slots
            .iter()
            .map(|(id, slot)| {
                Row::new(
                    *id,
                    slot.endpoint,
                    slot.established,
                    slot.started_unix,
                    slot.started_mono,
                )
            })
            .collect();
        self.board = Board::from_rows(rows);
    }
}

pub(crate) struct Shared<C: Clock + Clone> {
    pub(crate) sockets: Sockets,
    pub(crate) config: SessionConfig,
    pub(crate) owners: Owners,
    pub(crate) connectors: Arc<dyn Dial>,
    pub(crate) timing: Handle<C>,
    pub(crate) tip: watch::Receiver<CoreSyncData>,
    runtime: tokio::runtime::Handle,
    pub(crate) rng: Mutex<Box<dyn RelayRng + Send>>,
    pub(crate) nonces: HandshakeNonceSet,
    table: Mutex<Table>,
}

/// The session layer. Clones share one table.
pub struct SessionLayer<C: Clock + Clone> {
    shared: Arc<Shared<C>>,
}

impl<C: Clock + Clone> Clone for SessionLayer<C> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> SessionLayer<C> {
    /// Build the layer. Nothing runs until a connection is adopted or
    /// dialed.
    #[must_use]
    pub fn new(parts: Parts<C>) -> Self {
        let shared = Shared {
            sockets: parts.sockets,
            config: parts.config,
            owners: parts.owners,
            connectors: parts.connectors,
            timing: parts.timing,
            tip: parts.tip,
            runtime: parts.runtime,
            rng: Mutex::new(parts.rng),
            nonces: HandshakeNonceSet::new(),
            table: Mutex::new(Table {
                slots: HashMap::new(),
                board: Board::empty(),
            }),
        };
        Self {
            shared: Arc::new(shared),
        }
    }

    /// The nonce set, for the managed Tor's probe mint.
    #[must_use]
    pub fn nonces(&self) -> &HandshakeNonceSet {
        &self.shared.nonces
    }

    /// This node's tip as the layer last read it.
    #[must_use]
    pub fn tip(&self) -> CoreSyncData {
        self.shared.tip.borrow().clone()
    }

    /// The rows at this moment.
    #[must_use]
    pub fn board(&self) -> Board {
        self.shared
            .table
            .lock()
            .expect("session table")
            .board
            .clone()
    }

    /// Adopt a connection a connector accepted. The row is placed, its
    /// task started, and the inbound handshake awaited under the
    /// connector's `handshake_within`.
    pub fn adopt(&self, channel: Channel) {
        let id = channel.open.id();
        self.shared.place(channel, Role::Inbound);
        tracing::debug!(?id, "session adopted (inbound)");
    }

    /// The engine clock's now: the one clock every owner dates by.
    #[must_use]
    pub fn now(&self) -> Tick {
        self.shared.timing.clock().now()
    }

    /// The runtime session tasks run on, for an owner's own tasks.
    #[must_use]
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.shared.runtime
    }

    /// Open a channel to `endpoint` with a 1001 request minted for it: the
    /// nonce is in the set from here. The caller dates the open and runs
    /// [`Dialed::handshake`].
    ///
    /// # Errors
    /// The connector's end: the dial never reached a stream, or the
    /// request could not be built.
    pub async fn connect(&self, endpoint: Endpoint) -> Result<Dialed<C>, DialEnd> {
        let shared = &self.shared;
        let connector = endpoint.connector();
        let nonce = {
            let mut rng = shared.rng.lock().expect("session rng");
            shared.nonces.mint(connector, &mut **rng)
        };
        let tip = shared.tip.borrow().clone();
        let Some(request) =
            handshake::request_bucket(shared.config.network_id, tip, *nonce.bytes())
        else {
            return Err(DialEnd::local_close());
        };
        let channel = shared.connectors.connect_async(&endpoint).await?;
        Ok(Dialed {
            shared: Arc::clone(shared),
            channel: Some(channel),
            nonce: Some(nonce),
            request,
        })
    }

    /// [`Self::connect`] then [`Dialed::handshake`].
    ///
    /// # Errors
    /// The connector's end, or the handshake's.
    pub async fn dial(&self, endpoint: Endpoint, aim: DialAim) -> Result<DialOutcome, DialEnd> {
        self.connect(endpoint).await?.handshake(aim).await
    }

    /// Mint the managed Tor's probe of this node's own onion
    /// (`TOR_SUPERVISOR.md` §4.5): a probe nonce on the Tor connector and
    /// the 1001 request carrying it. `None` when the request could not be
    /// built.
    #[must_use]
    pub fn mint_probe(&self) -> Option<ProbeHandshake> {
        let shared = &self.shared;
        let minted_at = self.now();
        let nonce = {
            let mut rng = shared.rng.lock().expect("session rng");
            shared
                .nonces
                .mint_probe(ConnectorId::Tor, minted_at, &mut **rng)
        };
        let tip = shared.tip.borrow().clone();
        let request = handshake::request_bucket(shared.config.network_id, tip, *nonce.bytes())?;
        Some(ProbeHandshake {
            nonce,
            request,
            minted_at,
        })
    }

    /// Record `end` as the session's first end and close it: the socket is
    /// closed with the end's cause, the send queue discarded, the task
    /// told to stop. A later end does not replace the first. A session
    /// already gone is left alone.
    pub fn close(&self, id: SocketId, end: DialEnd) {
        self.shared.close(id, end);
    }

    /// Close every session with this node's own close after the channel.
    pub fn shutdown(&self) {
        let ids: Vec<SocketId> = {
            let table = self.shared.table.lock().expect("session table");
            table.slots.keys().copied().collect()
        };
        for id in ids {
            self.shared.close(id, DialEnd::local_close_after_channel());
        }
    }

    /// The admission table, for the composition's reads (counts, bans in
    /// force) and the connectors that share it.
    #[must_use]
    pub fn sockets(&self) -> &Sockets {
        &self.shared.sockets
    }

    /// Ban `host` until `until` and close every session the ban drops.
    /// The ban itself is admission's (brief §7.8): it refuses the next
    /// accept and the next dial; this layer ends the sessions it already
    /// holds. A deadline already past bans nothing.
    pub fn ban_host(&self, host: IpAddr, until: Tick) -> Vec<SocketId> {
        let now = self.shared.timing.clock().now();
        let ids = self.shared.sockets.ban_host(host, until, now);
        self.drop_banned(&ids);
        ids
    }

    /// Ban an IPv4 subnet the same way as [`Self::ban_host`].
    pub fn ban_subnet(&self, subnet: Ipv4Subnet, until: Tick) -> Vec<SocketId> {
        let now = self.shared.timing.clock().now();
        let ids = self.shared.sockets.ban_subnet(subnet, until, now);
        self.drop_banned(&ids);
        ids
    }

    /// Ban `host` until it is lifted.
    pub fn ban_host_permanent(&self, host: IpAddr) -> Vec<SocketId> {
        let ids = self.shared.sockets.ban_host_permanent(host);
        self.drop_banned(&ids);
        ids
    }

    /// Ban an IPv4 subnet until it is lifted.
    pub fn ban_subnet_permanent(&self, subnet: Ipv4Subnet) -> Vec<SocketId> {
        let ids = self.shared.sockets.ban_subnet_permanent(subnet);
        self.drop_banned(&ids);
        ids
    }

    fn drop_banned(&self, ids: &[SocketId]) {
        for id in ids {
            self.shared.close(*id, DialEnd::local_close_after_channel());
        }
    }

    /// How many rows the table holds, established or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared.table.lock().expect("session table").slots.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> Shared<C> {
    /// Place the row and start the task. The board is republished with the
    /// row in `Handshaking`.
    fn place(self: &Arc<Self>, channel: Channel, role: Role) {
        let Channel {
            open,
            session,
            endpoint,
            gap,
        } = channel;
        let id = open.id();
        let stop = Arc::new(Notify::new());
        let slot = Slot {
            endpoint,
            established: false,
            end: None,
            open: Some(open),
            send: session.send_half(),
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            started_mono: monotonic_ms(),
            stop: Arc::clone(&stop),
        };
        {
            let mut table = self.table.lock().expect("session table");
            let replaced = table.slots.insert(id, slot);
            debug_assert!(replaced.is_none(), "one row per admission id");
            table.republish();
        }
        let shared = Arc::clone(self);
        let connector = endpoint.connector();
        self.runtime.spawn(session::run(
            shared, id, connector, session, gap, stop, role,
        ));
    }

    /// The first end wins. Closes the socket, discards the queue, and
    /// tells the task to stop. Idempotent.
    pub(crate) fn close(&self, id: SocketId, end: DialEnd) {
        let (open, send, stop) = {
            let mut table = self.table.lock().expect("session table");
            let Some(slot) = table.slots.get_mut(&id) else {
                return;
            };
            if slot.end.is_some() {
                return;
            }
            slot.end = Some(end);
            (slot.open.take(), slot.send.clone(), Arc::clone(&slot.stop))
        };
        if let Some(open) = open {
            let _ = open.close(end.cause());
        }
        send.discard();
        stop.notify_one();
    }

    /// A stream end the task observed: the connector stamps it.
    pub(crate) fn stream_end(&self, connector: ConnectorId, end: StreamEnd) -> DialEnd {
        let failure = self.connectors.stamp_stream_end(connector, end);
        let cause = match end {
            StreamEnd::PeerClosed => CloseCause::new(CloseKind::PeerClosed),
            StreamEnd::IoError => CloseCause::new(CloseKind::IoError),
            StreamEnd::SendQueueFull => CloseCause::new(CloseKind::SendQueueFull),
        };
        DialEnd::new(failure, cause)
    }

    /// The session's handshake completed: the row is established, the
    /// board republished.
    pub(crate) fn establish(self: &Arc<Self>, id: SocketId) -> Option<Established> {
        let endpoint = {
            let mut table = self.table.lock().expect("session table");
            let slot = table.slots.get_mut(&id)?;
            if slot.end.is_some() {
                return None;
            }
            slot.established = true;
            let endpoint = slot.endpoint;
            table.republish();
            endpoint
        };
        let control: Arc<dyn Control> = Arc::clone(self) as Arc<dyn Control>;
        Some(Established::mint(SessionHandle::new(id, endpoint, control)))
    }

    /// The task ended: take the row out, republish, tell the owners. The
    /// end is the recorded one, or `fallback` when the task observed the
    /// end itself (the peer closed, the connector errored).
    pub(crate) fn finish(&self, id: SocketId, fallback: DialEnd) -> (SessionFacts, DialEnd) {
        let (slot, end) = {
            let mut table = self.table.lock().expect("session table");
            let slot = table
                .slots
                .remove(&id)
                .expect("a session task finishes the row it was started for");
            table.republish();
            let end = slot.end.unwrap_or(fallback);
            (slot, end)
        };
        if let Some(open) = slot.open {
            let _ = open.close(end.cause());
        }
        slot.send.discard();
        let facts = SessionFacts {
            id,
            endpoint: slot.endpoint,
            established: slot.established,
        };
        self.owners.closed(&facts, end);
        (facts, end)
    }

    /// Whether `id` has an end recorded.
    pub(crate) fn ended(&self, id: SocketId) -> Option<DialEnd> {
        let table = self.table.lock().expect("session table");
        table.slots.get(&id).and_then(|slot| slot.end)
    }

    /// Queue `bytes` on `id`'s connector queue. A queue past its bound
    /// closes the session with the connector's stamped end.
    pub(crate) fn send_bytes(&self, id: SocketId, bytes: Vec<u8>) -> Result<(), SendRefused> {
        let (send, connector) = {
            let table = self.table.lock().expect("session table");
            let Some(slot) = table.slots.get(&id) else {
                return Err(SendRefused::Closed);
            };
            if slot.end.is_some() {
                return Err(SendRefused::Closed);
            }
            (slot.send.clone(), slot.endpoint.connector())
        };
        match send.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(CloseKind::SendQueueFull) => {
                let end = self.stream_end(connector, StreamEnd::SendQueueFull);
                self.close(id, end);
                Err(SendRefused::QueueFull)
            }
            Err(_) => Err(SendRefused::Closed),
        }
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> Control for Shared<C> {
    fn send(&self, id: SocketId, bytes: Vec<u8>) -> Result<(), SendRefused> {
        self.send_bytes(id, bytes)
    }

    fn close(&self, id: SocketId, cause: CloseCause) {
        let end = DialEnd::new(
            DialFailure::local(Retry::Again, Reached::StreamOpened),
            cause,
        );
        Shared::close(self, id, end);
    }
}
