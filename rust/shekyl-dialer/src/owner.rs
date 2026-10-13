// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's owner: one loop per connector that wakes, plans, draws,
//! dials, runs the Levin handshake, adopts the channel and reports the
//! outcome (dialer brief, "The fill", "The dial", "`DialOutcome`").
//!
//! The loop runs on a thread of its own. Its wake is a timing-engine owner
//! (Rick, 2026-10-13): each gap is armed on the engine and the thread
//! waits for the wake; the daemon has one scheduler and the dialer brings
//! no second one. `Hub::dial_channel` blocks that thread while the
//! connector opens the channel, and the handshake reads the channel's
//! frames on it. No p2p io worker is held.
//!
//! The handshake owner holds the close cause itself: a channel that ends
//! before a well-formed response reports the cause the connector stored on
//! the session, and nothing reads a registry row that the strand may have
//! reaped. The handshake's only clock is the connector's transport gap,
//! armed before `dial_channel` returns; when it fires the connector closes
//! the session and the read below returns. A channel that fails before it
//! is adopted is dropped: the session's drop closes the queue, and the
//! owner's outcome carries the cause it saw.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_draw_rng::RelayRng;
use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    PortableMap, Received, SupportFlags, COMMAND_HANDSHAKE,
};
use shekyl_peerlist::{
    white_diversity_floor, BanQuery, CloseCause, CloseKind, ConnectionId, ConnectorId, DialOutcome,
    Direction, Host, NetworkAddress, Peerlist, Refusal, RefusedSet, SessionRow, Source, Tick,
    WHITE_REFILL_LINE,
};
use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};
use shekyl_seam::{drive_inbound, Endpoint, Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, OwnerHandle};

use crate::attempts::Attempts;
use crate::candidate::CandidateFilter;
use crate::fill::{plan, Census, DialAim, DrawList};
use crate::memory::FailedAddresses;
use crate::nonce::{HandshakeNonce, HandshakeNonceSet, InFlightNonce};
use crate::pace::next_wake_nanos;

/// This node's sync payload, read at each handshake. `None` when the core
/// has not published a tip yet: the dialer then dials nothing, because a
/// handshake without the chain's height is not one.
pub type SnapshotSource = Arc<dyn Fn() -> Option<SyncPayload> + Send + Sync>;

/// A dial the strand has not yet answered.
#[derive(Debug, Clone)]
struct Pending {
    connector: ConnectorId,
    address: NetworkAddress,
    keep: bool,
}

/// The state the owner loops and the FFI calls share.
pub struct Shared {
    /// The peer lists. [`Peerlist::apply`] stays the only writer of gray
    /// and white; this struct is where the dialer keeps them.
    pub lists: Peerlist,
    /// The failed-address memory.
    pub memory: FailedAddresses,
    attempts: Vec<Attempts>,
    targets: Vec<usize>,
    own: Vec<Vec<NetworkAddress>>,
    /// Dials adopted and posted, awaiting the strand's verdict.
    pending: BTreeMap<u64, Pending>,
    /// Kept sessions by id, so a close can name the address.
    kept: BTreeMap<u64, NetworkAddress>,
    /// A closed network (`--add-exclusive-node`): the candidate
    /// population, when set. Not a dialer arm.
    exclusive: Option<BTreeSet<NetworkAddress>>,
}

impl Shared {
    fn attempts(&mut self, connector: ConnectorId) -> &mut Attempts {
        &mut self.attempts[connector.index()]
    }
}

/// The outbound dialer for every connector of one process.
pub struct Dialer {
    hub: Hub,
    shared: Arc<Mutex<Shared>>,
    nonces: HandshakeNonceSet,
    stop: Arc<AtomicBool>,
    /// Set when the zone host starts; the lists exist before it does.
    network_id: Mutex<Option<[u8; 16]>>,
    support_flags: u32,
    snapshot: SnapshotSource,
}

/// The transport layer's bans, asked through the hub.
struct HubBans<'a>(&'a Hub);

impl BanQuery for HubBans<'_> {
    fn is_banned(&mut self, host: IpAddr, _now: Tick) -> bool {
        self.0.is_banned(host)
    }
}

/// The peerlist's name for a seam session: the socket id, little-endian,
/// in the first eight bytes.
#[must_use]
pub fn session_of(id: SocketId) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&id.get().to_le_bytes());
    ConnectionId(bytes)
}

/// The seam endpoint a list address dials.
fn endpoint_of(address: &NetworkAddress) -> Option<Endpoint> {
    match address {
        NetworkAddress::Ipv4 { ip, port } => Some(Endpoint::Clearnet {
            ip: IpAddr::V4(*ip),
            port: *port,
            direction: Direction::Outbound,
        }),
        NetworkAddress::Ipv6 { ip, port } => Some(Endpoint::Clearnet {
            ip: IpAddr::V6(*ip),
            port: *port,
            direction: Direction::Outbound,
        }),
        NetworkAddress::Tor { host, port } => {
            shekyl_onion_v3::v3_pubkey(host).map(|key| Endpoint::Tor { key, port: *port })
        }
    }
}

/// The list address of a board row, when the row has one.
fn address_of(endpoint: &Endpoint) -> Option<NetworkAddress> {
    match endpoint {
        Endpoint::Clearnet {
            ip: IpAddr::V4(ip),
            port,
            ..
        } => Some(NetworkAddress::Ipv4 {
            ip: *ip,
            port: *port,
        }),
        Endpoint::Clearnet {
            ip: IpAddr::V6(ip),
            port,
            ..
        } => Some(NetworkAddress::Ipv6 {
            ip: *ip,
            port: *port,
        }),
        Endpoint::Tor { key, port } => Some(NetworkAddress::Tor {
            host: shekyl_onion_v3::v3_onion_hostname(key),
            port: *port,
        }),
        Endpoint::TorInbound => None,
    }
}

/// How one attempt ended on the owner's thread.
enum Attempt {
    /// A total outcome, before any adopt.
    Done(DialOutcome),
    /// Adopted and posted; the strand's verdict completes it.
    Posted(SocketId),
}

impl Dialer {
    /// A dialer over `hub`, with empty lists built over `refused`.
    ///
    /// `support_flags` is what every handshake request carries, with the
    /// network id given later by [`Self::set_network_id`]. `snapshot` is
    /// the core's latest published tip. Until both are known the owner
    /// loops dial nothing.
    #[must_use]
    pub fn new(
        hub: Hub,
        refused: RefusedSet,
        support_flags: u32,
        snapshot: SnapshotSource,
    ) -> Self {
        let mut targets = vec![0usize; ConnectorId::COUNT];
        targets[ConnectorId::Clearnet.index()] = P2P_DEFAULT_OUT_PEERS as usize;
        targets[ConnectorId::Tor.index()] = MIN_PROVISIONED_OUT_PEERS as usize;
        Self {
            hub,
            shared: Arc::new(Mutex::new(Shared {
                lists: Peerlist::new(refused),
                memory: FailedAddresses::new(),
                attempts: (0..ConnectorId::COUNT).map(|_| Attempts::new()).collect(),
                targets,
                own: vec![Vec::new(); ConnectorId::COUNT],
                pending: BTreeMap::new(),
                kept: BTreeMap::new(),
                exclusive: None,
            })),
            nonces: HandshakeNonceSet::new(),
            stop: Arc::new(AtomicBool::new(false)),
            network_id: Mutex::new(None),
            support_flags,
            snapshot,
        }
    }

    /// The network every handshake names. Set once, when the zone host
    /// starts.
    pub fn set_network_id(&self, network_id: [u8; 16]) {
        *self.network_id.lock().expect("network id") = Some(network_id);
    }

    fn network_id(&self) -> Option<[u8; 16]> {
        *self.network_id.lock().expect("network id")
    }

    /// The shared state, for the calls that read or write the lists.
    pub fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().expect("dialer state")
    }

    /// The hub this dialer dials through.
    #[must_use]
    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    /// The connector's outbound target. A cap of 0 is legal and dials
    /// nothing. Lowering it closes kept sessions only, uniformly, and
    /// returns the ids closed; a pending attempt and a confirm row are
    /// never what the cap closes.
    pub fn set_target<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        target: usize,
        rng: &mut R,
    ) -> Vec<SocketId> {
        let mut shared = self.shared();
        shared.targets[connector.index()] = target;
        let closing = shared.attempts(connector).over_target(target, rng);
        let ids: Vec<SocketId> = shared
            .kept
            .iter()
            .filter(|(_, address)| closing.contains(address))
            .filter_map(|(id, _)| SocketId::from_ffi(*id))
            .collect();
        drop(shared);
        for id in &ids {
            self.hub.close(*id);
        }
        ids
    }

    /// This node's own addresses on `connector`: never dial candidates,
    /// and the disclosure population's own member (slice 1 §5a).
    pub fn set_own_addresses(&self, connector: ConnectorId, addresses: Vec<NetworkAddress>) {
        let mut shared = self.shared();
        if let Some(first) = addresses.first() {
            // An address of another connector is refused there and kept here
            // for the filter only.
            match shared.lists.set_own_address(connector, Some(first.clone())) {
                Ok(()) | Err(_) => {}
            }
        }
        shared.own[connector.index()] = addresses;
    }

    /// Declare a closed network: the candidate population is exactly
    /// these addresses, which are admitted as operator-named.
    pub fn set_exclusive<R: RelayRng + ?Sized>(
        &self,
        addresses: Vec<NetworkAddress>,
        now: Tick,
        rng: &mut R,
    ) {
        let mut shared = self.shared();
        for address in &addresses {
            // Already seated, or refused as banned: the population is the
            // declaration either way.
            match shared.lists.admit_gray(
                address,
                Source::Operator,
                now,
                &mut HubBans(&self.hub),
                rng,
            ) {
                Ok(_) | Err(_) => {}
            }
        }
        shared.exclusive = Some(addresses.into_iter().collect());
    }

    /// An operator-named address (`--add-peer`, a seed): into gray.
    pub fn admit_operator<R: RelayRng + ?Sized>(
        &self,
        address: &NetworkAddress,
        now: Tick,
        rng: &mut R,
    ) -> Result<bool, Refusal> {
        self.shared()
            .lists
            .admit_gray(address, Source::Operator, now, &mut HubBans(&self.hub), rng)
    }

    /// The inbound handshake's question: is `nonce` one of ours in flight
    /// on `connector`? Erases it.
    #[must_use]
    pub fn take_nonce(&self, connector: ConnectorId, nonce: &HandshakeNonce) -> bool {
        self.nonces.take(connector, nonce)
    }

    /// The strand accepted or refused the sync payload of the handshake
    /// posted for `id`. A kept dial that was accepted stays; a confirm
    /// dial that was accepted is closed here; a refused dial of either
    /// aim is closed here. The outcome reaches the lists and the memory.
    pub fn verdict<R: RelayRng + ?Sized>(&self, id: SocketId, accepted: bool, rng: &mut R) {
        let pending = self.shared().pending.remove(&id.get());
        let Some(pending) = pending else {
            return;
        };
        let outcome = match (accepted, pending.keep) {
            (true, true) => DialOutcome::SessionAccepted(pending.address.clone()),
            (true, false) => DialOutcome::Confirmed(pending.address.clone()),
            (false, _) => DialOutcome::PayloadRefused(pending.address.clone()),
        };
        if !matches!(outcome, DialOutcome::SessionAccepted(_)) {
            self.hub.close(id);
        }
        let mut shared = self.shared();
        if matches!(outcome, DialOutcome::SessionAccepted(_)) {
            shared.kept.insert(id.get(), pending.address.clone());
        }
        Self::record(
            &mut shared,
            pending.connector,
            &outcome,
            self.hub.now(),
            rng,
        );
    }

    /// The session `id` closed. A kept session leaves the kept count; a
    /// dial still awaiting its verdict is a failure with the cause the
    /// connector stored.
    pub fn session_closed<R: RelayRng + ?Sized>(&self, id: SocketId, rng: &mut R) {
        let mut shared = self.shared();
        if let Some(address) = shared.kept.remove(&id.get()) {
            let connector = Peerlist::connector_of(&address);
            if let Some(connector) = connector {
                shared.attempts(connector).session_closed(&address);
            }
            return;
        }
        if let Some(pending) = shared.pending.remove(&id.get()) {
            let cause = self
                .hub
                .cause(id)
                .unwrap_or_else(|| CloseCause::new(CloseKind::LocalClose));
            let outcome = DialOutcome::DialFailed(pending.address, cause);
            Self::record(
                &mut shared,
                pending.connector,
                &outcome,
                self.hub.now(),
                rng,
            );
        }
    }

    /// Stop every owner loop at its next wake. A loop blocked in the
    /// engine's wait returns when its owner is deregistered or the engine
    /// closes, which zone shutdown does.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    fn record<R: RelayRng + ?Sized>(
        shared: &mut Shared,
        connector: ConnectorId,
        outcome: &DialOutcome,
        now: Tick,
        rng: &mut R,
    ) {
        shared.attempts(connector).finish(outcome);
        shared.lists.apply(outcome, now, rng);
        shared.memory.observe(outcome, now);
    }

    /// Run the owner loop for `connector` on the calling thread, until
    /// [`Self::stop`], the owner's deregistration, or the engine's close.
    ///
    /// `owner` is this loop's registration on the timing engine. Each
    /// wake is armed at the engine's clock plus the gap of
    /// [`next_wake_nanos`], drawn per dial from `rng`, the daemon's CSPRNG.
    pub fn run<C: Clock, R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        owner: &OwnerHandle<C>,
        rng: &mut R,
    ) {
        while !self.stop.load(Ordering::Acquire) {
            let deadline = Tick::new(
                owner
                    .clock()
                    .now()
                    .get()
                    .saturating_add(next_wake_nanos(rng)),
            );
            if owner.arm(deadline).is_err() || owner.wait_wake().is_err() {
                break;
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            let Some((address, aim, nonce)) = self.choose(connector, rng) else {
                continue;
            };
            match self.attempt(connector, &address, aim, &nonce, rng) {
                Attempt::Done(outcome) => {
                    let mut shared = self.shared();
                    Self::record(&mut shared, connector, &outcome, self.hub.now(), rng);
                }
                Attempt::Posted(id) => {
                    self.shared().pending.insert(
                        id.get(),
                        Pending {
                            connector,
                            address,
                            keep: aim == DialAim::Keep,
                        },
                    );
                }
            }
            // The nonce leaves the set here: the attempt ended, by any path.
            drop(nonce);
        }
    }

    /// One dial of `address` with `aim`, outside the wake loop: the draw
    /// of that address, the pending entry, the nonce, the handshake, the
    /// adopt and the post, or the total outcome. Returns the adopted id
    /// when the strand's verdict is still owed. The owner loop does this
    /// after its own draw; a test does it directly.
    ///
    /// A gray address is drawn here, so the outcome resolves an
    /// outstanding draw as the lists require. A white address is a
    /// re-contact and is not drawn. An address on neither list is not
    /// dialed.
    pub fn dial<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        rng: &mut R,
    ) -> Option<SocketId> {
        {
            let mut shared = self.shared();
            if shared.lists.is_gray(address) {
                let drawn = shared
                    .lists
                    .draw_gray_where(connector, &mut |a| a == address, rng)?;
                debug_assert_eq!(&drawn, address);
            } else if !shared.lists.is_white(address) {
                return None;
            }
            if !shared.attempts(connector).begin(address, aim) {
                return None;
            }
        }
        let nonce = self.nonces.mint(connector, rng);
        match self.attempt(connector, address, aim, &nonce, rng) {
            Attempt::Done(outcome) => {
                let mut shared = self.shared();
                Self::record(&mut shared, connector, &outcome, self.hub.now(), rng);
                None
            }
            Attempt::Posted(id) => {
                self.shared().pending.insert(
                    id.get(),
                    Pending {
                        connector,
                        address: address.clone(),
                        keep: aim == DialAim::Keep,
                    },
                );
                Some(id)
            }
        }
    }

    /// One wake's plan and draw. `None` when this wake dials nothing.
    fn choose<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Option<(NetworkAddress, DialAim, InFlightNonce)> {
        let now = self.hub.now();
        let board = self.hub.board();
        let mut sessions = BTreeSet::new();
        let mut outbound_hosts: BTreeSet<Host> = BTreeSet::new();
        for row in board.rows() {
            if row.connector() != connector {
                continue;
            }
            if let Some(address) = address_of(&row.endpoint()) {
                if row.direction() == Direction::Outbound {
                    outbound_hosts.insert(address.host());
                }
                sessions.insert(address);
            }
        }
        let hub = &self.hub;
        let mut shared = self.shared();
        let shared = &mut *shared;
        let target = shared.targets[connector.index()];
        let exclusive = shared.exclusive.clone();
        let own = shared.own[connector.index()].clone();
        let attempts = &shared.attempts[connector.index()];
        let memory = &shared.memory;
        let mut filter = CandidateFilter {
            own: &own,
            sessions: &sessions,
            outbound_hosts: &outbound_hosts,
            attempts,
            failed: memory,
            bans: &mut HubBans(hub),
            now,
        };
        let mut eligible = |address: &NetworkAddress| {
            exclusive
                .as_ref()
                .is_none_or(|population| population.contains(address))
                && filter.admits(address)
        };
        let lists = &mut shared.lists;
        let white = lists.white_count(connector, now, &mut HubBans(hub), rng);
        let white_candidates =
            lists.white_candidates(connector, now, &mut HubBans(hub), &mut eligible, rng);
        let gray = lists.gray_count(connector);
        let gray_candidates = lists.gray_candidates(connector, &mut eligible);
        let census = Census {
            kept: attempts.kept_count(),
            in_flight: attempts.in_flight(),
            target,
            white,
            white_candidates,
            gray,
            gray_candidates,
        };
        let plan = plan(&census, white_diversity_floor(), WHITE_REFILL_LINE)?;
        let address = match plan.list {
            DrawList::Gray => lists.draw_gray_where(connector, &mut eligible, rng)?,
            DrawList::White => {
                lists.draw_white_where(connector, now, &mut HubBans(hub), &mut eligible, rng)?
            }
        };
        if !shared.attempts[connector.index()].begin(&address, plan.aim) {
            return None;
        }
        let nonce = self.nonces.mint(connector, rng);
        Some((address, plan.aim, nonce))
    }

    /// Dial, handshake, adopt, post. Every end path is an [`Attempt`].
    fn attempt<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        nonce: &InFlightNonce,
        rng: &mut R,
    ) -> Attempt {
        let failed =
            |cause: CloseCause| Attempt::Done(DialOutcome::DialFailed(address.clone(), cause));
        let Some(endpoint) = endpoint_of(address) else {
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        let (Some(snapshot), Some(network_id)) = ((self.snapshot)(), self.network_id()) else {
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        let channel = match self.hub.dial_channel(&endpoint) {
            Ok(channel) => channel,
            Err(cause) => return failed(cause),
        };
        let request = HandshakeRequest {
            node_data: BasicNodeData {
                network_id,
                support_flags: SupportFlags::from_bits(self.support_flags),
            },
            payload_data: CoreSyncData {
                current_height: snapshot.current_height,
                cumulative_difficulty: snapshot.cumulative_difficulty,
                cumulative_difficulty_top64: snapshot.cumulative_difficulty_top64,
                top_id: snapshot.top_id,
            },
            nonce: *nonce.bytes(),
        };
        let Ok(payload) = request.store() else {
            drop(channel);
            return failed(CloseCause::new(CloseKind::LocalClose));
        };
        if let Err(kind) = channel
            .session
            .try_send(invoke(COMMAND_HANDSHAKE, &payload))
        {
            let cause = CloseCause::new(kind);
            drop(channel);
            return failed(cause);
        }

        let mut channel = channel;
        let response = match read_response(&mut channel.session) {
            Ok(response) => response,
            Err(Rejected::Closed) => return failed(channel.session.close_cause()),
            Err(Rejected::ByLevin) => {
                let cause = CloseCause::new(CloseKind::LevinHandshakeRejected);
                drop(channel);
                return failed(cause);
            }
        };
        if response.node_data.network_id != network_id {
            let cause = CloseCause::new(CloseKind::LevinHandshakeRejected);
            drop(channel);
            return failed(cause);
        }

        let id = channel.open.id();
        let now = self.hub.now();
        let addresses: Vec<NetworkAddress> = response
            .local_peerlist_new
            .iter()
            .map(|entry| entry.adr.clone())
            .collect();
        let admitted = self.shared().lists.admit_received_list(
            &addresses,
            SessionRow {
                id: session_of(id),
                connector,
                direction: Direction::Outbound,
            },
            now,
            &mut HubBans(&self.hub),
            rng,
        );
        if admitted.is_err() {
            drop(channel);
            return Attempt::Done(DialOutcome::PeerlistRefused(address.clone()));
        }

        let attached =
            match self
                .hub
                .adopt(channel.open, channel.session, channel.endpoint, channel.gap)
            {
                Ok(attached) => attached,
                Err(cause) => return failed(cause),
            };
        let keep = aim == DialAim::Keep;
        self.hub.post_handshake_result(
            id,
            connector,
            keep,
            response.node_data.support_flags.bits(),
            SyncPayload {
                current_height: response.payload_data.current_height,
                cumulative_difficulty: response.payload_data.cumulative_difficulty,
                cumulative_difficulty_top64: response.payload_data.cumulative_difficulty_top64,
                top_id: response.payload_data.top_id,
            },
        );
        let hub = self.hub.clone();
        let session = attached.session;
        let pump = std::thread::spawn(move || drive_inbound(&hub, id, session));
        self.hub.track_pump(id, pump);
        Attempt::Posted(id)
    }
}

/// Why no well-formed handshake response was read.
enum Rejected {
    /// The connector closed the session; its cause is on the session.
    Closed,
    /// The peer sent something that is not the handshake response.
    ByLevin,
}

/// Read frames until one whole `COMMAND_HANDSHAKE` response decodes.
fn read_response(
    session: &mut shekyl_capped_stream::Session,
) -> Result<HandshakeResponse, Rejected> {
    let mut reader = BucketReader::new();
    loop {
        let Some(frame) = session.recv_blocking() else {
            return Err(Rejected::Closed);
        };
        if reader.feed(&frame).is_err() {
            return Err(Rejected::ByLevin);
        }
        // The first whole message decides: the response, or not ours.
        match reader.next_message() {
            Ok(None) => {}
            Ok(Some(Received::Response { command, payload })) if command == COMMAND_HANDSHAKE => {
                return HandshakeResponse::load(&payload).map_err(|_| Rejected::ByLevin);
            }
            Ok(Some(_)) | Err(_) => return Err(Rejected::ByLevin),
        }
    }
}
