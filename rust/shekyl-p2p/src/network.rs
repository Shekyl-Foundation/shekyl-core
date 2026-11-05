// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network as one value: built from a [`NetworkPlan`] and the node's
//! two owners-in-waiting, started in the order its parts depend on each
//! other, stopped in the reverse.
//!
//! **Start order.** The transport runtime and the process clock; the
//! timing engine on that clock; the link gate on the same clock; the
//! inbound ceiling, resolved once; the peers owner (the dialer, its lists,
//! the plan's addresses); the relay owner; the connectors as the session
//! layer's dial; the session layer over all three owners; the dialer and
//! the ban verbs attached to it; the ban expiry and the periodic reports;
//! then each connector the plan names: its listeners bound, its route
//! published, its owner loop started, its accept pumps spawned.
//!
//! **Stop order.** The owner loops end and their threads are joined; the
//! session layer closes every slot; the relay owner stops; the engine
//! closes, which ends every timing owner; the runtime shuts down within
//! its timeout; the links are withdrawn.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_capped_stream::{node_gate, process_write_stall};
use shekyl_clearnet::{channel_choice, zero_tally, ClearnetOption, Linger};
use shekyl_dialer::Dialer;
use shekyl_p2p_session::{
    Channel, CoreSyncData, Endpoint, Intervals, Owners, Parts, PerConnector, ProbeHandshake,
    SessionConfig, SessionLayer,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::RefusedSet;
use shekyl_relay::owner::{
    self as relay, PoolDoor, RelayConfig, RelayHandle, RelayParts, RelayStartError, SecureRelayRng,
};
use shekyl_relay::{NodeSync, OriginVerdict};
use shekyl_runtime::{runtime, Pool, RuntimeBudget, ThreadName};
use shekyl_socks::{Proxy, SocksUsername};
use shekyl_timing_engine::{Clock, EngineService, Handle, MonotonicClock};
use shekyl_transport_layer::{
    spans, ConnectorId, Direction, DownCause, InboundFacet, Links, Route, RoutePublish, Sockets,
};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use crate::bans::{self, BanSpan, Bans};
use crate::descriptors;
use crate::dial::{ClearnetReady, Connectors, Spans, ACCEPT_BACKOFF};
use crate::facts::{self, ConnectionsSnapshot, LinkTotals, ListedPeer, PeerCounts};
use crate::peers::{self, OwnerLoops, Peers};
use crate::plan::{NetworkPlan, TorPlan};
use crate::tor::{TorLink, TOR_SOCKS_TIMEOUT};

pub use shekyl_dialer::TorLinkTally;
pub use shekyl_p2p_session::ProbeArrival;

/// What the node hands the network.
pub struct NetworkParts {
    /// The configuration, resolved.
    pub plan: NetworkPlan,
    /// The node's socket table: the one admission.
    pub sockets: Sockets,
    /// The sync owner's port. Its task is spawned by the node after the
    /// network starts, on the network's engine.
    pub sync: Arc<dyn shekyl_p2p_session::SyncOwner>,
    /// The pool, as the relay owner admits to it and serves from it.
    pub pool: Arc<dyn PoolDoor>,
    /// The node's synchronised/unsynchronised watch.
    pub node_sync: watch::Receiver<NodeSync>,
    /// The chain tip as the handshake and timed sync carry it.
    pub tip: watch::Receiver<CoreSyncData>,
}

/// Where the connectors listen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listening {
    /// The clearnet listeners, as bound.
    pub clearnet: Vec<SocketAddr>,
    /// The loopback listener an onion service forwards to.
    pub tor_forward: Option<SocketAddr>,
}

/// Why the network could not start. Nothing started is undone by the
/// error; the parts that did start are dropped with it.
#[derive(Debug)]
pub enum StartError {
    /// The transport runtime could not start.
    Runtime(std::io::Error),
    /// A listener could not bind.
    Bind {
        addr: SocketAddr,
        error: std::io::Error,
    },
    /// The clearnet channel choice was refused.
    Channel(String),
    /// The relay owner could not start.
    Relay(RelayStartError),
    /// A connector's owner loop could not start.
    OwnerLoop(ConnectorId),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "the transport runtime could not start: {e}"),
            Self::Bind { addr, error } => write!(f, "could not bind {addr}: {error}"),
            Self::Channel(e) => write!(f, "the clearnet channel could not be chosen: {e}"),
            Self::Relay(e) => write!(f, "the relay owner could not start: {e}"),
            Self::OwnerLoop(c) => write!(f, "{c:?}'s owner loop could not start"),
        }
    }
}

impl std::error::Error for StartError {}

/// The ban timer's generation: one per engine this process starts.
static ENGINE_GENERATION: AtomicU64 = AtomicU64::new(0);

type Layer = SessionLayer<MonotonicClock>;

struct Inner {
    pool: Mutex<Option<Pool>>,
    runtime: tokio::runtime::Handle,
    engine: EngineService<MonotonicClock>,
    handle: Handle<MonotonicClock>,
    clock: MonotonicClock,
    sockets: Sockets,
    links: Arc<Links>,
    dialer: Peers,
    loops: OwnerLoops,
    relay: RelayHandle,
    layer: Layer,
    connectors: Arc<Connectors>,
    tor_link: Arc<TorLink>,
    bans: Bans,
    listening: Listening,
    stopped: AtomicBool,
}

/// The network. Clones share one network; [`Network::stop`] stops it once.
#[derive(Clone)]
pub struct Network {
    inner: Arc<Inner>,
}

impl Network {
    /// Build and start the network `parts` describe.
    ///
    /// # Errors
    /// [`StartError`].
    pub fn start(parts: NetworkParts) -> Result<Self, StartError> {
        let NetworkParts {
            plan,
            sockets,
            sync,
            pool: door,
            node_sync,
            tip,
        } = parts;

        // The transport runtime and the one process clock. The engine
        // (every transport deadline) and the link gate read the origin
        // every ban reads, so an admission check that compares an engine
        // `now` with a ban compares on one clock.
        let name = ThreadName::new("p2p-transport").map_err(|e| {
            StartError::Runtime(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let pool = runtime(
            RuntimeBudget {
                workers: NonZeroUsize::new(spans::WORKERS).unwrap_or(NonZeroUsize::MIN),
                blocking: NonZeroUsize::new(spans::BLOCKING).unwrap_or(NonZeroUsize::MIN),
            },
            &name,
        )
        .map_err(StartError::Runtime)?;
        let handle = pool.handle().clone();
        let clock = MonotonicClock::new();
        let engine = EngineService::start(clock.clone());
        let timing = engine.handle();
        let generation = ENGINE_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
        {
            let gate_clock = clock.clone();
            node_gate().install_clock(Arc::new(move || gate_clock.now().get()));
        }
        node_gate().set_up(plan.limits.upload);
        node_gate().set_down(plan.limits.download);
        if spans::MEASUREMENT_SPANS {
            tracing::warn!(
                tor_dial_within_ns = spans::TOR_DIAL_WITHIN_NANOS,
                tor_gap_within_ns = spans::TOR_GAP_WITHIN_NANOS,
                "measurement build: the Tor gap deadline is lifted to the dial's; not a release"
            );
        }

        // The inbound ceiling, resolved once before the listeners bind, as
        // the seam resolved it; the plan's reservation covers them.
        let ceiling = descriptors::inbound_ceiling(plan.reserved_descriptors);
        tracing::info!(?ceiling, "inbound ceiling");

        // The peers owner.
        let links = Arc::new(Links::new());
        let refused = if plan.allow_local {
            RefusedSet::EMPTY
        } else {
            RefusedSet::NON_GLOBAL
        };
        let dialer: Peers = Arc::new(Dialer::new(
            timing.clone(),
            Arc::clone(&links),
            &sockets,
            refused,
            Box::new(SecureRelayRng),
        ));
        let tor_link = Arc::new(TorLink::new());
        dialer.report_tor_link(tor_link.sink());
        if let Some(clearnet) = &plan.clearnet {
            dialer.set_own_addresses(ConnectorId::Clearnet, clearnet.own.clone());
        }
        if let TorPlan::Operator { own, .. } = &plan.tor {
            dialer.set_own_addresses(ConnectorId::Tor, own.clone());
        }
        peers::apply(&dialer, &plan.peers);

        // The relay owner.
        let relay = relay::start(RelayParts {
            config: RelayConfig::inherited(plan.connectors(), plan.relay_noise),
            pool: door,
            node_sync,
            timing: timing.clone(),
            runtime: handle.clone(),
            rng: Box::new(SecureRelayRng),
        })
        .map_err(StartError::Relay)?;

        // The connectors and the session layer over the three owners.
        let connectors = Arc::new(Connectors {
            runtime: handle.clone(),
            engine: timing.clone(),
            sockets: sockets.clone(),
            links: Arc::clone(&links),
            network_id: plan.network_id,
            spans: Spans::measured(),
            on_cause: Connectors::on_cause(),
            clearnet: Mutex::new(None),
            tor_proxy: Mutex::new(None),
        });
        let layer = SessionLayer::new(Parts {
            sockets: sockets.clone(),
            config: SessionConfig {
                network_id: plan.network_id,
                handshake_within: PerConnector {
                    clearnet: Duration::from_nanos(spans::CLEARNET_GAP_WITHIN_NANOS),
                    tor: Duration::from_nanos(spans::TOR_GAP_WITHIN_NANOS),
                },
                intervals: Intervals::default(),
            },
            owners: Owners {
                peers: Arc::clone(&dialer) as Arc<dyn shekyl_p2p_session::PeerOwner>,
                sync,
                relay: Arc::clone(&relay.port) as Arc<dyn shekyl_p2p_session::RelayOwner>,
                probes: Arc::clone(&tor_link) as Arc<dyn shekyl_p2p_session::ProbeSink>,
            },
            connectors: Arc::clone(&connectors) as Arc<dyn shekyl_p2p_session::Dial>,
            timing: timing.clone(),
            tip,
            runtime: handle.clone(),
            rng: Box::new(SecureRelayRng),
        });
        dialer.attach(layer.clone());
        let bans = Bans::new(sockets.clone(), clock.clone());
        bans.attach(layer.clone());
        for target in &plan.bans {
            bans.ban(*target, BanSpan::Permanent);
        }
        bans::spawn_expiry(&handle, &timing, sockets.clone(), generation);
        crate::reports::spawn_lateness_report(&handle, timing.clone());
        crate::reports::spawn_refusal_report(&handle, sockets.clone());

        let (clearnet_tx, clearnet_rx) = mpsc::unbounded_channel();
        let (tor_tx, tor_rx) = mpsc::unbounded_channel();
        drop(handle.spawn(pump(
            layer.clone(),
            Arc::clone(&dialer),
            clearnet_rx,
            tor_rx,
        )));

        let mut network = Self {
            inner: Arc::new(Inner {
                pool: Mutex::new(Some(pool)),
                runtime: handle,
                engine,
                handle: timing,
                clock,
                sockets,
                links,
                dialer,
                loops: OwnerLoops::new(),
                relay: relay.handle,
                layer,
                connectors,
                tor_link,
                bans,
                listening: Listening::default(),
                stopped: AtomicBool::new(false),
            }),
        };
        let listening = match network.start_connectors(&plan, ceiling, &clearnet_tx, tor_tx) {
            Ok(listening) => listening,
            Err(err) => {
                network.stop();
                return Err(err);
            }
        };
        Arc::get_mut(&mut network.inner)
            .expect("no clone before the connectors start")
            .listening = listening;
        Ok(network)
    }

    fn start_connectors(
        &self,
        plan: &NetworkPlan,
        ceiling: InboundCeiling,
        clearnet_tx: &mpsc::UnboundedSender<shekyl_clearnet::Admitted>,
        tor_tx: mpsc::UnboundedSender<shekyl_tor::Admitted>,
    ) -> Result<Listening, StartError> {
        let inner = &self.inner;
        let mut listening = Listening::default();
        if let Some(clearnet) = &plan.clearnet {
            let option = if clearnet.encrypt {
                ClearnetOption::On
            } else {
                ClearnetOption::Off
            };
            let kind = channel_choice(ConnectorId::Clearnet.column(), option)
                .map_err(|e| StartError::Channel(format!("{e:?}")))?;
            let tally = Arc::new(zero_tally());
            let mut listeners = Vec::with_capacity(clearnet.listen.len());
            for addr in &clearnet.listen {
                let listener = inner
                    .runtime
                    .block_on(TcpListener::bind(*addr))
                    .map_err(|error| StartError::Bind { addr: *addr, error })?;
                listening.clearnet.push(
                    listener
                        .local_addr()
                        .map_err(|error| StartError::Bind { addr: *addr, error })?,
                );
                listeners.push(listener);
            }
            let route = clearnet
                .proxy
                .as_ref()
                .map_or(Route::Direct, |proxy| Route::Socks(proxy.at()));
            *inner.connectors.clearnet.lock().expect("clearnet") = Some(ClearnetReady {
                kind,
                tally: Arc::clone(&tally),
                proxy: clearnet.proxy.clone(),
            });
            if let RoutePublish::Installed { .. } =
                inner
                    .links
                    .publish_usable(ConnectorId::Clearnet, route, inner.clock.now())
            {
                tracing::info!("the clearnet connector dials {route:?}");
            }
            if !inner.loops.start(
                &inner.dialer,
                ConnectorId::Clearnet,
                &inner.handle,
                plan.seeds,
            ) {
                return Err(StartError::OwnerLoop(ConnectorId::Clearnet));
            }
            let spans = inner.connectors.spans;
            let linger = {
                let engine = inner.handle.clone();
                let span = spans.clearnet_handshake_within;
                let cap = inner.sockets.clearnet_linger_cap(span);
                inner
                    .runtime
                    .block_on(async move { Linger::spawn(engine, cap, span) })
            };
            for listener in listeners {
                let inbound = shekyl_clearnet::Inbound {
                    sockets: inner.sockets.clone(),
                    ceiling: move || ceiling,
                    kind,
                    network_id: plan.network_id,
                    handshake_within: spans.clearnet_handshake_within,
                    gap_within: Some(spans.clearnet_gap_within),
                    tally: Arc::clone(&tally),
                    on_cause: Arc::clone(&inner.connectors.on_cause),
                    send_queue_bytes: spans.send_queue_bytes,
                    admitted: clearnet_tx.clone(),
                    linger: linger.clone(),
                    backoff: ACCEPT_BACKOFF,
                };
                let engine = inner.handle.clone();
                drop(inner.runtime.spawn(async move {
                    shekyl_clearnet::accept_inbound(listener, inbound, engine).await;
                }));
            }
        }
        match &plan.tor {
            TorPlan::None => {}
            TorPlan::Managed => {
                if !inner
                    .loops
                    .start(&inner.dialer, ConnectorId::Tor, &inner.handle, plan.seeds)
                {
                    return Err(StartError::OwnerLoop(ConnectorId::Tor));
                }
                let forward = self.bind_tor(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
                listening.tor_forward = Some(forward.0);
                self.spawn_tor_accept(forward.1, ceiling, tor_tx);
            }
            TorPlan::Operator {
                socks,
                onion_listen,
                ..
            } => {
                self.install_tor_proxy(socks.clone());
                if !inner
                    .loops
                    .start(&inner.dialer, ConnectorId::Tor, &inner.handle, plan.seeds)
                {
                    return Err(StartError::OwnerLoop(ConnectorId::Tor));
                }
                if let Some(extra) = onion_listen {
                    let forward = self.bind_tor(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
                    listening.tor_forward = Some(forward.0);
                    self.spawn_tor_accept(forward.1, ceiling, tor_tx.clone());
                    let extra = self.bind_tor(*extra)?;
                    self.spawn_tor_accept(extra.1, ceiling, tor_tx);
                }
            }
        }
        Ok(listening)
    }

    fn bind_tor(&self, addr: SocketAddr) -> Result<(SocketAddr, TcpListener), StartError> {
        let listener = self
            .inner
            .runtime
            .block_on(TcpListener::bind(addr))
            .map_err(|error| StartError::Bind { addr, error })?;
        let local = listener
            .local_addr()
            .map_err(|error| StartError::Bind { addr, error })?;
        Ok((local, listener))
    }

    fn spawn_tor_accept(
        &self,
        listener: TcpListener,
        ceiling: InboundCeiling,
        tor_tx: mpsc::UnboundedSender<shekyl_tor::Admitted>,
    ) {
        let inner = &self.inner;
        let spans = inner.connectors.spans;
        let inbound = shekyl_tor::Inbound {
            sockets: inner.sockets.clone(),
            ceiling: move || ceiling,
            gap_within: spans.tor_gap_within,
            on_cause: Arc::clone(&inner.connectors.on_cause),
            send_queue_bytes: spans.send_queue_bytes,
            admitted: tor_tx,
            backoff: ACCEPT_BACKOFF,
        };
        let engine = inner.handle.clone();
        drop(inner.runtime.spawn(async move {
            shekyl_tor::accept_inbound(listener, inbound, engine).await;
        }));
    }

    /// An operator's Tor: its proxy is what every Tor dial presents, and
    /// its SOCKS address is the Tor link's route. An operator's Tor gives
    /// the dialer no window (its `SocksTimeout` is not this node's).
    fn install_tor_proxy(&self, socks: Proxy) {
        self.inner.dialer.set_window(ConnectorId::Tor, None);
        let (at, authenticates) = (socks.at(), socks.authenticates());
        self.inner.connectors.set_tor_proxy(socks);
        if let RoutePublish::Installed { .. } = self.inner.links.publish_usable(
            ConnectorId::Tor,
            Route::Socks(at),
            self.inner.clock.now(),
        ) {
            tracing::info!(
                "the Tor connector dials through the SOCKS proxy at {at}{}",
                if authenticates {
                    ", with the configured username and password"
                } else {
                    ""
                }
            );
        }
    }

    /// Where the connectors listen.
    #[must_use]
    pub fn listening(&self) -> &Listening {
        &self.inner.listening
    }

    /// The process timing engine: every wake in the node is one of its
    /// owners.
    #[must_use]
    pub fn engine(&self) -> Handle<MonotonicClock> {
        self.inner.handle.clone()
    }

    /// The process clock the engine, the link gate and the bans read.
    #[must_use]
    pub fn clock(&self) -> MonotonicClock {
        self.inner.clock.clone()
    }

    /// The transport runtime's handle.
    #[must_use]
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.inner.runtime
    }

    /// The relay owner's handle: local relay, departures, the origin
    /// verdict, the snapshot.
    #[must_use]
    pub fn relay(&self) -> &RelayHandle {
        &self.inner.relay
    }

    /// The origin verdict as the relay owner publishes it.
    #[must_use]
    pub fn origin_verdict(&self) -> watch::Receiver<OriginVerdict> {
        self.inner.relay.origin_verdict()
    }

    /// The ban verbs.
    #[must_use]
    pub fn bans(&self) -> &Bans {
        &self.inner.bans
    }

    /// The connections, read against one clock read.
    #[must_use]
    pub fn connections(&self, now_unix: u64) -> ConnectionsSnapshot {
        facts::connections(&self.inner.layer.board(), now_unix)
    }

    /// The link totals.
    #[must_use]
    pub fn link_totals(&self) -> LinkTotals {
        facts::link_totals()
    }

    /// The peer lists, white then gray, for every connector or clearnet
    /// only.
    #[must_use]
    pub fn peer_list(&self, public_only: bool) -> Vec<ListedPeer> {
        facts::listed_peers(&self.inner.dialer, public_only)
    }

    /// The sockets per connector and direction, and the clearnet list
    /// sizes.
    #[must_use]
    pub fn peer_counts(&self) -> PeerCounts {
        facts::peer_counts(&self.inner.sockets, &self.inner.dialer)
    }

    /// Established sessions, outbound then inbound.
    #[must_use]
    pub fn session_counts(&self) -> (u64, u64) {
        facts::session_counts(&self.inner.layer.board())
    }

    /// `get_stem_tallies`' body, in the JSON the C++ served.
    #[must_use]
    pub fn stem_tallies_json(&self) -> String {
        facts::stem_tallies_json(&self.inner.relay.snapshot())
    }

    /// Store the address file if its interval has passed. The node calls
    /// this from its housekeeping.
    ///
    /// # Errors
    /// The store's write.
    pub fn store_addresses_if_due(&self) -> std::io::Result<bool> {
        self.inner.dialer.store_if_due(self.inner.clock.now())
    }

    /// Mint the Tor probe's handshake (`TOR_SUPERVISOR.md` §4.5).
    #[must_use]
    pub fn mint_probe(&self) -> Option<ProbeHandshake> {
        self.inner.layer.mint_probe()
    }

    /// The probe that last arrived; `None` until one does.
    #[must_use]
    pub fn probe_arrivals(&self) -> watch::Receiver<Option<ProbeArrival>> {
        self.inner.tor_link.probe_arrivals()
    }

    /// This node's own Tor dials, as a tally for display.
    #[must_use]
    pub fn tor_link_tally(&self) -> watch::Receiver<TorLinkTally> {
        self.inner.tor_link.tally()
    }

    /// The managed Tor is running at `socks`: publish the route, give the
    /// dialer that Tor's `SocksTimeout` window, and return the route's
    /// incarnation.
    pub fn publish_managed_running(&self, socks: SocketAddr) -> u64 {
        let inner = &self.inner;
        inner
            .dialer
            .set_window(ConnectorId::Tor, TOR_SOCKS_TIMEOUT.earliest_expiry());
        inner
            .connectors
            .set_tor_proxy(Proxy::unauthenticated(socks));
        let published =
            inner
                .links
                .publish_usable(ConnectorId::Tor, Route::Socks(socks), inner.clock.now());
        inner
            .tor_link
            .record_managed(published.incarnation(), socks);
        published.incarnation()
    }

    /// The managed Tor's SOCKS address while the link is that route.
    #[must_use]
    pub fn managed_socks(&self) -> Option<SocketAddr> {
        self.inner.tor_link.managed_socks(&self.inner.links)
    }

    /// The managed route with `isolation` as its pair, for this node's own
    /// dials through its Tor.
    #[must_use]
    pub fn managed_route(&self, isolation: &Arc<SocksUsername>) -> Option<Proxy> {
        self.inner
            .tor_link
            .managed_route(&self.inner.links, isolation)
    }

    /// The Tor link's inbound facet for `incarnation`.
    pub fn publish_tor_inbound(&self, incarnation: u64, inbound: InboundFacet) -> bool {
        self.inner
            .links
            .publish_inbound(ConnectorId::Tor, incarnation, inbound)
    }

    /// The Tor link at `incarnation` fell.
    pub fn publish_tor_down(&self, incarnation: u64, cause: DownCause) -> bool {
        self.inner
            .links
            .publish_down(ConnectorId::Tor, incarnation, cause, self.inner.clock.now())
    }

    /// This node's own onion, once the managed Tor publishes it.
    pub fn note_own_onion(&self, service_id: &str, virtual_port: u16) {
        peers::note_own_onion(&self.inner.dialer, service_id, virtual_port);
    }

    /// Stop the network in dependency order. A second call does nothing.
    pub fn stop(&self) {
        let inner = &self.inner;
        if inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        inner.loops.stop(&inner.dialer);
        inner.layer.shutdown();
        inner.bans.detach();
        inner.relay.stop();
        inner.engine.close();
        let pool = inner.pool.lock().expect("pool").take();
        if let Some(pool) = pool {
            pool.shutdown(Duration::from_nanos(spans::SHUTDOWN_TIMEOUT_NANOS));
        }
        let stall = process_write_stall();
        tracing::info!(
            closes = stall.closes,
            max_ns = stall.max_ns,
            in_flight_at_close = stall.in_flight_at_close,
            in_flight_max_ns = stall.in_flight_at_close_max_ns,
            "process write stall"
        );
        inner.sockets.clear_zone_caps();
        for connector in ConnectorId::ALL {
            inner.links.withdraw(*connector);
        }
    }
}

/// Adopt what the connectors admit into the session layer. An inbound Tor
/// session is counted for the dialer's held tally; a Tor dial whose onion
/// is not a v3 service is refused here, before any byte.
async fn pump(
    layer: Layer,
    dialer: Peers,
    mut clearnet_rx: mpsc::UnboundedReceiver<shekyl_clearnet::Admitted>,
    mut tor_rx: mpsc::UnboundedReceiver<shekyl_tor::Admitted>,
) {
    loop {
        tokio::select! {
            biased;
            admitted = clearnet_rx.recv() => {
                let Some(admitted) = admitted else { break };
                layer.adopt(Channel {
                    open: admitted.open,
                    session: admitted.session,
                    endpoint: Endpoint::Clearnet {
                        ip: admitted.ip,
                        port: admitted.port,
                        direction: Direction::Inbound,
                    },
                    gap: admitted.gap,
                });
            }
            admitted = tor_rx.recv() => {
                let Some(admitted) = admitted else { break };
                let endpoint = match admitted.onion {
                    Some((host, port)) => match shekyl_onion_v3::v3_pubkey(&host) {
                        Some(key) => Endpoint::Tor { key, port },
                        None => {
                            tracing::error!("tor session refused: dialed host is not a v3 onion");
                            continue;
                        }
                    },
                    None => Endpoint::TorInbound,
                };
                let inbound = matches!(endpoint, Endpoint::TorInbound);
                layer.adopt(Channel {
                    open: admitted.open,
                    session: admitted.bytes,
                    endpoint,
                    gap: Some(admitted.gap),
                });
                if inbound {
                    dialer.note_inbound_tor();
                }
            }
        }
    }
}
