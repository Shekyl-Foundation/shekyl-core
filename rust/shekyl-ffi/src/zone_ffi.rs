// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The zone's listen and dial.
//!
//! The seam crate does not know about a connector. This module does: it
//! binds the clearnet and Tor listeners on one runtime, adopts each
//! admitted socket into the seam, and dials when the seam asks. A bind
//! that fails returns an error. Nothing here starts the epee server.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use shekyl_capped_stream::{node_gate, process_write_stall, Session};
use shekyl_clearnet::{
    accept_inbound as accept_clearnet_inbound, channel_choice, dial_one as dial_clearnet,
    zero_tally, Admitted as ClearnetAdmitted, ClearnetOption, Dial as ClearnetDial,
    Inbound as ClearnetInbound,
};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
/// The cause [`watch_managed_tor`] records on the Tor link.
pub use shekyl_seam::DownCause;
use shekyl_seam::{
    drive_inbound_async, Channel, CloseCause, CloseKind, ConnectorId, Dial, Direction, Endpoint,
    Hub, Route, RoutePublish, SocketId,
};
use shekyl_socks::Proxy;
use shekyl_timing_engine::{Clock, EngineService, Handle, MonotonicClock, Tick};
use shekyl_tor::{
    accept_inbound as accept_tor_inbound, dial_one as dial_tor, Admitted as TorAdmitted,
    Inbound as TorInbound,
};
use shekyl_transport_layer::spans;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::seam_ffi::{hub, process_sockets};

/// Pause after a transient accept error so the loop does not spin. Not a
/// protocol deadline.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(1);

struct Host {
    pool: Mutex<Option<shekyl_runtime::Pool>>,
    handle: tokio::runtime::Handle,
    /// The engine thread. Every handle shares its closed flag, and its
    /// `Drop` sets that flag, so the service lives here for as long as the
    /// host does and is stopped in [`shutdown`]. Holding only
    /// the handle closed the engine when `ensure` returned, and every
    /// transport deadline after that was `Closed`.
    engine_service: Mutex<Option<EngineService<MonotonicClock>>>,
    engine: Handle<MonotonicClock>,
    sockets: shekyl_seam::Sockets,
    /// The seam's hub. Accept reads its ceiling on every socket, and the
    /// gap sender lives on the connection row there.
    hub: Hub,
    /// The managed Tor's death watch ([`watch_managed_tor`]). The zone's
    /// runtime runs it and ends it at shutdown.
    tor_death: Mutex<Option<tokio::task::JoinHandle<()>>>,
    clearnet: Mutex<Option<ClearnetReady>>,
    /// The Tor proxy this node was configured with, and the RFC 1929 pair it
    /// presents there (DC-Q7). The route itself is the hub's Tor link; a dial
    /// presents this pair only when that route is this proxy's address
    /// ([`presented`]).
    tor_proxy: Mutex<Option<Proxy>>,
    clearnet_tx: mpsc::UnboundedSender<ClearnetAdmitted>,
    tor_tx: mpsc::UnboundedSender<TorAdmitted>,
    shutdown_timeout: Duration,
    network_id: [u8; 16],
    clearnet_dial_within: Tick,
    clearnet_handshake_within: Tick,
    clearnet_gap_within: Tick,
    tor_dial_within: Tick,
    tor_gap_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
}

/// The clearnet listener's channel choice and handshake tally. Its route is
/// the hub's clearnet link.
struct ClearnetReady {
    kind: shekyl_clearnet::ChannelChoice,
    tally: Arc<shekyl_clearnet::HandshakeTally>,
    /// The operator's clearnet proxy and its pair, when one is configured;
    /// the route itself is the hub's clearnet link ([`presented`]).
    proxy: Option<Proxy>,
}

static HOST: LazyLock<Mutex<Option<Arc<Host>>>> = LazyLock::new(|| Mutex::new(None));

struct ZoneDial {
    host: Arc<Host>,
}

impl Dial for ZoneDial {
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        // Accept reads the hub's ceiling. An outbound dial does not admit
        // against the inbound ceiling, so this copy is not stored.
        let _ = (ceiling, now);
        match endpoint {
            Endpoint::Clearnet {
                ip,
                port,
                direction,
            } => {
                if *direction != Direction::Outbound {
                    return Err(CloseCause::new(CloseKind::LocalClose));
                }
                self.dial_clearnet(*ip, *port)
            }
            Endpoint::Tor { key, port } => self.dial_tor(key, *port),
            Endpoint::TorInbound => Err(CloseCause::new(CloseKind::LocalClose)),
        }
    }

    /// One task per connection on the transport runtime, in both
    /// directions: a thread held for the life of a connection is outside
    /// the thread ledger, and on the pool's blocking lane it made every
    /// connection past the cap deaf.
    fn drive(&self, hub: &Hub, id: SocketId, session: Session) {
        let hub = hub.clone();
        self.host
            .handle
            .spawn(async move { drive_inbound_async(&hub, id, session).await });
    }
}

impl ZoneDial {
    fn dial_clearnet(&self, ip: IpAddr, port: u16) -> Result<Channel, CloseCause> {
        let ready = self
            .host
            .clearnet
            .lock()
            .expect("clearnet")
            .as_ref()
            .map(|ready| ClearnetReady {
                kind: ready.kind,
                tally: Arc::clone(&ready.tally),
                proxy: ready.proxy.clone(),
            })
            .ok_or_else(|| CloseCause::new(CloseKind::LocalClose))?;
        let proxy = match self.host.hub.links().get(ConnectorId::Clearnet).route {
            Some(Route::Direct) => None,
            Some(Route::Socks(at)) => Some(presented(at, ready.proxy.as_ref())),
            None => return Err(CloseCause::new(CloseKind::LocalClose)),
        };
        let address = match ip {
            IpAddr::V4(ip) => NetworkAddress::Ipv4 { ip, port },
            IpAddr::V6(ip) => NetworkAddress::Ipv6 { ip, port },
        };
        let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
        let (on_cause, fail_rx) = failure_slot();
        let dial = ClearnetDial {
            address,
            proxy,
            sockets: self.host.sockets.clone(),
            kind: ready.kind,
            network_id: self.host.network_id,
            dial_within: self.host.clearnet_dial_within,
            // `--proxy` is a SOCKS path the clearnet legs did not measure.
            // The Tor dial is the worst measured SOCKS path; a longer
            // deadline costs only the dialer. The owed distribution replaces it.
            proxied_dial_within: self.host.tor_dial_within,
            handshake_within: self.host.clearnet_handshake_within,
            gap_within: Some(self.host.clearnet_gap_within),
            tally: ready.tally,
            on_cause,
            send_queue_bytes: self.host.send_queue_bytes,
            admitted: admitted_tx,
        };
        let engine = self.host.engine.clone();
        self.host.handle.spawn(dial_clearnet(dial, engine));
        let admitted = self
            .host
            .handle
            .block_on(recv_admitted(admitted_rx, fail_rx))?;
        Ok(Channel {
            open: admitted.open,
            session: admitted.session,
            endpoint: Endpoint::Clearnet {
                ip,
                port,
                direction: Direction::Outbound,
            },
            gap: admitted.gap,
        })
    }

    fn dial_tor(&self, key: &[u8; 32], port: u16) -> Result<Channel, CloseCause> {
        // The route is read from the link at each dial. A link that fell
        // after the plan read it still costs this one draw (`TSR-F1`).
        let Some(Route::Socks(at)) = self.host.hub.links().get(ConnectorId::Tor).route else {
            return Err(CloseCause::new(CloseKind::LocalClose));
        };
        let proxy = presented(at, self.host.tor_proxy.lock().expect("tor proxy").as_ref());
        let address = NetworkAddress::Tor {
            host: shekyl_onion_v3::v3_onion_hostname(key),
            port,
        };
        let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
        let (on_cause, fail_rx) = failure_slot();
        let dial = shekyl_tor::Dial {
            address,
            proxy,
            sockets: self.host.sockets.clone(),
            dial_within: self.host.tor_dial_within,
            gap_within: self.host.tor_gap_within,
            on_cause,
            send_queue_bytes: self.host.send_queue_bytes,
            admitted: admitted_tx,
        };
        let engine = self.host.engine.clone();
        self.host.handle.spawn(dial_tor(dial, engine));
        let admitted = self
            .host
            .handle
            .block_on(recv_admitted(admitted_rx, fail_rx))?;
        Ok(Channel {
            open: admitted.open,
            session: admitted.bytes,
            endpoint: Endpoint::Tor { key: *key, port },
            gap: Some(admitted.gap),
        })
    }
}

fn failure_slot() -> (
    Arc<dyn Fn(CloseCause) + Send + Sync>,
    oneshot::Receiver<CloseCause>,
) {
    let (tx, rx) = oneshot::channel();
    let slot = Arc::new(Mutex::new(Some(tx)));
    let on_cause = Arc::new(move |cause: CloseCause| {
        if let Some(tx) = slot.lock().expect("dial failure").take() {
            match tx.send(cause) {
                Ok(()) | Err(_) => {}
            }
        }
    });
    (on_cause, rx)
}

async fn recv_admitted<T>(
    mut rx: mpsc::UnboundedReceiver<T>,
    fail: oneshot::Receiver<CloseCause>,
) -> Result<T, CloseCause> {
    tokio::pin!(fail);
    tokio::select! {
        biased;
        admitted = rx.recv() => match admitted {
            Some(value) => Ok(value),
            // The dial task sends the cause and then drops the admission
            // channel. Both are ready together, and this arm is first, so
            // a closed channel is not itself the cause. Awaiting `fail`
            // here is bounded by that task: it owns the sender, and the
            // sender is dropped when the task returns, which is the same
            // moment the channel closes.
            None => match fail.await {
                Ok(cause) => Err(cause),
                Err(_) => Err(CloseCause::new(CloseKind::LocalClose)),
            },
        },
        result = &mut fail => match result {
            Ok(cause) => Err(cause),
            Err(_) => Err(CloseCause::new(CloseKind::LocalClose)),
        },
    }
}

/// Why a connector could not start.
#[derive(Debug)]
pub enum ZoneStart {
    /// The seam is not bound: the remnant has not constructed `net_node`.
    NoSeam,
    /// The transport runtime could not start.
    Runtime(String),
    /// A listener could not bind.
    Bind {
        /// The endpoint.
        addr: SocketAddr,
        /// The operating system's error.
        error: std::io::Error,
    },
    /// The clearnet channel choice was refused.
    Channel(String),
}

impl std::fmt::Display for ZoneStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSeam => write!(f, "the seam is not bound"),
            Self::Runtime(e) => write!(f, "the transport runtime could not start: {e}"),
            Self::Bind { addr, error } => write!(f, "could not bind {addr}: {error}"),
            Self::Channel(e) => write!(f, "the clearnet channel was refused: {e}"),
        }
    }
}

impl std::error::Error for ZoneStart {}

/// The zone host, built once over the bound seam's hub, whose inbound
/// ceiling it reads (the seam binds with this process's, resolved in Rust).
fn ensure(network_id: [u8; 16]) -> Result<Arc<Host>, ZoneStart> {
    let mut slot = HOST.lock().expect("zone host");
    if let Some(host) = slot.as_ref() {
        return Ok(Arc::clone(host));
    }
    let Some(hub) = hub() else {
        return Err(ZoneStart::NoSeam);
    };
    let runtime_err = |e: &dyn std::fmt::Debug| ZoneStart::Runtime(format!("{e:?}"));
    let workers = NonZeroUsize::new(spans::WORKERS).ok_or_else(|| runtime_err(&"no workers"))?;
    let blocking = NonZeroUsize::new(spans::BLOCKING).ok_or_else(|| runtime_err(&"no blocking"))?;
    let name = ThreadName::new("p2p-transport").map_err(|e| runtime_err(&e))?;
    let pool = runtime(RuntimeBudget { workers, blocking }, &name).map_err(|e| runtime_err(&e))?;
    let handle = pool.handle().clone();
    // One process clock (Rick, 2026-10-14). The engine (every transport
    // deadline) and the link gate read the origin the hub and every ban
    // read, so the clearnet admission checks, which compare an engine `now`
    // with a ban, compare on one clock. A `MonotonicClock` is its origin:
    // the clone is the same clock. *Records-was:* the host started its own
    // clock here, one origin per zone host.
    let process = crate::seam_ffi::process_clock();
    let clock = MonotonicClock::clone(&process);
    node_gate().install_clock(Arc::new(move || process.now().get()));
    if spans::MEASUREMENT_SPANS {
        tracing::warn!(
            tor_dial_within_ns = spans::TOR_DIAL_WITHIN_NANOS,
            tor_gap_within_ns = spans::TOR_GAP_WITHIN_NANOS,
            "measurement build: the Tor gap deadline is lifted to the dial's; not a release"
        );
    }
    let engine = EngineService::start(clock);
    let engine_handle = engine.handle();
    spawn_lateness_report(engine_handle.clone());
    let (clearnet_tx, clearnet_rx) = mpsc::unbounded_channel();
    let (tor_tx, tor_rx) = mpsc::unbounded_channel();
    let on_cause: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(|cause| match cause.kind() {
        kind @ (CloseKind::AdmissionRefused | CloseKind::InboundNotAccepted) => {
            tracing::info!("seam accept refused cause {kind:?}");
        }
        kind => tracing::debug!(kind = ?kind, "zone socket"),
    });
    let host = Arc::new(Host {
        pool: Mutex::new(Some(pool)),
        handle: handle.clone(),
        engine_service: Mutex::new(Some(engine)),
        engine: engine_handle,
        sockets: process_sockets(),
        hub: hub.clone(),
        tor_death: Mutex::new(None),
        tor_proxy: Mutex::new(None),
        clearnet: Mutex::new(None),
        clearnet_tx,
        tor_tx,
        shutdown_timeout: Duration::from_nanos(spans::SHUTDOWN_TIMEOUT_NANOS),
        network_id,
        clearnet_dial_within: Tick::new(spans::CLEARNET_DIAL_WITHIN_NANOS),
        clearnet_handshake_within: Tick::new(spans::CLEARNET_HANDSHAKE_WITHIN_NANOS),
        clearnet_gap_within: Tick::new(spans::CLEARNET_GAP_WITHIN_NANOS),
        tor_dial_within: Tick::new(spans::TOR_DIAL_WITHIN_NANOS),
        tor_gap_within: Tick::new(spans::TOR_GAP_WITHIN_NANOS),
        send_queue_bytes: usize::try_from(spans::SEND_QUEUE_BYTES).unwrap_or(usize::MAX),
        on_cause,
    });
    hub.install_dial(Arc::new(ZoneDial {
        host: Arc::clone(&host),
    }));
    // The dialer's life is the zone host's: shutdown stops and drops it
    // while the seam stays bound, so a host built after one (a re-init in
    // one process) builds it again. A first build happened at the bind.
    crate::dialer_ffi::ensure_dialer(&hub);
    crate::dialer_ffi::set_network_id(network_id);
    handle.spawn(pump(hub, clearnet_rx, tor_rx));
    *slot = Some(Arc::clone(&host));
    Ok(host)
}

async fn pump(
    hub: Hub,
    mut clearnet_rx: mpsc::UnboundedReceiver<ClearnetAdmitted>,
    mut tor_rx: mpsc::UnboundedReceiver<TorAdmitted>,
) {
    loop {
        tokio::select! {
            biased;
            admitted = clearnet_rx.recv() => {
                let Some(admitted) = admitted else { break };
                adopt_clearnet(&hub, admitted);
            }
            admitted = tor_rx.recv() => {
                let Some(admitted) = admitted else { break };
                adopt_tor(&hub, admitted);
            }
        }
    }
}

fn adopt_clearnet(hub: &Hub, admitted: ClearnetAdmitted) {
    let id = admitted.open.id();
    let endpoint = Endpoint::Clearnet {
        ip: admitted.ip,
        port: admitted.port,
        direction: Direction::Inbound,
    };
    let Ok(attached) = hub.adopt(admitted.open, admitted.session, endpoint, admitted.gap) else {
        return;
    };
    hub.drive(id, attached.session);
}

fn adopt_tor(hub: &Hub, admitted: TorAdmitted) {
    let id = admitted.open.id();
    let endpoint = match admitted.onion {
        Some((host, port)) => match shekyl_onion_v3::v3_pubkey(&host) {
            Some(key) => Endpoint::Tor { key, port },
            None => {
                tracing::error!("tor session refused: dialed host is not a v3 onion");
                return;
            }
        },
        None => Endpoint::TorInbound,
    };
    let Ok(attached) = hub.adopt(admitted.open, admitted.bytes, endpoint, Some(admitted.gap))
    else {
        return;
    };
    hub.drive(id, attached.session);
}

/// Every 60 s, the engine's lateness totals for each class that has fired,
/// at debug (Rick, 2026-10-14: the transport diagnosis). The thread ends
/// when the engine closes.
fn spawn_lateness_report(engine: Handle<MonotonicClock>) {
    const EVERY: Duration = Duration::from_secs(60);
    let spawned = std::thread::Builder::new()
        .name("p2p-lateness".to_owned())
        .spawn(move || loop {
            std::thread::sleep(EVERY);
            for class in shekyl_timing_engine::OwnerClass::ALL {
                let Ok(totals) = engine.lateness(class) else {
                    return;
                };
                if totals.fires == 0 && totals.home_reports == 0 {
                    continue;
                }
                tracing::debug!(
                    class = ?class,
                    fires = totals.fires,
                    max_wake_delay_ns = totals.max_wake_delay,
                    wakes_late_1ms = totals.wakes_at_least(1_000_000),
                    wakes_late_100ms = totals.wakes_at_least(100_000_000),
                    home_reports = totals.home_reports,
                    max_home_delay_ns = totals.max_home_delay,
                    homes_late_1ms = totals.homes_at_least(1_000_000),
                    homes_late_100ms = totals.homes_at_least(100_000_000),
                    replaced_wakes = totals.replaced_wakes,
                    "engine lateness"
                );
            }
        });
    if spawned.is_err() {
        tracing::warn!("the engine lateness report could not start");
    }
}

/// Bind clearnet. `encrypt` nonzero selects [`ClearnetOption::On`]; zero
/// is off. `0` and the ports written on success. `-1` on failure, which
/// leaves this zone unbound.
///
/// # Safety
/// `params` is readable. `ipv4` is a NUL-terminated address. `ipv6` may be
/// null. `out_port` and `out_port_v6` are writable.
/// Starts the clearnet connector from its section: dials through `proxy`
/// (with its RFC 1929 pair, if any) when one is given, and listens on every endpoint of `listen` (none is
/// dial-only). Returns the bound endpoints. Fails when the seam is not
/// bound, when a listener cannot bind, or when the channel is refused;
/// nothing is started on failure.
///
/// # Errors
/// [`ZoneStart`].
pub fn start_clearnet(
    listen: &[SocketAddr],
    proxy: Option<Proxy>,
    encrypt: bool,
    network_id: [u8; 16],
) -> Result<Vec<SocketAddr>, ZoneStart> {
    let host = ensure(network_id)?;
    let option = if encrypt {
        ClearnetOption::On
    } else {
        ClearnetOption::Off
    };
    let kind = channel_choice(ConnectorId::Clearnet.column(), option)
        .map_err(|e| ZoneStart::Channel(format!("{e:?}")))?;
    let tally = Arc::new(zero_tally());
    let listeners = host.handle.block_on(async {
        // No reserve: the section's listen list is a handful, and a raw
        // `with_capacity` is a boundary reserve the SA-R-7 ratchet counts.
        let mut bound = Vec::new();
        for addr in listen {
            bound.push(
                TcpListener::bind(*addr)
                    .await
                    .map_err(|error| ZoneStart::Bind { addr: *addr, error })?,
            );
        }
        Ok::<_, ZoneStart>(bound)
    })?;
    let mut locals = Vec::new();
    for listener in &listeners {
        locals.push(listener.local_addr().map_err(|error| {
            ZoneStart::Bind {
                addr: listen
                    .first()
                    .copied()
                    .unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
                error,
            }
        })?);
    }
    // The listeners are bound: clearnet's outbound is usable. Its route is
    // direct, or the operator's proxy, whose pair stays with the host.
    let route = proxy
        .as_ref()
        .map_or(Route::Direct, |proxy| Route::Socks(proxy.at()));
    *host.clearnet.lock().expect("clearnet") = Some(ClearnetReady {
        kind,
        tally: Arc::clone(&tally),
        proxy,
    });
    if let RoutePublish::Installed { .. } =
        host.hub
            .links()
            .publish_usable(ConnectorId::Clearnet, route, host.hub.now())
    {
        tracing::info!("the clearnet zone dials {route:?}");
    }
    crate::dialer_ffi::start_connector(ConnectorId::Clearnet, &host.engine);
    for listener in listeners {
        spawn_clearnet(&host, listener, kind, Arc::clone(&tally));
    }
    Ok(locals)
}

fn spawn_clearnet(
    host: &Host,
    listener: TcpListener,
    kind: shekyl_clearnet::ChannelChoice,
    tally: Arc<shekyl_clearnet::HandshakeTally>,
) {
    let hub = host.hub.clone();
    let inbound = ClearnetInbound {
        sockets: host.sockets.clone(),
        ceiling: move || hub.ceiling(),
        kind,
        network_id: host.network_id,
        handshake_within: host.clearnet_handshake_within,
        gap_within: Some(host.clearnet_gap_within),
        tally,
        on_cause: Arc::clone(&host.on_cause),
        send_queue_bytes: host.send_queue_bytes,
        admitted: host.clearnet_tx.clone(),
        backoff: ACCEPT_BACKOFF,
    };
    let engine = host.engine.clone();
    host.handle.spawn(async move {
        accept_clearnet_inbound(listener, inbound, engine).await;
    });
}

/// Starts the Tor connector over `socks`: dials through it, and listens on
/// a loopback forward endpoint (port chosen by the operating system) for
/// the onion this daemon publishes, plus `extra` when the operator's own
/// Tor forwards to a named endpoint. Returns the forward endpoint.
///
/// # Errors
/// [`ZoneStart`].
pub fn start_tor(
    socks: Proxy,
    extra: Option<SocketAddr>,
    network_id: [u8; 16],
) -> Result<SocketAddr, ZoneStart> {
    let host = ensure(network_id)?;
    install_tor_proxy(&host, socks);
    crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine);
    let forward_at = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (forward, extra) = host.handle.block_on(async {
        let forward = TcpListener::bind(forward_at)
            .await
            .map_err(|error| ZoneStart::Bind {
                addr: forward_at,
                error,
            })?;
        let extra = match extra {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .map_err(|error| ZoneStart::Bind { addr, error })?,
            ),
            None => None,
        };
        Ok::<_, ZoneStart>((forward, extra))
    })?;
    let local = forward.local_addr().map_err(|error| ZoneStart::Bind {
        addr: forward_at,
        error,
    })?;
    spawn_tor(&host, forward);
    if let Some(extra) = extra {
        spawn_tor(&host, extra);
    }
    Ok(local)
}

/// Dials through `socks` on the Tor connector without listening: the
/// operator's own Tor with no onion of this node's.
///
/// # Errors
/// [`ZoneStart`].
pub fn dial_through_tor(socks: Proxy, network_id: [u8; 16]) -> Result<(), ZoneStart> {
    let host = ensure(network_id)?;
    install_tor_proxy(&host, socks);
    crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine);
    Ok(())
}

/// Record the Tor proxy and its pair, and publish its address as the Tor
/// link's route ([`publish_tor_route`]).
fn install_tor_proxy(host: &Host, socks: Proxy) {
    let (at, authenticates) = (socks.at(), socks.authenticates());
    *host.tor_proxy.lock().expect("tor proxy") = Some(socks);
    publish_tor_route(host, at, authenticates);
}

/// The proxy a dial through the route `at` presents: the configured one,
/// with its pair, when its address is that route's, and an unauthenticated
/// one otherwise. A pair given for one proxy is never presented to another
/// (DC-Q7): a route the supervisor publishes later, at the managed Tor's
/// port, does not take the operator's pair with it.
fn presented(at: SocketAddr, configured: Option<&Proxy>) -> Proxy {
    match configured {
        Some(proxy) if proxy.at() == at => proxy.clone(),
        _ => Proxy::unauthenticated(at),
    }
}

fn spawn_tor(host: &Host, listener: TcpListener) {
    let hub = host.hub.clone();
    let inbound = TorInbound {
        sockets: host.sockets.clone(),
        ceiling: move || hub.ceiling(),
        gap_within: host.tor_gap_within,
        on_cause: Arc::clone(&host.on_cause),
        send_queue_bytes: host.send_queue_bytes,
        admitted: host.tor_tx.clone(),
        backoff: ACCEPT_BACKOFF,
    };
    let engine = host.engine.clone();
    host.handle.spawn(async move {
        accept_tor_inbound(listener, inbound, engine).await;
    });
}

/// Publish the Tor link usable through `socks`, until the supervisor owns
/// the route (`TOR_SUPERVISOR.md` §4.1). Both Tor entry points install it.
/// A second publish of the same address is not a new route.
fn publish_tor_route(host: &Host, socks: SocketAddr, authenticates: bool) {
    if let RoutePublish::Installed { .. } =
        host.hub
            .links()
            .publish_usable(ConnectorId::Tor, Route::Socks(socks), host.hub.now())
    {
        tracing::info!(
            "the Tor zone dials through the SOCKS proxy at {socks}{}",
            if authenticates {
                ", with the configured username and password"
            } else {
                ""
            }
        );
    }
}

/// The managed Tor's death takes the Tor link down (`TSR-F1`), so the
/// dialer draws no onion it cannot reach. `death` is that end as a
/// [`DownCause`]: an exit and a stop both take the link down, and only an
/// exit is a fault. The caller maps its own process signal onto that
/// cause. The down names the incarnation installed now: a route published
/// later, by another Tor, is not taken down by this one's death. Only the
/// Tor this daemon manages is watched; an operator's Tor stays usable
/// until the supervisor brings its outbound evidence. A later call
/// replaces the watch. Returns false, and watches nothing, when no zone
/// host is running or no Tor route is installed.
pub fn watch_managed_tor(
    death: impl std::future::Future<Output = DownCause> + Send + 'static,
) -> bool {
    let Some(host) = HOST.lock().expect("zone host").clone() else {
        return false;
    };
    let link = host.hub.links().get(ConnectorId::Tor);
    if link.route.is_none() {
        return false;
    }
    let incarnation = link.incarnation;
    let hub = host.hub.clone();
    let watch = host.handle.spawn(async move {
        let cause = death.await;
        let fell = hub
            .links()
            .publish_down(ConnectorId::Tor, incarnation, cause, hub.now());
        tracing::debug!(
            "the managed Tor ended ({cause:?}); incarnation {incarnation} {}",
            if fell {
                "is down"
            } else {
                "was already replaced"
            }
        );
    });
    let replaced = host.tor_death.lock().expect("tor death").replace(watch);
    if let Some(replaced) = replaced {
        replaced.abort();
    }
    true
}

/// The handshake finished. The row's gap sender fires, which disarms the
/// connector's deadline. An unknown id has nothing to disarm.
#[no_mangle]
pub extern "C" fn shekyl_zone_session_established(id: u64) {
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    let Some(hub) = hub() else {
        return;
    };
    hub.session_established(id);
}

/// Stops the dialer and the zone host: every owner loop, the engine, the
/// transport runtime. A second call, and a call with no host, do nothing
/// but report the write stall.
pub fn shutdown() {
    crate::dialer_ffi::stop();
    let host = HOST.lock().expect("zone host").take();
    if let Some(host) = host {
        // The routes were this host's. A host built later installs its own.
        for connector in ConnectorId::ALL {
            host.hub.links().withdraw(*connector);
        }
        let engine = host.engine_service.lock().expect("engine").take();
        if let Some(engine) = engine.as_ref() {
            engine.close();
        }
        let pool = host.pool.lock().expect("pool").take();
        if let Some(pool) = pool {
            pool.shutdown(host.shutdown_timeout);
        }
        drop(engine);
    }
    let stall = process_write_stall();
    tracing::info!(
        closes = stall.closes,
        max_ns = stall.max_ns,
        in_flight_at_close = stall.in_flight_at_close,
        in_flight_max_ns = stall.in_flight_at_close_max_ns,
        "process write stall"
    );
    process_sockets().clear_zone_caps();
}

#[cfg(test)]
#[path = "zone_ffi_tests.rs"]
mod tests;
