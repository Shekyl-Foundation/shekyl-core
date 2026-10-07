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

use std::ffi::{c_char, CStr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use shekyl_capped_stream::{monotonic_ms, node_gate, process_write_stall, recv_mark_ms, Session};
use shekyl_clearnet::{
    accept_inbound as accept_clearnet_inbound, channel_choice, dial_one as dial_clearnet,
    zero_tally, Admitted as ClearnetAdmitted, ClearnetOption, Dial as ClearnetDial,
    Inbound as ClearnetInbound,
};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
use shekyl_seam::{
    connector_from_index, drive_inbound_async, Channel, CloseCause, CloseKind, ConnectorId, Dial,
    Direction, Endpoint, Hub, SocketId,
};
use shekyl_timing_engine::{Clock, EngineService, Handle, MonotonicClock, Tick};
use shekyl_tor::{
    accept_inbound as accept_tor_inbound, dial_one as dial_tor, Admitted as TorAdmitted,
    Inbound as TorInbound,
};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::inbound_ceiling_ffi::ShekylInboundCeiling;
use crate::seam_ffi::{ceiling_from_abi, hub, process_sockets};

/// Pause after a transient accept error so the loop does not spin. Not a
/// protocol deadline.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(1);

struct Host {
    pool: Mutex<Option<shekyl_runtime::Pool>>,
    handle: tokio::runtime::Handle,
    /// The engine thread. Every handle shares its closed flag, and its
    /// `Drop` sets that flag, so the service lives here for as long as the
    /// host does and is stopped in [`shekyl_zone_shutdown`]. Holding only
    /// the handle closed the engine when `ensure` returned, and every
    /// transport deadline after that was `Closed`.
    engine_service: Mutex<Option<EngineService<MonotonicClock>>>,
    engine: Handle<MonotonicClock>,
    sockets: shekyl_seam::Sockets,
    /// The seam's hub. Accept reads its ceiling on every socket, and the
    /// gap sender lives on the connection row there.
    hub: Hub,
    clearnet: Mutex<Option<ClearnetReady>>,
    tor_proxy: Mutex<Option<SocketAddr>>,
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

struct ClearnetReady {
    kind: shekyl_clearnet::ChannelChoice,
    tally: Arc<shekyl_clearnet::HandshakeTally>,
    proxy: Option<SocketAddr>,
}

static HOST: LazyLock<Mutex<Option<Arc<Host>>>> = LazyLock::new(|| Mutex::new(None));

/// Spans and the runtime budget. The numbers are the caller's. The five
/// deadlines are the measured spans; `workers` and `blocking` stay the
/// structural floor until the thread-budget leg. `shutdown_timeout_ns`
/// is the longest armed deadline. Field order matches `shekyl_zone_params`.
/// This module does not pick a thread count or a deadline.
#[repr(C)]
pub struct ShekylZoneParams {
    pub network_id: *const u8,
    pub clearnet_dial_within_ns: u64,
    pub clearnet_handshake_within_ns: u64,
    pub clearnet_gap_within_ns: u64,
    pub tor_dial_within_ns: u64,
    pub tor_gap_within_ns: u64,
    pub send_queue_bytes: u64,
    pub shutdown_timeout_ns: u64,
    pub workers: usize,
    pub blocking: usize,
}

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
                proxy: ready.proxy,
            })
            .ok_or_else(|| CloseCause::new(CloseKind::LocalClose))?;
        let address = match ip {
            IpAddr::V4(ip) => NetworkAddress::Ipv4 { ip, port },
            IpAddr::V6(ip) => NetworkAddress::Ipv6 { ip, port },
        };
        let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
        let (on_cause, fail_rx) = failure_slot();
        let dial = ClearnetDial {
            address,
            proxy: ready.proxy,
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
        let proxy = self
            .host
            .tor_proxy
            .lock()
            .expect("tor proxy")
            .ok_or_else(|| CloseCause::new(CloseKind::LocalClose))?;
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

fn ensure(params: &ShekylZoneParams, ceiling: InboundCeiling) -> Result<Arc<Host>, ()> {
    let mut slot = HOST.lock().expect("zone host");
    if let Some(host) = slot.as_ref() {
        return Ok(Arc::clone(host));
    }
    let Some(hub) = hub() else {
        return Err(());
    };
    hub.set_ceiling(ceiling);
    let network_id = read_id(params.network_id).ok_or(())?;
    let workers = NonZeroUsize::new(params.workers).ok_or(())?;
    let blocking = NonZeroUsize::new(params.blocking).ok_or(())?;
    let name = ThreadName::new("p2p-transport").map_err(|_| ())?;
    let pool = runtime(RuntimeBudget { workers, blocking }, &name).map_err(|_| ())?;
    let handle = pool.handle().clone();
    let clock = MonotonicClock::new();
    let budget_clock = clock.clone();
    node_gate().install_clock(Arc::new(move || budget_clock.now().get()));
    let engine = EngineService::start(clock);
    let engine_handle = engine.handle();
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
        clearnet: Mutex::new(None),
        tor_proxy: Mutex::new(None),
        clearnet_tx,
        tor_tx,
        shutdown_timeout: Duration::from_nanos(params.shutdown_timeout_ns),
        network_id,
        clearnet_dial_within: Tick::new(params.clearnet_dial_within_ns),
        clearnet_handshake_within: Tick::new(params.clearnet_handshake_within_ns),
        clearnet_gap_within: Tick::new(params.clearnet_gap_within_ns),
        tor_dial_within: Tick::new(params.tor_dial_within_ns),
        tor_gap_within: Tick::new(params.tor_gap_within_ns),
        send_queue_bytes: usize::try_from(params.send_queue_bytes).unwrap_or(usize::MAX),
        on_cause,
    });
    hub.install_dial(Arc::new(ZoneDial {
        host: Arc::clone(&host),
    }));
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
    spawn_drive(hub, id, attached.session);
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
    spawn_drive(hub, id, attached.session);
}

/// One task per connection, not one blocking thread: the pool has the
/// caller's cap, and a thread held for the life of a connection made
/// every connection past that cap deaf.
fn spawn_drive(hub: &Hub, id: SocketId, session: Session) {
    let hub = hub.clone();
    tokio::spawn(async move { drive_inbound_async(&hub, id, session).await });
}

fn read_id(ptr: *const u8) -> Option<[u8; 16]> {
    if ptr.is_null() {
        return None;
    }
    let mut id = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, id.as_mut_ptr(), 16);
    }
    Some(id)
}

fn c_str(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(ptr) }.to_str().ok()?;
    Some(text.to_owned())
}

/// Bind clearnet. `encrypt` nonzero selects [`ClearnetOption::On`]; zero
/// is off. `0` and the ports written on success. `-1` on failure, which
/// leaves this zone unbound.
///
/// # Safety
/// `params` is readable. `ipv4` is a NUL-terminated address. `ipv6` may be
/// null. `out_port` and `out_port_v6` are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_zone_listen_clearnet(
    ipv4: *const c_char,
    port: u16,
    ipv6: *const c_char,
    port_v6: u16,
    use_ipv6: i32,
    proxy_host: *const c_char,
    proxy_port: u16,
    encrypt: i32,
    params: *const ShekylZoneParams,
    ceiling: *const ShekylInboundCeiling,
    out_port: *mut i32,
    out_port_v6: *mut i32,
) -> i32 {
    if params.is_null() || ceiling.is_null() || out_port.is_null() || out_port_v6.is_null() {
        return -1;
    }
    let params = unsafe { &*params };
    let ceiling = match ceiling_from_abi(unsafe { *ceiling }) {
        Some(ceiling) => ceiling,
        None => return -1,
    };
    let Ok(host) = ensure(params, ceiling) else {
        return -1;
    };
    let Some(ipv4) = c_str(ipv4) else {
        return -1;
    };
    let Ok(ip) = ipv4.parse::<IpAddr>() else {
        return -1;
    };
    let proxy = match c_str(proxy_host) {
        Some(text) => {
            let Ok(ip) = text.parse::<IpAddr>() else {
                return -1;
            };
            Some(SocketAddr::new(ip, proxy_port))
        }
        None => None,
    };
    let option = if encrypt != 0 {
        ClearnetOption::On
    } else {
        ClearnetOption::Off
    };
    let kind = match channel_choice(ConnectorId::Clearnet.column(), option) {
        Ok(kind) => kind,
        Err(_) => return -1,
    };
    let tally = Arc::new(zero_tally());
    let ipv6_addr = if use_ipv6 != 0 {
        let Some(text) = c_str(ipv6) else {
            return -1;
        };
        let Ok(parsed) = text.parse::<IpAddr>() else {
            return -1;
        };
        Some(SocketAddr::new(parsed, port_v6))
    } else {
        None
    };
    // Bind every requested socket before accepting or publishing readiness.
    // A later failure drops the listeners, so no port stays up.
    let bound = host.handle.block_on(async {
        let v4 = TcpListener::bind(SocketAddr::new(ip, port)).await?;
        let v6 = match ipv6_addr {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        std::io::Result::Ok((v4, v6))
    });
    let (bound_v4, bound_v6) = match bound {
        Ok(pair) => pair,
        Err(_) => return -1,
    };
    let Ok(local) = bound_v4.local_addr() else {
        return -1;
    };
    let local_v6 = match &bound_v6 {
        Some(listener) => match listener.local_addr() {
            Ok(addr) => Some(addr.port()),
            Err(_) => return -1,
        },
        None => None,
    };
    *host.clearnet.lock().expect("clearnet") = Some(ClearnetReady {
        kind,
        tally: Arc::clone(&tally),
        proxy,
    });
    spawn_clearnet(&host, bound_v4, kind, Arc::clone(&tally));
    if let Some(listener) = bound_v6 {
        spawn_clearnet(&host, listener, kind, tally);
    }
    unsafe {
        *out_port = i32::from(local.port());
        *out_port_v6 = local_v6.map(i32::from).unwrap_or(-1);
    }
    0
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

/// Bind the Tor forward listener on `127.0.0.1:0` and, when `extra` is
/// non-null, the operator's inbound address. `0` and the forward port on
/// success.
///
/// # Safety
/// `params` and `socks_host` are readable. `extra` may be null. `out_port`
/// is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_zone_listen_tor(
    socks_host: *const c_char,
    socks_port: u16,
    extra: *const c_char,
    extra_port: u16,
    params: *const ShekylZoneParams,
    ceiling: *const ShekylInboundCeiling,
    out_port: *mut i32,
) -> i32 {
    if params.is_null() || ceiling.is_null() || out_port.is_null() {
        return -1;
    }
    let params = unsafe { &*params };
    let ceiling = match ceiling_from_abi(unsafe { *ceiling }) {
        Some(ceiling) => ceiling,
        None => return -1,
    };
    let Ok(host) = ensure(params, ceiling) else {
        return -1;
    };
    let Some(socks_host) = c_str(socks_host) else {
        return -1;
    };
    let Ok(socks_ip) = socks_host.parse::<IpAddr>() else {
        return -1;
    };
    *host.tor_proxy.lock().expect("tor proxy") = Some(SocketAddr::new(socks_ip, socks_port));
    let extra = match c_str(extra) {
        Some(text) => {
            let Ok(ip) = text.parse::<IpAddr>() else {
                return -1;
            };
            Some(SocketAddr::new(ip, extra_port))
        }
        None => None,
    };
    let bound = host.handle.block_on(async {
        let forward = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let extra = match extra {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        std::io::Result::Ok((forward, extra))
    });
    let (forward, extra) = match bound {
        Ok(pair) => pair,
        Err(_) => return -1,
    };
    let Ok(local) = forward.local_addr() else {
        return -1;
    };
    spawn_tor(&host, forward);
    if let Some(extra) = extra {
        spawn_tor(&host, extra);
    }
    unsafe {
        *out_port = i32::from(local.port());
    }
    0
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

/// The SOCKS proxy the Tor connector dials through, for a tor zone with no
/// inbound listener. [`shekyl_zone_listen_tor`] installs it for zones that
/// listen; an outbound-only `--tx-proxy tor` zone never called that, so the
/// host had no proxy and every Tor dial was `DialFailed` before the
/// network. Returns 0, or -1 when the host cannot be built or `socks_host`
/// does not parse.
///
/// # Safety
/// `socks_host`, `params`, and `ceiling` are readable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_zone_set_tor_proxy(
    socks_host: *const c_char,
    socks_port: u16,
    params: *const ShekylZoneParams,
    ceiling: *const ShekylInboundCeiling,
) -> i32 {
    if params.is_null() || ceiling.is_null() {
        return -1;
    }
    let params = unsafe { &*params };
    let ceiling = match ceiling_from_abi(unsafe { *ceiling }) {
        Some(ceiling) => ceiling,
        None => return -1,
    };
    let Ok(host) = ensure(params, ceiling) else {
        return -1;
    };
    let Some(socks_host) = c_str(socks_host) else {
        return -1;
    };
    let Ok(socks_ip) = socks_host.parse::<IpAddr>() else {
        return -1;
    };
    *host.tor_proxy.lock().expect("tor proxy") = Some(SocketAddr::new(socks_ip, socks_port));
    0
}

/// Replace the ceiling later accepts use.
///
/// Returns 0 when the seam hub holds the new ceiling. Returns -1 when
/// `ceiling` is null or not a known decision, or when the seam is unbound:
/// there is no hub to write, and a success would claim a ceiling that
/// the next bind would replace with its own.
#[no_mangle]
pub extern "C" fn shekyl_zone_set_ceiling(ceiling: *const ShekylInboundCeiling) -> i32 {
    if ceiling.is_null() {
        return -1;
    }
    let ceiling = match ceiling_from_abi(unsafe { *ceiling }) {
        Some(ceiling) => ceiling,
        None => return -1,
    };
    let Some(hub) = hub() else {
        return -1;
    };
    hub.set_ceiling(ceiling);
    0
}

/// The operator's inbound cap for one connector. Accept enforces it for
/// that connector and still enforces the process ceiling on the sum.
///
/// `connector` is the FFI connector word ([`connector_from_index`]).
/// Returns 0, or -1 when `connector` is not one.
#[no_mangle]
pub extern "C" fn shekyl_zone_set_connector_cap(connector: u32, cap: u32) -> i32 {
    let Some(connector) = connector_from_index(connector) else {
        return -1;
    };
    process_sockets().set_zone_cap(connector, Some(cap));
    0
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

const KIB: u64 = 1024;

fn store_rate(kbps: i64, set: impl Fn(Option<u64>)) {
    if kbps < 0 {
        set(None);
    } else {
        let kbps = u64::try_from(kbps).unwrap_or(0);
        set(Some(kbps.saturating_mul(KIB)));
    }
}

fn load_rate(rate: Option<u64>) -> i64 {
    match rate {
        None => -1,
        Some(bytes) => i64::try_from(bytes / KIB).unwrap_or(i64::MAX),
    }
}

/// `kbps` negative removes the up bucket. Zero or positive is KiB/s.
#[no_mangle]
pub extern "C" fn shekyl_link_set_up(kbps: i64) {
    store_rate(kbps, |rate| node_gate().set_up(rate));
}

/// `kbps` negative removes the down bucket. Zero or positive is KiB/s.
#[no_mangle]
pub extern "C" fn shekyl_link_set_down(kbps: i64) {
    store_rate(kbps, |rate| node_gate().set_down(rate));
}

/// The up rate in KiB/s, or -1 when that direction is unlimited.
#[no_mangle]
pub extern "C" fn shekyl_link_get_up() -> i64 {
    load_rate(node_gate().rate_up())
}

/// The down rate in KiB/s, or -1 when that direction is unlimited.
#[no_mangle]
pub extern "C" fn shekyl_link_get_down() -> i64 {
    load_rate(node_gate().rate_down())
}

/// Bytes and packets the budget has moved. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_totals(
    bytes_down: *mut u64,
    packets_down: *mut u64,
    bytes_up: *mut u64,
    packets_up: *mut u64,
) {
    let observed = node_gate().totals();
    unsafe {
        if !bytes_down.is_null() {
            *bytes_down = observed.bytes_down;
        }
        if !packets_down.is_null() {
            *packets_down = observed.packets_down;
        }
        if !bytes_up.is_null() {
            *bytes_up = observed.bytes_up;
        }
        if !packets_up.is_null() {
            *packets_up = observed.packets_up;
        }
    }
}

/// Bytes per second on this connection, from the engine's clock, over
/// the link budget's recent-speed window. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_speed(
    id: u64,
    bytes_per_sec_up: *mut u64,
    bytes_per_sec_down: *mut u64,
) {
    let (up, down) = node_gate().speed(id);
    unsafe {
        if !bytes_per_sec_up.is_null() {
            *bytes_per_sec_up = up;
        }
        if !bytes_per_sec_down.is_null() {
            *bytes_per_sec_down = down;
        }
    }
}

/// Bytes this connection has moved. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_connection(id: u64, bytes_up: *mut u64, bytes_down: *mut u64) {
    let observed = node_gate().connection(id);
    unsafe {
        if !bytes_up.is_null() {
            *bytes_up = observed.bytes_up;
        }
        if !bytes_down.is_null() {
            *bytes_down = observed.bytes_down;
        }
    }
}

/// Monotonic milliseconds of the last byte read or written. A grant is
/// not a byte. Zero until that direction has moved one. Null pointers
/// are skipped. The stall check uses this with [`shekyl_monotonic_ms`].
#[no_mangle]
pub extern "C" fn shekyl_link_activity(id: u64, last_send_ms: *mut u64, last_recv_ms: *mut u64) {
    let (send, recv) = node_gate().activity(id);
    unsafe {
        if !last_send_ms.is_null() {
            *last_send_ms = send;
        }
        if !last_recv_ms.is_null() {
            *last_recv_ms = recv;
        }
    }
}

/// The same instants as unix milliseconds, for the operator view.
/// Zero stays zero. The stall check does not call this.
#[no_mangle]
pub extern "C" fn shekyl_link_unix_ms(id: u64, last_send_ms: *mut u64, last_recv_ms: *mut u64) {
    let (send, recv) = node_gate().activity_unix(id);
    unsafe {
        if !last_send_ms.is_null() {
            *last_send_ms = send;
        }
        if !last_recv_ms.is_null() {
            *last_recv_ms = recv;
        }
    }
}

/// Milliseconds on the monotonic clock the byte stamps use.
#[no_mangle]
pub extern "C" fn shekyl_monotonic_ms() -> u64 {
    monotonic_ms()
}

/// The stall mark. A receive instant of zero uses admission.
#[no_mangle]
pub extern "C" fn shekyl_recv_mark_ms(recv_ms: u64, started_ms: u64) -> u64 {
    recv_mark_ms(recv_ms, started_ms)
}

/// Stop the transport runtime. Called from outside one of its tasks.
///
/// D6's order: the engine takes no new deadline, the transport's tasks
/// are cancelled, then the engine thread is joined. The process write-stall
/// histogram is read here: nothing else in the daemon reads it.
#[no_mangle]
pub extern "C" fn shekyl_zone_shutdown() {
    let stall = process_write_stall();
    tracing::info!(
        closes = stall.closes,
        max_ns = stall.max_ns,
        in_flight_at_close = stall.in_flight_at_close,
        in_flight_max_ns = stall.in_flight_at_close_max_ns,
        "process write stall"
    );
    let host = HOST.lock().expect("zone host").take();
    let Some(host) = host else {
        return;
    };
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

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use shekyl_peer_policy::UnboundedReason;
    use shekyl_timing_engine::OwnerClass;

    use super::*;
    use crate::inbound_ceiling_ffi::SHEKYL_INBOUND_CEILING_UNLIMITED;
    use crate::seam_ffi::{shekyl_seam_bind, ShekylSeamObserved};

    unsafe extern "C" fn discard(
        _ctx: *mut c_void,
        _id: u64,
        _kind: u32,
        _observed: *const ShekylSeamObserved,
        _bytes: *const u8,
        _len: usize,
        _cause: *const CloseCause,
    ) {
    }

    /// The connectors arm every transport deadline on the host's engine
    /// handle. `ensure` once stored the handle and dropped the service, so
    /// the engine closed the moment `ensure` returned and every NNhfs and
    /// Tor connection failed with `TransportHandshakeFailed`. The option-off
    /// path arms nothing and never saw it.
    #[test]
    fn the_engine_outlives_ensure() {
        let _bind = crate::seam_ffi::seam_bind_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut executor = 0u8;
        let ceiling = ShekylInboundCeiling {
            kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
            ceiling: 0,
            soft_limit: 0,
            held: 0,
        };
        let bound = unsafe {
            shekyl_seam_bind(
                std::ptr::addr_of_mut!(executor).cast::<c_void>(),
                Some(discard),
                &raw const ceiling,
            )
        };
        assert_eq!(bound, 0);
        let network_id = [7u8; 16];
        let params = ShekylZoneParams {
            network_id: network_id.as_ptr(),
            clearnet_dial_within_ns: 1_000_000_000,
            clearnet_handshake_within_ns: 1_000_000_000,
            clearnet_gap_within_ns: 1_000_000_000,
            tor_dial_within_ns: 1_000_000_000,
            tor_gap_within_ns: 1_000_000_000,
            send_queue_bytes: 65_536,
            shutdown_timeout_ns: 1_000_000_000,
            workers: 1,
            blocking: 1,
        };
        let host = ensure(
            &params,
            InboundCeiling::Unbounded(UnboundedReason::Unlimited),
        )
        .expect("zone host");

        let owner = host.engine.register(OwnerClass::Transport);
        assert!(
            owner.is_ok(),
            "a transport deadline must be armable after ensure returns"
        );
        drop(owner);

        // An outbound-only tor zone installs its proxy without listening.
        assert!(host.tor_proxy.lock().expect("tor proxy").is_none());
        let socks = std::ffi::CString::new("127.0.0.1").expect("socks host");
        let rc = unsafe {
            shekyl_zone_set_tor_proxy(socks.as_ptr(), 9050, &raw const params, &raw const ceiling)
        };
        assert_eq!(rc, 0);
        assert_eq!(
            *host.tor_proxy.lock().expect("tor proxy"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9050)),
            "dial_tor reads this; None is DialFailed before the network"
        );

        shekyl_zone_shutdown();
        assert!(
            host.engine.register(OwnerClass::Transport).is_err(),
            "shutdown closes the engine"
        );
        unsafe {
            shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
        }
    }

    #[test]
    fn a_closed_admission_keeps_the_dial_cause() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let (tx, rx) = mpsc::unbounded_channel::<u8>();
            let (fail_tx, fail_rx) = oneshot::channel();
            fail_tx
                .send(CloseCause::new(CloseKind::DialFailed))
                .expect("cause");
            drop(tx);
            let err = recv_admitted(rx, fail_rx).await.expect_err("dial failed");
            assert_eq!(err.kind(), CloseKind::DialFailed);
        });
    }
}
