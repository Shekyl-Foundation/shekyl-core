// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor connector.
//!
//! The Tor stream is the transport contract. There is no Noise layer and
//! no handshake on the blocking pool. The byte cap and the socket copy
//! are [`shekyl_capped_stream`]. Outbound dials an onion through the
//! operator's SOCKS5 proxy ([`shekyl_socks`]). The dial clock is one
//! engine owner covering that exchange, the circuit build, and
//! rendezvous. Inbound is [`Sockets::accept_tor`], then the same copy
//! with the gap as one arm of the wait. Onion-service proof-of-work and
//! `MaxStreams` are the accept bound. This crate does not add another.
//!
//! `--tx-proxy` and `--anonymous-inbound` stay parsed in C++. They arrive
//! here as [`Config`]. A bind failure returns before a listener exists,
//! which is the zone not being inserted. The 60-second Tor liveness poll
//! in `idle_worker` is a timing-table item and is not this connector's.

#![deny(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, Sockets};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

mod drive;
mod publish;

pub use publish::{publish_forward, publish_with_control, InboundPosture, PublishFault};

pub use drive::{accept_inbound, accept_one, dial_one, Accept, Admitted, Dial, Inbound};

/// Caller inputs. The dial span, the gap span, and the send-queue byte
/// cap are unmeasured until a measurement names them.
pub struct Config {
    /// The operator's SOCKS5 proxy. Outbound dials go here.
    pub proxy: SocketAddr,
    /// Binds from `--anonymous-inbound`. These are the operator's onions.
    /// They are not a [`ForwardAddr`], so [`publish_forward`] cannot name them.
    pub anonymous_inbound: Vec<OperatorInbound>,
    pub ceiling: InboundCeiling,
    /// Covers the SOCKS exchange, circuit build, and rendezvous.
    pub dial_within: Tick,
    /// Starts when the stream exists. The session layer ends it.
    pub gap_within: Tick,
    pub send_queue_bytes: usize,
    pub accept_backoff: Duration,
    pub shutdown_timeout: Duration,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
}

/// An onion the operator already published. The daemon binds `bind` and
/// does not publish it. There is no conversion to [`ForwardAddr`].
#[derive(Clone, Copy, Debug)]
pub struct OperatorInbound {
    bind: SocketAddr,
}

impl OperatorInbound {
    pub fn new(bind: SocketAddr) -> Self {
        Self { bind }
    }

    pub fn bind(self) -> SocketAddr {
        self.bind
    }
}

/// The loopback port a managed onion forwards to.
///
/// [`listen`] mints this from the forward listener. [`publish_forward`]
/// is the only publisher, and it takes this type. [`OperatorInbound`]
/// does not convert into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardAddr {
    socket: SocketAddr,
}

impl ForwardAddr {
    pub(crate) fn from_bound(socket: SocketAddr) -> std::io::Result<Self> {
        if socket.ip().is_loopback() {
            Ok(Self { socket })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tor forward listener is not loopback",
            ))
        }
    }

    /// The socket `ADD_ONION` targets.
    #[must_use]
    pub fn socket(self) -> SocketAddr {
        self.socket
    }
}

/// One Tor stream's session bytes, plus the gap signal.
///
/// `established` is dropped first. A drop before
/// [`Self::session_established`] ends the connection with
/// [`CloseKind::LocalClose`] instead of waiting out the gap.
pub struct Session {
    established: Option<oneshot::Sender<()>>,
    bytes: shekyl_capped_stream::Session,
}

impl Session {
    pub(crate) fn open(
        bytes: shekyl_capped_stream::Session,
        established: oneshot::Sender<()>,
    ) -> Self {
        Self {
            established: Some(established),
            bytes,
        }
    }

    /// The next bytes off the stream. `None` means the reader stopped.
    /// [`Self::close_cause`] is why.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.bytes.recv().await
    }

    /// The cause the connector stored when it closed this stream.
    ///
    /// [`CloseKind::PeerClosed`] only when the reader saw end-of-file.
    #[must_use]
    pub fn close_cause(&self) -> CloseCause {
        self.bytes.close_cause()
    }

    /// Queue bytes up to the caller's cap. A buffer that does not fit is
    /// not stored, and the connection closes with
    /// [`CloseKind::SendQueueFull`]. The cap is unmeasured until PWD-T6's
    /// session-established limit plus measurement names it.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        self.bytes.try_send(bytes)
    }

    /// The Levin handshake is done. The gap arm is disarmed.
    pub fn session_established(&mut self) {
        if let Some(sender) = self.established.take() {
            match sender.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
    }
}

/// The listener. [`Drop`] shuts the pool down with the caller's timeout.
/// [`shutdown`](Self::shutdown) is the same call, and neither may run
/// inside a task: Tokio panics if a runtime is dropped there. That is
/// [`shekyl_runtime::Pool`]'s rule. Dropping the listener is how a pool
/// that was not shut down explicitly still leaves.
pub struct Listener<C: Clock + Clone> {
    pool: Option<Pool>,
    handle: tokio::runtime::Handle,
    shutdown_timeout: Duration,
    forward: ForwardAddr,
    extra: Vec<SocketAddr>,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    engine: Handle<C>,
    sockets: Sockets,
    proxy: SocketAddr,
    dial_within: Tick,
    gap_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    admitted_tx: mpsc::UnboundedSender<drive::Admitted>,
}

impl<C: Clock + Clone> Listener<C> {
    /// The loopback forward target. Publish takes this value.
    #[must_use]
    pub fn forward_addr(&self) -> ForwardAddr {
        self.forward
    }

    pub fn extra_addrs(&self) -> &[SocketAddr] {
        &self.extra
    }

    pub fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("pool still held")
    }

    pub fn runtime_handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    pub fn shutdown(mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

impl<C> Listener<C>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    /// Dial an onion through the configured proxy.
    pub fn dial(&self, address: NetworkAddress) {
        let dial = Dial {
            address,
            proxy: self.proxy,
            sockets: self.sockets.clone(),
            dial_within: self.dial_within,
            gap_within: self.gap_within,
            on_cause: Arc::clone(&self.on_cause),
            send_queue_bytes: self.send_queue_bytes,
            admitted: self.admitted_tx.clone(),
        };
        let engine = self.engine.clone();
        self.handle.spawn(dial_one(dial, engine));
    }
}

impl<C: Clock + Clone> Drop for Listener<C> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

/// Bind the loopback forward target and any anonymous-inbound addresses.
///
/// `sockets` is the process-wide admission table. Clones share it, and
/// the ceiling counts every connector on that table. This function keeps
/// a clone and does not mint a table.
///
/// One failed bind drops the listeners that succeeded and returns the
/// error. The caller does not insert the zone. An accepted socket is
/// handed to admission directly. There is no queue of sockets ahead of
/// that check.
pub fn listen<C>(
    pool: Pool,
    engine: &Handle<C>,
    sockets: &Sockets,
    config: &Config,
) -> std::io::Result<Listener<C>>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let handle = pool.handle().clone();
    let (forward_listener, extras) = pool.block_on(bind_all(&config.anonymous_inbound))?;
    let forward = ForwardAddr::from_bound(forward_listener.local_addr()?)?;
    let mut extra_addrs = Vec::with_capacity(extras.len());
    for listener in &extras {
        extra_addrs.push(listener.local_addr()?);
    }
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel::<Admitted>();
    let engine_keep = engine.clone();
    let sockets_keep = sockets.clone();
    let admitted_keep = admitted_tx.clone();
    let on_cause_keep = Arc::clone(&config.on_cause);
    let shutdown_timeout = config.shutdown_timeout;
    let proxy = config.proxy;
    let dial_within = config.dial_within;
    let gap_within = config.gap_within;
    let send_queue_bytes = config.send_queue_bytes;
    let ceiling = config.ceiling;
    let backoff = config.accept_backoff;
    let on_cause = Arc::clone(&config.on_cause);
    handle.spawn(async move {
        while let Some(admitted) = admitted_rx.recv().await {
            drop(admitted.open);
            let session = Session::open(admitted.bytes, admitted.gap);
            if sessions_tx.send(session).is_err() {
                break;
            }
        }
    });
    let mut listeners = extras;
    listeners.push(forward_listener);
    for listener in listeners {
        let inbound = Inbound {
            sockets: sockets.clone(),
            ceiling: move || ceiling,
            gap_within,
            on_cause: Arc::clone(&on_cause),
            send_queue_bytes,
            admitted: admitted_tx.clone(),
            backoff,
        };
        let engine = engine.clone();
        handle.spawn(async move {
            accept_inbound(listener, inbound, engine).await;
        });
    }
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout,
        forward,
        extra: extra_addrs,
        sessions: sessions_rx,
        engine: engine_keep,
        sockets: sockets_keep,
        proxy,
        dial_within,
        gap_within,
        send_queue_bytes,
        on_cause: on_cause_keep,
        admitted_tx: admitted_keep,
    })
}

async fn bind_all(extra: &[OperatorInbound]) -> std::io::Result<(TcpListener, Vec<TcpListener>)> {
    let forward = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let mut bound = Vec::with_capacity(extra.len());
    for addr in extra {
        bound.push(TcpListener::bind(addr.bind()).await?);
    }
    Ok((forward, bound))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use shekyl_net_address::NetworkAddress;
    use shekyl_onion_v3::v3_onion_hostname;
    use shekyl_peer_policy::InboundCeiling;
    use shekyl_runtime::{runtime, RuntimeBudget, ThreadName, ThreadStart};
    use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
    use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, Direction, Sockets};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{listen, Config, Listener, OperatorInbound};

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("nonzero")
    }

    fn budget() -> RuntimeBudget {
        RuntimeBudget {
            workers: nz(2),
            blocking: nz(1),
        }
    }

    fn name() -> ThreadName {
        ThreadName::new("sk-tor").expect("name")
    }

    struct Recorded {
        sink: Arc<dyn Fn(CloseCause) + Send + Sync>,
        seen: Arc<Mutex<Vec<CloseCause>>>,
    }

    fn causes() -> Recorded {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let sink: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(move |cause| {
            record.lock().expect("causes").push(cause);
        });
        Recorded { sink, seen }
    }

    fn config(
        proxy: SocketAddr,
        inbound: Vec<SocketAddr>,
        ceiling: InboundCeiling,
        dial: Tick,
        gap: Tick,
        on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    ) -> Config {
        Config {
            proxy,
            anonymous_inbound: inbound.into_iter().map(OperatorInbound::new).collect(),
            ceiling,
            dial_within: dial,
            gap_within: gap,
            send_queue_bytes: 64,
            accept_backoff: Duration::from_millis(1),
            shutdown_timeout: Duration::from_millis(50),
            on_cause,
        }
    }

    fn start(
        proxy: SocketAddr,
        ceiling: InboundCeiling,
        gap: Tick,
    ) -> (
        EngineService<MonotonicClock>,
        Listener<MonotonicClock>,
        Arc<Mutex<Vec<CloseCause>>>,
    ) {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let recorded = causes();
        let listener = listen(
            pool,
            &engine.handle(),
            &Sockets::new(),
            &config(
                proxy,
                Vec::new(),
                ceiling,
                Tick::new(5_000_000_000),
                gap,
                recorded.sink,
            ),
        )
        .expect("listen");
        (engine, listener, recorded.seen)
    }

    fn onion() -> NetworkAddress {
        NetworkAddress::Tor {
            host: v3_onion_hostname(&[0x11; 32]),
            port: 18081,
        }
    }

    fn wait_kind(seen: &Mutex<Vec<CloseCause>>, kind: CloseKind) -> CloseCause {
        let start = Instant::now();
        loop {
            if let Some(cause) = seen
                .lock()
                .expect("causes")
                .iter()
                .copied()
                .find(|cause| cause.kind() == kind)
            {
                return cause;
            }
            assert!(start.elapsed() < Duration::from_secs(2), "cause {kind:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn an_ip_address_is_not_dialed() {
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let (engine, listener, seen) =
            start(proxy, InboundCeiling::Bounded(4), Tick::new(5_000_000_000));
        listener.dial(NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: 18080,
        });
        let cause = wait_kind(&seen, CloseKind::LocalClose);
        assert!(!cause.implicates_address(ConnectorId::Tor));
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_failed_anonymous_bind_does_not_leave_a_listener() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let held =
            std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("hold");
        let taken = held.local_addr().expect("addr");
        let recorded = causes();
        let result = listen(
            pool,
            &engine.handle(),
            &Sockets::new(),
            &config(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                vec![taken],
                InboundCeiling::Bounded(4),
                Tick::new(5_000_000_000),
                Tick::new(5_000_000_000),
                recorded.sink,
            ),
        );
        assert!(result.is_err());
        drop(held);
        drop(engine);
    }

    #[test]
    fn bytes_pass_through_the_socks_dial() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let recorded = causes();
        let runtime_handle = pool.handle().clone();
        let (proxy_port, got) = runtime_handle.block_on(async {
            let dest = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("dest");
            let dest_port = dest.local_addr().expect("addr").port();
            let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("proxy");
            let proxy_port = proxy.local_addr().expect("addr").port();
            let got = tokio::spawn(async move {
                let (mut sock, _) = dest.accept().await.expect("accept");
                let mut buf = [0u8; 3];
                sock.read_exact(&mut buf).await.expect("read");
                sock.write_all(b"in").await.expect("write");
                buf
            });
            tokio::spawn(async move {
                let (mut sock, _) = proxy.accept().await.expect("proxy");
                let mut greeting = [0u8; 3];
                sock.read_exact(&mut greeting).await.expect("greet");
                sock.write_all(&[0x05, 0x00]).await.expect("method");
                let mut head = [0u8; 5];
                sock.read_exact(&mut head).await.expect("head");
                assert_eq!(head[3], 0x03);
                let len = usize::from(head[4]);
                let mut name = vec![0u8; len + 2];
                sock.read_exact(&mut name).await.expect("name");
                let mut upstream =
                    TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, dest_port)))
                        .await
                        .expect("upstream");
                sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
                match tokio::io::copy_bidirectional(&mut sock, &mut upstream).await {
                    Ok(_) | Err(_) => {}
                }
            });
            (proxy_port, got)
        });
        let mut listener = listen(
            pool,
            &engine.handle(),
            &Sockets::new(),
            &config(
                SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)),
                Vec::new(),
                InboundCeiling::Bounded(4),
                Tick::new(5_000_000_000),
                Tick::new(5_000_000_000),
                recorded.sink,
            ),
        )
        .expect("listen");
        listener.dial(onion());
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        session.try_send(b"out".to_vec()).expect("send");
        assert_eq!(handle.block_on(got).expect("joined"), *b"out");
        let got = handle.block_on(session.recv()).expect("inbound");
        assert_eq!(got, b"in");
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_socks_refusal_keeps_the_reply_byte() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let recorded = causes();
        let handle_pool = pool.handle().clone();
        let proxy_port = handle_pool.block_on(async {
            let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("proxy");
            let port = proxy.local_addr().expect("addr").port();
            tokio::spawn(async move {
                let (mut sock, _) = proxy.accept().await.expect("accept");
                let mut greeting = [0u8; 3];
                sock.read_exact(&mut greeting).await.expect("greet");
                sock.write_all(&[0x05, 0x00]).await.expect("method");
                let mut head = [0u8; 5];
                sock.read_exact(&mut head).await.expect("head");
                let len = usize::from(head[4]);
                let mut rest = vec![0u8; len + 2];
                sock.read_exact(&mut rest).await.expect("rest");
                sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
            });
            port
        });
        let listener = listen(
            pool,
            &engine.handle(),
            &Sockets::new(),
            &config(
                SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)),
                Vec::new(),
                InboundCeiling::Bounded(4),
                Tick::new(5_000_000_000),
                Tick::new(5_000_000_000),
                recorded.sink,
            ),
        )
        .expect("listen");
        listener.dial(onion());
        let cause = wait_kind(&recorded.seen, CloseKind::ProxyRefused);
        assert_eq!(cause.reply_code(), 0x05);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn inbound_bytes_are_the_socket_bytes_and_the_gap_closes_an_unestablished_session() {
        let (engine, mut listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(400_000_000),
        );
        let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        client.set_read_timeout(Some(Duration::from_secs(2))).ok();
        client.write_all(b"levin").expect("write");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        let got = handle.block_on(session.recv()).expect("bytes");
        assert_eq!(got, b"levin");
        session.try_send(b"out".to_vec()).expect("send");
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"out");
        let cause = wait_kind(&seen, CloseKind::LevinHandshakeTimeout);
        assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_silent_acceptor_is_a_handshake_timeout() {
        let (engine, mut listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(300_000_000),
        );
        let client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        let cause = handle.block_on(async {
            while session.recv().await.is_some() {}
            session.close_cause()
        });
        assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
        assert_eq!(
            wait_kind(&seen, CloseKind::LevinHandshakeTimeout).kind(),
            CloseKind::LevinHandshakeTimeout
        );
        drop(client);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_peer_fin_is_peer_closed() {
        let (engine, mut listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(5_000_000_000),
        );
        let client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        client.shutdown(std::net::Shutdown::Write).expect("fin");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        let cause = handle.block_on(async {
            while session.recv().await.is_some() {}
            session.close_cause()
        });
        assert_eq!(cause.kind(), CloseKind::PeerClosed);
        assert_eq!(
            wait_kind(&seen, CloseKind::PeerClosed).kind(),
            CloseKind::PeerClosed
        );
        drop(client);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn session_established_disarms_the_gap() {
        let (engine, mut listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(1_000_000_000),
        );
        let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        session.session_established();
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(
            seen.lock()
                .expect("causes")
                .iter()
                .all(|cause| cause.kind() != CloseKind::LevinHandshakeTimeout),
            "the gap fired after the session was established"
        );
        client.write_all(b"still").expect("write");
        let got = handle.block_on(session.recv()).expect("bytes");
        assert_eq!(got, b"still");
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_name_that_is_not_onion_v3_is_not_dialed() {
        let (engine, listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(5_000_000_000),
        );
        listener.dial(NetworkAddress::Tor {
            host: "not-a-v3-name.onion".into(),
            port: 18081,
        });
        let cause = wait_kind(&seen, CloseKind::LocalClose);
        assert!(!cause.implicates_address(ConnectorId::Tor));
        listener.shutdown();
        drop(engine);
    }

    /// The SOCKS port is closed. Covers the TCP connect to the local proxy
    /// in `dial_one`. Does not cover a proxy that answers and then refuses,
    /// and does not cover the C++ forget cache.
    #[test]
    fn a_closed_socks_port_does_not_implicate_the_onion() {
        let (engine, listener, seen) = start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            InboundCeiling::Bounded(4),
            Tick::new(5_000_000_000),
        );
        listener.dial(NetworkAddress::Tor {
            host: v3_onion_hostname(&[0x11; 32]),
            port: 18081,
        });
        let cause = wait_kind(&seen, CloseKind::LocalClose);
        assert!(!cause.implicates_address(ConnectorId::Tor));
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn dropping_an_unestablished_session_releases_the_slot() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let recorded = causes();
        let sockets = Sockets::new();
        let mut listener = listen(
            pool,
            &engine.handle(),
            &sockets,
            &config(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                Vec::new(),
                InboundCeiling::Bounded(4),
                Tick::new(5_000_000_000),
                Tick::new(30_000_000_000),
                recorded.sink,
            ),
        )
        .expect("listen");
        assert!(listener.forward_addr().socket().ip().is_loopback());
        let client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        let handle = listener.runtime_handle().clone();
        let session = handle.block_on(next_session(&mut listener.sessions));
        drop(session);
        let cause = wait_kind(&recorded.seen, CloseKind::LocalClose);
        assert_eq!(cause.kind(), CloseKind::LocalClose);
        assert_eq!(
            sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
            0
        );
        drop(client);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_send_that_does_not_fit_closes_the_connection() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name(), ThreadStart::none()).expect("runtime");
        let recorded = causes();
        let mut capped = config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            Vec::new(),
            InboundCeiling::Bounded(4),
            Tick::new(5_000_000_000),
            Tick::new(30_000_000_000),
            recorded.sink,
        );
        capped.send_queue_bytes = 0;
        let mut listener =
            listen(pool, &engine.handle(), &Sockets::new(), &capped).expect("listen");
        let client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
        let handle = listener.runtime_handle().clone();
        let session = handle.block_on(next_session(&mut listener.sessions));
        let rejected = session.try_send(b"x".to_vec()).expect_err("over cap");
        assert_eq!(rejected, CloseKind::SendQueueFull);
        let cause = wait_kind(&recorded.seen, CloseKind::SendQueueFull);
        assert_eq!(cause.kind(), CloseKind::SendQueueFull);
        drop(client);
        listener.shutdown();
        drop(engine);
    }

    async fn next_session(
        sessions: &mut tokio::sync::mpsc::UnboundedReceiver<super::Session>,
    ) -> super::Session {
        tokio::time::timeout(Duration::from_secs(2), sessions.recv())
            .await
            .expect("session wait")
            .expect("session")
    }
}
