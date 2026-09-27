// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor connector.
//!
//! The Tor stream is the transport contract. There is no Noise layer and
//! no handshake on the blocking pool. Outbound dials an onion through the
//! operator's SOCKS5 proxy ([`shekyl_socks`]). The dial clock is one
//! engine owner covering that exchange, the circuit build, and
//! rendezvous. Inbound is [`Sockets::accept_tor`]: the zone, no address,
//! then the gap timer. Onion-service proof-of-work and `MaxStreams` are
//! the accept bound. This crate does not add another.
//!
//! `--tx-proxy` and `--anonymous-inbound` stay parsed in C++. They arrive
//! here as [`Config`]. A bind failure returns before a listener exists,
//! which is the zone not being inserted. The 60-second Tor liveness poll
//! in `idle_worker` is a timing-table item and is not this connector's.

#![deny(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, Sockets};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Notify};

mod drive;
mod publish;

pub use publish::{publish_forward, publish_with_control, InboundPosture, PublishFault};

use drive::{accept_one, dial_one, Accept, ByteQueue, Dial, PushError};

/// Caller inputs. The dial span, the gap span, and the send-queue byte
/// cap are unmeasured until a measurement names them.
pub struct Config {
    /// The operator's SOCKS5 proxy. Outbound dials go here.
    pub proxy: SocketAddr,
    /// Binds from `--anonymous-inbound`. These are the operator's onions.
    /// They are not published here, and they are not subject to the
    /// loopback check on [`publish_forward`].
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
/// does not publish it, and does not apply the loopback rule.
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

pub struct Session {
    inbound: mpsc::Receiver<Vec<u8>>,
    queue: ByteQueue,
    overfull: Arc<Notify>,
    overfull_flag: Arc<AtomicBool>,
    established: Option<oneshot::Sender<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.queue.close();
    }
}

impl Session {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Queue bytes up to the caller's cap. A buffer that does not fit is
    /// not stored, and the connection closes with
    /// [`CloseKind::SendQueueFull`]. The cap is unmeasured until PWD-T6's
    /// session-established limit plus measurement names it.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        match self.queue.try_push(bytes) {
            Ok(()) => Ok(()),
            Err(PushError::Full) => {
                self.overfull_flag.store(true, Ordering::Release);
                self.overfull.notify_waiters();
                Err(CloseKind::SendQueueFull)
            }
            Err(PushError::Closed) => Err(CloseKind::IoError),
        }
    }

    /// The Levin handshake is done. The gap timer stops.
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
    forward: SocketAddr,
    extra: Vec<SocketAddr>,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    engine: Handle<C>,
    sockets: Sockets,
    proxy: SocketAddr,
    dial_within: Tick,
    gap_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    sessions_tx: mpsc::UnboundedSender<Session>,
}

impl<C: Clock + Clone> Listener<C> {
    /// The loopback forward target. Publish names this port.
    pub fn forward_addr(&self) -> SocketAddr {
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
            sessions: self.sessions_tx.clone(),
            on_cause: Arc::clone(&self.on_cause),
            send_queue_bytes: self.send_queue_bytes,
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

/// A transient `accept` failure. The same class as the clearnet listener.
pub(crate) fn accept_error_is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    ) || too_many_open_files(err.raw_os_error())
}

fn too_many_open_files(code: Option<i32>) -> bool {
    let Some(code) = code else {
        return false;
    };
    #[cfg(unix)]
    {
        code == 24 || code == 23
    }
    #[cfg(windows)]
    {
        code == 4
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Bind the loopback forward target and any anonymous-inbound addresses.
///
/// `sockets` is the process-wide admission table. The ceiling counts
/// every connector that shares it. This function does not mint a table.
///
/// One failed bind drops the listeners that succeeded and returns the
/// error. The caller does not insert the zone. An accepted socket is
/// handed to admission directly. There is no queue of sockets ahead of
/// that check.
pub fn listen<C>(
    pool: Pool,
    engine: &Handle<C>,
    sockets: Sockets,
    config: &Config,
) -> std::io::Result<Listener<C>>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let handle = pool.handle().clone();
    let (forward, extras) = pool.block_on(bind_all(&config.anonymous_inbound))?;
    let forward_addr = forward.local_addr()?;
    let mut extra_addrs = Vec::with_capacity(extras.len());
    for listener in &extras {
        extra_addrs.push(listener.local_addr()?);
    }
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let engine_keep = engine.clone();
    let sockets_keep = sockets.clone();
    let sessions_keep = sessions_tx.clone();
    let on_cause_keep = Arc::clone(&config.on_cause);
    let shutdown_timeout = config.shutdown_timeout;
    let proxy = config.proxy;
    let dial_within = config.dial_within;
    let gap_within = config.gap_within;
    let send_queue_bytes = config.send_queue_bytes;
    let ceiling = config.ceiling;
    let backoff = config.accept_backoff;
    let on_cause = Arc::clone(&config.on_cause);
    let engine = engine.clone();
    let mut listeners = extras;
    listeners.push(forward);
    pool.spawn(async move {
        for listener in listeners {
            let sockets = sockets.clone();
            let sessions = sessions_tx.clone();
            let on_cause = Arc::clone(&on_cause);
            let engine = engine.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let accept = Accept {
                                stream,
                                sockets: sockets.clone(),
                                ceiling,
                                gap_within,
                                sessions: sessions.clone(),
                                on_cause: Arc::clone(&on_cause),
                                send_queue_bytes,
                            };
                            tokio::spawn(accept_one(accept, engine.clone()));
                        }
                        Err(error) if accept_error_is_transient(&error) => {
                            on_cause(CloseCause::new(CloseKind::IoError));
                            tokio::time::sleep(backoff).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout,
        forward: forward_addr,
        extra: extra_addrs,
        sessions: sessions_rx,
        engine: engine_keep,
        sockets: sockets_keep,
        proxy,
        dial_within,
        gap_within,
        send_queue_bytes,
        on_cause: on_cause_keep,
        sessions_tx: sessions_keep,
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
    use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
    use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
    use shekyl_transport_layer::{CloseCause, CloseKind, Sockets};
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
        let pool = runtime(budget(), &name()).expect("runtime");
        let recorded = causes();
        let listener = listen(
            pool,
            &engine.handle(),
            Sockets::new(),
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
        let cause = wait_kind(&seen, CloseKind::DialFailed);
        assert_eq!(cause.reply_code(), 0);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_failed_anonymous_bind_does_not_leave_a_listener() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(budget(), &name()).expect("runtime");
        let held =
            std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("hold");
        let taken = held.local_addr().expect("addr");
        let recorded = causes();
        let result = listen(
            pool,
            &engine.handle(),
            Sockets::new(),
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
        let pool = runtime(budget(), &name()).expect("runtime");
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
            Sockets::new(),
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
        let pool = runtime(budget(), &name()).expect("runtime");
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
            Sockets::new(),
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
        let mut client = StdStream::connect(listener.forward_addr()).expect("connect");
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

    async fn next_session(
        sessions: &mut tokio::sync::mpsc::UnboundedReceiver<super::Session>,
    ) -> super::Session {
        tokio::time::timeout(Duration::from_secs(2), sessions.recv())
            .await
            .expect("session wait")
            .expect("session")
    }
}
