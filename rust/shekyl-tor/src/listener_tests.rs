// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the Tor listener.

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
        proxy: shekyl_socks::Proxy::unauthenticated(proxy),
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
    assert!(!cause.proves_misbehaviour());
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

/// A Levin frame of `command` with `flags` and a `body`-byte body.
fn frame(command: u32, flags: shekyl_levin::Flags, body: usize) -> Vec<u8> {
    let head = shekyl_levin::BucketHead {
        payload_len: u64::try_from(body).expect("small"),
        expect_response: u8::from(flags.contains(shekyl_levin::Flags::REQUEST)),
        command,
        flags,
        protocol_version: shekyl_levin::PROTOCOL_VERSION_1,
    };
    let mut out = head.write().to_vec();
    out.extend(std::iter::repeat_n(7u8, body));
    out
}

/// The handshake request an inbound peer opens with.
fn levin_frame(body: usize) -> Vec<u8> {
    frame(
        shekyl_levin::COMMAND_HANDSHAKE,
        shekyl_levin::Flags::REQUEST,
        body,
    )
}

/// A timed-sync request: a complete frame that is not a handshake.
fn timed_sync_frame() -> Vec<u8> {
    frame(
        shekyl_levin::COMMAND_TIMED_SYNC,
        shekyl_levin::Flags::REQUEST,
        10,
    )
}

/// One dialed session, with what it needs kept alive.
struct DialedPeer {
    engine: EngineService<MonotonicClock>,
    listener: Listener<MonotonicClock>,
    session: super::Session,
    seen: Arc<Mutex<Vec<CloseCause>>>,
}

/// Dial an onion through a fake SOCKS proxy to a peer that writes
/// `reply` and then holds the connection open, silent, for 2 s.
fn dial_peer_that_writes(gap: Tick, reply: Vec<u8>) -> DialedPeer {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(budget(), &name()).expect("runtime");
    let recorded = causes();
    let proxy_port = pool.handle().clone().block_on(async {
        let dest = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("dest");
        let dest_port = dest.local_addr().expect("addr").port();
        let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("proxy");
        let proxy_port = proxy.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut sock, _) = dest.accept().await.expect("accept");
            sock.write_all(&reply).await.expect("reply");
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        tokio::spawn(async move {
            let (mut sock, _) = proxy.accept().await.expect("proxy");
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.expect("greet");
            sock.write_all(&[0x05, 0x00]).await.expect("method");
            let mut head = [0u8; 5];
            sock.read_exact(&mut head).await.expect("head");
            let mut name = vec![0u8; usize::from(head[4]) + 2];
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
        proxy_port
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
            gap,
            recorded.sink,
        ),
    )
    .expect("listen");
    listener.dial(onion());
    let handle = listener.runtime_handle().clone();
    let session = handle.block_on(next_session(&mut listener.sessions));
    DialedPeer {
        engine,
        listener,
        session,
        seen: recorded.seen,
    }
}

fn no_gap_timeout(seen: &Mutex<Vec<CloseCause>>) -> bool {
    seen.lock()
        .expect("causes")
        .iter()
        .all(|cause| cause.kind() != CloseKind::LevinHandshakeTimeout)
}

fn read_bytes(
    handle: &tokio::runtime::Handle,
    session: &mut super::Session,
    len: usize,
) -> Vec<u8> {
    handle.block_on(async {
        let mut got = Vec::new();
        while got.len() < len {
            let chunk = tokio::time::timeout(Duration::from_secs(2), session.recv())
                .await
                .expect("bytes in time")
                .expect("bytes");
            got.extend(chunk);
        }
        got
    })
}

/// The gap measures the peer's silence (Rick, 2026-10-14): the peer's
/// handshake frame ends it, and a strand verdict that is slow after
/// that frame (here, never given) does not time the peer out. *Records-was:* the strand's verdict ended the gap, so this
/// node's own slowness timed out a peer that had spoken.
#[test]
fn a_complete_frame_ends_the_gap_while_the_verdict_is_slow() {
    let (engine, mut listener, seen) = start(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        InboundCeiling::Bounded(4),
        Tick::new(300_000_000),
    );
    let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let frame = levin_frame(40);
    client.write_all(&frame).expect("write");
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(next_session(&mut listener.sessions));
    assert_eq!(read_bytes(&handle, &mut session, frame.len()), frame);
    std::thread::sleep(Duration::from_millis(900));
    assert!(
        no_gap_timeout(&seen),
        "the gap fired after the peer's handshake frame"
    );
    client.write_all(b"still").expect("write");
    assert_eq!(read_bytes(&handle, &mut session, 5), b"still");
    listener.shutdown();
    drop(engine);
}

/// **A complete frame that is not the handshake does not end the gap**
/// (Copilot on #1056). An inbound peer that sends another command's
/// request and stops had held its session with no deadline at all; it
/// is still silent, and the gap times it out.
#[test]
fn an_inbound_peer_that_sends_a_timed_sync_and_stops_is_timed_out() {
    let (engine, mut listener, seen) = start(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        InboundCeiling::Bounded(4),
        Tick::new(300_000_000),
    );
    let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
    client.write_all(&timed_sync_frame()).expect("write");
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(next_session(&mut listener.sessions));
    // Bounded: with the defect the session stays open, and the test
    // fails instead of waiting for ever.
    let cause = handle.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            while session.recv().await.is_some() {}
        })
        .await
        .expect("the gap closes the session");
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

/// On a session this node dialed, the peer's handshake response ends
/// the gap.
#[test]
fn a_dialed_peer_s_handshake_response_ends_the_gap() {
    let response = frame(
        shekyl_levin::COMMAND_HANDSHAKE,
        shekyl_levin::Flags::RESPONSE,
        40,
    );
    let len = response.len();
    let DialedPeer {
        engine,
        listener,
        mut session,
        seen,
    } = dial_peer_that_writes(Tick::new(300_000_000), response);
    let handle = listener.runtime_handle().clone();
    assert_eq!(read_bytes(&handle, &mut session, len).len(), len);
    std::thread::sleep(Duration::from_millis(900));
    assert!(
        no_gap_timeout(&seen),
        "the gap fired after the peer's handshake response"
    );
    listener.shutdown();
    drop(engine);
}

/// A dialed peer that answers with a handshake *request* has not
/// answered: the gap still times it out.
#[test]
fn a_dialed_peer_s_handshake_request_does_not_end_the_gap() {
    let DialedPeer {
        engine,
        listener,
        mut session,
        seen,
    } = dial_peer_that_writes(Tick::new(300_000_000), levin_frame(40));
    let handle = listener.runtime_handle().clone();
    let cause = handle.block_on(async {
        while session.recv().await.is_some() {}
        session.close_cause()
    });
    assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
    assert_eq!(
        wait_kind(&seen, CloseKind::LevinHandshakeTimeout).kind(),
        CloseKind::LevinHandshakeTimeout
    );
    listener.shutdown();
    drop(engine);
}

/// A complete header with part of the body it declares is not a frame:
/// the peer is still silent, and the gap times it out.
#[test]
fn a_partial_frame_still_times_out() {
    let (engine, mut listener, seen) = start(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        InboundCeiling::Bounded(4),
        Tick::new(300_000_000),
    );
    let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
    let frame = levin_frame(40);
    client.write_all(&frame[..frame.len() - 1]).expect("write");
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

/// Data that arrived before the deadline is read even when the driver
/// resumes after it (Rick, 2026-10-14). Both runtime workers are held
/// across the deadline, as a blocked log call held them in the PR-3
/// measurement; the peer's frame arrives while they are held. When the
/// driver resumes, the gap's wake has fired, and the frame must win.
#[test]
fn a_frame_that_arrived_before_the_deadline_wins_when_the_driver_resumes_after_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (engine, mut listener, seen) = start(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        InboundCeiling::Bounded(4),
        Tick::new(300_000_000),
    );
    let mut client = StdStream::connect(listener.forward_addr().socket()).expect("connect");
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(next_session(&mut listener.sessions));
    let held = Arc::new(AtomicUsize::new(0));
    for _ in 0..budget().workers.get() {
        let held = Arc::clone(&held);
        handle.spawn(async move {
            held.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(900));
        });
    }
    let waiting = Instant::now();
    while held.load(Ordering::SeqCst) < budget().workers.get() {
        assert!(waiting.elapsed() < Duration::from_secs(2), "workers held");
        std::thread::sleep(Duration::from_millis(1));
    }
    let frame = levin_frame(40);
    client.write_all(&frame).expect("write");
    assert_eq!(read_bytes(&handle, &mut session, frame.len()), frame);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        no_gap_timeout(&seen),
        "the gap fired although the frame arrived before its deadline"
    );
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
    assert!(!cause.proves_misbehaviour());
    listener.shutdown();
    drop(engine);
}

/// The SOCKS port is closed: the TCP connect to this node's own proxy
/// fails. That is `ProxyUnavailable`, which names the proxy and never
/// the onion (Rick, 2026-10-14).
#[test]
fn a_closed_socks_port_is_the_proxy_and_does_not_implicate_the_onion() {
    let (engine, listener, seen) = start(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        InboundCeiling::Bounded(4),
        Tick::new(5_000_000_000),
    );
    listener.dial(NetworkAddress::Tor {
        host: v3_onion_hostname(&[0x11; 32]),
        port: 18081,
    });
    let cause = wait_kind(&seen, CloseKind::ProxyUnavailable);
    assert!(!cause.proves_misbehaviour());
    listener.shutdown();
    drop(engine);
}

/// The proxy accepts and closes the SOCKS exchange without a reply, as
/// a Tor that is going down does: `ProxyUnavailable`, not `LocalClose`.
#[test]
fn a_socks_exchange_closed_without_a_reply_is_the_proxy() {
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
            // No method selection, no reply: the exchange just ends.
            drop(sock);
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
    let cause = wait_kind(&recorded.seen, CloseKind::ProxyUnavailable);
    assert!(!cause.proves_misbehaviour());
    listener.shutdown();
    drop(engine);
}

#[test]
fn dropping_an_unestablished_session_releases_the_slot() {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(budget(), &name()).expect("runtime");
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
    let pool = runtime(budget(), &name()).expect("runtime");
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
    let mut listener = listen(pool, &engine.handle(), &Sockets::new(), &capped).expect("listen");
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
