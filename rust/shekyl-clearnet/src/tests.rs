// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::{prefix_for, Initiator, MESSAGE2_LEN, PREFIX_LEN};
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, NetworkColumn, Sockets};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use super::inode::socket_descriptors;
use super::{channel_choice, listen, ChannelChoice, ClearnetOption, Config, Listener};

const ID: [u8; 16] = [0x11; 16];

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("nonzero")
}

/// Harness inputs. Not the daemon's budget, span, or shutdown timeout.
fn harness_budget() -> RuntimeBudget {
    RuntimeBudget {
        workers: nz(2),
        blocking: nz(1),
    }
}

fn name(text: &str) -> ThreadName {
    ThreadName::new(text).expect("name")
}

struct Recorded {
    sink: Arc<dyn Fn(CloseCause) + Send + Sync>,
    seen: Arc<Mutex<Vec<CloseKind>>>,
}

fn causes() -> Recorded {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let sink: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(move |cause: CloseCause| {
        record.lock().expect("causes").push(cause.kind());
    });
    Recorded { sink, seen }
}

fn config(
    option: ClearnetOption,
    within: Tick,
    ceiling: InboundCeiling,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
) -> Config {
    Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        option,
        column: ConnectorId::Clearnet.column(),
        network_id: ID,
        ceiling,
        handshake_within: within,
        shutdown_timeout: Duration::from_millis(50),
        // Harness inputs. Not PWD-T6's derived limit, and not a
        // measured accept pause.
        send_queue_bytes: 64,
        accept_backoff: Duration::from_millis(1),
        on_cause,
    }
}

fn start(
    option: ClearnetOption,
    within: Tick,
    ceiling: InboundCeiling,
) -> (
    EngineService<MonotonicClock>,
    Listener<MonotonicClock>,
    Arc<Mutex<Vec<CloseKind>>>,
) {
    start_on(Sockets::new(), option, within, ceiling)
}

fn start_on(
    sockets: Sockets,
    option: ClearnetOption,
    within: Tick,
    ceiling: InboundCeiling,
) -> (
    EngineService<MonotonicClock>,
    Listener<MonotonicClock>,
    Arc<Mutex<Vec<CloseKind>>>,
) {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet")).expect("runtime");
    let recorded = causes();
    let seen = Arc::clone(&recorded.seen);
    let listener = listen(
        pool,
        &engine.handle(),
        sockets,
        &config(option, within, ceiling, recorded.sink),
    )
    .expect("listen");
    (engine, listener, seen)
}

fn connect(addr: SocketAddr) -> StdStream {
    let client = StdStream::connect(addr).expect("connect");
    client.set_read_timeout(Some(Duration::from_secs(3))).ok();
    client.set_write_timeout(Some(Duration::from_secs(3))).ok();
    client
}

async fn next_session(sessions: &mut mpsc::UnboundedReceiver<super::Session>) -> super::Session {
    tokio::time::timeout(Duration::from_secs(3), sessions.recv())
        .await
        .expect("session wait")
        .expect("session")
}

#[test]
fn the_option_reads_the_plan_and_not_a_connector_id() {
    assert_eq!(
        channel_choice(NetworkColumn::Clearnet, ClearnetOption::Off),
        Ok(ChannelChoice::Plain)
    );
    assert_eq!(
        channel_choice(NetworkColumn::Clearnet, ClearnetOption::On),
        Ok(ChannelChoice::Noise)
    );
    assert_eq!(
        channel_choice(NetworkColumn::Tor, ClearnetOption::On),
        Ok(ChannelChoice::Plain)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn one_descriptor_after_the_socket_is_split() {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-inode")).expect("runtime");
    pool.block_on(async move {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let (stream, _) = listener.accept().await.expect("accept");
        let fd = stream.as_raw_fd();
        assert_eq!(socket_descriptors(fd).expect("inode"), 1);
        let (read, write) = stream.into_split();
        assert_eq!(socket_descriptors(fd).expect("inode"), 1);
        drop((read, write, client));
    });
    drop(engine);
    pool.shutdown(Duration::from_millis(50));
}

#[test]
fn option_off_carries_the_bytes_it_is_given() {
    let (engine, mut listener, _) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let mut client = connect(listener.local_addr());
    client.write_all(b"levin-bytes").expect("write");
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(next_session(&mut listener.sessions));
    let got = handle.block_on(session.recv()).expect("bytes");
    assert_eq!(got, b"levin-bytes");
    session.try_send(b"out".to_vec()).expect("send");
    let mut buf = [0u8; 3];
    client.read_exact(&mut buf).expect("read");
    assert_eq!(&buf, b"out");
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_bad_prefix_is_fin_after_zero_bytes() {
    let (engine, listener, seen) = start(
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let mut client = connect(listener.local_addr());
    client.write_all(&[0u8; PREFIX_LEN]).expect("write");
    let mut buf = [0u8; 8];
    let n = client.read(&mut buf).expect("read");
    assert_eq!(n, 0);
    let start = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::PrefixMismatch)
    {
        assert!(start.elapsed() < Duration::from_secs(2), "cause");
        std::thread::sleep(Duration::from_millis(5));
    }
    listener.shutdown();
    drop(engine);
}

#[test]
fn option_on_seals_above_the_seam() {
    let (engine, mut listener, _) = start(
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let mut client = connect(listener.local_addr());
    let (initiator, message1) = Initiator::new(&ID).expect("initiator");
    client.write_all(&prefix_for(&ID)).expect("prefix");
    client.write_all(&message1).expect("message1");
    let mut prefix = [0u8; PREFIX_LEN];
    client.read_exact(&mut prefix).expect("prefix");
    assert_eq!(prefix, prefix_for(&ID));
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    client.read_exact(&mut message2).expect("message2");
    let (mut send, _recv) = initiator
        .read_message2(&message2)
        .expect("message2")
        .split();
    let wire = send.seal(b"hello").expect("seal");
    client.write_all(&wire).expect("record");
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(next_session(&mut listener.sessions));
    let got = handle.block_on(session.recv()).expect("plain");
    assert_eq!(got, b"hello");
    assert_eq!(listener.tally.computed(), 1);
    assert_eq!(listener.tally.skipped(), 0);
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_queued_handshake_past_its_deadline_is_skipped() {
    let within = Tick::new(150_000_000);
    let (engine, listener, _) = start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    listener.pool().spawn_blocking(move || {
        held_tx.send(()).expect("held");
        if release_rx.recv().is_err() {}
    });
    held_rx.recv().expect("blocking thread held");
    let mut client = connect(listener.local_addr());
    let (_initiator, message1) = Initiator::new(&ID).expect("initiator");
    client.write_all(&prefix_for(&ID)).expect("prefix");
    client.write_all(&message1).expect("message1");
    let start = Instant::now();
    while listener.tally.queued() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "job was not queued"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(400));
    release_tx.send(()).expect("release");
    let mut buf = [0u8; 8];
    let n = client.read(&mut buf).expect("read");
    assert_eq!(n, 0);
    let start = Instant::now();
    while listener.tally.skipped() == 0 {
        assert!(start.elapsed() < Duration::from_secs(2), "skip");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(listener.tally.computed(), 0);
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_zero_ceiling_refuses_before_any_handshake() {
    let (engine, listener, seen) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(0),
    );
    let mut client = connect(listener.local_addr());
    client.write_all(b"handshake").expect("write");
    let mut buf = [0u8; 4];
    let n = client.read(&mut buf).expect("read");
    assert_eq!(n, 0);
    let start = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::InboundNotAccepted)
    {
        assert!(start.elapsed() < Duration::from_secs(2), "refused");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(listener.tally.queued(), 0);
    assert_eq!(listener.tally.computed(), 0);
    listener.shutdown();
    drop(engine);
}

/// An inbound connection over the accept rate closes before the
/// handshake: nothing written to it, no handshake queued or computed
/// (D10.3). The rate is a test shape, not a ruled value: one accept per
/// host a minute.
#[test]
fn an_inbound_over_the_accept_rate_is_not_a_handshake() {
    use shekyl_transport_layer::{AcceptGate, AcceptRate};
    let gate = AcceptGate::new(
        AcceptRate {
            token_every_nanos: 1,
            burst: 1_000,
        },
        AcceptRate {
            token_every_nanos: 60_000_000_000,
            burst: 1,
        },
    );
    let (engine, listener, seen) = start_on(
        Sockets::with_clearnet_gate(gate),
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let _first = connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let computed_before = listener.tally.computed();
    let mut second = connect(listener.local_addr());
    let mut buf = [0u8; 4];
    let n = second.read(&mut buf).expect("read");
    assert_eq!(n, 0, "closed with nothing written");
    let start = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::AcceptRateExceeded)
    {
        assert!(start.elapsed() < Duration::from_secs(2), "refused");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(listener.tally.computed(), computed_before);
    assert_eq!(listener.sockets.take_accept_rate_refusals().host, 1);
    listener.shutdown();
    drop(engine);
}

#[test]
fn the_second_inbound_past_the_ceiling_is_not_a_handshake() {
    let (engine, mut listener, seen) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(1),
    );
    let mut first = connect(listener.local_addr());
    first.write_all(b"one").expect("write");
    let handle = listener.runtime_handle().clone();
    let _session = handle.block_on(next_session(&mut listener.sessions));
    let mut second = connect(listener.local_addr());
    second.write_all(b"two").expect("write");
    let mut buf = [0u8; 4];
    let n = second.read(&mut buf).expect("read");
    assert_eq!(n, 0);
    let start = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::AdmissionRefused)
    {
        assert!(start.elapsed() < Duration::from_secs(2), "refused");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(listener.tally.computed(), 0);
    assert_eq!(listener.tally.queued(), 0);
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_direct_dial_carries_plaintext_when_the_option_is_off() {
    let (engine, mut listener, _) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let handle = listener.runtime_handle().clone();
    let (port, got) = handle.block_on(async {
        let server = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let port = server.local_addr().expect("addr").port();
        let got = tokio::spawn(async move {
            let (mut sock, _) = server.accept().await.expect("accept");
            let mut buf = [0u8; 3];
            use tokio::io::AsyncReadExt;
            sock.read_exact(&mut buf).await.expect("read");
            buf
        });
        (port, got)
    });
    listener.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port,
        },
        None,
    );
    let session = handle.block_on(next_session(&mut listener.sessions));
    session.try_send(b"out".to_vec()).expect("send");
    assert_eq!(handle.block_on(got).expect("peer"), *b"out");
    listener.shutdown();
    drop(engine);
}

#[test]
fn an_onion_name_is_not_dialed() {
    let (engine, listener, seen) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    listener.dial(
        NetworkAddress::Tor {
            host: "not-an-address.onion".to_string(),
            port: 18080,
        },
        None,
    );
    let start = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::LocalClose)
    {
        assert!(start.elapsed() < Duration::from_secs(2), "dial");
        std::thread::sleep(Duration::from_millis(5));
    }
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_refused_direct_connect_names_the_address() {
    let (engine, listener, seen) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    // Bound, not listening. The port stays ours, so a parallel test cannot
    // accept the dial, and the kernel answers it with RST.
    let refusing = TcpSocket::new_v4().expect("socket");
    refusing
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind");
    let port = refusing.local_addr().expect("addr").port();
    listener.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port,
        },
        None,
    );
    let start_at = Instant::now();
    loop {
        let kinds = seen.lock().expect("causes").clone();
        if kinds.contains(&CloseKind::DialFailed) {
            break;
        }
        assert!(
            start_at.elapsed() < Duration::from_secs(2),
            "refused, saw {kinds:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(refusing);
    listener.shutdown();
    drop(engine);
}

#[test]
fn an_unreachable_network_stays_dialable() {
    let (engine, listener, seen) = start(
        ClearnetOption::Off,
        Tick::new(2_000_000_000),
        InboundCeiling::Bounded(4),
    );
    listener.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(255, 255, 255, 255),
            port: 9,
        },
        None,
    );
    let start_at = Instant::now();
    while !seen
        .lock()
        .expect("causes")
        .contains(&CloseKind::LocalClose)
    {
        assert!(start_at.elapsed() < Duration::from_secs(3), "unreachable");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::DialFailed),
        "an unreachable network is this node's link"
    );
    listener.shutdown();
    drop(engine);
}

#[test]
fn option_on_dials_and_both_sides_read_what_was_sent() {
    let within = Tick::new(5_000_000_000);
    let (engine_a, mut responder, _) =
        start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
    let (engine_b, mut initiator, _) =
        start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
    let port = responder.local_addr().port();
    initiator.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port,
        },
        None,
    );
    let handle_a = responder.runtime_handle().clone();
    let handle_b = initiator.runtime_handle().clone();
    let mut from_responder = handle_a.block_on(next_session(&mut responder.sessions));
    let mut from_initiator = handle_b.block_on(next_session(&mut initiator.sessions));
    from_initiator.try_send(b"ping".to_vec()).expect("ping");
    let got = handle_a.block_on(from_responder.recv()).expect("ping");
    assert_eq!(got, b"ping");
    from_responder.try_send(b"pong".to_vec()).expect("pong");
    let got = handle_b.block_on(from_initiator.recv()).expect("pong");
    assert_eq!(got, b"pong");
    responder.shutdown();
    initiator.shutdown();
    drop((engine_a, engine_b));
}

#[test]
fn a_socks_proxy_is_the_path_and_a_refusal_keeps_the_reply() {
    let (engine, mut listener, _) = start(
        ClearnetOption::Off,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let handle = listener.runtime_handle().clone();
    let (proxy_port, dest_port, got) = handle.block_on(async {
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
            use tokio::io::AsyncReadExt;
            sock.read_exact(&mut buf).await.expect("read");
            buf
        });
        tokio::spawn(async move {
            let (mut sock, _) = proxy.accept().await.expect("proxy accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.expect("greet");
            sock.write_all(&[0x05, 0x00]).await.expect("method");
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.expect("head");
            let mut addr = [0u8; 6];
            sock.read_exact(&mut addr).await.expect("addr");
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[4], addr[5]]);
            let mut upstream = TcpStream::connect(SocketAddr::from((ip, port)))
                .await
                .expect("upstream");
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
            match tokio::io::copy_bidirectional(&mut sock, &mut upstream).await {
                Ok(_) | Err(_) => {}
            }
        });
        (proxy_port, dest_port, got)
    });
    listener.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: dest_port,
        },
        Some(shekyl_socks::Proxy::unauthenticated(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            proxy_port,
        )))),
    );
    let session = handle.block_on(next_session(&mut listener.sessions));
    session.try_send(b"out".to_vec()).expect("send");
    assert_eq!(handle.block_on(got).expect("peer"), *b"out");
    listener.shutdown();
    drop(engine);
}

#[test]
fn a_socks_refusal_carries_the_reply_byte() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let sink: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(move |cause| {
        record.lock().expect("causes").push(cause);
    });
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet")).expect("runtime");
    let listener = listen(
        pool,
        &engine.handle(),
        Sockets::new(),
        &config(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
            sink,
        ),
    )
    .expect("listen");
    let handle = listener.runtime_handle().clone();
    let proxy_port = handle.block_on(async {
        let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("proxy");
        let port = proxy.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut sock, _) = proxy.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.expect("greet");
            sock.write_all(&[0x05, 0x00]).await.expect("method");
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.expect("head");
            let mut addr = [0u8; 6];
            sock.read_exact(&mut addr).await.expect("addr");
            sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
        });
        port
    });
    listener.dial(
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: 9,
        },
        Some(shekyl_socks::Proxy::unauthenticated(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            proxy_port,
        )))),
    );
    let start = Instant::now();
    let cause = loop {
        if let Some(cause) = seen
            .lock()
            .expect("causes")
            .iter()
            .copied()
            .find(|cause| cause.kind() == CloseKind::ProxyRefused)
        {
            break cause;
        }
        assert!(start.elapsed() < Duration::from_secs(2), "refusal");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(cause.reply_code(), 0x05);
    listener.shutdown();
    drop(engine);
}

#[path = "gap_tests.rs"]
mod gap_tests;

/// A gate refusing every inbound from one host after its first, whose
/// connector admits `burst` at once and one more every `every`: the linger
/// cap for a span is `burst + span / every`. Test shapes, not ruled values.
fn refusing_gate(every: u64, burst: u32) -> Sockets {
    use shekyl_transport_layer::{AcceptGate, AcceptRate};
    Sockets::with_clearnet_gate(AcceptGate::new(
        AcceptRate {
            token_every_nanos: every,
            burst,
        },
        AcceptRate {
            token_every_nanos: 60_000_000_000,
            burst: 1,
        },
    ))
}

fn wait_for_refusals(seen: &Arc<Mutex<Vec<CloseKind>>>, count: usize) {
    let start = Instant::now();
    while seen
        .lock()
        .expect("causes")
        .iter()
        .filter(|kind| **kind == CloseKind::AcceptRateExceeded)
        .count()
        < count
    {
        assert!(start.elapsed() < Duration::from_secs(2), "refusal {count}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// What a refused client sees when it writes its first flight `after` its
/// connect, as a Noise initiator on the internet does: `None` for an
/// orderly end, or the socket error an RST left.
fn flight_after(mut client: StdStream, after: Duration) -> Option<std::io::Error> {
    std::thread::sleep(after);
    client
        .write_all(&[0x5a; shekyl_p2p_transport::INITIATOR_FLIGHT_LEN])
        .expect("the flight");
    let mut buf = [0u8; 4];
    let read = client.read(&mut buf);
    std::thread::sleep(Duration::from_millis(50));
    match (read, client.take_error().expect("socket error")) {
        (_, Some(error)) | (Err(error), None) => Some(error),
        (Ok(n), None) => {
            assert_eq!(n, 0, "nothing written to a refused peer");
            None
        }
    }
}

/// The refusal comes first and the flight 50 ms later, at a socket the
/// accept refused: it is held half-closed until the flight arrives, so
/// the far side sees FIN and no RST (D10.2).
#[test]
fn a_flight_written_after_the_refusal_ends_with_fin_not_rst() {
    let (engine, listener, seen) = start_on(
        refusing_gate(100_000_000, 4),
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let _first = connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let refused = connect(listener.local_addr());
    wait_for_refusals(&seen, 1);
    let error = flight_after(refused, Duration::from_millis(50));
    assert!(error.is_none(), "an RST answered the flight: {error:?}");
    listener.shutdown();
    drop(engine);
}

/// The linger cap holds: with room for two, the third refusal closes at
/// once and its late flight is answered with RST (the residual D10.2
/// states), while the two held sockets still end with FIN.
#[test]
fn refusals_past_the_linger_cap_close_at_once() {
    // Burst 1, one token per 5 s span: a cap of 1 + 1 = 2.
    let (engine, listener, seen) = start_on(
        refusing_gate(5_000_000_000, 1),
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(8),
    );
    let _first = connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let held_a = connect(listener.local_addr());
    wait_for_refusals(&seen, 1);
    let held_b = connect(listener.local_addr());
    wait_for_refusals(&seen, 2);
    let past_cap = connect(listener.local_addr());
    wait_for_refusals(&seen, 3);
    assert!(
        flight_after(past_cap, Duration::from_millis(50)).is_some(),
        "the refusal past the cap closed at once"
    );
    for (name, held) in [("first", held_a), ("second", held_b)] {
        let error = flight_after(held, Duration::ZERO);
        assert!(error.is_none(), "the {name} held socket: {error:?}");
    }
    listener.shutdown();
    drop(engine);
}
