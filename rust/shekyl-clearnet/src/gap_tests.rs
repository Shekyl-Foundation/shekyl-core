// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clearnet silence gap: a handshake frame ends it, and any other
//! complete frame does not.
//!
//! The harness lives in the parent test module. These tests open one
//! dial or one accept and watch that gap.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::runtime;
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, Sockets};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::ChannelChoice;
use super::{causes, connect, harness_budget, name, ID};

/// One plain dial, admitted, with its session still open.
struct Dialled {
    engine: EngineService<MonotonicClock>,
    pool: shekyl_runtime::Pool,
    session: shekyl_capped_stream::Session,
    // Dropping `gap` is a local close. The hub holds it in production.
    gap: Option<tokio::sync::oneshot::Sender<()>>,
    seen: Arc<Mutex<Vec<CloseKind>>>,
}

fn dial_session<F>(gap: Tick, accept: F) -> Dialled
where
    F: FnOnce(std::net::TcpStream) + Send + 'static,
{
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet-cause")).expect("runtime");
    let recorded = causes();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let port = pool.block_on(async {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let sock = sock.into_std().expect("std");
            std::thread::spawn(move || accept(sock));
        });
        port
    });
    let dial = super::super::Dial {
        address: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port,
        },
        proxy: None,
        sockets: Sockets::new(),
        kind: crate::seam::ChannelChoice::Plain,
        network_id: ID,
        dial_within: Tick::new(2_000_000_000),
        proxied_dial_within: Tick::new(2_000_000_000),
        handshake_within: Tick::new(2_000_000_000),
        gap_within: Some(gap),
        tally: Arc::new(super::super::zero_tally()),
        on_cause: Arc::clone(&recorded.sink),
        send_queue_bytes: 65_536,
        admitted: admitted_tx,
    };
    let handle = engine.handle();
    pool.spawn(super::super::dial_one(dial, handle));
    let admitted = pool.block_on(async { admitted_rx.recv().await.expect("admitted") });
    Dialled {
        engine,
        pool,
        session: admitted.session,
        gap: admitted.gap,
        seen: recorded.seen,
    }
}

fn dial_against<F>(gap: Tick, accept: F) -> (CloseCause, Vec<CloseKind>)
where
    F: FnOnce(std::net::TcpStream) + Send + 'static,
{
    let Dialled {
        engine,
        pool,
        mut session,
        gap,
        seen: recorded,
    } = dial_session(gap, accept);
    let cause = pool.block_on(async {
        while session.recv().await.is_some() {}
        session.close_cause()
    });
    drop(gap);
    // The session publishes the cause at the seal. The sink is told after
    // the writer join returns, so a snapshot taken here can still be empty.
    let start = Instant::now();
    let seen = loop {
        let seen = recorded.lock().expect("causes").clone();
        if seen.contains(&cause.kind()) {
            break seen;
        }
        assert!(start.elapsed() < Duration::from_secs(2), "cause");
        std::thread::sleep(Duration::from_millis(5));
    };
    pool.shutdown(Duration::from_millis(50));
    drop(engine);
    (cause, seen)
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

/// The handshake response a dialed peer answers with.
fn levin_frame(body: usize) -> Vec<u8> {
    frame(
        shekyl_levin::COMMAND_HANDSHAKE,
        shekyl_levin::Flags::RESPONSE,
        body,
    )
}

/// The handshake request an inbound peer opens with.
fn handshake_request(body: usize) -> Vec<u8> {
    frame(
        shekyl_levin::COMMAND_HANDSHAKE,
        shekyl_levin::Flags::REQUEST,
        body,
    )
}

/// A support-flags request: a complete frame that is not a handshake.
fn support_flags_frame() -> Vec<u8> {
    frame(
        shekyl_levin::COMMAND_REQUEST_SUPPORT_FLAGS,
        shekyl_levin::Flags::REQUEST,
        10,
    )
}

/// One plain inbound connection under a `gap`: the accept loop, as the
/// zone host runs it, and a client socket that has written `opening`.
struct AcceptedPeer {
    engine: EngineService<MonotonicClock>,
    pool: shekyl_runtime::Pool,
    session: shekyl_capped_stream::Session,
    // Dropping `gap` is a local close. The hub holds it in production.
    gap: Option<tokio::sync::oneshot::Sender<()>>,
    client: StdStream,
    seen: Arc<Mutex<Vec<CloseKind>>>,
}

fn accept_peer_that_writes(gap: Tick, opening: &[u8]) -> AcceptedPeer {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet-in")).expect("runtime");
    let recorded = causes();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let inbound = super::super::Inbound {
        sockets: Sockets::new(),
        ceiling: || InboundCeiling::Bounded(4),
        kind: ChannelChoice::Plain,
        network_id: ID,
        handshake_within: Tick::new(2_000_000_000),
        gap_within: Some(gap),
        tally: Arc::new(super::super::zero_tally()),
        on_cause: Arc::clone(&recorded.sink),
        send_queue_bytes: 65_536,
        admitted: admitted_tx,
        backoff: Duration::from_millis(1),
    };
    let handle = engine.handle();
    let addr = pool.block_on(async {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(super::super::accept_inbound(listener, inbound, handle));
        addr
    });
    let mut client = connect(addr);
    client.write_all(opening).expect("opening");
    let admitted = pool.block_on(async { admitted_rx.recv().await.expect("admitted") });
    AcceptedPeer {
        engine,
        pool,
        session: admitted.session,
        gap: admitted.gap,
        client,
        seen: recorded.seen,
    }
}

fn read_bytes(
    pool: &shekyl_runtime::Pool,
    session: &mut shekyl_capped_stream::Session,
    len: usize,
) -> Vec<u8> {
    pool.block_on(async {
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
/// handshake frame ends it, and a strand verdict that is slow after that
/// frame (here, never given) does not time the peer out.
/// *Records-was:* the strand's verdict ended the gap.
#[test]
fn a_complete_frame_ends_the_gap_while_the_verdict_is_slow() {
    let frame = levin_frame(40);
    let sent = frame.clone();
    let mut dialled = dial_session(Tick::new(300_000_000), move |mut sock| {
        sock.write_all(&sent).expect("frame");
        std::thread::sleep(Duration::from_millis(1_500));
        drop(sock);
    });
    assert_eq!(
        read_bytes(&dialled.pool, &mut dialled.session, frame.len()),
        frame
    );
    std::thread::sleep(Duration::from_millis(900));
    assert!(
        !dialled
            .seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::LevinHandshakeTimeout),
        "the gap fired after the peer's handshake frame"
    );
    drop(dialled.gap.take());
    dialled.pool.shutdown(Duration::from_millis(50));
    drop(dialled.engine);
}

/// **A complete frame that is not the handshake does not end the gap**
/// (Copilot on #1056). A dialed peer that answers with a support-flags
/// request and stops has not answered: the gap times it out.
#[test]
fn a_dialed_peer_that_sends_support_flags_and_stops_is_timed_out() {
    let (cause, seen) = dial_against(Tick::new(200_000_000), move |mut sock| {
        sock.write_all(&support_flags_frame()).expect("frame");
        std::thread::sleep(Duration::from_secs(2));
        drop(sock);
    });
    assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
    assert!(seen.contains(&CloseKind::LevinHandshakeTimeout));
}

/// An inbound peer's handshake request ends the gap.
#[test]
fn an_inbound_peer_s_handshake_request_ends_the_gap() {
    let request = handshake_request(40);
    let mut peer = accept_peer_that_writes(Tick::new(300_000_000), &request);
    assert_eq!(
        read_bytes(&peer.pool, &mut peer.session, request.len()),
        request
    );
    std::thread::sleep(Duration::from_millis(900));
    assert!(
        !peer
            .seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::LevinHandshakeTimeout),
        "the gap fired after the inbound peer's handshake request"
    );
    drop(peer.client);
    drop(peer.gap.take());
    peer.pool.shutdown(Duration::from_millis(50));
    drop(peer.engine);
}

/// **An inbound peer that sends a support-flags request and stops is timed
/// out** (Copilot on #1056): the strand answers that request before any
/// handshake, and the session had then held an admission slot with no
/// deadline at all.
#[test]
fn an_inbound_peer_that_sends_support_flags_and_stops_is_timed_out() {
    let mut peer = accept_peer_that_writes(Tick::new(200_000_000), &support_flags_frame());
    // Bounded: with the defect the session stays open, and the test fails
    // instead of waiting for ever.
    let cause = peer.pool.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            while peer.session.recv().await.is_some() {}
        })
        .await
        .expect("the gap closes the session");
        peer.session.close_cause()
    });
    assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
    drop(peer.client);
    drop(peer.gap.take());
    peer.pool.shutdown(Duration::from_millis(50));
    drop(peer.engine);
}

/// A complete header with part of the body it declares is not a frame: the
/// peer is still silent, and the gap times it out.
#[test]
fn a_partial_frame_still_times_out() {
    let frame = levin_frame(40);
    let (cause, seen) = dial_against(Tick::new(200_000_000), move |mut sock| {
        sock.write_all(&frame[..frame.len() - 1]).expect("partial");
        std::thread::sleep(Duration::from_secs(2));
        drop(sock);
    });
    assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
    assert!(seen.contains(&CloseKind::LevinHandshakeTimeout));
}

/// Data that arrived before the deadline is read even when the driver
/// resumes after it (Rick, 2026-10-14). Both runtime workers are held
/// across the deadline, as a blocked log call held them in the PR-3
/// measurement; the peer's frame arrives while they are held. When the
/// driver resumes, the gap's wake has fired, and the frame must win.
#[test]
fn a_frame_that_arrived_before_the_deadline_wins_when_the_driver_resumes_after_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let frame = levin_frame(40);
    let sent = frame.clone();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let mut dialled = dial_session(Tick::new(300_000_000), move |mut sock| {
        if go_rx.recv().is_ok() {
            sock.write_all(&sent).expect("frame");
        }
        std::thread::sleep(Duration::from_millis(1_500));
        drop(sock);
    });
    let workers = harness_budget().workers.get();
    let held = Arc::new(AtomicUsize::new(0));
    for _ in 0..workers {
        let held = Arc::clone(&held);
        dialled.pool.spawn(async move {
            held.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(900));
        });
    }
    let waiting = Instant::now();
    while held.load(Ordering::SeqCst) < workers {
        assert!(waiting.elapsed() < Duration::from_secs(2), "workers held");
        std::thread::sleep(Duration::from_millis(1));
    }
    go_tx.send(()).expect("go");
    assert_eq!(
        read_bytes(&dialled.pool, &mut dialled.session, frame.len()),
        frame
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !dialled
            .seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::LevinHandshakeTimeout),
        "the gap fired although the frame arrived before its deadline"
    );
    drop(dialled.gap.take());
    dialled.pool.shutdown(Duration::from_millis(50));
    drop(dialled.engine);
}

#[test]
fn a_silent_acceptor_is_a_handshake_timeout() {
    let (cause, seen) = dial_against(Tick::new(200_000_000), |sock| {
        std::thread::sleep(Duration::from_secs(2));
        drop(sock);
    });
    assert_eq!(cause.kind(), CloseKind::LevinHandshakeTimeout);
    assert!(seen.contains(&CloseKind::LevinHandshakeTimeout));
    assert!(!seen.contains(&CloseKind::PeerClosed));
}

#[test]
fn a_peer_fin_is_peer_closed() {
    let (cause, seen) = dial_against(Tick::new(5_000_000_000), |sock| {
        sock.shutdown(std::net::Shutdown::Write).expect("fin");
        std::thread::sleep(Duration::from_millis(200));
    });
    assert_eq!(cause.kind(), CloseKind::PeerClosed);
    assert!(seen.contains(&CloseKind::PeerClosed));
}
