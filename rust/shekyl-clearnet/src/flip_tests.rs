// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A peer that still speaks plaintext Levin meets a node that speaks only
//! Noise, in each direction. The connection ends with one typed cause, and
//! nothing about it marks the peer: a node left on an old release is not an
//! attacker, and clearnet authenticates no one.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use shekyl_levin::{invoke, COMMAND_HANDSHAKE};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::runtime;
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseKind, DialEnd, Evidence, Proof, Reached, Retry, Sockets};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::ChannelChoice;
use super::{await_close_kind, connect, harness_budget, name, sealed_plaintext, start, ID};

/// How long a second end is watched for after the first.
const NO_SECOND_END: Duration = Duration::from_millis(300);
/// The plaintext Levin handshake's body, as a test shape.
const PLAINTEXT_BODY: usize = 40;

/// A plaintext handshake to a flipped node is answered with nothing and
/// closed with one `PrefixMismatch`. The host is not banned: the same host
/// opens a Noise session straight after.
/// Red edit: ban the host on a prefix mismatch, or answer before the check.
#[test]
fn a_plaintext_dial_ends_once_and_the_host_can_come_back() {
    let (engine, mut listener, seen) = start(Tick::new(5_000_000_000), InboundCeiling::Bounded(4));
    let mut plain = connect(listener.local_addr());
    plain
        .write_all(&invoke(COMMAND_HANDSHAKE, &[0u8; PLAINTEXT_BODY]))
        .expect("the plaintext handshake");
    let mut answer = [0u8; 8];
    // The node stopped reading at the prefix, so the unread rest of the
    // frame may turn its close into a reset. Either way no byte came back.
    match plain.read(&mut answer) {
        Ok(n) => assert_eq!(n, 0, "a plaintext peer was answered"),
        Err(error) => assert_eq!(error.kind(), ErrorKind::ConnectionReset),
    }
    await_close_kind(&seen, CloseKind::PrefixMismatch, "the node's cause");
    std::thread::sleep(NO_SECOND_END);
    assert_eq!(
        *seen.lock().expect("causes"),
        vec![CloseKind::PrefixMismatch],
        "one cause, the first"
    );

    let mut back = connect(listener.local_addr());
    let got = sealed_plaintext(&mut listener, &mut back, &ID, b"upgraded");
    assert_eq!(got, b"upgraded", "the same host is not banned");
    listener.shutdown();
    drop(engine);
}

/// A flipped node that dials a plaintext node sends its first flight, and
/// the plaintext node closes on bytes that are not Levin. The dial ends once
/// as a failed handshake that keeps its retry, which is how any failed dial
/// cools an address, and it proves no misbehaviour.
/// Red edit: stamp `HandshakeBroken` as `refused_by_peer`, or `Retry::Final`.
#[test]
fn a_dial_to_a_plaintext_node_ends_once_and_proves_nothing() {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet-flip")).expect("runtime");
    let (end_tx, end_rx) = std::sync::mpsc::channel();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let port = pool.block_on(async {
        let plaintext_node = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let port = plaintext_node.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut sock, _) = plaintext_node.accept().await.expect("accept");
            let mut flight = [0u8; 8];
            sock.read_exact(&mut flight).await.expect("the first bytes");
            // Not a Levin signature: the old node drops the connection.
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
        kind: ChannelChoice::Noise,
        network_id: ID,
        dial_within: Tick::new(2_000_000_000),
        proxied_dial_within: Tick::new(2_000_000_000),
        handshake_within: Tick::new(2_000_000_000),
        gap_within: None,
        tally: Arc::new(super::super::zero_tally()),
        on_end: Arc::new(move |end: DialEnd| {
            let _sent = end_tx.send(end);
        }),
        send_queue_bytes: 65_536,
        admitted: super::super::publish_on(admitted_tx),
    };
    pool.spawn(super::super::dial_one(dial, engine.handle()));
    let end = end_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the dial ends");
    assert_eq!(end.cause().kind(), CloseKind::TransportHandshakeFailed);
    let failure = end.failure();
    assert!(!failure.proves_misbehaviour());
    assert_eq!(failure.evidence(), Evidence::Destination(Proof::ABSENT));
    assert_eq!(failure.retry(), Retry::Again);
    assert_ne!(failure.reached(), Reached::NoStream, "the socket opened");
    assert!(
        end_rx.recv_timeout(NO_SECOND_END).is_err(),
        "one end for one dial"
    );
    assert!(admitted_rx.try_recv().is_err(), "no session was admitted");
    pool.shutdown(Duration::from_millis(50));
    drop(engine);
}
