// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A dial's admission runs before its connect: a host banned between the
//! draw and the dial is refused here, and its listener sees no connection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_runtime::runtime;
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseKind, DialEnd, Evidence, Reached, Sockets};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::{harness_budget, name, ID};

/// How long a listener is watched for a connection that must not come.
const NO_CONNECTION: Duration = Duration::from_millis(500);

/// Dial a localhost listener over `sockets`. Returns the dial's first end,
/// if it ended within the wait, and whether the listener accepted.
fn dial_a_listener(sockets: Sockets) -> (Option<DialEnd>, bool) {
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(harness_budget(), &name("sk-clearnet-admit")).expect("runtime");
    let (end_tx, end_rx) = std::sync::mpsc::channel();
    let (admitted_tx, _admitted_rx) = mpsc::unbounded_channel();
    let listener = pool.block_on(async {
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind")
    });
    let port = listener.local_addr().expect("addr").port();
    let dial = super::super::Dial {
        address: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port,
        },
        proxy: None,
        sockets,
        kind: crate::seam::ChannelChoice::Plain,
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
    let accepted = pool.block_on(async {
        tokio::time::timeout(NO_CONNECTION, listener.accept())
            .await
            .is_ok()
    });
    (end_rx.recv_timeout(NO_CONNECTION).ok(), accepted)
}

/// A banned host is refused at admission with no SYN: the dial ends as this
/// node's own refusal and the listener never accepts. Without the ban the
/// same dial connects, so the listener's silence is the ban's. The edit that
/// makes this red is admitting after the TCP connect.
#[test]
fn a_banned_host_is_refused_before_the_connect() {
    let banned = Sockets::new();
    drop(banned.ban_host_permanent(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let (end, accepted) = dial_a_listener(banned);
    assert!(!accepted, "a banned host saw a connection");
    let end = end.expect("the refusal ends the dial at once");
    assert_eq!(end.failure().evidence(), Evidence::Local);
    assert_eq!(end.failure().reached(), Reached::NoStream);
    assert_eq!(end.cause().kind(), CloseKind::AdmissionRefused);

    let (_, accepted) = dial_a_listener(Sockets::new());
    assert!(accepted, "an unbanned dial connects");
}
