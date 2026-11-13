// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The accept-rate linger cap: a refused inbound is held, then closed,
//! and listeners share one cap (D10.2).
//!
//! The harness lives in the parent test module.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::runtime;
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseKind, Sockets};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::{ChannelChoice, ClearnetOption};

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
    let (engine, listener, seen) = super::start_on(
        refusing_gate(100_000_000, 4),
        super::ID,
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(4),
    );
    let _first = super::connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let refused = super::connect(listener.local_addr());
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
    let (engine, listener, seen) = super::start_on(
        refusing_gate(5_000_000_000, 1),
        super::ID,
        ClearnetOption::On,
        Tick::new(5_000_000_000),
        InboundCeiling::Bounded(8),
    );
    let _first = super::connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let held_a = super::connect(listener.local_addr());
    wait_for_refusals(&seen, 1);
    let held_b = super::connect(listener.local_addr());
    wait_for_refusals(&seen, 2);
    let past_cap = super::connect(listener.local_addr());
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

/// Two listeners share one linger cap. With room for two, both filled on
/// the first listener, a refusal on the second closes at once: a cap per
/// listener would hold that socket and its late flight would end with FIN
/// (D10.2).
#[test]
fn two_listeners_share_the_linger_cap() {
    let span = Tick::new(5_000_000_000);
    let sockets = refusing_gate(span.get(), 1);
    assert_eq!(sockets.clearnet_linger_cap(span), 2);
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(super::harness_budget(), &super::name("sk-clearnet-two")).expect("runtime");
    let recorded = super::causes();
    let seen = Arc::clone(&recorded.seen);
    let (admitted_tx, admitted_rx) = mpsc::unbounded_channel();
    let sockets_for_loops = sockets.clone();
    let on_cause = Arc::clone(&recorded.sink);
    let linger_engine = engine.handle();
    let cap = sockets.clearnet_linger_cap(span);
    let (addr_a, addr_b) = pool.block_on(async move {
        let linger = super::super::Linger::spawn(linger_engine.clone(), cap, span);
        let make_inbound = || super::super::Inbound {
            sockets: sockets_for_loops.clone(),
            ceiling: || InboundCeiling::Bounded(8),
            kind: ChannelChoice::Plain,
            network_id: super::ID,
            handshake_within: span,
            gap_within: None,
            tally: Arc::new(super::super::zero_tally()),
            on_cause: Arc::clone(&on_cause),
            send_queue_bytes: 65_536,
            admitted: super::super::publish_on(admitted_tx.clone()),
            linger: linger.clone(),
            backoff: Duration::from_millis(1),
        };
        let listener_a = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let listener_b = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr_a = listener_a.local_addr().expect("addr");
        let addr_b = listener_b.local_addr().expect("addr");
        tokio::spawn(super::super::accept_inbound(
            listener_a,
            make_inbound(),
            linger_engine.clone(),
        ));
        tokio::spawn(super::super::accept_inbound(
            listener_b,
            make_inbound(),
            linger_engine,
        ));
        (addr_a, addr_b)
    });
    let _keep_admitted = admitted_rx;
    let _admitted = super::connect(addr_a);
    let start = Instant::now();
    while sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let held_a = super::connect(addr_a);
    wait_for_refusals(&seen, 1);
    let held_b = super::connect(addr_a);
    wait_for_refusals(&seen, 2);
    let past = super::connect(addr_b);
    wait_for_refusals(&seen, 3);
    assert!(
        flight_after(past, Duration::from_millis(50)).is_some(),
        "the second listener shares the cap, so this refusal closed at once"
    );
    for (label, held) in [("first", held_a), ("second", held_b)] {
        let error = flight_after(held, Duration::ZERO);
        assert!(error.is_none(), "the {label} held socket: {error:?}");
    }
    pool.shutdown(Duration::from_millis(50));
    drop(engine);
}

/// A refused peer that never writes is held until the span passes, then
/// closed, and its slot is free again: twice over, so the second expiry
/// rests on the timing engine's deadline re-arming after its first wake.
/// The span here is 300 ms and the cap two.
#[test]
fn idle_refusals_close_at_the_span_and_free_their_slots() {
    let span = Duration::from_millis(300);
    // Burst 1, one token per 300 ms span: a cap of 1 + 1 = 2.
    let (engine, listener, seen) = super::start_on(
        refusing_gate(300_000_000, 1),
        super::ID,
        ClearnetOption::On,
        Tick::new(300_000_000),
        InboundCeiling::Bounded(8),
    );
    let _first = super::connect(listener.local_addr());
    let start = Instant::now();
    while listener.sockets.live() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the first is admitted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut refused = 0;
    let mut refuse = || {
        let client = super::connect(listener.local_addr());
        refused += 1;
        wait_for_refusals(&seen, refused);
        client
    };
    // Round one: two idle holds fill the cap, then the span passes.
    let idle_a = refuse();
    let idle_b = refuse();
    std::thread::sleep(span * 2);
    let late = refuse();
    assert!(
        flight_after(late, Duration::from_millis(50)).is_none(),
        "the expired holds freed their slots, so this one lingered"
    );
    for (name, idle) in [("first", idle_a), ("second", idle_b)] {
        assert!(
            flight_after(idle, Duration::ZERO).is_some(),
            "the {name} idle hold was closed at the span"
        );
    }
    // Round two, after the engine's first wakes.
    let _idle_c = refuse();
    let _idle_d = refuse();
    std::thread::sleep(span * 2);
    let later = refuse();
    assert!(
        flight_after(later, Duration::from_millis(50)).is_none(),
        "the second round of holds expired too"
    );
    listener.shutdown();
    drop(engine);
}
