// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wake (R3; Rick, 2026-10-13): the owner loop is an owner of the
//! timing engine, on `ManualClock`. Each gap is `0.5 s + U(0, 1.0 s)`,
//! drawn per dial; one dial is in flight per connector.
//!
//! The clock is the test's. The engine parks until a command when a manual
//! clock is not yet due, so after moving the clock the test nudges the
//! engine with a throwaway registration.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_dialer::{Dialer, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::SupportFlags;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, Post, SocketId, SyncPayload};
use shekyl_timing_engine::{Clock, EngineService, ManualClock, OwnerClass};
use shekyl_transport_layer::Sockets;

const SEND_CAP: usize = 64 * 1024;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 13, 0, n),
        port: 18080,
    }
}

/// Whether the loopback has opened the channel with admission id `id`.
fn channel_open(hub: &Hub, id: u64) -> bool {
    let id = SocketId::from_ffi(id).expect("an id");
    // An empty frame is harmless: the reader takes it and keeps waiting.
    hub.inject(id, Vec::new())
}

fn wait_until(what: &str, deadline: Duration, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < deadline, "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn the_owner_dials_only_after_the_engine_wakes_it_and_once_per_wake() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let service = EngineService::start(clock.clone());
    let posts: Arc<Mutex<VecDeque<Post>>> = Arc::new(Mutex::new(VecDeque::new()));
    let queue = Arc::clone(&posts);
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(move |post| queue.lock().expect("posts").push_back(post)),
        Arc::new(clock.clone()),
    );
    hub.install_loopback(SEND_CAP);
    let dialer = Arc::new(Dialer::new(
        hub.clone(),
        RefusedSet::NON_GLOBAL,
        SupportFlags::ADVERTISED.bits(),
        Arc::new(|| {
            Some(SyncPayload {
                current_height: 1,
                cumulative_difficulty: 1,
                cumulative_difficulty_top64: 0,
                top_id: [0; 32],
            })
        }),
    ));
    dialer.set_network_id([7; 16]);
    let mut rng = SplitMix64::new(1);
    for n in 1..=8 {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }

    let owner = service
        .handle()
        .register(OwnerClass::Discovery)
        .expect("register");
    let loop_dialer = Arc::clone(&dialer);
    let loop_thread = thread::spawn(move || {
        loop_dialer.run(ConnectorId::Clearnet, &owner, &mut SplitMix64::new(2));
    });

    // Before the shortest possible gap: no dial, whatever real time passes.
    let start = clock.now().get();
    thread::sleep(Duration::from_millis(200));
    assert!(
        !channel_open(&hub, 1),
        "a dial before the engine woke the owner"
    );
    clock.set(Tick::new(start + WAKE_BASE_NANOS - 1));
    let nudge = service
        .handle()
        .register(OwnerClass::Interim)
        .expect("nudge");
    thread::sleep(Duration::from_millis(100));
    assert!(!channel_open(&hub, 1), "a dial before 0.5 s");

    // Past the longest possible gap: exactly one dial, then nothing more
    // while it is in flight, however far the clock moves.
    clock.set(Tick::new(start + WAKE_BASE_NANOS + WAKE_JITTER_NANOS + 1));
    drop(nudge);
    let nudge = service
        .handle()
        .register(OwnerClass::Interim)
        .expect("nudge");
    wait_until(
        "the owner did not dial after its wake",
        Duration::from_secs(5),
        || channel_open(&hub, 1),
    );
    clock.set(Tick::new(
        start + 10 * (WAKE_BASE_NANOS + WAKE_JITTER_NANOS),
    ));
    drop(nudge);
    let _nudge = service
        .handle()
        .register(OwnerClass::Interim)
        .expect("nudge");
    thread::sleep(Duration::from_millis(200));
    assert!(
        !channel_open(&hub, 2),
        "a second dial opened while the first was in flight: the bound is one per connector"
    );

    // End the dial in flight: a frame that is not the handshake response
    // is a rejected handshake, so the owner returns to the engine. The
    // loopback arms no gap deadline; a connector would have ended it.
    assert!(hub.inject(
        SocketId::from_ffi(1).expect("an id"),
        shekyl_levin::notify(2002, b"not a handshake response")
    ));
    dialer.stop();
    service.close();
    loop_thread
        .join()
        .expect("the owner loop ends when the engine closes");
}
