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

#[path = "support/rig.rs"]
mod rig;
#[path = "support/tables.rs"]
mod tables;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rig::{wait_until, Rig};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::Received;
use shekyl_p2p_session::Command;
use shekyl_peerlist::{ConnectorId, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock, OwnerClass};

/// The wake spacing this file's connector dials at: its dial profile's.
const WAKE_BASE_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .base_nanos;
const WAKE_JITTER_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .jitter_nanos;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 13, 0, n),
        port: 18080,
    }
}

#[test]
fn the_owner_dials_only_after_the_engine_wakes_it_and_once_per_wake() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = Rig::on(&clock);
    let dialer = &rig.dialer;
    let mut rng = SplitMix64::new(1);
    for n in 1..=8 {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }

    let owner = rig
        .timing
        .register(OwnerClass::Discovery)
        .expect("register");
    let loop_dialer = Arc::clone(dialer);
    let loop_thread = thread::spawn(move || {
        loop_dialer.run(ConnectorId::Clearnet, &owner, &mut SplitMix64::new(2));
    });

    // Before the shortest possible gap: no dial, whatever real time passes.
    let start = clock.now().get();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        rig.peer.connects(),
        0,
        "a dial before the engine woke the owner"
    );
    clock.set(Tick::new(start + WAKE_BASE_NANOS - 1));
    let nudge = rig.timing.register(OwnerClass::Interim).expect("nudge");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(rig.peer.connects(), 0, "a dial before 0.5 s");

    // Past the longest possible gap: exactly one dial, then nothing more
    // while it is in flight, however far the clock moves.
    clock.set(Tick::new(start + WAKE_BASE_NANOS + WAKE_JITTER_NANOS + 1));
    drop(nudge);
    let nudge = rig.timing.register(OwnerClass::Interim).expect("nudge");
    wait_until("the owner did not dial after its wake", || {
        rig.peer.connects() == 1
    });
    let mut wire = rig.dialed();
    let received = wire.read_blocking();
    assert!(
        matches!(received, Received::Request { command, .. } if command == Command::Handshake.wire_id()),
        "the dial wrote its handshake request, not {received:?}"
    );
    clock.set(Tick::new(
        start + 10 * (WAKE_BASE_NANOS + WAKE_JITTER_NANOS),
    ));
    drop(nudge);
    let _nudge = rig.timing.register(OwnerClass::Interim).expect("nudge");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        rig.peer.connects(),
        1,
        "a second dial opened while the first was in flight: the bound is one per connector"
    );

    // End the dial in flight: a frame that is not the handshake response
    // is a rejected handshake, so the owner returns to the engine.
    wire.inject_blocking(shekyl_levin::notify(2002, b"not a handshake response"));
    rig.wait_closed(wire.id);
    dialer.stop();
    rig.close_engine();
    loop_thread
        .join()
        .expect("the owner loop ends when the engine closes");
}
