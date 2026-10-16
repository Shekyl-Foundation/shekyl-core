// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer draws only when it can dial (`TOR_SUPERVISOR.md` `TSR-F1`).
//!
//! A draw a connector cannot dial ends as `DialFailed(LocalClose)`, and the
//! list rule drops a drawn gray address on that outcome. So the plan reads the
//! connector's link, the tip and the network id before it draws, and while one
//! is missing the owner loop waits on the change, not on its timer.
//!
//! Each wake here is [`Dialer::wake`], what the owner loop runs when its timer
//! fires. The hub has no connector installed, so a dial that is made fails at
//! once as a local close, as a dial through a dead proxy does.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use shekyl_dialer::{Dialer, NotReady, SnapshotSource, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::SupportFlags;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, ListName, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{DownCause, Hub, Route, RoutePublish, SyncPayload};
use shekyl_timing_engine::{Clock, EngineService, ManualClock, OwnerClass};
use shekyl_transport_layer::Sockets;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const WAKES: usize = 12;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

fn tip() -> SnapshotSource {
    Arc::new(|| {
        Some(SyncPayload {
            current_height: 1,
            cumulative_difficulty: 1,
            cumulative_difficulty_top64: 0,
            top_id: [0; 32],
        })
    })
}

/// A dialer over a hub with no connector, with four clearnet addresses in
/// gray. The link and the network id are left to each test.
fn dialer(clock: &ManualClock, snapshot: SnapshotSource) -> Arc<Dialer> {
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(clock.clone()),
    );
    let dialer = Arc::new(Dialer::new(
        hub,
        RefusedSet::NON_GLOBAL,
        SupportFlags::ADVERTISED.bits(),
        snapshot,
    ));
    let mut rng = SplitMix64::new(1);
    for n in 1..=4 {
        dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    dialer
}

/// The clearnet gray list.
fn gray(dialer: &Dialer) -> BTreeSet<NetworkAddress> {
    dialer
        .shared()
        .lists
        .snapshot()
        .into_iter()
        .filter(|(address, list)| {
            *list == ListName::Gray
                && shekyl_peerlist::Peerlist::connector_of(address) == Some(CLEARNET)
        })
        .map(|(address, _)| address)
        .collect()
}

/// Run `n` wakes; how many of them dialed.
fn wakes(dialer: &Dialer, n: usize) -> usize {
    let mut rng = SplitMix64::new(9);
    (0..n).filter(|_| dialer.wake(CLEARNET, &mut rng)).count()
}

/// Usable, then down, as the zone host publishes a Tor route and that Tor's
/// death.
fn take_link_down(dialer: &Dialer) {
    let links = dialer.hub().links();
    let incarnation = links
        .publish_usable(CLEARNET, Route::Direct, Tick::new(1))
        .incarnation();
    assert!(links.publish_down(
        CLEARNET,
        incarnation,
        DownCause::ProcessExited,
        Tick::new(2)
    ));
}

/// **A down link keeps the gray list.** `WAKES` wakes draw nothing, and the
/// gray seats are the ones that were there. Before `TSR-F1` each wake drew
/// one address, the dial failed locally, and the address left gray.
#[test]
fn a_connector_whose_link_is_down_keeps_its_gray_list() {
    let dialer = dialer(&ManualClock::new(Tick::new(1)), tip());
    dialer.set_network_id([7; 16]);
    take_link_down(&dialer);
    let before = gray(&dialer);
    assert_eq!(before.len(), 4);
    assert_eq!(
        dialer.readiness(CLEARNET),
        Err(NotReady::LinkDown(DownCause::ProcessExited))
    );
    assert_eq!(wakes(&dialer, WAKES), 0, "no wake dialed");
    assert_eq!(gray(&dialer), before, "gray is unchanged, seat for seat");
}

/// The control: the same wakes over a usable link dial, and each failed
/// dial costs its address. This is what a down link did before the plan
/// read it.
#[test]
fn the_same_wakes_over_a_usable_link_draw_and_lose_their_addresses() {
    let dialer = dialer(&ManualClock::new(Tick::new(1)), tip());
    dialer.set_network_id([7; 16]);
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1)),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    assert_eq!(wakes(&dialer, 3), 3);
    assert_eq!(gray(&dialer).len(), 1, "three draws, three addresses gone");
}

#[test]
fn a_connector_with_no_route_draws_nothing() {
    let dialer = dialer(&ManualClock::new(Tick::new(1)), tip());
    dialer.set_network_id([7; 16]);
    let before = gray(&dialer);
    assert_eq!(dialer.readiness(CLEARNET), Err(NotReady::NoRoute));
    assert_eq!(wakes(&dialer, WAKES), 0);
    assert_eq!(gray(&dialer), before);
}

#[test]
fn a_connector_with_no_published_tip_draws_nothing() {
    let dialer = dialer(&ManualClock::new(Tick::new(1)), Arc::new(|| None));
    dialer.set_network_id([7; 16]);
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1)),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    let before = gray(&dialer);
    assert_eq!(dialer.readiness(CLEARNET), Err(NotReady::NoTip));
    assert_eq!(wakes(&dialer, WAKES), 0);
    assert_eq!(gray(&dialer), before);
}

#[test]
fn a_connector_with_no_network_id_draws_nothing() {
    let dialer = dialer(&ManualClock::new(Tick::new(1)), tip());
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1)),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    let before = gray(&dialer);
    assert_eq!(dialer.readiness(CLEARNET), Err(NotReady::NoNetworkId));
    assert_eq!(wakes(&dialer, WAKES), 0);
    assert_eq!(gray(&dialer), before);
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// **The owner loop parks on change.** While the link is down the loop arms
/// no timer: however far the clock moves, the engine fires no Discovery wake.
/// When the link returns, the loop arms its normal spacing and dials. A wake
/// that fires after a fall draws nothing because `choose` reads readiness at
/// every wake; the tests above show that without a clock.
#[test]
fn the_owner_loop_waits_on_the_link_and_resumes_when_it_returns() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let service = EngineService::start(clock.clone());
    let dialer = dialer(&clock, tip());
    dialer.set_network_id([7; 16]);
    take_link_down(&dialer);
    let before = gray(&dialer);

    let owner = service
        .handle()
        .register(OwnerClass::Discovery)
        .expect("register");
    let running = Arc::clone(&dialer);
    let loop_thread = thread::spawn(move || {
        running.run(CLEARNET, &owner, &mut SplitMix64::new(2));
    });
    let fires = || {
        service
            .handle()
            .lateness(OwnerClass::Discovery)
            .expect("lateness")
            .fires
    };

    // Ten of the longest wake spacings pass: no wake fires, nothing drawn.
    let spacing = WAKE_BASE_NANOS + WAKE_JITTER_NANOS;
    thread::sleep(Duration::from_millis(100));
    clock.set(Tick::new(clock.now().get() + 10 * spacing));
    let nudge = service
        .handle()
        .register(OwnerClass::Interim)
        .expect("nudge");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(fires(), 0, "a parked loop armed a timer");
    assert_eq!(gray(&dialer), before);
    drop(nudge);

    // The link returns: a return from down is a new route, the loop arms
    // its spacing, and a wake dials.
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(CLEARNET, Route::Direct, clock.now()),
            RoutePublish::Installed { .. }
        ),
        "a return from down is a new route"
    );
    thread::sleep(Duration::from_millis(100));
    clock.set(Tick::new(clock.now().get() + spacing + 1));
    let _nudge = service
        .handle()
        .register(OwnerClass::Interim)
        .expect("nudge");
    wait_until("the loop did not dial after the link returned", || {
        gray(&dialer).len() < before.len()
    });
    assert!(fires() >= 1);

    // Closing the engine ends the loop wherever it waits.
    service.close();
    wait_until("the loop did not end when the engine closed", || {
        loop_thread.is_finished()
    });
    loop_thread.join().expect("the loop");
}

/// How a parked loop is ended, in each test below.
#[derive(Clone, Copy)]
enum Ending {
    Stop,
    EngineClosed,
    OwnerDeregistered,
}

/// A loop whose link is down from its first wake parks before it arms any
/// timer. `run` ends at the stop, at the owner's deregistration and at the
/// engine's close (Copilot on #1092: the bell alone saw only the stop).
fn a_parked_loop_ends_at(ending: Ending) {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let service = EngineService::start(clock.clone());
    let dialer = dialer(&clock, tip());
    dialer.set_network_id([7; 16]);
    take_link_down(&dialer);
    let owner = Arc::new(
        service
            .handle()
            .register(OwnerClass::Discovery)
            .expect("register"),
    );
    let running = Arc::clone(&dialer);
    let held = Arc::clone(&owner);
    let loop_thread = thread::spawn(move || {
        running.run(CLEARNET, &held, &mut SplitMix64::new(3));
    });
    thread::sleep(Duration::from_millis(100));
    assert!(
        !loop_thread.is_finished(),
        "the loop parks; it does not end"
    );
    match ending {
        Ending::Stop => dialer.stop(),
        Ending::EngineClosed => service.close(),
        Ending::OwnerDeregistered => owner.deregister().expect("deregister"),
    }
    wait_until("the parked loop did not end", || loop_thread.is_finished());
    loop_thread.join().expect("the loop");
}

#[test]
fn a_parked_loop_ends_at_the_stop() {
    a_parked_loop_ends_at(Ending::Stop);
}

#[test]
fn a_parked_loop_ends_when_the_engine_closes() {
    a_parked_loop_ends_at(Ending::EngineClosed);
}

#[test]
fn a_parked_loop_ends_when_its_owner_is_deregistered() {
    a_parked_loop_ends_at(Ending::OwnerDeregistered);
}
