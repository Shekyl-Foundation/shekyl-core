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
//! fires. [`Dialer::dial`] is the named draw, and it reads the same gate. No
//! connector is installed on the rig's peer, so a dial that is made fails at
//! once as a local close, as a dial through a dead proxy does.

#[path = "support/rig.rs"]
mod rig;
#[path = "support/tables.rs"]
mod tables;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rig::{wait_until, Build, Rig};
use shekyl_dialer::{DialAim, Dialer, NotReady};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{ConnectorId, ListName, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock, OwnerClass};
use shekyl_transport_layer::{DialEnd, DownCause, Route, RoutePublish};

const CLEARNET: ConnectorId = ConnectorId::Clearnet;

/// The wake spacing this file's connector dials at: its dial profile's.
const WAKE_BASE_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .base_nanos;
const WAKE_JITTER_NANOS: u64 = shekyl_peerlist::dial_profile(ConnectorId::Clearnet)
    .wake
    .jitter_nanos;
const WAKES: usize = 12;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

type TestDialer = Dialer<ManualClock>;

/// A rig with no connector installed and no route published, with four
/// clearnet addresses in gray. The link and the layer are left to each
/// test.
fn rig_on(clock: &ManualClock, attached: bool) -> Rig {
    let build = Build::on(clock).routes(&[]);
    let rig = if attached { build } else { build.unattached() }.finish();
    rig.peer.refuse_unqueued(DialEnd::local_close());
    let mut rng = SplitMix64::new(1);
    for n in 1..=4 {
        rig.dialer
            .admit_operator(&peer(n), Tick::new(1), &mut rng)
            .expect("admitted");
    }
    rig
}

fn rig() -> Rig {
    rig_on(&ManualClock::new(Tick::new(1)), true)
}

/// The clearnet gray list.
fn gray(dialer: &TestDialer) -> BTreeSet<NetworkAddress> {
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
fn wakes(dialer: &TestDialer, n: usize) -> usize {
    let mut rng = SplitMix64::new(9);
    (0..n).filter(|_| dialer.wake(CLEARNET, &mut rng)).count()
}

/// Usable, then down, as the zone host publishes a Tor route and that Tor's
/// death.
fn take_link_down(dialer: &TestDialer) {
    let links = dialer.links();
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
    let rig = rig();
    let dialer = &rig.dialer;
    take_link_down(dialer);
    let before = gray(dialer);
    assert_eq!(before.len(), 4);
    assert_eq!(
        dialer.readiness(CLEARNET),
        Err(NotReady::LinkDown(DownCause::ProcessExited))
    );
    assert_eq!(wakes(dialer, WAKES), 0, "no wake dialed");
    assert_eq!(gray(dialer), before, "gray is unchanged, seat for seat");
}

/// A named dial is the other draw. It reads the same gate, so a down
/// link costs nothing: removing the check in [`Dialer::dial`] draws the
/// address, the dial fails locally, and the address leaves gray.
#[test]
fn a_direct_dial_draws_nothing_while_the_link_is_down() {
    let rig = rig();
    let dialer = &rig.dialer;
    take_link_down(dialer);
    let before = gray(dialer);
    let address = before.iter().next().expect("a gray address").clone();
    assert!(dialer
        .dial(CLEARNET, &address, DialAim::Keep, &mut SplitMix64::new(4))
        .is_none());
    assert_eq!(gray(dialer), before, "an unready dial does not draw");
}

/// A stop and an exit are different causes. The waiting line names which.
#[test]
fn a_stopped_link_is_not_described_as_an_exit() {
    assert_eq!(
        NotReady::LinkDown(DownCause::ProcessStopped).describe(),
        "its link is down: the Tor it dials through was stopped"
    );
    assert_eq!(
        NotReady::LinkDown(DownCause::ProcessExited).describe(),
        "its link is down: the Tor it dials through has exited"
    );
}

/// The control: the same wakes over a usable link dial, and each failed
/// dial cools its address, so it is not drawn again until its cooldown
/// ends. This is what a down link did before the plan read it, when a
/// failed draw still left gray. *Records-was (to 2026-10-24): "three
/// draws, three addresses gone".*
#[test]
fn the_same_wakes_over_a_usable_link_draw_and_cool_their_addresses() {
    let rig = rig();
    let dialer = &rig.dialer;
    assert!(
        matches!(
            dialer
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1)),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    assert_eq!(wakes(dialer, 3), 3);
    let gray = gray(dialer);
    assert_eq!(gray.len(), 4, "three draws, nothing gone");
    let cooling = gray
        .iter()
        .filter(|address| dialer.shared().lists.is_cooling(address))
        .count();
    assert_eq!(cooling, 3, "three draws, three addresses cooling");
}

#[test]
fn a_connector_with_no_route_draws_nothing() {
    let rig = rig();
    let dialer = &rig.dialer;
    let before = gray(dialer);
    assert_eq!(dialer.readiness(CLEARNET), Err(NotReady::NoRoute));
    assert_eq!(wakes(dialer, WAKES), 0);
    assert_eq!(gray(dialer), before);
}

/// Before the composition attaches the session layer there is nothing to
/// dial through: the tip and the network id are the layer's (brief §2.1),
/// so the one gate that was `NoTip` and `NoNetworkId` is the layer's
/// absence. *Records-was (to the remnant cutover): the dialer read a tip
/// closure and a network id of its own.*
#[test]
fn a_connector_with_no_session_layer_draws_nothing() {
    let rig = rig_on(&ManualClock::new(Tick::new(1)), false);
    let dialer = &rig.dialer;
    assert!(
        matches!(
            dialer
                .links()
                .publish_usable(CLEARNET, Route::Direct, Tick::new(1)),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    let before = gray(dialer);
    assert_eq!(dialer.readiness(CLEARNET), Err(NotReady::NoLayer));
    assert_eq!(
        NotReady::NoLayer.describe(),
        "the session layer is not attached"
    );
    assert_eq!(wakes(dialer, WAKES), 0);
    assert_eq!(gray(dialer), before);
}

/// **The owner loop parks on change.** While the link is down the loop arms
/// no timer: however far the clock moves, the engine fires no Discovery wake.
/// When the link returns, the loop arms its normal spacing and dials. A wake
/// that fires after a fall draws nothing because `choose` reads readiness at
/// every wake; the tests above show that without a clock.
#[test]
fn the_owner_loop_waits_on_the_link_and_resumes_when_it_returns() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = rig_on(&clock, true);
    let dialer = &rig.dialer;
    let service = &rig.timing;
    take_link_down(dialer);
    let before = gray(dialer);

    let owner = service.register(OwnerClass::Discovery).expect("register");
    let running = Arc::clone(dialer);
    let loop_thread = thread::spawn(move || {
        running.run(CLEARNET, &owner, &mut SplitMix64::new(2));
    });
    let fires = || {
        service
            .lateness(OwnerClass::Discovery)
            .expect("lateness")
            .fires
    };

    // Ten of the longest wake spacings pass: no wake fires, nothing drawn.
    let spacing = WAKE_BASE_NANOS + WAKE_JITTER_NANOS;
    thread::sleep(Duration::from_millis(100));
    clock.set(Tick::new(clock.now().get() + 10 * spacing));
    let nudge = service.register(OwnerClass::Interim).expect("nudge");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(fires(), 0, "a parked loop armed a timer");
    assert_eq!(gray(dialer), before);
    drop(nudge);

    // The link returns: a return from down is a new route, the loop arms
    // its spacing, and a wake dials.
    assert!(
        matches!(
            dialer
                .links()
                .publish_usable(CLEARNET, Route::Direct, clock.now()),
            RoutePublish::Installed { .. }
        ),
        "a return from down is a new route"
    );
    thread::sleep(Duration::from_millis(100));
    clock.set(Tick::new(clock.now().get() + spacing + 1));
    let _nudge = service.register(OwnerClass::Interim).expect("nudge");
    // A dial that fails cools its address rather than dropping it (the gray
    // lifecycle), so the sign of a dial is a cooling address.
    wait_until("the loop did not dial after the link returned", || {
        gray(dialer)
            .iter()
            .any(|address| dialer.shared().lists.is_cooling(address))
    });
    assert_eq!(gray(dialer).len(), before.len(), "nothing left gray");
    assert!(fires() >= 1);

    // Stopping the dialer ends the loop wherever it waits.
    dialer.stop();
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
    let rig = rig_on(&clock, true);
    let dialer = &rig.dialer;
    take_link_down(dialer);
    let owner = Arc::new(
        rig.timing
            .register(OwnerClass::Discovery)
            .expect("register"),
    );
    let running = Arc::clone(dialer);
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
        Ending::EngineClosed => rig.close_engine(),
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
