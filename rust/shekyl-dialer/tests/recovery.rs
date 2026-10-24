// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Recovery (Rick, 2026-10-14; amended 2026-10-24): a connector whose wake
//! finds it under its target, nothing in flight and no drawable white or
//! gray candidate re-admits its configured addresses to gray as
//! operator-named: the
//! compiled seeds and `--add-peer`, or, when a closed network is declared,
//! that list alone. The wake that re-admits dials nothing; the next draws.
//!
//! The cases here have no kept session. The one-kept-session case needs a
//! connector that keeps a dial, and lives in `tests/owner.rs`.
//!
//! The hub here has no connector installed, so every dial fails at once
//! as a local close. Under the gray lifecycle (Rick, 2026-10-24) a failed
//! test that proves no misbehaviour returns the address to gray with a
//! cooldown, so it stays seated and is not drawable until the cooldown
//! ends: a connector whose every address is cooling is stranded, and
//! recovery re-admits nothing new for it; the clock is what frees the
//! address, no faster than its cooldown. *Records-was (2026-10-14 to
//! 2026-10-24): the failed draw left gray, and the stranded wake
//! re-admitted it.*

use std::net::Ipv4Addr;
use std::sync::Arc;

use shekyl_dialer::{DialAim, Dialer};
use shekyl_draw_rng::SplitMix64;
use shekyl_peer_policy::InboundCeiling;
use shekyl_peerlist::{ConnectorId, ListName, NetworkAddress, RefusedSet, Tick};
use shekyl_seam::{Hub, Route, RoutePublish, SyncPayload};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::Sockets;

const CLEARNET: ConnectorId = ConnectorId::Clearnet;

fn peer(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 15, 0, n),
        port: 18080,
    }
}

/// Past the longest cooldown and its jitter.
const PAST_COOLDOWN_NANOS: u64 = 2 * shekyl_peerlist::COOLDOWN_CAP_NANOS;

fn dialer() -> Arc<Dialer> {
    dialer_on(&ManualClock::new(Tick::new(1)))
}

fn dialer_on(clock: &ManualClock) -> Arc<Dialer> {
    let hub = Hub::new(
        Sockets::new(),
        InboundCeiling::Bounded(8),
        Arc::new(|_post| {}),
        Arc::new(clock.clone()),
    );
    let dialer = Arc::new(Dialer::new(
        hub,
        RefusedSet::NON_GLOBAL,
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
    // The link is usable: the plan draws only then (TSR-F1).
    assert!(
        matches!(
            dialer
                .hub()
                .links()
                .publish_usable(ConnectorId::Clearnet, Route::Direct, Tick::new(1),),
            RoutePublish::Installed { .. }
        ),
        "the test route was not already usable"
    );
    dialer
}

/// The clearnet gray list, as addresses.
fn gray(dialer: &Dialer) -> Vec<NetworkAddress> {
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

/// Dial `address` once: with no connector it fails, and cools in gray.
fn fail_out(dialer: &Dialer, address: &NetworkAddress, rng: &mut SplitMix64) {
    assert!(
        gray(dialer).contains(address),
        "{address:?} is in gray to fail"
    );
    assert!(
        dialer.dial(CLEARNET, address, DialAim::Keep, rng).is_none(),
        "no connector: the dial fails at once"
    );
    assert!(
        gray(dialer).contains(address),
        "{address:?} stays gray: a connection problem drops nothing"
    );
    assert!(
        dialer.shared().lists.is_cooling(address),
        "{address:?} cools after the failed test"
    );
}

/// Move the clock past every cooldown, so what cooled is drawable again.
fn past_cooldowns(clock: &ManualClock) {
    clock.set(Tick::new(clock.now().get() + PAST_COOLDOWN_NANOS));
}

/// A configured dead address under recovery is redialled no faster than
/// its cooldown (the gray lifecycle, test 6e). The failed address cools in
/// gray; the connector, with nothing drawable, is stranded and re-admits
/// nothing it does not already hold; wakes inside the cooldown draw
/// nothing; the first wake past it draws the address again.
#[test]
fn a_stranded_connector_redials_a_cooling_configured_address_no_faster_than_its_cooldown() {
    let clock = ManualClock::new(Tick::new(1));
    let dialer = dialer_on(&clock);
    let mut rng = SplitMix64::new(1);
    let named = peer(1);
    dialer
        .admit_operator(&named, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &named, &mut rng);

    // Stranded, inside the cooldown: every wake re-admits nothing new and
    // draws nothing.
    for _ in 0..5 {
        assert!(dialer.choose(CLEARNET, &mut rng).is_none());
        assert_eq!(
            gray(&dialer),
            vec![named.clone()],
            "still seated, still cooling"
        );
        assert!(dialer.shared().lists.is_cooling(&named));
    }

    // Past the cooldown the address is drawable, and the wake draws it.
    past_cooldowns(&clock);
    let (drawn, _aim, _nonce) = dialer
        .choose(CLEARNET, &mut rng)
        .expect("the cooled address is drawn once its cooldown ends");
    assert_eq!(drawn, named);
}

#[test]
fn a_healthy_connector_leaves_a_dead_add_peer_cooling() {
    let dialer = dialer();
    let mut rng = SplitMix64::new(2);
    let dead = peer(1);
    dialer
        .admit_operator(&dead, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &dead, &mut rng);

    // A candidate is drawable, so the connector is not stranded, and the
    // dead address is left where its failed test put it: cooling.
    let live = peer(2);
    dialer
        .admit_operator(&live, Tick::new(1), &mut rng)
        .expect("admitted");
    let (drawn, _aim, _nonce) = dialer.choose(CLEARNET, &mut rng).expect("a draw");
    assert_eq!(drawn, live);
    assert!(
        dialer.shared().lists.is_cooling(&dead),
        "a healthy connector leaves a dead --add-peer cooling, not redrawn"
    );
}

#[test]
fn a_declared_closed_network_draws_only_its_list_once_its_cooldowns_end() {
    let clock = ManualClock::new(Tick::new(1));
    let dialer = dialer_on(&clock);
    let mut rng = SplitMix64::new(3);
    // Named before the declaration, and failed: it cools in gray.
    let outside = peer(9);
    dialer
        .admit_operator(&outside, Tick::new(1), &mut rng)
        .expect("admitted");
    fail_out(&dialer, &outside, &mut rng);

    let population = vec![peer(1), peer(2)];
    dialer.set_exclusive(population.clone(), Tick::new(1), &mut rng);
    for address in &population {
        fail_out(&dialer, address, &mut rng);
    }
    // Everything is seated and cooling: the stranded wake has nothing to
    // re-admit and draws nothing.
    assert!(dialer.choose(CLEARNET, &mut rng).is_none());
    assert_eq!(gray(&dialer).len(), 3, "nothing left gray");

    // Past the cooldowns, every wake draws from the declared list: the
    // address named outside it is seated and drawable, and never drawn.
    // A wake's dial fails at once (no connector), so what it drew is the
    // address whose failed-test count rose, and it cools again.
    let failed = |address: &NetworkAddress| dialer.shared().lists.failed_tests(address);
    for round in 1..=4u32 {
        past_cooldowns(&clock);
        assert!(dialer.wake(CLEARNET, &mut rng), "the closed network dials");
        assert_eq!(failed(&outside), 1, "the outside address is never drawn");
        assert_eq!(
            failed(&population[0]) + failed(&population[1]),
            2 + round,
            "one member of the list was drawn and failed again"
        );
    }
}
