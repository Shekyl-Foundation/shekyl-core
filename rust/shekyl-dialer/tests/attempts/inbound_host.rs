// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A host that dialed in is not dialed back (Rick, 2026-11-09).
//!
//! Dialing a node because it connected to us hands any node that connects
//! a free outbound slot, the eclipse attacker's cheapest step. The dialer
//! makes a best effort at its target of distinct nodes, and a node already
//! in a session, in either direction, is not a new one.
//!
//! The case that found it: two regtest daemons, each told to dial the
//! other. The second to start dialed the first, which already held an
//! inbound session from it, so the pair held two sessions. A stem the first
//! sent came straight back on the second session, and the origin published
//! its own transaction at 2 s instead of at its embargo (#1294).

use std::net::IpAddr;
use std::time::Duration;

use shekyl_dialer::DialAim;
use shekyl_draw_rng::SplitMix64;
use shekyl_p2p_session::Endpoint;
use shekyl_peerlist::{dial_profile, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::Direction;

use super::rig::{Answer, Rig};
use super::{peer, reply, CLEARNET, NETWORK};

/// A port the far side dials from: not the port it listens on.
const EPHEMERAL_PORT: u16 = 51_000;

/// A rig whose peer would answer any dial, with `address` admitted gray.
fn rig_with_gray(address: &NetworkAddress, rng: &mut SplitMix64) -> Rig {
    let rig = Rig::new();
    rig.peer.answer_unqueued(Answer::Answered(reply(NETWORK)));
    rig.dialer
        .admit_operator(address, Tick::new(1), rng)
        .expect("admitted");
    rig
}

fn ip_of(address: &NetworkAddress) -> IpAddr {
    address.ip().expect("a clearnet address")
}

/// **The control:** with no session from its host, the gray address is
/// dialed at the wake. Without it, the test below could pass on a dialer
/// that dials nothing at all.
#[test]
fn a_gray_address_with_no_session_from_its_host_is_dialed() {
    let mut rng = SplitMix64::new(61);
    let address = peer(61);
    let rig = rig_with_gray(&address, &mut rng);
    assert!(rig.dialer.wake(CLEARNET, &mut rng), "the wake dials");
    assert_eq!(rig.peer.connects(), 1, "one dial, to the gray address");
}

/// **A host with an inbound session is not dialed.** The host connects in
/// from a port of its own; the address it listens on is gray. A second
/// host, with no session, is the one the wake dials. The inbound host's
/// listen address stays gray.
///
/// Red edit: `host_occupied` ignores live sessions (the rule before
/// 2026-11-09, which counted outbound rows only). The wake then dials the
/// host that connected, and this assertion on the second host is what
/// keeps a dialer that dials nothing from passing.
#[test]
fn a_host_with_an_inbound_session_is_not_dialed_on_its_listening_port() {
    let mut rng = SplitMix64::new(62);
    let listening = peer(62);
    let other = peer(63);
    let rig = Rig::new();
    rig.peer.answer_unqueued(Answer::Answered(reply(NETWORK)));
    for address in [&listening, &other] {
        rig.dialer
            .admit_operator(address, Tick::new(1), &mut rng)
            .expect("admitted");
    }
    let mut inbound = rig.accept(Endpoint::Clearnet {
        ip: ip_of(&listening),
        port: EPHEMERAL_PORT,
        direction: Direction::Inbound,
    });
    rig.establish_inbound(&mut inbound);

    assert!(
        rig.dialer.wake(CLEARNET, &mut rng),
        "the host with no session is dialed"
    );
    assert_eq!(
        rig.peer.connects(),
        1,
        "one dial, to the host that did not connect"
    );
    assert!(
        rig.dialer.shared().lists.is_gray(&listening),
        "the inbound host's listen address stays gray"
    );
    assert!(
        !rig.dialer.shared().lists.is_gray(&other),
        "the free host was drawn"
    );
    drop(inbound);
}

/// The longest wait before a second attempt: its base plus its whole
/// jitter. A failure that starts this far after another has a retry that
/// is strictly later, whichever jitter each one drew.
fn after_every_second_attempt_wait() -> Duration {
    let wait = dial_profile(CLEARNET).retry_waits.before_second;
    Duration::from_nanos(wait.base_nanos.saturating_add(wait.jitter_nanos))
}

fn advance(clock: &ManualClock, by: Duration) {
    let by = u64::try_from(by.as_nanos()).expect("a short span");
    clock.set(Tick::new(clock.now().get().saturating_add(by)));
}

/// **A retry that comes due is the same check.** Two white addresses fail
/// once and wait. The earlier one's host connects in while it waits. The
/// wake dials the later host and leaves the earlier wait outstanding:
/// still white, not cooled, not demoted.
///
/// The earlier failure is `dial`, not `wake`, so the later failure can
/// start after the earlier retry is already due without that wake taking
/// it. Red edit: `plan_wake` resumes the earliest due test before it asks
/// whether the host is occupied. The occupied address is then the one
/// demoted.
#[test]
fn a_due_retry_is_not_made_to_a_host_that_connected_while_it_waited() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = Rig::on(&clock);
    let occupied = peer(80);
    let free = peer(81);
    let addresses = [&occupied, &free];
    rig.peer
        .answer_each(addresses.len(), || Answer::Answered(reply(NETWORK)));
    let mut rng = SplitMix64::new(80);
    for address in addresses {
        rig.dialer
            .admit_operator(address, Tick::new(1), &mut rng)
            .expect("admitted");
    }
    for _ in addresses {
        assert!(rig.dialer.wake(CLEARNET, &mut rng), "a keep");
    }
    for address in addresses {
        assert!(
            rig.dialer.shared().lists.is_white(address),
            "{address:?} white"
        );
    }
    for id in rig.opened() {
        rig.close_as_peer(id);
    }
    assert_eq!(rig.dialer.kept_sessions(CLEARNET), 0, "none held");

    let refused = shekyl_clearnet::Observed::ConnectRefused.end();
    rig.peer.refuse_after(refused, Duration::ZERO);
    assert!(
        rig.dialer
            .dial(CLEARNET, &occupied, DialAim::Keep, &mut rng)
            .is_none(),
        "the first failure waits"
    );
    assert!(rig.dialer.shared().lists.is_white(&occupied));

    // Past every jitter the first retry could have drawn, so the second
    // failure's retry is strictly later. `dial` does not resume the one
    // that is already due.
    advance(&clock, after_every_second_attempt_wait());
    rig.peer.refuse_after(refused, Duration::ZERO);
    assert!(
        rig.dialer
            .dial(CLEARNET, &free, DialAim::Keep, &mut rng)
            .is_none(),
        "the free host's first failure waits"
    );
    assert!(rig.dialer.shared().lists.is_white(&free));

    let mut inbound = rig.accept(Endpoint::Clearnet {
        ip: ip_of(&occupied),
        port: EPHEMERAL_PORT,
        direction: Direction::Inbound,
    });
    rig.establish_inbound(&mut inbound);
    advance(&clock, after_every_second_attempt_wait());

    let connects = rig.peer.connects();
    rig.peer.refuse_after(refused, Duration::ZERO);
    assert!(
        rig.dialer.wake(CLEARNET, &mut rng),
        "the free host's retry is made"
    );
    assert_eq!(rig.peer.connects(), connects + 1, "one dial");
    let shared = rig.dialer.shared();
    assert!(
        shared.lists.is_white(&occupied) && !shared.lists.is_cooling(&occupied),
        "the occupied host's retry stays outstanding"
    );
    assert!(
        !shared.lists.is_white(&free),
        "the free host's redial was the one refused"
    );
    drop(inbound);
}
