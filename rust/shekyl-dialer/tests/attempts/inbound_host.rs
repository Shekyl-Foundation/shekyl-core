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

use shekyl_draw_rng::SplitMix64;
use shekyl_p2p_session::Endpoint;
use shekyl_peerlist::{NetworkAddress, Tick};
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
/// from a port of its own; the address it listens on is gray. The wake
/// dials nothing: the host already holds a session with this node.
///
/// Red edit: in `owner/address.rs`, insert a row's host into
/// `session_hosts` only when the row is outbound (the rule before
/// 2026-11-09). The wake then dials the host back.
#[test]
fn a_host_with_an_inbound_session_is_not_dialed_on_its_listening_port() {
    let mut rng = SplitMix64::new(62);
    let address = peer(62);
    let rig = rig_with_gray(&address, &mut rng);
    let mut inbound = rig.accept(Endpoint::Clearnet {
        ip: ip_of(&address),
        port: EPHEMERAL_PORT,
        direction: Direction::Inbound,
    });
    rig.establish_inbound(&mut inbound);

    assert!(
        !rig.dialer.wake(CLEARNET, &mut rng),
        "the host that dialed in is not dialed back"
    );
    assert_eq!(rig.peer.connects(), 0, "no dial was attempted");
    assert!(
        rig.dialer.shared().lists.is_gray(&address),
        "the address stays gray, undrawn"
    );
    drop(inbound);
}
