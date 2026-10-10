// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! ProxyMark reproductions against this relay (`DAEMON_RELAY_PRIVACY.md`
//! §99). PM-2b, height bias (the paper's TC-II): a peer that advertises
//! falsified fresh block heights so that it is chosen as the stem proxy.
//!
//! This relay has no height input. A session enters the stem candidate set
//! through [`Relay::on_session_established`], which takes the session's
//! id, direction and connector and nothing else; `outbound_ids` says in
//! its doc that recorded height is not a filter, and the C++ side's stem
//! set is the zone's established outbound sessions with no height filter
//! (`levin_notify.cpp`, the comment above `shekyl_relay_zone_poll`). The
//! measurement below is therefore of the claim, not of a code path that
//! reads a height: attacker sessions, however fresh the height they
//! advertise, hold the hidden slot and the other slot at their uniform
//! share and no more.

use super::*;

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

/// PM-2b. Twelve address-hiding sessions, four of them the attacker's,
/// and four clearnet sessions. The attacker's falsified heights are not an
/// input this relay has, so they are not represented: every session is
/// established the same way. Over 3000 epochs the attacker's share of the
/// origin's hop (the hidden slot) is 4/12, its share of the other slot is
/// the class-blind draw's (8/12 · 4/15 + 4/12 · 3/15), and its chance of
/// holding both slots is 4/12 · 3/15 — the paper's precondition for TC-II,
/// at its uniform rate.
#[test]
fn pm_2b_falsified_heights_buy_no_stem_or_hidden_slot_share() {
    let mut rng = SplitMix64::new(0x2b);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    // Attacker hidden sessions 1..=4, honest hidden 5..=12, clearnet 21..=24.
    for byte in 1..=12 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Tor,
            &mut rng,
        );
    }
    for byte in 21..=24 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }
    let attacker = |peer: ConnectionId| (1..=4).contains(&peer.as_bytes()[0]);

    let epochs = 3_000_u32;
    let mut hop_attacker = 0_u32;
    let mut other_attacker = 0_u32;
    let mut both_attacker = 0_u32;
    for _ in 0..epochs {
        z.rebuild_stems(&mut rng);
        let RelayPlan::OwnEdge(hop) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
        else {
            panic!("twelve hidden sessions and no pin");
        };
        let slot1 = z.stem_slots()[1].expect("filled");
        let hop_is = attacker(hop);
        let other_is = attacker(slot1);
        hop_attacker += u32::from(hop_is);
        other_attacker += u32::from(other_is);
        both_attacker += u32::from(hop_is && other_is);
    }
    let share = |n: u32| f64::from(n) / f64::from(epochs);
    let hop = share(hop_attacker);
    let other = share(other_attacker);
    let both = share(both_attacker);
    let expect_hop = 4.0 / 12.0;
    let expect_other = (8.0 / 12.0) * (4.0 / 15.0) + (4.0 / 12.0) * (3.0 / 15.0);
    let expect_both = (4.0 / 12.0) * (3.0 / 15.0);
    println!("PM-2b: hop {hop:.3} (uniform {expect_hop:.3}), other {other:.3} ({expect_other:.3}), both {both:.3} ({expect_both:.3}) over {epochs} epochs");
    assert!(
        (hop - expect_hop).abs() < 0.02,
        "the attacker holds the origin's hop at its uniform share: {hop} vs {expect_hop}"
    );
    assert!(
        (other - expect_other).abs() < 0.02,
        "and the other slot at the class-blind draw's: {other} vs {expect_other}"
    );
    assert!(
        (both - expect_both).abs() < 0.015,
        "and both slots at the product: {both} vs {expect_both}"
    );
}
