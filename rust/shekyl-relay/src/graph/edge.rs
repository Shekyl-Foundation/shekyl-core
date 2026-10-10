// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Connector-edge behavior of one relay: hop 0, fluff fan-out, and the
//! embargo recorded for the connector a stem was forwarded on.
//!
//! Split from `tests` so that file stays under the line ceiling.

use super::*;

use shekyl_relay_privacy::basis::DerivationMs;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;

fn id(byte: u8) -> ConnectionId {
    let mut b = [0u8; 16];
    b[0] = byte;
    ConnectionId::from_bytes(b)
}

fn zone(rng: &mut SplitMix64) -> Relay {
    Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet],
        0,
        rng,
    )
    .unwrap()
}

#[test]
fn a_fluff_reaches_an_inbound_anonymity_session() {
    // D7 is deleted. A fluff floods every session except the source,
    // including an inbound peer on an anonymity edge.
    let mut rng = SplitMix64::new(77);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(id(1), PeerDirection::Inbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(
        id(3),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    assert_eq!(z.queue_fluff(&[vec![7]], None, 0, &mut rng), 3);
    assert_eq!(z.peer(&id(1)).unwrap().queued.len(), 1);
    assert_eq!(z.peer(&id(2)).unwrap().queued.len(), 1);
    assert_eq!(z.peer(&id(3)).unwrap().queued.len(), 1);

    // The same fan-out with every session on clearnet. A relay that queued
    // nothing would pass the assertions above.
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(1),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(3),
        PeerDirection::Inbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.queue_fluff(&[vec![7]], None, 0, &mut rng),
        3,
        "fluff reaches every session except the source"
    );
}

#[test]
fn a_hidden_connector_origin_does_not_draw_a_clear_edge() {
    let mut rng = SplitMix64::new(91);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    // The epoch role is irrelevant: a restricted hop 0 returns before it.
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge,
    );
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(id(2)),
    );
    // A forwarded stem draws from every outbound edge.
    let forwarded = z.plan_relay(Some(id(2)), false, NodeSync::Synchronised, &mut rng);
    assert!(matches!(forwarded, RelayPlan::Stem(_)));
}

#[test]
fn a_hidden_connector_refuses_a_stem_width_below_two() {
    let mut rng = SplitMix64::new(3);
    for stems in [0, 1] {
        let built = Relay::new(
            DandelionParams::inherited(),
            stems,
            false,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        );
        assert!(
            matches!(built, Err(RelayNewError::HiddenSlotWidth { got }) if got == stems),
            "slot 0 is reserved and the origin's pin needs an alternate: width {stems} refused"
        );
    }
    assert!(Relay::new(
        DandelionParams::inherited(),
        1,
        false,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .is_ok());
}

#[test]
fn a_restricted_hop_0_is_constant_within_the_epoch() {
    let mut rng = SplitMix64::new(3);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    for byte in 2..=4 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Tor,
            &mut rng,
        );
    }
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let first = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
    let RelayPlan::OwnEdge(dest) = first else {
        panic!("hop 0 had a hidden-address pool and returned {first:?}");
    };
    assert!((2..=4).contains(&dest.as_bytes()[0]));
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(dest),
        "the origin's pin is one peer for the epoch"
    );
    assert_eq!(
        z.stem_slots()[0],
        Some(dest),
        "and that peer is the hidden stem slot"
    );
}

#[test]
fn eight_clearnet_and_one_tor_originates_every_epoch() {
    let mut rng = SplitMix64::new(8);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    let tor = id(9);
    for byte in 1..=8 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }
    z.on_session_established(tor, PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    for _ in 0..200 {
        z.rebuild_stems(&mut rng);
        assert_eq!(
            z.stem_slots()[0],
            Some(tor),
            "the one address-hiding session holds the hidden slot every epoch (§95.3)"
        );
        assert!(
            (1..=8).contains(&z.stem_slots()[1].expect("filled").as_bytes()[0]),
            "the other slot is drawn from the rest"
        );
        let first = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        let second = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        assert_eq!(first, RelayPlan::OwnEdge(tor));
        assert_eq!(second, first);
    }
}

#[test]
fn four_hidden_peers_share_the_hidden_slot() {
    let mut rng = SplitMix64::new(4);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    for byte in 1..=4 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Tor,
            &mut rng,
        );
    }
    for byte in 5..=8 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }
    let mut counts = [0u32; 4];
    for _ in 0..200 {
        z.rebuild_stems(&mut rng);
        let first = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        let RelayPlan::OwnEdge(dest) = first else {
            panic!("hop 0 returned {first:?}");
        };
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            first
        );
        let index = dest.as_bytes()[0];
        assert!(
            (1..=4).contains(&index),
            "hidden slot {index} is not an address-hiding session"
        );
        assert_eq!(z.stem_slots()[0], Some(dest), "the origin rides slot 0");
        counts[usize::from(index - 1)] += 1;
    }
    // Equal quarters. 1.5σ on the largest of four counts rejects a uniform
    // sample often: this seed's maximum is 63 against a 59 ceiling. The
    // chi-square is the uniformity check, and the ceiling is the plain
    // statement that no peer is far from a quarter.
    let expected = 50.0_f64;
    let mut chi = 0.0_f64;
    for count in counts {
        assert!(
            count > 0,
            "a hidden peer never held the hidden slot: {counts:?}"
        );
        assert!(
            count <= 80,
            "hidden-slot count {count} is far from a quarter ({counts:?})"
        );
        let delta = f64::from(count) - expected;
        chi += delta * delta / expected;
    }
    assert!(
        chi < 11.34,
        "hidden-slot counts are not a uniform draw over the class: {counts:?} (chi {chi})"
    );
}

/// D-PR1-1 (c′) at the relay: the origin's pin is slot 0's peer plus one
/// alternate drawn from the other address-hiding sessions at its first
/// origination. A later hidden session does not re-point a live pin. When
/// the slot's peer drops, the next origination rides the alternate (merged
/// into slot 0, or found where the class-blind draw already slotted it).
/// When the alternate drops too, the pin is exhausted: `NoOwnEdge` until the
/// epoch ends, however many address-hiding sessions are up — a session
/// opened after the pin never serves the origin. The next epoch pins afresh.
#[test]
fn the_origin_pin_walks_to_its_alternate_and_then_holds_until_the_epoch() {
    for seed in 0..16 {
        let mut rng = SplitMix64::new(11 + seed);
        let mut z = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        for byte in 1..=3 {
            z.on_session_established(
                id(byte),
                PeerDirection::Outbound,
                ConnectorId::Tor,
                &mut rng,
            );
        }
        z.on_session_established(
            id(11),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
        z.rebuild_stems(&mut rng);
        let RelayPlan::OwnEdge(primary) =
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
        else {
            panic!("three address-hiding sessions and no pin");
        };
        assert_eq!(
            z.stem_slots()[0],
            Some(primary),
            "the pin's head is the hidden slot"
        );

        // A fourth hidden session opens after the pin.
        z.on_session_established(id(4), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::OwnEdge(primary),
            "a live pin is not re-pointed when another hidden session connects"
        );

        // The slot's peer drops. The next origination rides the alternate.
        z.on_connection_close(&primary);
        let RelayPlan::OwnEdge(alternate) =
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
        else {
            panic!("the alternate was live and the origin held");
        };
        assert_ne!(alternate, primary);
        assert!(
            (1..=3).contains(&alternate.as_bytes()[0]),
            "the alternate was drawn at the pin, before session 4 existed: got {alternate:?}"
        );
        assert!(
            z.stem_slots().contains(&Some(alternate)),
            "the alternate occupies a slot: moved into slot 0 by the fill, or already in slot 1"
        );
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::OwnEdge(alternate),
            "the alternate stays while it is live"
        );

        // The alternate drops too: the pin is exhausted. Two address-hiding
        // sessions are still up (the third initial one and session 4) and
        // neither serves the origin this epoch.
        z.on_connection_close(&alternate);
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::NoOwnEdge,
            "an exhausted pin holds until the epoch ends"
        );
        assert!(
            z.stem_slots()[0].is_some(),
            "slot 0 refilled from the class for relayed traffic while the origin holds"
        );
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::NoOwnEdge,
            "and keeps holding"
        );
        let forwarded = z.plan_relay(Some(id(11)), false, NodeSync::Synchronised, &mut rng);
        assert!(
            matches!(forwarded, RelayPlan::Stem(_)) || z.is_fluffing(),
            "relayed traffic still routes"
        );

        // The next epoch pins afresh over what is live.
        z.rebuild_stems(&mut rng);
        let RelayPlan::OwnEdge(fresh) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
        else {
            panic!("a new epoch with hidden sessions up pins again");
        };
        assert!(fresh == id(4) || (1..=3).contains(&fresh.as_bytes()[0]));
    }
}

/// One of the two other address-hiding sessions is the pin's alternate and
/// the other is not. Dropping one of them and then the primary shows which:
/// if it was the alternate, the pin is exhausted at the primary's drop
/// although the third session is up; if it was the third, the pin walks to
/// the live alternate untouched. Over the seeds both happen.
#[test]
fn an_alternate_that_dropped_first_leaves_the_origin_holding_at_the_primary_drop() {
    let mut exhausted = 0;
    let mut walked = 0;
    for seed in 0..24 {
        let mut rng = SplitMix64::new(31 + seed);
        let mut z = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        for byte in 1..=3 {
            z.on_session_established(
                id(byte),
                PeerDirection::Outbound,
                ConnectorId::Tor,
                &mut rng,
            );
        }
        z.rebuild_stems(&mut rng);
        let RelayPlan::OwnEdge(primary) =
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
        else {
            panic!("no pin");
        };
        let others: Vec<ConnectionId> = (1..=3).map(id).filter(|p| *p != primary).collect();
        let (dropped, kept) = (others[0], others[1]);

        z.on_connection_close(&dropped);
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::OwnEdge(primary),
            "the primary is live; nothing moves"
        );
        z.on_connection_close(&primary);
        match z.plan_relay(None, true, NodeSync::Synchronised, &mut rng) {
            RelayPlan::NoOwnEdge => {
                // `dropped` was the alternate: exhausted although `kept` is up.
                assert!(z.peer(&kept).is_some());
                exhausted += 1;
            }
            RelayPlan::OwnEdge(dest) => {
                // `dropped` was the third session: the pin walks to its live
                // alternate, which is `kept`.
                assert_eq!(dest, kept);
                walked += 1;
            }
            other => panic!("unexpected plan {other:?}"),
        }
    }
    assert!(
        exhausted > 0 && walked > 0,
        "exhausted {exhausted}, walked {walked}"
    );
}

/// The stranded state: an all-hidden node's slot 0 dies before the origin
/// has pinned, the survivor holds slot 1 and is not moved, and the origin
/// plans `OwnEdge(survivor)` from where it sits — not `NoOwnEdge`, and
/// without a merge on every origination.
#[test]
fn an_all_hidden_node_whose_slot_zero_died_before_the_pin_rides_the_survivor() {
    for seed in 0..16 {
        let mut rng = SplitMix64::new(61 + seed);
        let mut z = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        z.rebuild_stems(&mut rng);
        let dead = z.stem_slots()[0].expect("filled");
        let survivor = z.stem_slots()[1].expect("filled");
        // Slot 0's peer dies before any origination; the next outbound
        // handshake merges (a repeat of the survivor is enough).
        z.on_connection_close(&dead);
        z.update_stems(&mut rng);
        assert_eq!(
            z.stem_slots()[0],
            None,
            "no unslotted hidden session to fill slot 0"
        );
        assert_eq!(
            z.stem_slots()[1],
            Some(survivor),
            "the survivor is not moved"
        );
        let before = z.stem_slots().to_vec();
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::OwnEdge(survivor),
            "the origin pins on the address-hiding peer where it sits"
        );
        assert_eq!(z.stem_slots(), before.as_slice(), "no merge, nothing moved");
        assert_eq!(
            z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
            RelayPlan::OwnEdge(survivor)
        );
    }
}

/// The same stranded state on a mixed node: the only live address-hiding
/// session sits in slot 1 beside a clearnet peer, and the origin plans
/// `OwnEdge` on it.
#[test]
fn a_mixed_node_with_its_only_hidden_session_in_slot_one_still_plans_own_edge() {
    let mut reached = 0;
    for seed in 0..64 {
        let mut rng = SplitMix64::new(71 + seed);
        let mut z = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        z.on_session_established(
            id(11),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
        z.rebuild_stems(&mut rng);
        let dead = z.stem_slots()[0].expect("filled");
        let other = z.stem_slots()[1].expect("filled");
        if other == id(11) {
            // The class-blind draw took the clearnet peer: not the state
            // under test (slot 0 would refill from the unslotted hidden one).
            continue;
        }
        reached += 1;
        z.on_connection_close(&dead);
        z.update_stems(&mut rng);
        assert_eq!(z.stem_slots()[0], None);
        assert_eq!(
            z.stem_slots()[1],
            Some(other),
            "the only hidden session stays in slot 1"
        );
        let plan = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        assert_eq!(plan, RelayPlan::OwnEdge(other));
        assert_eq!(
            z.plan_relay(Some(id(11)), false, NodeSync::Synchronised, &mut rng),
            if z.is_fluffing() {
                RelayPlan::FluffEpoch
            } else {
                RelayPlan::Stem(other)
            },
            "relayed traffic routes over the one live slot"
        );
    }
    assert!(
        reached >= 8,
        "the hidden-in-slot-1 draw was reached {reached} times in 64"
    );
}

/// A node that originates at boot with one address-hiding session up has a
/// pin of one. If that session drops, the origin holds until the epoch ends
/// however many such sessions the dialer opens afterwards (§98.5).
#[test]
fn a_boot_pin_over_one_hidden_session_holds_after_it_drops() {
    let mut rng = SplitMix64::new(41);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(id(1))
    );
    z.on_connection_close(&id(1));
    for byte in 2..=5 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Tor,
            &mut rng,
        );
    }
    assert!(
        z.stem_slots()[0].is_some(),
        "slot 0 refilled for relayed traffic"
    );
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge,
        "a session opened after the pin never serves the origin this epoch"
    );
    z.rebuild_stems(&mut rng);
    assert!(matches!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(_)
    ));
}

/// An origination that finds no address-hiding session makes no pin, so the
/// first hidden session to arrive serves the next origination.
#[test]
fn an_origination_with_no_hidden_session_makes_no_pin() {
    let mut rng = SplitMix64::new(43);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(11),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge
    );
    z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(id(1)),
        "no pin was made on the empty slot; the arrival fills it at the merge and serves"
    );
}

/// Relayed sources are unchanged by the reserved slot: they pin over both
/// slots, hidden or not.
#[test]
fn relayed_sources_reach_both_slots_under_a_hidden_connector() {
    let mut rng = SplitMix64::new(47);
    let mut z = None;
    for _ in 0..10_000 {
        let built = Relay::new(
            DandelionParams::inherited(),
            2,
            false,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        if !built.is_fluffing() {
            z = Some(built);
            break;
        }
    }
    let mut z = z.expect("a stem epoch");
    z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(
        id(11),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let mut seen = std::collections::BTreeSet::new();
    for byte in 100..140 {
        let RelayPlan::Stem(dest) =
            z.plan_relay(Some(id(byte)), false, NodeSync::Synchronised, &mut rng)
        else {
            panic!("a stem epoch routes relayed traffic");
        };
        seen.insert(dest);
    }
    assert_eq!(
        seen.len(),
        2,
        "relayed sources reach the hidden slot and the clear slot"
    );
}

#[test]
fn the_hidden_slot_origin_uses_the_ordinary_carrier_beside_a_clearnet_slot() {
    let mut rng = SplitMix64::new(5);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        true,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    let dispatch = z.plan_dispatch(None, true, NodeSync::Synchronised, &mut rng);
    assert_eq!(dispatch.plan, RelayPlan::OwnEdge(id(2)));
    assert_eq!(
        z.stem_slots()[0],
        Some(id(2)),
        "the one address-hiding session holds slot 0; a clearnet peer the other"
    );
    assert!(z.stem_slots()[1] == Some(id(1)) || z.stem_slots()[1] == Some(id(3)));
    assert_eq!(
        dispatch.carrier,
        RelayCarrier::Ordinary,
        "no cover on Tor: the hidden slot's channel carries nothing"
    );
}

#[test]
fn a_slotted_tor_own_edge_still_leaves_immediately() {
    let mut rng = SplitMix64::new(6);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        true,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    let dispatch = z.plan_dispatch(None, true, NodeSync::Synchronised, &mut rng);
    let RelayPlan::OwnEdge(dest) = dispatch.plan else {
        panic!("hop 0 returned {:?}", dispatch.plan);
    };
    assert!(
        z.stem_slots().contains(&Some(dest)),
        "both Tor peers fill the two slots"
    );
    assert_eq!(
        dispatch.carrier,
        RelayCarrier::Ordinary,
        "no cover on Tor, even when the own-edge occupies a stem slot"
    );
}

#[test]
fn a_clearnet_slot_rides_the_cover_channel() {
    let mut rng = SplitMix64::new(5);
    let mut z = None;
    for _ in 0..10_000 {
        let built = Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        if !built.is_fluffing() {
            z = Some(built);
            break;
        }
    }
    let mut z = z.expect("a stem epoch");
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let dispatch = z.plan_dispatch(Some(id(9)), false, NodeSync::Synchronised, &mut rng);
    assert_eq!(dispatch.plan, RelayPlan::Stem(id(1)));
    assert!(
        matches!(dispatch.carrier, RelayCarrier::Noise { .. }),
        "a clearnet slot rides the cover channel, got {:?}",
        dispatch.carrier
    );
}

/// No hidden-address session: the plan is terminal, and the spare clearnet
/// peer stays out of the dead slot. A refresh would have bound it.
#[test]
fn an_empty_hidden_pool_does_not_refresh_the_stem_map() {
    let mut rng = SplitMix64::new(12);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Clearnet, ConnectorId::Tor],
        0,
        &mut rng,
    )
    .unwrap();
    for byte in 1..=3 {
        z.on_session_established(
            id(byte),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
    }
    assert_eq!(
        z.stem_slots()[0],
        None,
        "slot 0 is reserved and no session hides the address"
    );
    let slotted = z.stem_slots()[1].expect("one clearnet peer holds the other slot");
    let spare = [id(1), id(2), id(3)]
        .into_iter()
        .find(|peer| *peer != slotted)
        .expect("two peers are unslotted");
    z.on_connection_close(&slotted);
    let before = z.stem_slots().to_vec();
    assert!(
        !before.contains(&Some(spare)),
        "the spare peer is the one a refresh would bind"
    );
    assert_eq!(
        z.plan_relay_with_refresh(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge,
    );
    assert_eq!(
        z.stem_slots(),
        before.as_slice(),
        "NoOwnEdge does not refresh the stem map"
    );
}

/// A clearnet local origin has no hidden-address pool, so its first hop is
/// the stem slot. With the carrier on, that slot is the channel: the send
/// waits for cadence instead of leaving off-cadence.
#[test]
fn a_clearnet_origin_is_slot_aligned() {
    let mut rng = SplitMix64::new(13);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        2,
        true,
        &[ConnectorId::Clearnet],
        0,
        &mut rng,
    )
    .unwrap();
    z.on_session_established(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );
    let dispatch = z.plan_dispatch(None, true, NodeSync::Synchronised, &mut rng);
    assert_eq!(dispatch.plan, RelayPlan::Stem(id(1)));
    assert!(
        matches!(dispatch.carrier, RelayCarrier::Noise { .. }),
        "on a cover-bearing link the own-edge is slot-aligned, got {:?}",
        dispatch.carrier
    );
}

/// A forwarded stem on Tor takes the ordinary connection even when the
/// carrier is on. The envelope runs on the open link, not on volume cover.
#[test]
fn a_forwarded_tor_stem_takes_no_envelope() {
    let mut rng = SplitMix64::new(14);
    let mut built = None;
    for _ in 0..10_000 {
        let zone = Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            0,
            &mut rng,
        )
        .unwrap();
        if !zone.is_fluffing() {
            built = Some(zone);
            break;
        }
    }
    let mut z = built.expect("a stem epoch");
    z.on_session_established(id(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    let dispatch = z.plan_dispatch(Some(id(9)), false, NodeSync::Synchronised, &mut rng);
    assert_eq!(dispatch.plan, RelayPlan::Stem(id(1)));
    assert_eq!(
        dispatch.carrier,
        RelayCarrier::Ordinary,
        "no cover on Tor by ruling"
    );
}

fn embargo_mean(transit: DerivationMs) -> u32 {
    shekyl_relay_privacy::schedule::EmbargoTimer::adopted(&DandelionParams::adopted_for_transit_ms(
        transit,
    ))
    .mean_secs()
}

fn stem_records(connector: ConnectorId, transit: DerivationMs) {
    let mut rng = SplitMix64::new(11);
    let mut z = zone(&mut rng);
    z.on_session_established(id(1), PeerDirection::Outbound, connector, &mut rng);
    let tx = TxId::from_bytes([9u8; 32]);
    z.record_stem(&[tx], id(1), None, 0, &mut rng);
    assert_eq!(z.stem_connector(tx), Some(connector));
    assert_eq!(z.embargo_mean_secs(connector), Some(embargo_mean(transit)));
}

#[test]
fn a_clearnet_stem_records_the_clearnet_embargo() {
    stem_records(
        ConnectorId::Clearnet,
        shekyl_relay_privacy::verify_cost::ADOPTED_TRANSIT,
    );
}

#[test]
fn a_tor_stem_records_the_tor_embargo() {
    stem_records(
        ConnectorId::Tor,
        shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT,
    );
}

#[test]
fn the_longest_transit_is_the_max_of_the_assessed_entries() {
    let longest = longest_transit();
    let mut saw = false;
    for connector in ConnectorId::ALL {
        if let Some(transit) = transit_ms(*connector) {
            saw = true;
            assert!(
                longest.ms() >= transit.ms(),
                "{connector:?} at {} exceeds {}",
                transit.ms(),
                longest.ms()
            );
        }
    }
    assert!(saw, "no connector has an assessed transit");
    assert_eq!(
        longest,
        shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT
    );
}

/// Neither built column's transit is a measurement (§97). A column that
/// claimed one would have to say which path it was taken on.
#[test]
fn both_built_transits_are_labelled_assumptions() {
    for connector in ConnectorId::ALL {
        let transit = transit_ms(*connector).expect("both built columns stem");
        assert_eq!(
            transit.basis(),
            shekyl_relay_privacy::basis::AdmissibleBasis::Assumption,
            "{connector:?}"
        );
    }
}
