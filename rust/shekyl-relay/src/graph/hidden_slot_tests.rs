// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hidden-slot pin walk (`DAEMON_RELAY_PRIVACY.md` §98.3, §98.6).
//!
//! Split out of `edge` so that file stays under the line ceiling. The
//! distributional draw and the carrier tests stay there.

use super::*;

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;

fn id(byte: u8) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    ConnectionId::from_bytes(bytes)
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
        assert_eq!(
            z.stem_slots(),
            before.as_slice(),
            "the route's merge moved nothing"
        );
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
