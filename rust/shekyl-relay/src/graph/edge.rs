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
fn a_restricted_hop_0_is_constant_within_the_epoch() {
    let mut rng = SplitMix64::new(3);
    let mut z = Relay::new(
        DandelionParams::inherited(),
        1,
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
        "the own-edge is one peer for the epoch"
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
    let mut tor_unslotted = 0;
    for _ in 0..200 {
        z.rebuild_stems(&mut rng);
        if !z.stem_slots().contains(&Some(tor)) {
            tor_unslotted += 1;
        }
        let first = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        let second = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
        assert_eq!(first, RelayPlan::OwnEdge(tor));
        assert_eq!(second, first);
    }
    assert!(
        tor_unslotted > 100,
        "the Tor peer was absent from the stem map in only {tor_unslotted} of 200 epochs"
    );
}

#[test]
fn four_hidden_peers_share_the_own_edge() {
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
            "own-edge {index} is not in the hidden pool"
        );
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
            "a hidden peer was never the own-edge: {counts:?}"
        );
        assert!(
            count <= 80,
            "own-edge count {count} is far from a quarter ({counts:?})"
        );
        let delta = f64::from(count) - expected;
        chi += delta * delta / expected;
    }
    assert!(
        chi < 11.34,
        "own-edge counts are not a uniform draw over the pool: {counts:?} (chi {chi})"
    );
}

#[test]
fn a_dead_own_edge_is_replaced_and_a_live_one_is_not() {
    let mut rng = SplitMix64::new(11);
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
    let RelayPlan::OwnEdge(dest) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
    else {
        panic!("hop 0 had two hidden peers");
    };
    z.on_session_established(id(3), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(dest),
        "a live own-edge is not re-pointed when another hidden peer connects"
    );
    z.on_connection_close(&dest);
    let RelayPlan::OwnEdge(replaced) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
    else {
        panic!("a dead own-edge with peers still up returned no route");
    };
    assert_ne!(replaced, dest);
    assert!(
        replaced == id(1) || replaced == id(2) || replaced == id(3),
        "replacement {replaced:?} is not in the remaining pool"
    );
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::OwnEdge(replaced),
        "the replacement stays while it is live"
    );
    z.on_connection_close(&replaced);
    for byte in 1..=3 {
        let peer = id(byte);
        if peer != dest && peer != replaced {
            z.on_connection_close(&peer);
        }
    }
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::NoOwnEdge,
        "an empty hidden-address pool has nothing to draw"
    );
}

#[test]
fn an_unslotted_own_edge_uses_the_ordinary_carrier() {
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
    assert!(
        !z.stem_slots().contains(&Some(id(2))),
        "the two clearnet peers already fill the stem map"
    );
    assert_eq!(dispatch.carrier, RelayCarrier::Ordinary);
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
    let slotted: Vec<_> = z.stem_slots().iter().copied().flatten().collect();
    assert_eq!(slotted.len(), 2, "width 2 with three outbound peers");
    let spare = [id(1), id(2), id(3)]
        .into_iter()
        .find(|peer| !slotted.contains(peer))
        .expect("one peer is unslotted");
    z.on_connection_close(&slotted[0]);
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
        DerivationMs::admit(shekyl_relay_privacy::verify_cost::ADOPTED_TRANSIT),
    );
}

#[test]
fn a_tor_stem_records_the_tor_embargo() {
    stem_records(
        ConnectorId::Tor,
        DerivationMs::admit(shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT),
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
        DerivationMs::admit(shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT)
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
            shekyl_relay_privacy::basis::TimingBasis::Assumption,
            "{connector:?}"
        );
    }
}
