// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Connector-edge behavior of one relay: hop 0, fluff fan-out, and the
//! embargo recorded for the connector a stem was forwarded on.
//!
//! Split from `tests` so that file stays under the line ceiling.

use super::*;

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
        RelayPlan::NoRoute,
    );
    z.on_session_established(id(2), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(id(2)),
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
    let RelayPlan::Stem(dest) = first else {
        panic!("hop 0 had a hidden-address pool and returned {first:?}");
    };
    assert!((2..=4).contains(&dest.as_bytes()[0]));
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(dest),
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
        assert_eq!(first, RelayPlan::Stem(tor));
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
        let RelayPlan::Stem(dest) = first else {
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
    let RelayPlan::Stem(dest) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng) else {
        panic!("hop 0 had two hidden peers");
    };
    z.on_session_established(id(3), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(dest),
        "a live own-edge is not re-pointed when another hidden peer connects"
    );
    z.on_connection_close(&dest);
    let RelayPlan::Stem(replaced) = z.plan_relay(None, true, NodeSync::Synchronised, &mut rng)
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
        RelayPlan::Stem(replaced),
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
        RelayPlan::NoRoute,
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
    assert_eq!(dispatch.plan, RelayPlan::Stem(id(2)));
    assert!(
        !z.stem_slots().contains(&Some(id(2))),
        "the two clearnet peers already fill the stem map"
    );
    assert_eq!(dispatch.carrier, RelayCarrier::Ordinary);
}

#[test]
fn a_clearnet_slot_stems_on_the_ordinary_carrier() {
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
        matches!(dispatch.carrier, RelayCarrier::Ordinary),
        "a clearnet slot must not carry noise, got {:?}",
        dispatch.carrier
    );
}

fn embargo_mean(transit_ms: f64) -> u32 {
    shekyl_relay_privacy::schedule::EmbargoTimer::adopted(&DandelionParams::adopted_for_transit_ms(
        transit_ms,
    ))
    .mean_secs()
}

fn stem_records(connector: ConnectorId, transit_ms: f64) {
    let mut rng = SplitMix64::new(11);
    let mut z = zone(&mut rng);
    z.on_session_established(id(1), PeerDirection::Outbound, connector, &mut rng);
    let tx = TxId::from_bytes([9u8; 32]);
    z.record_stem(&[tx], id(1), None, 0, &mut rng);
    assert_eq!(z.stem_connector(tx), Some(connector));
    assert_eq!(
        z.embargo_mean_secs(connector),
        Some(embargo_mean(transit_ms))
    );
}

#[test]
fn a_clearnet_stem_records_the_clearnet_embargo() {
    stem_records(
        ConnectorId::Clearnet,
        shekyl_relay_privacy::verify_cost::ADOPTED_TRANSIT_ASSUMPTION_MS,
    );
}

#[test]
fn a_tor_stem_records_the_tor_embargo() {
    stem_records(
        ConnectorId::Tor,
        shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT_ASSUMPTION_MS,
    );
}

#[test]
fn the_longest_measured_transit_is_the_max_of_the_measured_entries() {
    let longest = longest_measured_transit();
    let mut saw = false;
    for connector in ConnectorId::ALL {
        if let Some(ms) = shekyl_relay_privacy::transit_ms_for_connector_index(connector.index()) {
            saw = true;
            assert!(
                longest.total_cmp(&ms).is_ge(),
                "{connector:?} at {ms} exceeds {longest}"
            );
        }
    }
    assert!(saw, "no connector has a measured transit");
    assert_eq!(
        longest.to_bits(),
        shekyl_relay_privacy::verify_cost::ANON_ZONE_TRANSIT_ASSUMPTION_MS.to_bits()
    );
}
