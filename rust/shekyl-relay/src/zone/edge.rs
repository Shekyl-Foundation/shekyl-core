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
fn a_restricted_hop_0_pins_a_slotted_anonymity_peer() {
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
    // The first outbound fills the one slot. Later peers do not displace it,
    // so the three Tor sessions are not all slotted, and the clearnet peer
    // is not slotted at all.
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
        panic!("hop 0 had an anonymity slot and returned {first:?}");
    };
    assert!(
        z.stem_slots().contains(&Some(dest)),
        "hop 0 landed on a peer the stem map did not slot"
    );
    assert_eq!(dest, id(2), "hop 0 drew a peer that does not hold the slot");
    assert_eq!(
        z.plan_relay(None, true, NodeSync::Synchronised, &mut rng),
        RelayPlan::Stem(dest),
        "the local source is pinned for the epoch"
    );
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
